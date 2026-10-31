"""Cross-platform desktop notification dispatcher for Provenant.

Standard library only. Dispatches notifications on Windows, macOS, and Linux
using native desktop utilities in a fast, non-blocking background process.
Never raises exceptions; gracefully falls back to console warnings on failure.
"""
from __future__ import annotations

import base64
import json
import os
import shutil
import subprocess
import sys


def send_desktop_notification(title: str, message: str, severity: str = "HIGH", sync: bool = False) -> bool:
    """Send a native desktop notification without blocking.

    Args:
        title: Notification title header.
        message: Notification body text.
        severity: "LOW", "MEDIUM", "HIGH", or "CRITICAL".
        sync: If True, waits for the process to finish (useful in tests).

    Returns:
        True if the notification process was successfully launched, False if it failed
        and fell back to a console warning.
    """
    try:
        title_str = str(title).strip()
        msg_str = str(message).strip()
        sev_str = str(severity).upper()

        if sys.platform == "win32":
            exe = shutil.which("powershell.exe") or shutil.which("powershell") or "powershell"
            ps_script = f"""
$title = {json.dumps(title_str)}
$message = {json.dumps(msg_str)}
try {{
    [Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null
    $template = [Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent([Windows.UI.Notifications.ToastTemplateType]::ToastText02)
    $texts = $template.GetElementsByTagName('text')
    $texts.Item(0).AppendChild($template.CreateTextNode($title)) | Out-Null
    $texts.Item(1).AppendChild($template.CreateTextNode($message)) | Out-Null
    $toast = [Windows.UI.Notifications.ToastNotification]::new($template)
    [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier('Provenant').Show($toast)
}} catch {{
    try {{
        Add-Type -AssemblyName System.Windows.Forms
        $b = New-Object System.Windows.Forms.NotifyIcon
        $b.Icon = [System.Drawing.SystemIcons]::Warning
        $b.BalloonTipTitle = $title
        $b.BalloonTipText = $message
        $b.Visible = $True
        $b.ShowBalloonTip(3000)
        Start-Sleep -Milliseconds 500
        $b.Dispose()
    }} catch {{
        $w = New-Object -ComObject WScript.Shell
        $w.Popup($message, 3, $title, 48) | Out-Null
    }}
}}
"""
            encoded = base64.b64encode(ps_script.encode("utf-16le")).decode("ascii")
            cmd = [exe, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-EncodedCommand", encoded]
        elif sys.platform == "darwin":
            exe = shutil.which("osascript") or "osascript"
            script = f'display notification {json.dumps(msg_str)} with title {json.dumps(title_str)}'
            cmd = [exe, "-e", script]
        else:
            exe = shutil.which("notify-send")
            if not exe:
                raise FileNotFoundError("notify-send not found on this system")
            urgency = "critical" if sev_str in ("CRITICAL", "HIGH") else "normal"
            cmd = [exe, "-u", urgency, "-a", "Provenant", title_str, msg_str]

        flags = getattr(subprocess, "CREATE_NO_WINDOW", 0) if sys.platform == "win32" else 0
        proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, creationflags=flags)
        if sync:
            proc.wait(timeout=5)
        return True
    except Exception:
        try:
            sys.stderr.write(f"[Desktop Notification] {title}: {message}\n")
            sys.stderr.flush()
        except Exception:
            pass
        return False
