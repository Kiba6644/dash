"""Tests for Email Security server endpoints and status dashboard integration."""
from __future__ import annotations

import json
import tempfile
import threading
import unittest
from pathlib import Path
from urllib.request import urlopen, Request

from agentshield import server as server_mod


class TestServerMailIntegration(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.data_dir = Path(self.tmp.name)
        self.httpd = server_mod.serve(host="127.0.0.1", port=0, audit_dir=self.data_dir)
        self.port = self.httpd.server_address[1]
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        self.base = f"http://127.0.0.1:{self.port}"

    def tearDown(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.tmp.cleanup()

    def test_mail_samples_endpoint(self):
        url = f"{self.base}/api/mail/samples"
        with urlopen(url) as resp:
            self.assertEqual(resp.status, 200)
            data = json.loads(resp.read().decode())
            self.assertTrue(data.get("ok"))
            samples = data.get("samples", [])
            self.assertGreaterEqual(len(samples), 3)
            ids = [s["id"] for s in samples]
            self.assertIn("ms365_phish", ids)
            self.assertIn("ceo_wire", ids)
            self.assertIn("prompt_injection", ids)

    def test_mail_scan_and_summary_alerts(self):
        # 1. Post a high-risk phishing email to /api/mail/scan
        scan_url = f"{self.base}/api/mail/scan"
        phish_payload = {
            "from": "support@micros0ft-verify.com",
            "reply_to": "attacker@evil.com",
            "subject": "URGENT: Microsoft 365 Account Suspended - Verify your password immediately",
            "raw": "Dear user, your account has unusual activity. Click here within 24 hours to enter your password: http://bit.ly/fake-login"
        }
        req = Request(scan_url, data=json.dumps(phish_payload).encode(), headers={"Content-Type": "application/json"}, method="POST")
        with urlopen(req) as resp:
            self.assertEqual(resp.status, 200)
            data = json.loads(resp.read().decode())
            self.assertTrue(data.get("ok"))
            report = data.get("report", {})
            self.assertEqual(report.get("verdict"), "high")
            self.assertGreaterEqual(report.get("risk_score", 0), 5)
            codes = [r.get("code") for r in report.get("reasons", []) if isinstance(r, dict)]
            self.assertIn("urgency", codes)
            self.assertIn("credential_or_payment_language", codes)

        # 2. Check /api/status/summary has the email threat indexed in alerts
        summary_url = f"{self.base}/api/status/summary"
        with urlopen(summary_url) as resp:
            self.assertEqual(resp.status, 200)
            summary = json.loads(resp.read().decode())
            alerts = summary.get("alerts", [])
            mail_alerts = [a for a in alerts if a.get("category") == "email_threat"]
            self.assertGreater(len(mail_alerts), 0)
            first_alert = mail_alerts[0]
            self.assertIn("Email", first_alert["title"])
            self.assertIn(first_alert["severity"], ("HIGH", "CRITICAL"))
            self.assertIn("micros0ft-verify.com", str(first_alert))

            # Verify metrics breakdown
            m = summary.get("metrics", {})
            self.assertGreaterEqual(m.get("categories", {}).get("email_threat", 0), 1)

    def test_status_html_contains_email_defense_elements(self):
        url = f"{self.base}/status"
        with urlopen(url) as resp:
            self.assertEqual(resp.status, 200)
            html = resp.read().decode()
            self.assertIn("Agent Email Defense", html)
            self.assertIn("btn-scan-mail", html)
            self.assertIn("pipeline-tracker", html)
            self.assertIn("Email Threats", html)


if __name__ == "__main__":
    unittest.main()
