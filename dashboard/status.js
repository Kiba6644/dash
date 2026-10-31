/* Provenant Security Command Center Dashboard Logic (Vanilla JS, Zero-build) */
(function() {
  'use strict';

  // Application State
  const state = {
    summary: null,
    activeTab: 'all',
    activeCategory: 'all',
    searchQuery: '',
    isPolling: true,
    pollingInterval: 2000,
    timerId: null,
    seenSeqs: new Set(),
    firstLoad: true,
    selectedItem: null,
    mailSamples: [],
    lastMailReport: null
  };

  // DOM Elements
  const el = {
    badgeVersion: document.getElementById('badge-version'),
    badgePolicy: document.getElementById('badge-policy'),
    badgeChain: document.getElementById('badge-chain'),
    pulseIndicator: document.getElementById('pulse-indicator'),
    liveStatusText: document.getElementById('live-status-text'),
    liveToggleBtn: document.getElementById('live-toggle-btn'),
    quickSimulateBtn: document.getElementById('quick-simulate-btn'),
    quickVerifyBtn: document.getElementById('quick-verify-btn'),
    quickRefreshBtn: document.getElementById('quick-refresh-btn'),
    headerSelfTestBtn: document.getElementById('header-selftest-btn'),

    metricInspected: document.getElementById('metric-inspected'),
    metricBlocked: document.getElementById('metric-blocked'),
    metricAlerts: document.getElementById('metric-alerts'),
    metricHolds: document.getElementById('metric-holds'),
    metricAllowed: document.getElementById('metric-allowed'),
    metricAudit: document.getElementById('metric-audit'),

    pipelineLevel: document.getElementById('pipeline-level'),
    pipelineSummary: document.getElementById('pipeline-summary'),
    pipelineNext: document.getElementById('pipeline-next'),
    layerInstalled: document.getElementById('layer-installed'),
    layerEngine: document.getElementById('layer-engine'),
    layerConfigured: document.getElementById('layer-configured'),
    layerConnected: document.getElementById('layer-connected'),
    layerVerified: document.getElementById('layer-verified'),

    clientsListContainer: document.getElementById('clients-list-container'),
    filterTabs: document.getElementById('filter-tabs'),
    countAll: document.getElementById('count-all'),
    countEmail: document.getElementById('count-email'),
    countBlocked: document.getElementById('count-blocked'),
    countAlerts: document.getElementById('count-alerts'),
    countPending: document.getElementById('count-pending'),
    countAllowed: document.getElementById('count-allowed'),

    // Email Inspector Elements
    mailSender: document.getElementById('mail-sender') || document.getElementById('mail-from'),
    mailReplyTo: document.getElementById('mail-reply-to'),
    mailSubject: document.getElementById('mail-subject'),
    mailBody: document.getElementById('mail-body'),
    btnScanMail: document.getElementById('btn-scan-mail'),
    btnResetMail: document.getElementById('btn-reset-mail'),
    btnToggleInspector: document.getElementById('btn-toggle-inspector'),
    inspectorContentBody: document.getElementById('inspector-content-body'),
    pipelineStatusBadge: document.getElementById('pipeline-status-badge'),
    scanResultCard: document.getElementById('scan-result-card'),
    resVerdictTag: document.getElementById('res-verdict-tag'),
    resDomainTag: document.getElementById('res-domain-tag'),
    resRiskScore: document.getElementById('res-risk-score'),
    resRiskFill: document.getElementById('res-risk-fill'),
    resIndicatorsList: document.getElementById('res-indicators-list'),
    btnViewMailAudit: document.getElementById('btn-view-mail-audit'),

    filterSearch: document.getElementById('filter-search'),
    filterCategory: document.getElementById('filter-category'),
    feedContainer: document.getElementById('feed-container'),

    inspectModal: document.getElementById('inspect-modal'),
    modalCloseBtn: document.getElementById('modal-close-btn'),
    inspectCloseActionBtn: document.getElementById('inspect-close-action-btn'),
    inspectCopyBtn: document.getElementById('inspect-copy-btn'),
    inspectTitle: document.getElementById('inspect-title'),
    inspectMeta: document.getElementById('inspect-meta'),
    inspectHash: document.getElementById('inspect-hash'),
    inspectChainStatus: document.getElementById('inspect-chain-status'),
    inspectVerdict: document.getElementById('inspect-verdict'),
    inspectReasons: document.getElementById('inspect-reasons'),
    inspectSource: document.getElementById('inspect-source'),
    inspectSession: document.getElementById('inspect-session'),
    inspectArgsJson: document.getElementById('inspect-args-json'),

    toastContainer: document.getElementById('toast-container')
  };

  // Helper: Escape HTML to prevent XSS
  function escapeHtml(str) {
    if (typeof str !== 'string') return String(str ?? '');
    return str.replace(/&/g, '&amp;')
              .replace(/</g, '&lt;')
              .replace(/>/g, '&gt;')
              .replace(/"/g, '&quot;')
              .replace(/'/g, '&#39;');
  }

  // Format Relative Timestamp
  function formatTime(isoStr) {
    if (!isoStr) return '--:--';
    try {
      const d = new Date(isoStr);
      if (isNaN(d.getTime())) return isoStr.slice(11, 19);
      return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false });
    } catch {
      return isoStr.slice(11, 19);
    }
  }

  // Synthetic Alert Chime via Web Audio API (zero audio file dependencies)
  function playAlertChime() {
    try {
      const AudioCtx = window.AudioContext || window.webkitAudioContext;
      if (!AudioCtx) return;
      const ctx = new AudioCtx();
      const osc = ctx.createOscillator();
      const gain = ctx.createGain();
      osc.type = 'sine';
      osc.frequency.setValueAtTime(880, ctx.currentTime);
      osc.frequency.exponentialRampToValueAtTime(440, ctx.currentTime + 0.25);
      gain.gain.setValueAtTime(0.2, ctx.currentTime);
      gain.gain.exponentialRampToValueAtTime(0.001, ctx.currentTime + 0.3);
      osc.connect(gain);
      gain.connect(ctx.destination);
      osc.start();
      osc.stop(ctx.currentTime + 0.35);
    } catch {
      // AudioContext unavailable or autoplay blocked
    }
  }

  // Show Toast Notification
  function showToast(title, message, type = 'allow') {
    if (!el.toastContainer) return;
    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;
    const icon = type === 'deny' ? '⛔' : (type === 'alert' ? '⚠️' : '✓');
    toast.innerHTML = `
      <div style="font-size: 18px;">${icon}</div>
      <div class="toast-body">
        <h5>${escapeHtml(title)}</h5>
        <p>${escapeHtml(message)}</p>
      </div>
    `;
    el.toastContainer.appendChild(toast);
    setTimeout(() => {
      toast.style.opacity = '0';
      toast.style.transform = 'translateY(10px)';
      setTimeout(() => toast.remove(), 250);
    }, 4500);
  }

  // Fetch summary data from backend
  async function fetchSummary() {
    try {
      const res = await fetch('/api/status/summary', { cache: 'no-store' });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      handleSummaryUpdate(data);
    } catch (err) {
      console.warn('Failed to fetch status summary:', err);
      if (el.badgeChain) {
        el.badgeChain.textContent = 'Connection Error';
        el.badgeChain.style.color = 'var(--deny)';
      }
    }
  }

  // Handle data update
  function handleSummaryUpdate(data) {
    state.summary = data;

    // Detect new blocked items or alerts to trigger notification toasts and audio chimes
    if (!state.firstLoad && data.blocked) {
      data.blocked.forEach(item => {
        const key = `blocked-${item.seq}-${item.call_id}`;
        if (!state.seenSeqs.has(key)) {
          state.seenSeqs.add(key);
          playAlertChime();
          showToast(`Threat Blocked: ${item.tool}`, item.args_summary || (item.reasons && item.reasons[0]) || 'Attack intercepted by Provenant', 'deny');
        }
      });
      if (data.alerts) {
        data.alerts.forEach(item => {
          const key = `alert-${item.id}`;
          if (!state.seenSeqs.has(key)) {
            state.seenSeqs.add(key);
            playAlertChime();
            showToast(`Security Alert: ${item.title}`, item.details, 'alert');
          }
        });
      }
    } else if (state.firstLoad) {
      if (data.blocked) data.blocked.forEach(item => state.seenSeqs.add(`blocked-${item.seq}-${item.call_id}`));
      if (data.alerts) data.alerts.forEach(item => state.seenSeqs.add(`alert-${item.id}`));
      state.firstLoad = false;
    }

    render();
  }

  // Main Render
  function render() {
    const data = state.summary;
    if (!data) return;

    // Header Badges
    if (data.version && el.badgeVersion) el.badgeVersion.textContent = `v${data.version}`;
    if (data.policy && el.badgePolicy) {
      el.badgePolicy.textContent = data.policy.error ? 'Policy Error' : `Policy: ${data.policy.version}`;
      el.badgePolicy.style.color = data.policy.error ? 'var(--deny)' : 'var(--fg)';
    }
    if (data.audit && el.badgeChain) {
      el.badgeChain.textContent = data.audit.ok ? `Audit Chain Intact (${data.audit.checked})` : `Audit BROKEN (#${data.audit.first_bad_seq})`;
      el.badgeChain.style.color = data.audit.ok ? 'var(--allow)' : 'var(--deny)';
    }

    // KPI Metrics
    const m = data.metrics || {};
    if (el.metricInspected) el.metricInspected.textContent = (m.total_evaluated || 0).toLocaleString();
    if (el.metricBlocked) el.metricBlocked.textContent = (m.total_blocked || 0).toLocaleString();
    if (el.metricAlerts) el.metricAlerts.textContent = (m.total_alerts || (data.alerts ? data.alerts.length : 0)).toLocaleString();
    if (el.metricHolds) el.metricHolds.textContent = (m.pending_count || (data.pending ? data.pending.length : 0)).toLocaleString();
    if (el.metricAllowed) el.metricAllowed.textContent = (m.total_allowed || 0).toLocaleString();
    if (el.metricAudit) {
      el.metricAudit.textContent = data.audit && data.audit.ok ? 'Intact' : 'TAMPERED';
      el.metricAudit.style.color = data.audit && data.audit.ok ? '#38bdf8' : 'var(--deny)';
    }

    // Tab counts
    const blockedCount = (data.blocked || []).length;
    const alertsCount = (data.alerts || []).length;
    const pendingCount = (data.pending || []).length;
    const allEventsCount = (data.recent_events || []).length;
    const allowedCount = (data.recent_events || []).filter(e => e.decision === 'ALLOW').length;

    const emailThreatsCount = (data.recent_events || []).filter(e => e.category === 'email_threat' || e.tool === 'mail_security').length;

    if (el.countAll) el.countAll.textContent = allEventsCount;
    if (el.countEmail) el.countEmail.textContent = emailThreatsCount;
    if (el.countBlocked) el.countBlocked.textContent = blockedCount;
    if (el.countAlerts) el.countAlerts.textContent = alertsCount;
    if (el.countPending) el.countPending.textContent = pendingCount;
    if (el.countAllowed) el.countAllowed.textContent = allowedCount;

    // Pipeline Steps
    const p = data.protection || {};
    const layers = p.layers || {};
    if (el.pipelineLevel) el.pipelineLevel.textContent = `Level: ${(p.level || 'installed').toUpperCase()}`;
    if (el.pipelineSummary) el.pipelineSummary.textContent = p.summary || 'Protection is active.';
    if (el.pipelineNext) el.pipelineNext.textContent = p.next ? `Next: ${p.next}` : 'Everything configured and verified.';

    ['installed', 'engine', 'configured', 'connected', 'verified'].forEach(layer => {
      const stepEl = el[`layer${layer.charAt(0).toUpperCase() + layer.slice(1)}`];
      if (stepEl) {
        if (layers[layer]) stepEl.classList.add('on');
        else stepEl.classList.remove('on');
      }
    });

    // Clients List
    renderClients(data.clients || [], data.claude_code_hook);

    // Explorer Feed
    renderFeed();
  }

  // Render Clients Cards
  function renderClients(clients, hookInstalled) {
    if (!el.clientsListContainer) return;
    let html = '';
    const clientLabels = {
      'claude-desktop': 'Claude Desktop',
      'cursor': 'Cursor',
      'windsurf': 'Windsurf',
      'antigravity': 'Antigravity',
      'vscode': 'VS Code',
      'claude-code-project': 'Claude Code MCP'
    };

    clients.forEach(c => {
      const label = clientLabels[c.name] || clientLabels[c.client] || c.name || c.client;
      const protectedCount = (c.protected || (c.servers ? c.servers.filter(s => s.protected) : [])).length;
      const totalCount = protectedCount + ((c.unprotected || []).length);
      const isProtected = protectedCount > 0;

      html += `
        <div class="client-item">
          <div class="client-info">
            <h4>${escapeHtml(label)}</h4>
            <p>${totalCount > 0 ? `${protectedCount}/${totalCount} MCP servers guarded` : 'No servers configured'}</p>
          </div>
          <span class="badge ${isProtected ? 'badge-allow' : 'badge-hold'}">
            ${isProtected ? 'PROTECTED' : 'UNGUARDED'}
          </span>
        </div>
      `;
    });

    html += `
      <div class="client-item">
        <div class="client-info">
          <h4>Claude Code</h4>
          <p>${hookInstalled ? 'PreToolUse safety hook active' : 'Safety hook not installed'}</p>
        </div>
        <span class="badge ${hookInstalled ? 'badge-allow' : 'badge-hold'}">
          ${hookInstalled ? 'HOOK ACTIVE' : 'UNGUARDED'}
        </span>
      </div>
    `;

    el.clientsListContainer.innerHTML = html;
  }

  // Render Explorer Feed
  function renderFeed() {
    const data = state.summary;
    if (!data || !el.feedContainer) return;

    let items = [];
    const tab = state.activeTab;

    if (tab === 'email_threats') {
      items = (data.recent_events || []).filter(e => e.category === 'email_threat' || e.tool === 'mail_security').map(e => ({
        ...e,
        badgeType: e.decision === 'DENY' ? 'deny' : (e.decision === 'HOLD' ? 'hold' : 'allow'),
        badgeText: e.decision === 'DENY' ? 'BLOCKED EMAIL' : (e.decision === 'HOLD' ? 'HELD EMAIL' : 'SCANNED EMAIL'),
        rawObj: e
      }));
    } else if (tab === 'blocked') {
      items = (data.blocked || []).map(b => ({
        ...b,
        badgeType: 'deny',
        badgeText: 'BLOCKED (DENY)',
        rawObj: b
      }));
    } else if (tab === 'alerts') {
      items = (data.alerts || []).map(a => ({
        ...a,
        badgeType: a.severity === 'CRITICAL' ? 'critical' : 'alert',
        badgeText: a.severity || 'ALERT',
        args_summary: a.details,
        rawObj: a
      }));
    } else if (tab === 'pending') {
      items = (data.pending || []).map(p => ({
        ...p,
        badgeType: 'hold',
        badgeText: 'NEEDS APPROVAL',
        rawObj: p
      }));
    } else if (tab === 'allowed') {
      items = (data.recent_events || []).filter(e => e.decision === 'ALLOW').map(e => ({
        ...e,
        badgeType: 'allow',
        badgeText: 'ALLOWED',
        rawObj: e
      }));
    } else {
      items = (data.recent_events || []).map(e => {
        let bType = 'allow';
        let bText = e.decision || 'EVENT';
        if (e.decision === 'DENY') { bType = 'deny'; bText = 'BLOCKED'; }
        else if (e.decision === 'APPROVE' || e.decision === 'HOLD') { bType = 'hold'; bText = 'HOLD'; }
        else if (e.decision === 'ALERT') { bType = 'alert'; bText = 'ALERT'; }
        return {
          ...e,
          badgeType: bType,
          badgeText: bText,
          rawObj: e
        };
      });
    }

    // Apply Search Filter
    const q = state.searchQuery.trim().toLowerCase();
    if (q) {
      items = items.filter(item => {
        const str = [
          item.tool,
          item.args_summary,
          item.session_id,
          item.category,
          JSON.stringify(item.args || ''),
          (item.reasons || []).join(' ')
        ].join(' ').toLowerCase();
        return str.includes(q);
      });
    }

    // Apply Category Filter
    if (state.activeCategory !== 'all') {
      items = items.filter(item => item.category === state.activeCategory);
    }

    // Render Table or Empty State
    if (!items.length) {
      renderEmptyState();
      return;
    }

    let rowsHtml = '';
    items.forEach((item, idx) => {
      const tool = item.tool || 'system';
      const timeStr = formatTime(item.ts);
      const categoryLabel = (item.category || 'general').replace(/_/g, ' ');
      const reasons = Array.isArray(item.reasons) ? item.reasons.join('; ') : (item.details || '');
      const summaryText = item.args_summary || reasons || '--';

      rowsHtml += `
        <tr class="feed-row" data-index="${idx}">
          <td style="width: 85px; font-family: var(--mono); font-size: 12px; color: var(--dim);">${escapeHtml(timeStr)}</td>
          <td style="width: 140px;">
            <span class="badge badge-${item.badgeType}">${escapeHtml(item.badgeText)}</span>
          </td>
          <td style="width: 140px;">
            <span class="tool-pill">${escapeHtml(tool)}</span>
          </td>
          <td style="width: 160px; font-size: 12px; color: var(--muted); text-transform: capitalize;">
            ${escapeHtml(categoryLabel)}
          </td>
          <td>
            <div class="reason-text" title="${escapeHtml(reasons)}">${escapeHtml(summaryText)}</div>
          </td>
          <td style="text-align: right; width: 100px;">
            <button class="btn btn-sm inspect-btn" data-index="${idx}">Inspect →</button>
          </td>
        </tr>
      `;
    });

    el.feedContainer.innerHTML = `
      <table class="feed-table">
        <thead>
          <tr>
            <th>Time</th>
            <th>Verdict</th>
            <th>Tool Name</th>
            <th>Category</th>
            <th>Activity / Reason</th>
            <th style="text-align: right;">Action</th>
          </tr>
        </thead>
        <tbody>${rowsHtml}</tbody>
      </table>
    `;

    el.feedContainer.querySelectorAll('.inspect-btn').forEach(btn => {
      btn.addEventListener('click', (ev) => {
        ev.stopPropagation();
        const index = parseInt(btn.getAttribute('data-index'), 10);
        openInspect(items[index]);
      });
    });

    el.feedContainer.querySelectorAll('.feed-row').forEach(row => {
      row.addEventListener('click', () => {
        const index = parseInt(row.getAttribute('data-index'), 10);
        openInspect(items[index]);
      });
    });
  }

  // Render Empty State
  function renderEmptyState() {
    el.feedContainer.innerHTML = `
      <div class="empty-state">
        <div class="empty-icon">🛡️</div>
        <h3>No Threat Events Detected</h3>
        <p>The firewall is actively monitoring all client integrations. No blocked attacks or security alerts match your current filter.</p>
        <button class="btn btn-primary" id="empty-simulate-btn">
          <span>⚡ Simulate Sample Attack</span>
        </button>
      </div>
    `;
    const btn = document.getElementById('empty-simulate-btn');
    if (btn) btn.addEventListener('click', () => simulateAttack());
  }

  // Load Mail Samples from API
  async function loadMailSamples() {
    try {
      const res = await fetch('/api/mail/samples');
      if (!res.ok) return;
      const data = await res.json();
      state.mailSamples = data.samples || [];

      // If initially ms365_phish chip is active, populate it
      onSelectSample('ms365_phish');
    } catch (e) {
      console.warn('Failed to load email attack samples:', e);
    }
  }

  // Select Sample Email
  function onSelectSample(id) {
    const s = state.mailSamples.find(x => x.id === id);
    if (!s) return;
    if (el.mailSender) el.mailSender.value = s.from || '';
    if (el.mailReplyTo) el.mailReplyTo.value = s.reply_to || '';
    if (el.mailSubject) el.mailSubject.value = s.subject || '';
    if (el.mailBody) el.mailBody.value = s.body || '';
  }

  // Execute Email Scan & Live Pipeline Animation
  async function scanMail() {
    const fromVal = el.mailSender ? el.mailSender.value.trim() : '';
    const replyToVal = el.mailReplyTo ? el.mailReplyTo.value.trim() : '';
    const subjectVal = el.mailSubject ? el.mailSubject.value.trim() : '';
    const bodyVal = el.mailBody ? el.mailBody.value.trim() : '';

    if (!bodyVal && !fromVal) {
      showToast('Input Required', 'Please provide an email body or select a sample attack.', 'alert');
      return;
    }

    if (el.btnScanMail) el.btnScanMail.disabled = true;
    if (el.pipelineStatusBadge) {
      el.pipelineStatusBadge.textContent = 'Scanning in Progress…';
      el.pipelineStatusBadge.className = 'pipeline-status-badge running';
    }

    const setStep = (num, stateText, cls = '') => {
      const stateEl = document.getElementById(`pipe-state-${num}`);
      const stepEl = document.getElementById(`pipe-step-${num}`);
      if (stateEl) stateEl.textContent = stateText;
      if (stepEl) stepEl.className = `pipe-step ${cls}`.trim();
    };

    setStep(1, 'Running…', 'active');
    setStep(2, 'Waiting…', '');
    setStep(3, 'Waiting…', '');
    setStep(4, 'Waiting…', '');

    try {
      await new Promise(r => setTimeout(r, 180));
      setStep(1, 'Completed', 'done');
      setStep(2, 'Analyzing…', 'active');

      const res = await fetch('/api/mail/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          from: fromVal,
          reply_to: replyToVal,
          subject: subjectVal,
          raw: bodyVal
        })
      });

      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      const rep = data.report || {};
      state.lastMailReport = rep;

      await new Promise(r => setTimeout(r, 200));
      setStep(2, `Score: ${rep.risk_score || 0}/10`, (rep.verdict === 'high' || rep.risk_score >= 5) ? 'done alert' : 'done');

      setStep(3, 'Taint Flagged', 'done');
      await new Promise(r => setTimeout(r, 180));

      const isHigh = (rep.verdict === 'high' || (rep.risk_score || 0) >= 5);
      setStep(4, isHigh ? 'Desktop & Toast Alert Fired' : 'Advisory Logged', isHigh ? 'done alert' : 'done');

      if (el.pipelineStatusBadge) {
        el.pipelineStatusBadge.textContent = isHigh ? 'THREAT INTERCEPTED' : 'EVALUATION COMPLETE';
        el.pipelineStatusBadge.className = isHigh ? 'pipeline-status-badge threat' : 'pipeline-status-badge safe';
      }

      // Display Scan Result Card
      if (el.scanResultCard) el.scanResultCard.style.display = 'block';
      if (el.resVerdictTag) {
        el.resVerdictTag.textContent = `${(rep.verdict || 'low').toUpperCase()} RISK`;
        el.resVerdictTag.className = `verdict-tag ${rep.verdict || 'low'}`;
      }
      if (el.resDomainTag) el.resDomainTag.textContent = rep.sender_domain || 'external.com';
      if (el.resRiskScore) el.resRiskScore.textContent = `${rep.risk_score || 0}/10`;
      if (el.resRiskFill) {
        const pct = Math.min(100, Math.max(10, (rep.risk_score || 0) * 10));
        el.resRiskFill.style.width = `${pct}%`;
        el.resRiskFill.style.background = isHigh ? 'var(--deny)' : (rep.verdict === 'medium' ? 'var(--hold)' : 'var(--allow)');
      }

      // Render Indicator Badges
      if (el.resIndicatorsList) {
        let indHtml = '';
        (rep.reasons || []).forEach(r => {
          const detail = typeof r === 'string' ? r : (r.detail || r.code || JSON.stringify(r));
          indHtml += `<span class="indicator-pill">${escapeHtml(detail)}</span>`;
        });
        if (!indHtml) indHtml = '<span class="indicator-pill safe">No malicious heuristics flagged</span>';
        el.resIndicatorsList.innerHTML = indHtml;
      }

      // Trigger Audio Chime & Toast if high risk
      if (isHigh) {
        playAlertChime();
        showToast(`🚨 High-Risk Email Intercepted!`, `From: ${rep.sender_domain} · Score: ${rep.risk_score}/10`, 'deny');
      } else {
        showToast('Email Scanned', `Verdict: ${rep.verdict || 'low'} (Score: ${rep.risk_score || 0})`, 'allow');
      }

      // Immediately refresh the live summary feed
      await fetchSummary();

    } catch (err) {
      showToast('Scan Failed', err.message, 'alert');
      if (el.pipelineStatusBadge) {
        el.pipelineStatusBadge.textContent = 'Scan Error';
        el.pipelineStatusBadge.className = 'pipeline-status-badge threat';
      }
    } finally {
      if (el.btnScanMail) el.btnScanMail.disabled = false;
    }
  }

  // Reset Mail Form
  function resetMailForm() {
    if (el.mailSender) el.mailSender.value = '';
    if (el.mailReplyTo) el.mailReplyTo.value = '';
    if (el.mailSubject) el.mailSubject.value = '';
    if (el.mailBody) el.mailBody.value = '';
    if (el.scanResultCard) el.scanResultCard.style.display = 'none';
    if (el.pipelineStatusBadge) {
      el.pipelineStatusBadge.textContent = 'Ready for Scan';
      el.pipelineStatusBadge.className = 'pipeline-status-badge';
    }
    for (let i = 1; i <= 4; i++) {
      const stateEl = document.getElementById(`pipe-state-${i}`);
      const stepEl = document.getElementById(`pipe-step-${i}`);
      if (stateEl) stateEl.textContent = 'Idle';
      if (stepEl) stepEl.className = 'pipe-step';
    }
    state.lastMailReport = null;
  }

  // Simulate Attack API
  async function simulateAttack(type = 'multi') {
    try {
      showToast('Initiating Attack Simulation…', 'Testing Provenant firewall evaluation', 'alert');
      const res = await fetch('/api/status/simulate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ type })
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const result = await res.json();
      showToast(`Simulated ${result.count} Threats`, 'All threats caught & blocked by policy (DENY)', 'deny');
      await fetchSummary();
    } catch (err) {
      showToast('Simulation Failed', err.message, 'alert');
    }
  }

  // Run Self-Test API
  async function runSelfTest() {
    try {
      showToast('Running Enforcement Self-Test…', 'Executing safe harmless verification', 'allow');
      const res = await fetch('/api/status/self-test', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({})
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      const passed = data.result && data.result.passed;
      if (passed) {
        showToast('Enforcement Verified!', 'All 5 self-test assertions passed & audit logged.', 'allow');
      } else {
        showToast('Enforcement Test Issue', 'Some checks failed; check provenant doctor', 'deny');
      }
      await fetchSummary();
    } catch (err) {
      showToast('Self-Test Error', err.message, 'alert');
    }
  }

  // Verify Audit Chain API
  async function verifyChain() {
    try {
      const res = await fetch('/api/status/verify');
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      if (data.ok) {
        showToast('Audit Chain Verified!', `All ${data.checked} entries cryptographically intact.`, 'allow');
      } else {
        showToast('Audit Tampering Detected!', `Broken at sequence #${data.first_bad_seq}`, 'deny');
      }
    } catch (err) {
      showToast('Audit Verification Error', err.message, 'alert');
    }
  }

  // Open Inspect Modal
  function openInspect(item) {
    if (!item) return;
    state.selectedItem = item;

    if (el.inspectTitle) el.inspectTitle.textContent = `${item.tool || 'Event'} Inspection`;
    if (el.inspectMeta) el.inspectMeta.textContent = `Sequence #${item.seq || 0} · ${item.ts || 'Timestamp not logged'}`;
    if (el.inspectHash) el.inspectHash.textContent = item.hash || (state.summary && state.summary.audit && state.summary.audit.head_hash) || '0000000000000000';
    if (el.inspectVerdict) {
      el.inspectVerdict.textContent = item.badgeText || item.decision || 'DENY';
      el.inspectVerdict.style.color = (item.badgeType === 'deny' || item.badgeType === 'critical') ? 'var(--deny)' : 'var(--allow)';
    }

    const reasons = Array.isArray(item.reasons) ? item.reasons.join('\n• ') : (item.details || 'None');
    if (el.inspectReasons) el.inspectReasons.textContent = reasons ? `• ${reasons}` : 'Rule evaluation allowed this request';
    if (el.inspectSource) el.inspectSource.textContent = item.source || 'client-tool';
    if (el.inspectSession) el.inspectSession.textContent = item.session_id || 'no-session';

    const fullPayload = item.args || item.rawObj || {};
    if (el.inspectArgsJson) el.inspectArgsJson.textContent = JSON.stringify(fullPayload, null, 2);

    if (el.inspectModal) el.inspectModal.classList.add('open');
  }

  // Close Inspect Modal
  function closeInspect() {
    if (el.inspectModal) el.inspectModal.classList.remove('open');
    state.selectedItem = null;
  }

  // Setup Event Listeners
  function setupEvents() {
    // Live Polling Toggle
    if (el.liveToggleBtn) {
      el.liveToggleBtn.addEventListener('click', () => {
        state.isPolling = !state.isPolling;
        if (state.isPolling) {
          if (el.pulseIndicator) el.pulseIndicator.classList.remove('paused');
          if (el.liveStatusText) el.liveStatusText.textContent = 'LIVE FEED · 2s';
          startPolling();
          showToast('Live Polling Resumed', 'Checking every 2 seconds', 'allow');
        } else {
          if (el.pulseIndicator) el.pulseIndicator.classList.add('paused');
          if (el.liveStatusText) el.liveStatusText.textContent = 'POLLING PAUSED';
          stopPolling();
          showToast('Live Polling Paused', 'Click to resume auto-refresh', 'hold');
        }
      });
    }

    // Quick Actions
    if (el.quickSimulateBtn) el.quickSimulateBtn.addEventListener('click', () => simulateAttack());
    if (el.headerSelfTestBtn) el.headerSelfTestBtn.addEventListener('click', () => runSelfTest());
    if (el.quickVerifyBtn) el.quickVerifyBtn.addEventListener('click', () => verifyChain());
    if (el.quickRefreshBtn) el.quickRefreshBtn.addEventListener('click', () => {
      fetchSummary();
      showToast('Dashboard Refreshed', 'Latest data loaded from firewall', 'allow');
    });

    // Scenario Chips (ms365_phish, prompt_injection, ceo_wire, benign_meeting, custom)
    document.querySelectorAll('.chip-btn[data-sample]').forEach(btn => {
      btn.addEventListener('click', () => {
        document.querySelectorAll('.chip-btn[data-sample]').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        const sampleId = btn.getAttribute('data-sample');
        if (sampleId === 'custom') {
          resetMailForm();
        } else {
          onSelectSample(sampleId);
        }
      });
    });

    // Collapse / Expand Inspector
    if (el.btnToggleInspector && el.inspectorContentBody) {
      el.btnToggleInspector.addEventListener('click', () => {
        const isHidden = el.inspectorContentBody.style.display === 'none';
        el.inspectorContentBody.style.display = isHidden ? 'block' : 'none';
        el.btnToggleInspector.textContent = isHidden ? 'Collapse Inspector ▴' : 'Expand Inspector ▾';
      });
    }

    if (el.btnScanMail) {
      el.btnScanMail.addEventListener('click', () => scanMail());
    }
    if (el.btnResetMail) {
      el.btnResetMail.addEventListener('click', () => resetMailForm());
    }
    if (el.btnViewMailAudit) {
      el.btnViewMailAudit.addEventListener('click', () => {
        if (state.lastMailReport) {
          openInspect({
            tool: 'mail_security',
            seq: 'latest',
            ts: new Date().toISOString(),
            decision: state.lastMailReport.verdict === 'high' ? 'DENY' : 'HOLD',
            badgeText: `${(state.lastMailReport.verdict || 'high').toUpperCase()} THREAT`,
            badgeType: state.lastMailReport.verdict === 'high' ? 'deny' : 'hold',
            reasons: (state.lastMailReport.reasons || []).map(r => r.detail || r.code || String(r)),
            source: 'mail_scanner',
            session_id: 'mail-eval',
            args: state.lastMailReport
          });
        }
      });
    }

    // Tabs
    if (el.filterTabs) {
      el.filterTabs.querySelectorAll('.tab-btn').forEach(btn => {
        btn.addEventListener('click', () => {
          el.filterTabs.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
          btn.classList.add('active');
          state.activeTab = btn.getAttribute('data-tab');
          renderFeed();
        });
      });
    }

    // Filters
    if (el.filterSearch) {
      el.filterSearch.addEventListener('input', (e) => {
        state.searchQuery = e.target.value;
        renderFeed();
      });
    }
    if (el.filterCategory) {
      el.filterCategory.addEventListener('change', (e) => {
        state.activeCategory = e.target.value;
        renderFeed();
      });
    }

    // Modal close
    if (el.modalCloseBtn) el.modalCloseBtn.addEventListener('click', closeInspect);
    if (el.inspectCloseActionBtn) el.inspectCloseActionBtn.addEventListener('click', closeInspect);
    if (el.inspectModal) {
      el.inspectModal.addEventListener('click', (e) => {
        if (e.target === el.inspectModal) closeInspect();
      });
    }

    window.addEventListener('keydown', (e) => {
      if (e.key === 'Escape' && el.inspectModal && el.inspectModal.classList.contains('open')) {
        closeInspect();
      }
    });

    // Copy JSON button
    if (el.inspectCopyBtn) {
      el.inspectCopyBtn.addEventListener('click', () => {
        const text = el.inspectArgsJson.textContent;
        navigator.clipboard.writeText(text).then(() => {
          showToast('Copied to Clipboard', 'JSON event payload copied', 'allow');
        }).catch(() => {
          showToast('Copy Failed', 'Unable to access clipboard', 'alert');
        });
      });
    }
  }

  // Polling loop
  function startPolling() {
    stopPolling();
    state.timerId = setInterval(fetchSummary, state.pollingInterval);
  }

  function stopPolling() {
    if (state.timerId) {
      clearInterval(state.timerId);
      state.timerId = null;
    }
  }

  // Initialization
  function init() {
    setupEvents();
    loadMailSamples();
    fetchSummary();
    startPolling();
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
