/**
 * CloudGuard: Core Application Logic & State Orchestrator
 */

class CloudGuardApp {
  constructor() {
    this.state = {
      scenario: 'vulnerable',
      threat_level: 'CRITICAL',
      controls: {
        ssrf_protection: false,
        imds_version: 'v1',
        iam_least_privilege: false,
        s3_bucket_policy: false
      },
      iam_role: {},
      harvested_credentials: null,
      exfiltrated_records: []
    };

    this.stepResults = [null, null, null, null];
    this.topology = null;
    this.terminal = null;

    this.init();
  }

  async init() {
    this.bindTabNavigation();
    this.bindHeaderControls();
    this.bindAttackPipeline();
    this.bindToggles();

    // Initialize Canvas Topology & Terminal
    this.topology = new CloudTopology('topologyCanvas');
    this.terminal = new CloudTerminal('terminalBody', 'terminalInput');

    // Fetch initial status, policies, and educational info
    await this.refreshStatus();
    await this.loadPolicies();
    await this.loadBreachInfo();
    await this.refreshAuditLogs();

    // Polling for live audit logs every 4 seconds
    setInterval(() => this.refreshAuditLogs(false), 4000);
  }

  // -------------------------------------------------------------
  // UI Tab Navigation
  // -------------------------------------------------------------
  bindTabNavigation() {
    const tabs = document.querySelectorAll('.tab-btn');
    tabs.forEach(tab => {
      tab.addEventListener('click', () => {
        tabs.forEach(t => t.classList.remove('active'));
        document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));

        tab.classList.add('active');
        const targetPanel = document.getElementById(tab.getAttribute('data-target'));
        if (targetPanel) {
          targetPanel.classList.add('active');
          if (tab.getAttribute('data-target') === 'tab-topology' && this.topology) {
            this.topology.resizeCanvas();
          }
        }
      });
    });
  }

  // -------------------------------------------------------------
  // Scenario Switching
  // -------------------------------------------------------------
  bindHeaderControls() {
    const btnVulnerable = document.getElementById('btnSwitchVulnerable');
    const btnSecured = document.getElementById('btnSwitchSecured');
    const btnReset = document.getElementById('btnResetAttack');

    if (btnVulnerable) {
      btnVulnerable.addEventListener('click', () => this.switchScenario('vulnerable'));
    }
    if (btnSecured) {
      btnSecured.addEventListener('click', () => this.switchScenario('secured'));
    }
    if (btnReset) {
      btnReset.addEventListener('click', () => this.resetAttackPipeline());
    }
  }

  async switchScenario(scenarioName) {
    try {
      const resp = await fetch('/api/config/scenario', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ scenario: scenarioName })
      });
      const data = await resp.json();
      if (data.success) {
        this.showToast(`Switched to ${scenarioName.toUpperCase()} configuration!`, scenarioName === 'secured' ? 'success' : 'error');
        this.resetAttackPipeline();
        await this.refreshStatus();
        await this.loadPolicies();
        if (this.topology) {
          this.topology.triggerStepAnimation(0, scenarioName === 'secured');
        }
      }
    } catch (err) {
      this.showToast(`Error switching scenario: ${err.message}`, 'error');
    }
  }

  // -------------------------------------------------------------
  // Defense Toggles Matrix
  // -------------------------------------------------------------
  bindToggles() {
    const toggles = [
      { id: 'toggleSSRF', key: 'ssrf_protection' },
      { id: 'toggleIMDS', key: 'imds_version', isVersion: true },
      { id: 'toggleIAM', key: 'iam_least_privilege' },
      { id: 'toggleS3', key: 's3_bucket_policy' }
    ];

    toggles.forEach(t => {
      const el = document.getElementById(t.id);
      if (el) {
        el.addEventListener('change', async (e) => {
          let val = e.target.checked;
          if (t.isVersion) {
            val = e.target.checked ? 'v2' : 'v1';
          }
          await this.toggleDefense(t.key, val);
        });
      }
    });
  }

  async toggleDefense(key, value) {
    try {
      const resp = await fetch('/api/config/toggle', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ key, value })
      });
      const data = await resp.json();
      if (data.success) {
        this.showToast(`Updated ${key} to ${value}`, 'info');
        await this.refreshStatus();
      }
    } catch (err) {
      this.showToast(`Error updating defense: ${err.message}`, 'error');
    }
  }

  // -------------------------------------------------------------
  // System Status & Metrics
  // -------------------------------------------------------------
  async refreshStatus() {
    try {
      const resp = await fetch('/api/status');
      const data = await resp.json();
      this.state = data;
      this.updateStatusBadges();
    } catch (err) {
      console.error('Error fetching status:', err);
    }
  }

  updateStatusBadges() {
    const pill = document.getElementById('globalStatusPill');
    const pillText = document.getElementById('globalStatusText');
    const isSecured = this.state.scenario === 'secured';

    if (pill && pillText) {
      pill.className = `status-pill ${isSecured ? 'secured' : 'vulnerable'}`;
      pillText.textContent = isSecured ? 'SECURED CONFIGURATION' : 'VULNERABLE CONFIGURATION';
    }

    // Top Metric Cards
    const metricThreat = document.getElementById('metricThreatLevel');
    const metricSSRF = document.getElementById('metricSSRFStatus');
    const metricIMDS = document.getElementById('metricIMDSStatus');
    const metricIAM = document.getElementById('metricIAMStatus');
    const metricS3 = document.getElementById('metricS3Status');

    if (metricThreat) {
      metricThreat.textContent = this.state.threat_level;
      metricThreat.parentElement.className = `metric-card ${isSecured ? 'secure' : 'critical'}`;
    }
    if (metricSSRF) {
      metricSSRF.textContent = this.state.controls.ssrf_protection ? 'BLOCKED (Link-Local Filtered)' : 'OPEN (SSRF Vulnerable)';
      const badge = document.getElementById('badgeSSRF');
      if (badge) {
        badge.className = `metric-badge ${this.state.controls.ssrf_protection ? 'good' : 'bad'}`;
        badge.textContent = this.state.controls.ssrf_protection ? 'DEFENDED' : 'EXPLOITABLE';
      }
    }
    if (metricIMDS) {
      metricIMDS.textContent = this.state.controls.imds_version.toUpperCase();
      const badge = document.getElementById('badgeIMDS');
      if (badge) {
        badge.className = `metric-badge ${this.state.controls.imds_version === 'v2' ? 'good' : 'bad'}`;
        badge.textContent = this.state.controls.imds_version === 'v2' ? 'TOKEN REQUIRED' : 'NO TOKEN (IMDSv1)';
      }
    }
    if (metricIAM) {
      metricIAM.textContent = this.state.controls.iam_least_privilege ? 'LEAST PRIVILEGE (Scoped)' : 'OVER-PRIVILEGED (s3:*)';
      const badge = document.getElementById('badgeIAM');
      if (badge) {
        badge.className = `metric-badge ${this.state.controls.iam_least_privilege ? 'good' : 'bad'}`;
        badge.textContent = this.state.controls.iam_least_privilege ? 'RESTRICTED' : 'WILDCARD s3:*';
      }
    }
    if (metricS3) {
      metricS3.textContent = this.state.controls.s3_bucket_policy ? 'VPC-ENDPOINT ENFORCED' : 'OPEN INTERNAL ACCESS';
      const badge = document.getElementById('badgeS3');
      if (badge) {
        badge.className = `metric-badge ${this.state.controls.s3_bucket_policy ? 'good' : 'bad'}`;
        badge.textContent = this.state.controls.s3_bucket_policy ? 'PROTECTED' : 'UNRESTRICTED';
      }
    }

    // Synchronize switches
    const tSSRF = document.getElementById('toggleSSRF');
    const tIMDS = document.getElementById('toggleIMDS');
    const tIAM = document.getElementById('toggleIAM');
    const tS3 = document.getElementById('toggleS3');
    if (tSSRF) tSSRF.checked = this.state.controls.ssrf_protection;
    if (tIMDS) tIMDS.checked = this.state.controls.imds_version === 'v2';
    if (tIAM) tIAM.checked = this.state.controls.iam_least_privilege;
    if (tS3) tS3.checked = this.state.controls.s3_bucket_policy;
  }

  // -------------------------------------------------------------
  // 4-Step Interactive Breach Pipeline
  // -------------------------------------------------------------
  bindAttackPipeline() {
    const btnStep1 = document.getElementById('btnExecStep1');
    const btnStep2 = document.getElementById('btnExecStep2');
    const btnStep3 = document.getElementById('btnExecStep3');
    const btnStep4 = document.getElementById('btnExecStep4');
    const btnAuto = document.getElementById('btnAutoRunAttack');

    if (btnStep1) btnStep1.addEventListener('click', () => this.executeStep1());
    if (btnStep2) btnStep2.addEventListener('click', () => this.executeStep2());
    if (btnStep3) btnStep3.addEventListener('click', () => this.executeStep3());
    if (btnStep4) btnStep4.addEventListener('click', () => this.executeStep4());
    if (btnAuto) btnAuto.addEventListener('click', () => this.autoRunAttack());
  }

  resetAttackPipeline() {
    this.stepResults = [null, null, null, null];
    this.harvested_credentials = null;
    this.exfiltrated_records = [];

    for (let i = 1; i <= 4; i++) {
      const card = document.getElementById(`stepCard${i}`);
      const badge = document.getElementById(`stepBadge${i}`);
      if (card) card.className = 'step-card';
      if (badge) {
        badge.className = 'step-badge pending';
        badge.textContent = 'PENDING';
      }
    }

    const outBox = document.getElementById('attackOutputBox');
    if (outBox) {
      outBox.textContent = 'Attack pipeline initialized. Ready to execute Step 1 or "Auto-Run Full Attack Pipeline".';
    }

    const tableContainer = document.getElementById('exfiltratedDataTable');
    if (tableContainer) {
      tableContainer.innerHTML = '<p style="color: var(--text-dim); text-align: center; padding: 2rem;">No data exfiltrated yet. Run Step 4 in Vulnerable Mode to demonstrate credit card application compromise.</p>';
    }

    const exfilBadge = document.getElementById('exfilCountBadge');
    if (exfilBadge) exfilBadge.textContent = '0 Records Compromised';
  }

  async executeStep1() {
    this.logStepOutput('Executing Step 1: Probing WAF Reverse Proxy with SSRF request to 169.254.169.254...\n');
    try {
      const targetUrl = 'http://169.254.169.254/latest/meta-data/iam/security-credentials/';
      const resp = await fetch(`/api/waf/proxy?url=${encodeURIComponent(targetUrl)}`);
      const data = await resp.json();

      const card = document.getElementById('stepCard1');
      const badge = document.getElementById('stepBadge1');

      if (resp.status === 403 || !data.success) {
        // SSRF Blocked!
        card.className = 'step-card blocked';
        badge.className = 'step-badge blocked';
        badge.textContent = 'BLOCKED (SSRF Filter)';
        this.logStepOutput(`[+] DEFENSE ACTIVE: SSRF request was BLOCKED!\nHTTP 403 Forbidden\nReason: ${data.reason}\n${data.educational_note}\n`);
        if (this.topology) this.topology.triggerStepAnimation(1, true);
        return false;
      } else {
        // SSRF Succeeded!
        card.className = 'step-card exploited';
        badge.className = 'step-badge exploited';
        badge.textContent = 'EXPLOITED (SSRF Active)';
        const roleName = data.imds_response ? data.imds_response.trim() : 'app-waf-production-role';
        this.logStepOutput(`[!] VULNERABILITY CONFIRMED: SSRF Succeeded!\nHTTP 200 OK\nEC2 reverse proxy made internal request to 169.254.169.254.\nDiscovered IAM Role Name: "${roleName}"\n`);
        if (this.topology) this.topology.triggerStepAnimation(1, false);
        return true;
      }
    } catch (err) {
      this.logStepOutput(`[ERROR] Step 1 failed: ${err.message}\n`);
      return false;
    }
  }

  async executeStep2() {
    this.logStepOutput('Executing Step 2: Fetching IAM Temporary Security Credentials from IMDS endpoint...\n');
    try {
      const targetUrl = 'http://169.254.169.254/latest/meta-data/iam/security-credentials/app-waf-production-role';
      const resp = await fetch(`/api/waf/proxy?url=${encodeURIComponent(targetUrl)}`);
      const data = await resp.json();

      const card = document.getElementById('stepCard2');
      const badge = document.getElementById('stepBadge2');

      if (resp.status === 403 || !data.success) {
        card.className = 'step-card blocked';
        badge.className = 'step-badge blocked';
        badge.textContent = 'BLOCKED';
        this.logStepOutput(`[+] BLOCKED: Could not retrieve credentials.\n${JSON.stringify(data, null, 2)}\n`);
        if (this.topology) this.topology.triggerStepAnimation(2, true);
        return false;
      }

      // Check if IMDSv2 blocked it with 401
      if (data.http_status === 401) {
        card.className = 'step-card blocked';
        badge.className = 'step-badge blocked';
        badge.textContent = 'BLOCKED (IMDSv2 Enforced)';
        this.logStepOutput(`[+] DEFENSE ACTIVE: AWS IMDSv2 blocked unauthenticated metadata request!\nHTTP 401 Unauthorized\n${data.imds_response}\n`);
        if (this.topology) this.topology.triggerStepAnimation(2, true);
        return false;
      }

      // Credentials Harvested!
      card.className = 'step-card exploited';
      badge.className = 'step-badge exploited';
      badge.textContent = 'CREDENTIALS STOLEN';
      this.harvested_credentials = data.imds_response;

      this.logStepOutput(`[!] CRITICAL: Temporary AWS STS Credentials Harvested via IMDSv1:\n${JSON.stringify(data.imds_response, null, 2)}\n`);
      if (this.topology) this.topology.triggerStepAnimation(2, false);
      return true;
    } catch (err) {
      this.logStepOutput(`[ERROR] Step 2 failed: ${err.message}\n`);
      return false;
    }
  }

  async executeStep3() {
    this.logStepOutput('Executing Step 3: Performing Cloud Reconnaissance (aws s3 ls) using harvested IAM role...\n');
    if (!this.harvested_credentials) {
      this.logStepOutput('[!] Note: No credentials harvested in Step 2. Using instance active STS key.\n');
      this.harvested_credentials = this.state.iam_role.credentials_active;
    }

    try {
      const resp = await fetch('/api/aws/s3', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          action: 'ListBuckets',
          auth: this.harvested_credentials
        })
      });
      const data = await resp.json();

      const card = document.getElementById('stepCard3');
      const badge = document.getElementById('stepBadge3');

      if (!data.success) {
        card.className = 'step-card blocked';
        badge.className = 'step-badge blocked';
        badge.textContent = 'BLOCKED (Least Privilege)';
        this.logStepOutput(`[+] DEFENSE ACTIVE: IAM Policy blocked s3:ListAllMyBuckets!\n${data.error_message}\n`);
        if (this.topology) this.topology.triggerStepAnimation(3, true);
        return false;
      }

      card.className = 'step-card exploited';
      badge.className = 'step-badge exploited';
      badge.textContent = 'BUCKETS ENUMERATED';
      
      const bucketNames = data.buckets.map(b => b.name).join('\n  - ');
      this.logStepOutput(`[!] RECONNAISSANCE SUCCESS: Discovered ${data.buckets.length} Corporate S3 Buckets:\n  - ${bucketNames}\nTarget Selected for Exfiltration: "c1-prod-credit-applications"\n`);
      if (this.topology) this.topology.triggerStepAnimation(3, false);
      return true;
    } catch (err) {
      this.logStepOutput(`[ERROR] Step 3 failed: ${err.message}\n`);
      return false;
    }
  }

  async executeStep4() {
    this.logStepOutput('Executing Step 4: Exfiltrating Customer Credit Applications (aws s3 sync s3://c1-prod-credit-applications/)...\n');
    try {
      const resp = await fetch('/api/aws/s3', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          action: 'GetObject',
          bucket: 'c1-prod-credit-applications',
          key: 'customer_credit_applications_2019.json',
          auth: this.harvested_credentials || this.state.iam_role.credentials_active
        })
      });
      const data = await resp.json();

      const card = document.getElementById('stepCard4');
      const badge = document.getElementById('stepBadge4');

      if (!data.success) {
        card.className = 'step-card blocked';
        badge.className = 'step-badge blocked';
        badge.textContent = 'BLOCKED (Access Denied)';
        this.logStepOutput(`[+] DEFENSE ACTIVE: S3 Data Download Rejected!\n${data.error_message}\n`);
        if (this.topology) this.topology.triggerStepAnimation(4, true);
        return false;
      }

      card.className = 'step-card exploited';
      badge.className = 'step-badge exploited';
      badge.textContent = 'DATA EXFILTRATED!';

      this.exfiltrated_records = data.data || [];
      this.logStepOutput(`[🚨 BREACH SUCCESSFUL]: Unauthorized S3 Data Exfiltrated!\nExtracted ${data.records_count} customer credit records.\n${data.note}\n`);
      this.renderExfiltratedTable(this.exfiltrated_records);

      if (this.topology) this.topology.triggerStepAnimation(4, false);
      return true;
    } catch (err) {
      this.logStepOutput(`[ERROR] Step 4 failed: ${err.message}\n`);
      return false;
    }
  }

  async autoRunAttack() {
    this.resetAttackPipeline();
    this.logStepOutput('>>> Starting Automated End-to-End Attack Simulation...\n');
    
    const step1Ok = await this.executeStep1();
    await new Promise(r => setTimeout(r, 900));

    if (!step1Ok && this.state.scenario === 'secured') {
      this.logStepOutput('\n>>> Attack halted at Step 1: SSRF Defense Filter successfully protected the environment.\n');
      return;
    }

    const step2Ok = await this.executeStep2();
    await new Promise(r => setTimeout(r, 900));

    if (!step2Ok && this.state.scenario === 'secured') {
      this.logStepOutput('\n>>> Attack halted at Step 2: IMDSv2 token enforcement prevented credential theft.\n');
      return;
    }

    const step3Ok = await this.executeStep3();
    await new Promise(r => setTimeout(r, 900));

    if (!step3Ok && this.state.scenario === 'secured') {
      this.logStepOutput('\n>>> Attack halted at Step 3: IAM Least Privilege policy blocked S3 enumeration.\n');
      return;
    }

    await this.executeStep4();
  }

  logStepOutput(text) {
    const box = document.getElementById('attackOutputBox');
    if (box) {
      box.textContent += text;
      box.scrollTop = box.scrollHeight;
    }
  }

  // -------------------------------------------------------------
  // Exfiltrated Data Table Rendering
  // -------------------------------------------------------------
  renderExfiltratedTable(records) {
    const container = document.getElementById('exfiltratedDataTable');
    const badge = document.getElementById('exfilCountBadge');

    if (badge) {
      badge.textContent = `${records.length} Confidential Records Compromised`;
      badge.className = 'status-pill vulnerable';
    }

    if (!records || records.length === 0) {
      container.innerHTML = '<p style="color: var(--text-dim); padding: 1.5rem; text-align: center;">No records to display.</p>';
      return;
    }

    let html = `
      <div class="data-table-wrapper">
        <table class="data-table">
          <thead>
            <tr>
              <th>App ID</th>
              <th>Applicant Name</th>
              <th>SSN (Exposed)</th>
              <th>Credit Score</th>
              <th>Annual Income</th>
              <th>Card Applied</th>
              <th>Address</th>
              <th>Status</th>
            </tr>
          </thead>
          <tbody>
    `;

    records.forEach(r => {
      html += `
        <tr>
          <td><code style="color: #38bdf8;">${r.application_id}</code></td>
          <td style="font-weight: 600;">${r.applicant_name}</td>
          <td><span class="pii-tag">⚠️ ${r.ssn}</span></td>
          <td style="font-weight: 700; color: #34d399;">${r.credit_score}</td>
          <td>$${r.annual_income.toLocaleString()}</td>
          <td style="color: #cbd5e1;">${r.card_tier}</td>
          <td style="color: var(--text-muted); font-size: 0.75rem;">${r.city}, ${r.state} ${r.zip}</td>
          <td><span style="background: rgba(16, 185, 129, 0.2); color: #34d399; padding: 0.15rem 0.45rem; border-radius: 4px; font-size: 0.7rem; font-weight: 700;">${r.status}</span></td>
        </tr>
      `;
    });

    html += `
          </tbody>
        </table>
      </div>
    `;

    container.innerHTML = html;
  }

  // -------------------------------------------------------------
  // Policy Comparator & Diffs
  // -------------------------------------------------------------
  async loadPolicies() {
    try {
      const resp = await fetch('/api/policies');
      const data = await resp.json();

      const vulIAM = document.getElementById('vulnIAMPolicy');
      const secIAM = document.getElementById('secIAMPolicy');
      const vulS3 = document.getElementById('vulnS3Policy');
      const secS3 = document.getElementById('secS3Policy');

      if (vulIAM && data.scenarios) {
        vulIAM.textContent = JSON.stringify(data.scenarios.vulnerable.iam_policy, null, 2);
      }
      if (secIAM && data.scenarios) {
        secIAM.textContent = JSON.stringify(data.scenarios.secured.iam_policy, null, 2);
      }
      if (vulS3 && data.scenarios) {
        vulS3.textContent = JSON.stringify(data.scenarios.vulnerable.s3_bucket_policy, null, 2);
      }
      if (secS3 && data.scenarios) {
        secS3.textContent = JSON.stringify(data.scenarios.secured.s3_bucket_policy, null, 2);
      }
    } catch (err) {
      console.error('Failed to load policies:', err);
    }
  }

  // -------------------------------------------------------------
  // CloudTrail Audit Logs
  // -------------------------------------------------------------
  async refreshAuditLogs(showNotification = true) {
    try {
      const resp = await fetch('/api/logs');
      const data = await resp.json();
      this.renderAuditLogs(data.logs || []);
      if (showNotification) {
        this.showToast('CloudTrail audit logs refreshed.', 'info');
      }
    } catch (err) {
      console.error('Failed to load logs:', err);
    }
  }

  renderAuditLogs(logs) {
    const container = document.getElementById('auditLogsContainer');
    if (!container) return;

    if (!logs || logs.length === 0) {
      container.innerHTML = '<p style="color: var(--text-dim); padding: 1.5rem; text-align: center;">No audit logs recorded yet.</p>';
      return;
    }

    let html = `
      <div class="data-table-wrapper">
        <table class="data-table">
          <thead>
            <tr>
              <th>Timestamp (UTC)</th>
              <th>Event Name</th>
              <th>Status</th>
              <th>Source IP</th>
              <th>Event Details</th>
            </tr>
          </thead>
          <tbody>
    `;

    logs.forEach(log => {
      let badgeStyle = 'background: #334155; color: #94a3b8;';
      if (log.status === 'SUCCESS') badgeStyle = 'background: rgba(16, 185, 129, 0.2); color: #34d399;';
      else if (log.status === 'BLOCKED' || log.status === 'DENIED') badgeStyle = 'background: rgba(59, 130, 246, 0.2); color: #60a5fa;';
      else if (log.status === 'WARNING') badgeStyle = 'background: rgba(245, 158, 11, 0.2); color: #fbbf24;';
      else if (log.status === 'EXPLOITED' || log.status === 'BREACH_CRITICAL') badgeStyle = 'background: rgba(239, 68, 68, 0.2); color: #f87171; font-weight: 700;';

      html += `
        <tr>
          <td style="font-family: var(--font-mono); font-size: 0.72rem; color: var(--text-dim);">${log.timestamp}</td>
          <td><code style="color: #38bdf8; font-weight: 700;">${log.event_name}</code></td>
          <td><span style="${badgeStyle} padding: 0.15rem 0.5rem; border-radius: 4px; font-size: 0.7rem;">${log.status}</span></td>
          <td style="font-family: var(--font-mono); font-size: 0.75rem;">${log.source_ip}</td>
          <td style="color: var(--text-main); font-size: 0.78rem;">${log.details}</td>
        </tr>
      `;
    });

    html += `
          </tbody>
        </table>
      </div>
    `;

    container.innerHTML = html;
  }

  // -------------------------------------------------------------
  // Educational Knowledge Hub & Timeline
  // -------------------------------------------------------------
  async loadBreachInfo() {
    try {
      const resp = await fetch('/api/breach-info');
      const info = await resp.json();

      // Render Root Causes
      const rootCausesEl = document.getElementById('rootCausesContainer');
      if (rootCausesEl && info.root_causes) {
        let html = '';
        info.root_causes.forEach(rc => {
          html += `
            <div style="background: var(--bg-secondary); border: 1px solid var(--border-color); border-radius: 10px; padding: 1rem; margin-bottom: 0.75rem;">
              <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.3rem;">
                <h4 style="font-size: 0.9rem; color: #f8fafc;">${rc.order}. ${rc.name}</h4>
                <span style="font-size: 0.68rem; font-weight: 700; background: rgba(239, 68, 68, 0.2); color: #f87171; padding: 0.15rem 0.45rem; border-radius: 4px;">${rc.severity}</span>
              </div>
              <p style="font-size: 0.78rem; color: var(--text-muted); margin-bottom: 0.4rem;">${rc.summary}</p>
              <code style="font-size: 0.7rem; color: var(--accent-cyan);">${rc.cve_pattern}</code>
            </div>
          `;
        });
        rootCausesEl.innerHTML = html;
      }

      // Render Timeline
      const timelineEl = document.getElementById('breachTimeline');
      if (timelineEl && info.timeline) {
        let html = '';
        info.timeline.forEach(item => {
          html += `
            <div class="timeline-event">
              <div class="timeline-date">${item.date}</div>
              <div class="timeline-text">${item.event}</div>
            </div>
          `;
        });
        timelineEl.innerHTML = html;
      }
    } catch (err) {
      console.error('Failed to load breach info:', err);
    }
  }

  // -------------------------------------------------------------
  // Topology Node Details Modal / Panel
  // -------------------------------------------------------------
  showNodeDetails(node) {
    this.showToast(`Selected Node: ${node.label} (${node.subtext})`, 'info');
  }

  // -------------------------------------------------------------
  // Notification Toasts
  // -------------------------------------------------------------
  showToast(message, type = 'info') {
    const container = document.getElementById('toastContainer');
    if (!container) return;

    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    const icon = type === 'success' ? '✅' : type === 'error' ? '🚨' : 'ℹ️';
    toast.innerHTML = `<span>${icon}</span> <span>${message}</span>`;

    container.appendChild(toast);
    setTimeout(() => {
      toast.style.opacity = '0';
      toast.style.transform = 'translateX(100%)';
      toast.style.transition = 'all 0.3s ease';
      setTimeout(() => toast.remove(), 300);
    }, 3500);
  }
}

// Global bootstrap
document.addEventListener('DOMContentLoaded', () => {
  window.CloudGuardApp = new CloudGuardApp();
});
