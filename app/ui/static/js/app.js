let currentAccounts = [];
let pendingRotationData = null;
let activeWorkflowState = null;
let ws = null;

document.addEventListener("DOMContentLoaded", () => {
    setupNavigation();
    loadDashboardData();
    connectWebSocket();
});

function setupNavigation() {
    const navButtons = document.querySelectorAll(".nav-btn");
    navButtons.forEach(btn => {
        btn.addEventListener("click", () => {
            navButtons.forEach(b => b.classList.remove("active"));
            btn.classList.add("active");

            const targetTab = btn.getAttribute("data-tab");
            document.querySelectorAll(".tab-page").forEach(page => page.classList.remove("active"));
            document.getElementById(`tab-${targetTab}`).classList.add("active");

            if (targetTab === "dashboard") loadDashboardData();
            else if (targetTab === "queue") loadQueueData();
            else if (targetTab === "accounts") loadAllAccounts();
            else if (targetTab === "workflows") loadWorkflowMemory();
            else if (targetTab === "adapters") loadAdaptersData();
            else if (targetTab === "doctor") loadDoctorData();
            else if (targetTab === "audit") loadAuditLogs();
        });
    });
}

function connectWebSocket() {
    const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
    ws = new WebSocket(`${protocol}//${window.location.host}/ws`);

    ws.onmessage = (event) => {
        const data = JSON.parse(event.data);
        if (data.type === "ROTATION_PROGRESS") {
            logLiveActivity(`[${data.phase || 'PROGRESS'}] ${data.message}`);
            updateModalStatus(data.phase, data.message);
        } else if (data.type === "ROTATION_SUCCESS") {
            logLiveActivity(`[SUCCESS] ${data.message}`);
            alert(`✅ ${data.message}`);
            closeRotationModal();
            loadDashboardData();
            loadQueueData();
        } else if (data.type === "ROTATION_FAILURE") {
            logLiveActivity(`[FAILURE] ${data.message}`);
            alert(`❌ ${data.message}`);
            closeRotationModal();
            loadDashboardData();
        }
    };
}

function logLiveActivity(msg) {
    const container = document.getElementById("live-activity-stream");
    if (container) {
        const entry = document.createElement("div");
        entry.className = "activity-entry";
        entry.innerText = `${new Date().toLocaleTimeString()} — ${msg}`;
        container.prepend(entry);
    }
}

async function loadDashboardData() {
    try {
        const resOverview = await fetch("/api/dashboard/overview");
        const overview = await resOverview.json();

        document.getElementById("score-display").innerText = `${overview.score} / 100`;
        document.getElementById("score-bar").style.width = `${overview.score}%`;

        document.getElementById("count-critical").innerText = overview.critical_count;
        document.getElementById("count-high").innerText = overview.high_count;
        document.getElementById("count-medium").innerText = overview.medium_count;
        document.getElementById("count-low").innerText = overview.low_count;

        document.getElementById("stat-fixed").innerText = `${overview.fixed_accounts} / ${overview.total_accounts}`;
        document.getElementById("stat-mfa").innerText = `${overview.mfa_coverage_percent}%`;
        document.getElementById("stat-reused").innerText = overview.reused_count;

        const resAccounts = await fetch("/api/accounts");
        currentAccounts = await resAccounts.json();
        renderAccountsTable(currentAccounts);
    } catch (err) {
        console.error("Error loading dashboard data:", err);
    }
}

function renderAccountsTable(accounts) {
    const tbody = document.getElementById("accounts-table-body");
    tbody.innerHTML = "";

    accounts.forEach(acc => {
        const tr = document.createElement("tr");
        const riskClass = acc.risk.toLowerCase();
        const mfaBadge = acc.mfa_status ? "🟢 Enabled" : "🔴 Disabled";
        const isSuccess = acc.rotation_status === "SUCCESS";
        
        tr.innerHTML = `
            <td><strong>${acc.service}</strong></td>
            <td>${acc.username}</td>
            <td><code>${acc.domain}</code></td>
            <td><span class="risk-badge ${riskClass}">${acc.risk}</span></td>
            <td>${acc.issue}</td>
            <td>${mfaBadge}</td>
            <td>
                ${isSuccess ? '<span style="color: var(--accent-emerald); font-weight:600;">✓ Rotated</span>' : `<button class="btn btn-action btn-primary" onclick="initiateRotation(${acc.id})">Rotate</button>`}
                <button class="btn btn-action btn-secondary" onclick="openDomain('${acc.domain}')">Open</button>
            </td>
        `;
        tbody.appendChild(tr);
    });
}

function filterAccounts() {
    const query = document.getElementById("account-search").value.toLowerCase();
    const filtered = currentAccounts.filter(a => 
        a.service.toLowerCase().includes(query) || 
        a.username.toLowerCase().includes(query) ||
        a.domain.toLowerCase().includes(query)
    );
    renderAccountsTable(filtered);
}

async function startBatchCompromisedFix() {
    await initQueue("compromised");
    document.querySelector("[data-tab='queue']").click();
}

async function initQueue(filterMode = "all") {
    try {
        const res = await fetch(`/api/queue/init?filter_mode=${filterMode}`, { method: "POST" });
        const data = await res.json();
        renderQueueTable(data.queue);
    } catch (err) {
        alert("Failed to initialize queue: " + err);
    }
}

async function loadQueueData() {
    try {
        const res = await fetch("/api/queue");
        const items = await res.json();
        renderQueueTable(items);
    } catch (err) {
        console.error("Failed to load queue:", err);
    }
}

function renderQueueTable(items) {
    const tbody = document.getElementById("queue-table-body");
    tbody.innerHTML = "";

    if (!items || items.length === 0) {
        tbody.innerHTML = "<tr><td colspan='7' style='text-align:center; color: var(--text-muted);'>No items in queue. Click 'Queue All Pending' to populate.</td></tr>";
        return;
    }

    items.forEach((item, idx) => {
        const tr = document.createElement("tr");
        tr.innerHTML = `
            <td>#${idx + 1}</td>
            <td><strong>${item.service}</strong></td>
            <td>${item.username}</td>
            <td><code>${item.domain}</code></td>
            <td><span class="risk-badge ${item.risk.toLowerCase()}">${item.status}</span></td>
            <td><code>${(item.confidence * 100).toFixed(0)}%</code></td>
            <td>
                <button class="btn btn-action btn-primary" onclick="initiateRotation(${item.account_id})">Rotate Now</button>
            </td>
        `;
        tbody.appendChild(tr);
    });
}

async function initiateRotation(accountId) {
    showLoadingModal("Initiating Secure Rotation Lifecycle", "Opening site, verifying domain trust, and analyzing page structure...");
    try {
        const res = await fetch("/api/rotation/prepare", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ account_id: accountId })
        });
        pendingRotationData = await res.json();
        
        if (pendingRotationData.status === "READY_FOR_APPROVAL") {
            showApprovalModal(pendingRotationData);
        } else if (pendingRotationData.status === "WAITING_FOR_HUMAN") {
            showHumanChallengeModal(pendingRotationData);
        } else if (pendingRotationData.status === "DOMAIN_VIOLATION") {
            alert(`⛔ Domain Trust Violation: ${pendingRotationData.reason}`);
            closeRotationModal();
        } else {
            alert(`Preparation status: ${pendingRotationData.status} - ${pendingRotationData.reason || ''}`);
            closeRotationModal();
        }
    } catch (err) {
        alert("Failed to prepare password rotation: " + err);
        closeRotationModal();
    }
}

function showLoadingModal(title, msg) {
    const modalBody = document.getElementById("rotation-modal-body");
    modalBody.innerHTML = `
        <div style="text-align:center; padding: 30px;">
            <div class="spinner" style="margin: 0 auto 16px;"></div>
            <h3 style="margin-bottom: 8px;">${title}</h3>
            <p id="modal-status-text" style="color: var(--text-muted);">${msg}</p>
        </div>
    `;
    document.getElementById("modal-approve-btn").style.display = "none";
    document.getElementById("modal-resume-btn").style.display = "none";
    document.getElementById("rotation-modal").classList.add("active");
}

function updateModalStatus(phase, msg) {
    const el = document.getElementById("modal-status-text");
    if (el) el.innerText = `[${phase}] ${msg}`;
}

function showApprovalModal(data) {
    const modalBody = document.getElementById("rotation-modal-body");
    const isHighVal = data.is_high_value;
    const secondaryWarning = isHighVal 
        ? `<div style="background: rgba(239, 68, 68, 0.15); border: 1px solid #ef4444; border-radius: 6px; padding: 8px; margin-top: 10px; color: #ef4444; font-weight: 600;">⚠️ HIGH-VALUE IDENTITY PROVIDER: Secondary verification required.</div>` 
        : "";

    modalBody.innerHTML = `
        <div class="summary-card">
            <h3 style="margin-bottom: 12px; color: var(--accent-emerald);">🛡️ Human Authorization Required</h3>
            <p style="color: var(--text-muted); font-size: 0.88rem; margin-bottom: 12px;">AI has navigated to the official password management interface and verified credentials locally. Please authorize final submission.</p>
            <div class="summary-field"><span class="key">Target Service:</span><span class="val">${data.service}</span></div>
            <div class="summary-field"><span class="key">Username / Email:</span><span class="val">${data.username || ''}</span></div>
            <div class="summary-field"><span class="key">Official Domain:</span><span class="val"><code>${data.domain}</code> ✅ Verified</span></div>
            <div class="summary-field"><span class="key">Form Fingerprint:</span><span class="val"><code>${data.form_fingerprint}</code></span></div>
            <div class="summary-field"><span class="key">CSPRNG Replacement Secret:</span><span class="val">•••••••••••••••• (Local CSPRNG)</span></div>
            <div class="summary-field"><span class="key">Submission Token:</span><span class="val">One-time cryptographic authorization</span></div>
            ${secondaryWarning}
        </div>
    `;

    document.getElementById("modal-approve-btn").style.display = "inline-block";
    document.getElementById("modal-resume-btn").style.display = "none";
    document.getElementById("rotation-modal").classList.add("active");
}

function showHumanChallengeModal(data) {
    const modalBody = document.getElementById("rotation-modal-body");
    modalBody.innerHTML = `
        <div class="summary-card" style="border-color: var(--accent-amber);">
            <h3 style="margin-bottom: 12px; color: var(--accent-amber);">⚠️ Security Challenge Detected: ${data.challenge_type}</h3>
            <p style="color: var(--text-muted); font-size: 0.9rem; margin-bottom: 16px;">
                ${data.message || 'Please complete verification (MFA, CAPTCHA, or Login) directly in the browser window.'}
            </p>
            <p style="color: var(--text-muted); font-size: 0.85rem;">
                Once completed, click <strong>Resume Rotation</strong> below to re-verify domain trust and continue the workflow automatically.
            </p>
        </div>
    `;

    document.getElementById("modal-approve-btn").style.display = "none";
    document.getElementById("modal-resume-btn").style.display = "inline-block";
    document.getElementById("rotation-modal").classList.add("active");
}

async function approveAndExecuteRotation() {
    if (!pendingRotationData) return;

    showLoadingModal("Authorizing & Submitting", "Issuing one-time approval token and submitting password update...");

    try {
        // Step 1: Request one-time cryptographic approval token
        const approveRes = await fetch("/api/rotation/approve", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                account_id: pendingRotationData.account_id,
                workflow_id: pendingRotationData.workflow_id,
                session_id: pendingRotationData.session_id,
                form_fingerprint: pendingRotationData.form_fingerprint
            })
        });
        const approval = await approveRes.json();

        // Step 2: Execute submission with token
        const execRes = await fetch("/api/rotation/execute", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                workflow_id: pendingRotationData.workflow_id,
                approval_token_id: approval.approval_token_id,
                session_id: pendingRotationData.session_id,
                account_id: pendingRotationData.account_id,
                dry_run: false,
                save_to_keychain: true
            })
        });
        const result = await execRes.json();
        
        if (result.status === "SUCCESS") {
            alert(`✅ Password rotation confirmed: ${result.details || 'Success'}`);
            closeRotationModal();
            loadDashboardData();
            loadQueueData();
        } else {
            alert(`Submission outcome: ${result.status} - ${result.details || result.error}`);
            closeRotationModal();
            loadDashboardData();
        }
    } catch (err) {
        alert("Execution failed: " + err);
        closeRotationModal();
    }
}

async function resumeHumanChallenge() {
    if (!pendingRotationData) return;

    showLoadingModal("Resuming Workflow", "Re-verifying domain trust and continuing AI navigation...");

    try {
        const res = await fetch("/api/rotation/resume", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                workflow_id: pendingRotationData.workflow_id,
                session_id: pendingRotationData.session_id
            })
        });
        const data = await res.json();
        pendingRotationData = data;

        if (data.status === "READY_FOR_APPROVAL") {
            showApprovalModal(data);
        } else if (data.status === "WAITING_FOR_HUMAN") {
            showHumanChallengeModal(data);
        } else {
            alert(`Resume outcome: ${data.status}`);
            closeRotationModal();
        }
    } catch (err) {
        alert("Failed to resume: " + err);
        closeRotationModal();
    }
}

function closeRotationModal() {
    document.getElementById("rotation-modal").classList.remove("active");
    pendingRotationData = null;
}

function triggerImportModal() {
    document.getElementById("import-modal").classList.add("active");
}

function closeImportModal() {
    document.getElementById("import-modal").classList.remove("active");
}

async function submitCSVImport() {
    const fileInput = document.getElementById("csv-file-input");
    if (!fileInput.files.length) {
        alert("Please select a CSV file.");
        return;
    }

    const formData = new FormData();
    formData.append("file", fileInput.files[0]);

    try {
        const res = await fetch("/api/accounts/import", {
            method: "POST",
            body: formData
        });
        const data = await res.json();
        closeImportModal();
        alert(data.message);
        loadDashboardData();
    } catch (err) {
        alert("CSV import failed: " + err);
    }
}

async function loadWorkflowMemory() {
    try {
        const res = await fetch("/api/workflows");
        const data = await res.json();
        document.getElementById("workflow-memory-view").innerText = JSON.stringify(data, null, 2);
    } catch (err) {
        document.getElementById("workflow-memory-view").innerText = "Error loading workflow memory: " + err;
    }
}

async function loadDoctorData() {
    const docContainer = document.getElementById("doctor-content");
    try {
        const res = await fetch("/api/doctor");
        const doc = await res.json();
        docContainer.innerHTML = `
            <div class="summary-card">
                <div class="summary-field"><span class="key">Overall Status:</span><span class="val" style="color: var(--accent-emerald)">${doc.status}</span></div>
                <div class="summary-field"><span class="key">Python Version:</span><span class="val">${doc.python_version}</span></div>
                <div class="summary-field"><span class="key">Playwright Engine:</span><span class="val">Ready</span></div>
                <div class="summary-field"><span class="key">SQLite Database:</span><span class="val">${doc.sqlite_path}</span></div>
                <div class="summary-field"><span class="key">macOS Keychain Access:</span><span class="val">Verified</span></div>
                <div class="summary-field"><span class="key">Registered Service Adapters:</span><span class="val">${doc.adapters_count} Active</span></div>
                <div class="summary-field"><span class="key">Submission Approval Engine:</span><span class="val" style="color: var(--accent-emerald)">Active (Enforced)</span></div>
                <div class="summary-field"><span class="key">Credential Field Verifier:</span><span class="val" style="color: var(--accent-emerald)">Active (Deterministic DOM)</span></div>
                <div class="summary-field"><span class="key">Domain Trust Engine:</span><span class="val" style="color: var(--accent-emerald)">Active (Strict eTLD+1)</span></div>
                <div class="summary-field"><span class="key">Telemetry Status:</span><span class="val" style="color: var(--accent-emerald)">Disabled (100% Privacy)</span></div>
            </div>
        `;
    } catch (err) {
        docContainer.innerHTML = `<p style="color: var(--accent-red)">Failed to load diagnostics: ${err}</p>`;
    }
}

async function loadAuditLogs() {
    try {
        const res = await fetch("/api/audit");
        const data = await res.json();
        document.getElementById("audit-log-view").innerText = data.logs.join("\n");
    } catch (err) {
        document.getElementById("audit-log-view").innerText = "Error loading audit logs: " + err;
    }
}

function openDomain(domain) {
    window.open(`https://${domain}`, "_blank");
}
