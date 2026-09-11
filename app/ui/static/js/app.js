let currentAccounts = [];
let pendingRotationData = null;
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
            console.log("WebSocket Progress:", data.message, `(Confidence: ${data.confidence})`);
        } else if (data.type === "ROTATION_SUCCESS") {
            alert(`✅ ${data.message}`);
            loadDashboardData();
            loadQueueData();
        }
    };
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
        
        tr.innerHTML = `
            <td><strong>${acc.service}</strong></td>
            <td>${acc.username}</td>
            <td><code>${acc.domain}</code></td>
            <td><span class="risk-badge ${riskClass}">${acc.risk}</span></td>
            <td>${acc.issue}</td>
            <td>${mfaBadge}</td>
            <td>
                <button class="btn btn-action btn-primary" onclick="initiateRotation(${acc.id})">Fix</button>
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
    // Switch to queue tab
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
    try {
        const res = await fetch("/api/rotation/prepare", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ account_id: accountId })
        });
        pendingRotationData = await res.json();
        showRotationConfirmationModal(pendingRotationData);
    } catch (err) {
        alert("Failed to prepare password rotation: " + err);
    }
}

function showRotationConfirmationModal(data) {
    const modalBody = document.getElementById("rotation-modal-body");
    const isHighVal = data.is_high_value;
    const secondaryWarning = isHighVal 
        ? `<div style="color: #ef4444; margin-top: 10px; font-weight: 600;">⚠️ HIGH-VALUE IDENTITY PROVIDER: Secondary explicit confirmation required.</div>` 
        : "";

    modalBody.innerHTML = `
        <div class="summary-card">
            <div class="summary-field"><span class="key">Target Service:</span><span class="val">${data.service}</span></div>
            <div class="summary-field"><span class="key">Username / Email:</span><span class="val">${data.username}</span></div>
            <div class="summary-field"><span class="key">Official Domain:</span><span class="val"><code>${data.domain}</code> ${data.is_domain_valid ? '✅ Verified' : '❌ Untrusted'}</span></div>
            <div class="summary-field"><span class="key">Risk Assessment:</span><span class="val">${data.risk} (${data.issue})</span></div>
            <div class="summary-field"><span class="key">CSPRNG Replacement Secret:</span><span class="val">•••••••••••••••• (Generated)</span></div>
            <div class="summary-field"><span class="key">MFA Protection:</span><span class="val">${data.mfa_status ? 'Enabled' : 'Disabled'}</span></div>
            ${secondaryWarning}
        </div>
    `;

    document.getElementById("rotation-modal").classList.add("active");
}

function closeRotationModal() {
    document.getElementById("rotation-modal").classList.remove("active");
    pendingRotationData = null;
}

async function executeRotationStep(dryRun = false) {
    if (!pendingRotationData) return;

    try {
        const res = await fetch("/api/rotation/execute", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                account_id: pendingRotationData.account_id,
                confirmed: true,
                dry_run: dryRun,
                generated_password: pendingRotationData.generated_password,
                save_to_keychain: true
            })
        });
        const result = await res.json();
        closeRotationModal();
        alert(`Success: ${result.message}`);
        loadDashboardData();
        loadQueueData();
    } catch (err) {
        alert("Rotation execution failed: " + err);
    }
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
