const API_BASE = "https://phishguard-production-93c3.up.railway.app";
const API_URL    = `${API_BASE}/analyse`;
const STATUS_URL = `${API_BASE}/status`;

const scanBtn         = document.getElementById("scanBtn");
const emailInput      = document.getElementById("emailInput");
const resultDiv       = document.getElementById("result");
const scansBadge      = document.getElementById("scansBadge");
const autoDetectBtn   = document.getElementById("autoDetectBtn");
const scanAutoBtn     = document.getElementById("scanAutoBtn");
const detectedPreview = document.getElementById("detectedPreview");
const previewSubject  = document.getElementById("previewSubject");
const tabAuto         = document.getElementById("tabAuto");
const tabPaste        = document.getElementById("tabPaste");
const autoPanel       = document.getElementById("autoPanel");
const pastePanel      = document.getElementById("pastePanel");
const premiumLink     = document.getElementById("premiumLink");
const premiumPanel    = document.getElementById("premiumPanel");
const premiumInput    = document.getElementById("premiumInput");
const activateBtn     = document.getElementById("activateBtn");
const premiumMsg      = document.getElementById("premiumMsg");

let detectedEmailText = "";
let clientId = null;
let premiumToken = null;

// ── IDENTITY + STATE (persisted, so quota survives popup reopen) ──
async function loadState() {
  const store = await chrome.storage.local.get(["clientId", "premiumToken"]);
  clientId = store.clientId;
  if (!clientId) {
    clientId = (crypto.randomUUID && crypto.randomUUID()) ||
               (Date.now() + "-" + Math.random().toString(16).slice(2));
    await chrome.storage.local.set({ clientId });
  }
  premiumToken = store.premiumToken || null;
}

function authHeaders() {
  const h = { "Content-Type": "application/json", "X-Client-Id": clientId };
  if (premiumToken) h["X-Premium-Token"] = premiumToken;
  return h;
}

// Sync the real remaining-scan count from the server on open.
async function syncStatus() {
  try {
    const res = await fetch(STATUS_URL, { headers: authHeaders() });
    if (!res.ok) return;
    const data = await res.json();
    updateScansBadge(data.premium ? -1 : data.scans_remaining);
  } catch (_) { /* leave badge as-is if offline */ }
}

// ── TAB SWITCHING ──
function switchTab(which) {
  const auto = which === "auto";
  autoPanel.style.display  = auto ? "block" : "none";
  pastePanel.style.display = auto ? "none" : "block";
  tabAuto.classList.toggle("active", auto);
  tabPaste.classList.toggle("active", !auto);
  resultDiv.style.display = "none";
  resultDiv.innerHTML = "";
}
tabAuto.addEventListener("click", () => switchTab("auto"));
tabPaste.addEventListener("click", () => switchTab("paste"));
switchTab("auto");

// ── PREMIUM ACTIVATION ──
premiumLink.addEventListener("click", () => {
  premiumPanel.style.display = premiumPanel.style.display === "block" ? "none" : "block";
  if (premiumToken) premiumInput.value = premiumToken;
});

activateBtn.addEventListener("click", async () => {
  const code = premiumInput.value.trim();
  if (!code) { premiumMsg.textContent = "Enter a premium code."; return; }
  premiumToken = code;
  await chrome.storage.local.set({ premiumToken: code });
  premiumMsg.textContent = "Checking...";
  const res = await fetch(STATUS_URL, { headers: authHeaders() }).then(r => r.json()).catch(() => null);
  if (res && res.premium) {
    premiumMsg.textContent = "✓ Premium activated.";
    updateScansBadge(-1);
  } else {
    premiumToken = null;
    await chrome.storage.local.remove("premiumToken");
    premiumMsg.textContent = "✗ Invalid code.";
    syncStatus();
  }
});

// ── AUTO DETECT ──
autoDetectBtn.addEventListener("click", async () => {
  autoDetectBtn.disabled = true;
  autoDetectBtn.textContent = "Detecting...";
  detectedPreview.style.display = "none";
  scanAutoBtn.style.display = "none";
  detectedEmailText = "";
  resultDiv.style.display = "none";

  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab || !tab.url || !tab.url.includes("mail.google.com")) {
      showInfo("Please open Gmail and open an email first, then click Detect.");
      return;
    }
    const response = await chrome.tabs.sendMessage(tab.id, { action: "extractEmail" });
    if (!response || !response.success) {
      showInfo(response?.reason || "No email found. Make sure an email is open in Gmail.");
      return;
    }
    detectedEmailText = response.emailText;
    previewSubject.textContent = response.subject || "(No subject)";
    detectedPreview.style.display = "block";
    scanAutoBtn.style.display = "block";
  } catch (err) {
    showInfo("Could not connect to Gmail. Make sure Gmail is open with an email expanded.");
  } finally {
    autoDetectBtn.disabled = false;
    autoDetectBtn.textContent = "Detect Email from Gmail";
  }
});

scanAutoBtn.addEventListener("click", async () => {
  if (!detectedEmailText) return;
  await runScan(detectedEmailText, scanAutoBtn);
});

scanBtn.addEventListener("click", async () => {
  const text = emailInput.value.trim();
  if (!text) { showError("Please paste some email content first."); return; }
  await runScan(text, scanBtn);
});

// ── CORE SCAN ──
async function runScan(emailText, btn) {
  btn.disabled = true;
  resultDiv.style.display = "block";
  resultDiv.innerHTML = `<div class="loading"><span class="spinner"></span>Analysing email...</div>`;

  try {
    const response = await fetch(API_URL, {
      method: "POST",
      headers: authHeaders(),
      body: JSON.stringify({ email_text: emailText })
    });
    const data = await response.json();

    if (response.status === 403 && data.upgrade) { showUpgrade(); updateScansBadge(0); return; }
    if (!response.ok) { showError(data.error || "Server error."); return; }

    showResult(data);
    updateScansBadge(data.premium ? -1 : data.scans_remaining);
  } catch (err) {
    showError("Could not reach Jester server. Check your connection.");
  } finally {
    btn.disabled = false;
  }
}

function updateScansBadge(remaining) {
  if (remaining === -1) { scansBadge.textContent = "Premium ✦"; scansBadge.className = "scans-badge premium"; return; }
  if (remaining === null || remaining === undefined) return;
  scansBadge.textContent = `${remaining} scan${remaining !== 1 ? "s" : ""} left`;
  scansBadge.className = "scans-badge" + (remaining === 0 ? " empty" : remaining <= 2 ? " low" : "");
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, c =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

function showResult(data) {
  const verdict     = (data.verdict || "UNKNOWN").toUpperCase();
  const risk        = (data.risk_level || "unknown").toLowerCase();
  const explanation = escapeHtml(data.explanation || "");
  const signals     = data.signals || [];
  const urlCheck    = data.url_check || {};
  const action      = data.recommended_action || "";
  const isPremium   = !!data.premium;

  const badgeClass = verdict === "PHISHING" ? "badge-phishing"
                   : verdict === "LEGITIMATE" ? "badge-legitimate"
                   : verdict === "SUSPICIOUS" ? "badge-suspicious" : "badge-unknown";
  const riskWidth  = risk === "high" ? "88%" : risk === "medium" ? "52%" : risk === "low" ? "18%" : "5%";

  let urlHTML = "";
  if (urlCheck.safe_browsing_checked) {
    if (urlCheck.flagged && urlCheck.flagged.length > 0) {
      urlHTML = `<div class="url-section"><span class="url-flagged">⚠ ${urlCheck.flagged.length} URL(s) flagged by Google Safe Browsing</span></div>`;
    } else if (urlCheck.urls_checked > 0) {
      urlHTML = `<div class="url-section"><span class="url-clean">✓ ${urlCheck.urls_checked} URL(s) checked — all clean</span></div>`;
    }
  }

  let signalsHTML = "";
  let actionHTML  = "";
  let lockHTML    = "";

  if (isPremium) {
    signalsHTML = signals.length > 0
      ? `<div class="signals-section"><div class="signals-title">Signals detected</div><div class="signals-wrap">${signals.map(s => `<span class="signal-tag">${escapeHtml(s)}</span>`).join("")}</div></div>`
      : "";
    actionHTML = action
      ? `<div class="action-section"><span class="action-title">Recommended action</span><div class="action-text">${escapeHtml(action)}</div></div>`
      : "";
  } else {
    // Free tier: hide details, nudge to premium.
    lockHTML = `<div class="lock-section">🔒 Detailed signals &amp; recommended action are a <a href="#" id="lockUpgrade">Premium</a> feature.</div>`;
  }

  resultDiv.style.display = "block";
  resultDiv.innerHTML = `
    <div class="result-card">
      <div class="verdict-header">
        <span class="verdict-badge ${badgeClass}">${verdict}</span>
        <span class="risk-pill risk-${risk}">${risk} risk</span>
      </div>
      <div class="risk-bar-section"><div class="risk-bar-wrap"><div class="risk-bar bar-${risk}" style="width:${riskWidth}"></div></div></div>
      <div class="explanation">${explanation}</div>
      ${urlHTML}${signalsHTML}${actionHTML}${lockHTML}
    </div>`;

  const lu = document.getElementById("lockUpgrade");
  if (lu) lu.addEventListener("click", (e) => { e.preventDefault(); premiumPanel.style.display = "block"; });
}

function showUpgrade() {
  resultDiv.style.display = "block";
  resultDiv.innerHTML = `<div class="upgrade-card"><h3>Free tier limit reached</h3><p>You have used your free scans for today. Activate Jester Premium for unlimited scans and detailed signals.</p></div>`;
}
function showError(msg) {
  resultDiv.style.display = "block";
  resultDiv.innerHTML = `<div class="error-card">⚠ ${escapeHtml(msg)}</div>`;
}
function showInfo(msg) {
  resultDiv.style.display = "block";
  resultDiv.innerHTML = `<div class="info-card">ℹ ${escapeHtml(msg)}</div>`;
}

// ── INIT ──
(async () => {
  await loadState();
  await syncStatus();
})();
