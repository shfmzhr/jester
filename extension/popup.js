const API_URL = "https://phishguard-production-93c3.up.railway.app/analyse";

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

let detectedEmailText = "";

// ── STORAGE HELPERS ──
async function getStoredData() {
  return new Promise(resolve => {
    chrome.storage.local.get(["premiumToken", "scansDate", "scansUsed"], resolve);
  });
}

async function saveScansUsed(used) {
  const today = new Date().toISOString().slice(0, 10); // YYYY-MM-DD
  return new Promise(resolve => {
    chrome.storage.local.set({ scansDate: today, scansUsed: used }, resolve);
  });
}

async function getEffectiveScansRemaining() {
  const { premiumToken, scansDate, scansUsed } = await getStoredData();
  if (premiumToken) return -1;
  const today = new Date().toISOString().slice(0, 10);
  if (scansDate !== today) return 5; // New day — reset locally
  return Math.max(0, 5 - (scansUsed || 0));
}

// ── INIT: restore badge on popup open ──
(async () => {
  const remaining = await getEffectiveScansRemaining();
  updateScansBadge(remaining);
})();

// ── TAB SWITCHING ──
tabAuto.addEventListener("click", () => {
  autoPanel.style.display  = "block";
  pastePanel.style.display = "none";
  tabAuto.classList.add("active");
  tabPaste.classList.remove("active");
  resultDiv.style.display = "none";
  resultDiv.innerHTML = "";
});

tabPaste.addEventListener("click", () => {
  autoPanel.style.display  = "none";
  pastePanel.style.display = "block";
  tabPaste.classList.add("active");
  tabAuto.classList.remove("active");
  resultDiv.style.display = "none";
  resultDiv.innerHTML = "";
});

// Show auto panel by default
autoPanel.style.display  = "block";
pastePanel.style.display = "none";

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

// ── SCAN AUTO ──
scanAutoBtn.addEventListener("click", async () => {
  if (!detectedEmailText) return;
  await runScan(detectedEmailText, scanAutoBtn);
});

// ── SCAN PASTE ──
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
    const { premiumToken } = await getStoredData();

    const headers = { "Content-Type": "application/json" };
    if (premiumToken) {
      headers["X-Premium-Token"] = premiumToken;
    }

    const response = await fetch(API_URL, {
      method: "POST",
      headers,
      body: JSON.stringify({ email_text: emailText })
    });

    const data = await response.json();

    if (response.status === 403 && data.upgrade) {
      showUpgrade();
      updateScansBadge(0);
      await saveScansUsed(5);
      return;
    }
    if (!response.ok) { showError(data.error || "Server error."); return; }

    showResult(data);

    // Update badge and persist count
    const remaining = data.scans_remaining;
    updateScansBadge(remaining);
    if (remaining !== -1 && remaining !== null && remaining !== undefined) {
      await saveScansUsed(5 - remaining);
    }

  } catch (err) {
    showError("Could not reach Jester server. Check your connection.");
  } finally {
    btn.disabled = false;
  }
}

function updateScansBadge(remaining) {
  if (remaining === -1) {
    scansBadge.textContent = "Premium ✦";
    scansBadge.className = "scans-badge premium";
    return;
  }
  if (remaining === null || remaining === undefined) return;
  scansBadge.textContent = `${remaining} scan${remaining !== 1 ? "s" : ""} left`;
  scansBadge.className = "scans-badge" + (remaining === 0 ? " empty" : remaining <= 2 ? " low" : "");
}

function showResult(data) {
  const verdict     = (data.verdict || "UNKNOWN").toUpperCase();
  const risk        = (data.risk_level || "unknown").toLowerCase();
  const explanation = data.explanation || "";
  const signals     = data.signals || [];
  const urlCheck    = data.url_check || {};

  const badgeClass = verdict === "PHISHING" ? "badge-phishing" : verdict === "LEGITIMATE" ? "badge-legitimate" : "badge-unknown";
  const riskWidth  = risk === "high" ? "88%" : risk === "medium" ? "52%" : risk === "low" ? "18%" : "5%";

  let urlHTML = "";
  if (urlCheck.safe_browsing_checked) {
    if (urlCheck.flagged && urlCheck.flagged.length > 0) {
      urlHTML = `<div class="url-section"><span class="url-flagged">⚠ ${urlCheck.flagged.length} URL(s) flagged by Google Safe Browsing</span></div>`;
    } else if (urlCheck.urls_checked > 0) {
      urlHTML = `<div class="url-section"><span class="url-clean">✓ ${urlCheck.urls_checked} URL(s) checked — all clean</span></div>`;
    }
  }

  // Premium: show full signals. Free tier: show teaser message instead.
  let signalsHTML = "";
  if (signals.length > 0) {
    signalsHTML = `<div class="signals-section"><div class="signals-title">Signals detected</div><div class="signals-wrap">${signals.map(s => `<span class="signal-tag">${s}</span>`).join("")}</div></div>`;
  } else if (verdict === "PHISHING") {
    signalsHTML = `<div class="signals-section signals-locked"><span class="lock-icon">🔒</span> Upgrade to <strong>Jester Premium</strong> to see detailed phishing signals.</div>`;
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
      ${urlHTML}${signalsHTML}
    </div>`;
}

function showUpgrade() {
  resultDiv.style.display = "block";
  resultDiv.innerHTML = `<div class="upgrade-card"><h3>Free tier limit reached</h3><p>You have used your 5 free scans for today. Upgrade to <strong>Jester Premium</strong> for unlimited scans and full signal analysis.</p></div>`;
}

function showError(msg) {
  resultDiv.style.display = "block";
  resultDiv.innerHTML = `<div class="error-card">⚠ ${msg}</div>`;
}

function showInfo(msg) {
  resultDiv.style.display = "block";
  resultDiv.innerHTML = `<div class="info-card">ℹ ${msg}</div>`;
}
