const API_URL = "https://phishguard-production-93c3.up.railway.app/analyse";

const scanBtn    = document.getElementById("scanBtn");
const emailInput = document.getElementById("emailInput");
const resultDiv  = document.getElementById("result");
const scansBadge = document.getElementById("scansBadge");

scanBtn.addEventListener("click", async () => {
  const text = emailInput.value.trim();
  if (!text) {
    showError("Please paste some email content first.");
    return;
  }
  setLoading(true);
  try {
    const response = await fetch(API_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email_text: text })
    });

    const data = await response.json();

    if (response.status === 403 && data.upgrade) {
      showUpgrade();
      updateScansBadge(0);
      return;
    }

    if (!response.ok) {
      showError(data.error || "Server error. Please try again.");
      return;
    }

    showResult(data);
    updateScansBadge(data.scans_remaining);

  } catch (err) {
    showError("Could not reach Jester server. Check your connection.");
  } finally {
    setLoading(false);
  }
});

function updateScansBadge(remaining) {
  if (remaining === -1) {
    scansBadge.textContent = "Premium ✦";
    scansBadge.className = "scans-badge";
    return;
  }
  if (remaining === null || remaining === undefined) return;
  scansBadge.textContent = `${remaining} scan${remaining !== 1 ? "s" : ""} left`;
  scansBadge.className = "scans-badge" + (remaining === 0 ? " empty" : remaining <= 2 ? " low" : "");
}

function setLoading(on) {
  scanBtn.disabled = on;
  if (on) {
    resultDiv.style.display = "block";
    resultDiv.innerHTML = `<div class="loading"><span class="spinner"></span>Analysing email...</div>`;
  }
}

function showResult(data) {
  const verdict   = (data.verdict || "UNKNOWN").toUpperCase();
  const risk      = (data.risk_level || "unknown").toLowerCase();
  const explanation = data.explanation || "";
  const signals   = data.signals || [];
  const urlCheck  = data.url_check || {};

  const badgeClass = verdict === "PHISHING" ? "badge-phishing"
                   : verdict === "LEGITIMATE" ? "badge-legitimate"
                   : "badge-unknown";

  const riskWidth = risk === "high" ? "88%" : risk === "medium" ? "52%" : risk === "low" ? "18%" : "5%";
  const barClass  = `bar-${risk}`;
  const pillClass = `risk-${risk}`;

  // URL check section
  let urlHTML = "";
  if (urlCheck.safe_browsing_checked) {
    if (urlCheck.flagged && urlCheck.flagged.length > 0) {
      urlHTML = `<div class="url-section">
        <span class="url-flagged">⚠ ${urlCheck.flagged.length} URL(s) flagged by Google Safe Browsing</span>
      </div>`;
    } else if (urlCheck.urls_checked > 0) {
      urlHTML = `<div class="url-section">
        <span class="url-clean">✓ ${urlCheck.urls_checked} URL(s) checked — all clean</span>
      </div>`;
    }
  }

  // Signals section (premium only)
  let signalsHTML = "";
  if (signals.length > 0) {
    signalsHTML = `<div class="signals-section">
      <div class="signals-title">Signals detected</div>
      <div class="signals-wrap">${signals.map(s => `<span class="signal-tag">${s}</span>`).join("")}</div>
    </div>`;
  }

  resultDiv.style.display = "block";
  resultDiv.innerHTML = `
    <div class="result-card">
      <div class="verdict-header">
        <span class="verdict-badge ${badgeClass}">${verdict}</span>
        <span class="risk-pill ${pillClass}">${risk} risk</span>
      </div>
      <div class="risk-bar-section">
        <div class="risk-bar-wrap">
          <div class="risk-bar ${barClass}" style="width:${riskWidth}"></div>
        </div>
      </div>
      <div class="explanation">${explanation}</div>
      ${urlHTML}
      ${signalsHTML}
    </div>`;
}

function showUpgrade() {
  resultDiv.style.display = "block";
  resultDiv.innerHTML = `
    <div class="upgrade-card">
      <div class="icon">🃏</div>
      <h3>Free tier limit reached</h3>
      <p>You've used your 5 free scans for today.<br>Upgrade to Jester Premium for unlimited scans + full signal analysis.</p>
    </div>`;
}

function showError(msg) {
  resultDiv.style.display = "block";
  resultDiv.innerHTML = `<div class="error-card">⚠ ${msg}</div>`;
}
