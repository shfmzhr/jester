const API_URL = "https://phishguard-production-93c3.up.railway.app/analyse";

const scanBtn     = document.getElementById("scanBtn");
const emailInput  = document.getElementById("emailInput");
const resultDiv   = document.getElementById("result");

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

    if (!response.ok) {
      showError(data.error || "Server error. Please try again.");
      return;
    }

    showResult(data);

  } catch (err) {
    showError("Could not reach PhishGuard server. Check your connection.");
  } finally {
    setLoading(false);
  }
});

function setLoading(on) {
  scanBtn.disabled = on;
  if (on) {
    resultDiv.style.display = "block";
    resultDiv.innerHTML = `<div class="loading"><span class="spinner"></span>Analysing email...</div>`;
  }
}

function showResult(data) {
  const verdict    = (data.verdict || "UNKNOWN").toUpperCase();
  const riskLevel  = (data.risk_level || "unknown").toLowerCase();
  const explanation = data.explanation || "No explanation provided.";
  const signals    = data.signals || [];

  const badgeClass = verdict === "PHISHING"   ? "badge-phishing"
                   : verdict === "LEGITIMATE" ? "badge-legitimate"
                   : "badge-unknown";

  const riskWidth = riskLevel === "high"   ? "85%"
                  : riskLevel === "medium" ? "50%"
                  : riskLevel === "low"    ? "20%"
                  : "5%";

  const signalsHTML = signals.length
    ? `<div class="signals-title">Signals detected</div>
       <div class="signals">${signals.map(s => `<span class="signal-tag">${s}</span>`).join("")}</div>`
    : "";

  resultDiv.style.display = "block";
  resultDiv.innerHTML = `
    <span class="verdict-badge ${badgeClass}">${verdict}</span>
    <div class="risk-row risk-${riskLevel}">
      <span class="risk-label">Risk: ${riskLevel}</span>
      <div class="risk-bar-wrap">
        <div class="risk-bar" style="width: ${riskWidth}"></div>
      </div>
    </div>
    <div class="explanation">${explanation}</div>
    ${signalsHTML}
  `;
}

function showError(msg) {
  resultDiv.style.display = "block";
  resultDiv.innerHTML = `<div class="error-msg">⚠️ ${msg}</div>`;
}
