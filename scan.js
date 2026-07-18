/* ==========================================================================
   PhishGuard AI — scan.js
   Owns: URL validation, the scan lifecycle (terminal animation + real API
   call), and rendering the API response into the results dashboard.
   ========================================================================== */

// Point this at your running Flask backend (see backend/README section).
const API_BASE_URL = window.PHISHGUARD_API_BASE || "http://localhost:5000";

const CHECK_LABELS = {
  ssl: "SSL Certificate",
  whois: "WHOIS / Domain Age",
  dns: "DNS Resolution",
  redirects: "Redirect Chain",
  virustotal: "VirusTotal",
  safe_browsing: "Google Safe Browsing",
  phishtank: "PhishTank",
  openphish: "OpenPhish",
  heuristics: "Heuristic Engine",
};

const STATUS_ICON = { safe: "✔", warning: "⚠", danger: "✖", unavailable: "–" };

const TERMINAL_STEPS = [
  "Validating URL...",
  "Checking SSL...",
  "Resolving DNS...",
  "Checking WHOIS...",
  "Checking Redirects...",
  "Checking Google Safe Browsing...",
  "Checking VirusTotal...",
  "Checking PhishTank & OpenPhish...",
  "Running AI Heuristic Analysis...",
  "Calculating Risk Score...",
];

let lastScanRecord = null;

function isLikelyUrl(value) {
  if (!value || value.trim().length === 0) return false;
  const candidate = value.includes("://") ? value.trim() : `https://${value.trim()}`;
  try {
    const parsed = new URL(candidate);
    return Boolean(parsed.hostname && parsed.hostname.includes("."));
  } catch {
    return false;
  }
}

function showInputError(message) {
  const el = document.getElementById("inputError");
  el.textContent = message;
  el.classList.remove("hidden");
}

function clearInputError() {
  document.getElementById("inputError").classList.add("hidden");
}

async function runTerminalAnimation() {
  const section = document.getElementById("terminalSection");
  const log = document.getElementById("terminalLog");
  section.classList.remove("hidden");
  log.textContent = "";
  section.scrollIntoView({ behavior: "smooth", block: "start" });

  const perStepDelay = 2400 / TERMINAL_STEPS.length;
  for (const step of TERMINAL_STEPS) {
    await new Promise((r) => setTimeout(r, perStepDelay));
    log.textContent += `[INFO] ${step}\n`;
    log.scrollTop = log.scrollHeight;
  }
}

async function callScanApi(url) {
  const resp = await fetch(`${API_BASE_URL}/api/scan`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url }),
  });

  if (!resp.ok) {
    const payload = await resp.json().catch(() => ({}));
    throw new Error(payload.error || `Scan failed (HTTP ${resp.status}).`);
  }
  return resp.json();
}

function statusToTier(status) {
  if (status === "safe") return "safe";
  if (status === "danger") return "danger";
  if (status === "warning") return "warning";
  return "unavailable";
}

function renderReportGrid(checks) {
  const grid = document.getElementById("reportGrid");
  grid.innerHTML = "";

  Object.entries(CHECK_LABELS).forEach(([key, label]) => {
    const result = checks[key] || { status: "unavailable", message: "No data returned." };
    const tier = statusToTier(result.status);

    const card = document.createElement("div");
    card.className = "check-card";
    card.innerHTML = `
      <div class="check-card-head">
        <span class="check-card-title">${label}</span>
        <span class="check-card-status ${tier}">${STATUS_ICON[tier]} ${tier === "unavailable" ? "N/A" : tier.charAt(0).toUpperCase() + tier.slice(1)}</span>
      </div>
      <p class="check-card-msg">${result.message || ""}</p>
    `;
    grid.appendChild(card);
  });
}

function renderAiAnalysis(risk) {
  const list = document.getElementById("aiReasons");
  list.innerHTML = "";
  risk.reasons.forEach((reason) => {
    const li = document.createElement("li");
    li.className = "reason-item";
    li.textContent = reason;
    list.appendChild(li);
  });
  document.getElementById("aiRecommendation").textContent = risk.recommendation;
}

function renderVerdict(record) {
  const { verdict, score } = record.risk;
  const badge = document.getElementById("verdictBadge");
  badge.className = `verdict-badge ${verdict.tier}`;
  document.getElementById("verdictEmoji").textContent = verdict.emoji;
  document.getElementById("verdictLabel").textContent = verdict.label;
  document.getElementById("verdictUrl").textContent = record.url;
  document.getElementById("verdictMeta").textContent =
    `Scanned in ${record.duration_ms}ms · ${new Date(record.timestamp * 1000).toLocaleString()}`;

  animateGauge(score);
  document.getElementById("threatMeterFill").style.width = `${score}%`;
}

async function handleScan() {
  const input = document.getElementById("urlInput");
  const btn = document.getElementById("scanBtn");
  const raw = input.value.trim();
  console.log("RAW =", JSON.stringify(raw));
  console.log("VALID =", isLikelyUrl(raw));

  clearInputError();

  if (!isLikelyUrl(raw)) {
    showInputError("Enter a valid URL, e.g. https://example.com/login");
    return;
  }

  document.getElementById("resultsSection").classList.add("hidden");
  btn.disabled = true;
  const originalLabel = btn.innerHTML;
  btn.innerHTML = "<span>Scanning…</span>";

  const terminalPromise = runTerminalAnimation();
  const apiPromise = callScanApi(raw).catch((err) => ({ __error: err.message }));

  const [, apiResult] = await Promise.all([terminalPromise, apiPromise]);

  const log = document.getElementById("terminalLog");

  if (apiResult && apiResult.__error) {
    log.textContent += `[ERROR] ${apiResult.__error}\n`;
    showInputError(apiResult.__error + " — check that the backend is running and reachable.");
    btn.disabled = false;
    btn.innerHTML = originalLabel;
    return;
  }

  log.textContent += "[SUCCESS] Scan Completed\n";
  log.scrollTop = log.scrollHeight;

  lastScanRecord = apiResult;
  renderVerdict(apiResult);
  renderReportGrid(apiResult.checks);
  renderAiAnalysis(apiResult.risk);
  renderTimelineChart(apiResult);

  document.getElementById("resultsSection").classList.remove("hidden");
  document.getElementById("resultsSection").scrollIntoView({ behavior: "smooth", block: "start" });

  btn.disabled = false;
  btn.innerHTML = originalLabel;

  if (typeof refreshHistory === "function") refreshHistory();
}

document.addEventListener("DOMContentLoaded", () => {
  document.getElementById("scanBtn").addEventListener("click", handleScan);
  document.getElementById("urlInput").addEventListener("keydown", (e) => {
    if (e.key === "Enter") handleScan();
  });
});
