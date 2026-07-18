/* ==========================================================================
   PhishGuard AI — app.js
   Owns: nav/theme toggle, scan history table (fetch/search/sort), and the
   export actions (PDF / JSON / copy) for the most recent scan.
   ========================================================================== */

document.getElementById("themeToggle")?.addEventListener("click", () => {
  document.documentElement.classList.toggle("dark");
});

/* ---------------- History ---------------- */

async function fetchHistory(query = "") {
  const url = new URL(`${API_BASE_URL}/api/history`);
  if (query) url.searchParams.set("q", query);
  const resp = await fetch(url);
  if (!resp.ok) throw new Error("Could not load history.");
  return resp.json();
}

function verdictTier(label) {
  const map = { Safe: "safe", Suspicious: "warning", Phishing: "danger" };
  return map[label] || "unavailable";
}

function renderHistoryTable(records, sortMode) {
  const tbody = document.getElementById("historyTableBody");
  const empty = document.getElementById("historyEmpty");
  tbody.innerHTML = "";

  const sorted = [...records];
  if (sortMode === "risk") {
    sorted.sort((a, b) => b.score - a.score);
  } else {
    sorted.sort((a, b) => b.timestamp - a.timestamp);
  }

  if (sorted.length === 0) {
    empty.classList.remove("hidden");
    return;
  }
  empty.classList.add("hidden");

  sorted.forEach((record) => {
    const tr = document.createElement("tr");
    const tier = verdictTier(record.verdict);
    tr.innerHTML = `
      <td class="font-mono text-xs max-w-xs truncate" title="${record.url}">${record.url}</td>
      <td class="text-xs text-slate-500">${new Date(record.timestamp * 1000).toLocaleString()}</td>
      <td class="text-xs">${record.score}%</td>
      <td><span class="badge-mini ${tier}">${record.verdict}</span></td>
    `;
    tbody.appendChild(tr);
  });
}

async function refreshHistory() {
  try {
    const query = document.getElementById("historySearch").value.trim();
    const sortMode = document.getElementById("historySort").value;
    const { results } = await fetchHistory(query);
    renderHistoryTable(results, sortMode);
  } catch {
    // Backend unreachable — leave the "no scans yet" empty state in place.
  }
}

document.getElementById("historySearch")?.addEventListener("input", () => {
  clearTimeout(window.__historySearchDebounce);
  window.__historySearchDebounce = setTimeout(refreshHistory, 250);
});
document.getElementById("historySort")?.addEventListener("change", refreshHistory);

document.addEventListener("DOMContentLoaded", refreshHistory);

/* ---------------- Export actions ---------------- */

document.getElementById("exportJsonBtn")?.addEventListener("click", () => {
  if (!lastScanRecord) return;
  const blob = new Blob([JSON.stringify(lastScanRecord, null, 2)], { type: "application/json" });
  const link = document.createElement("a");
  link.href = URL.createObjectURL(blob);
  link.download = `phishguard-scan-${lastScanRecord.id}.json`;
  link.click();
  URL.revokeObjectURL(link.href);
});

document.getElementById("copyResultBtn")?.addEventListener("click", async () => {
  if (!lastScanRecord) return;
  const { url, risk } = lastScanRecord;
  const summary = `PhishGuard AI Scan Result\nURL: ${url}\nVerdict: ${risk.verdict.label}\nRisk score: ${risk.score}%\nReasons: ${risk.reasons.join(", ")}\nRecommendation: ${risk.recommendation}`;
  try {
    await navigator.clipboard.writeText(summary);
    const btn = document.getElementById("copyResultBtn");
    const original = btn.textContent;
    btn.textContent = "Copied!";
    setTimeout(() => (btn.textContent = original), 1500);
  } catch {
    showInputError("Could not copy to clipboard.");
  }
});

document.getElementById("exportPdfBtn")?.addEventListener("click", () => {
  if (!lastScanRecord || !window.jspdf) return;
  const { jsPDF } = window.jspdf;
  const doc = new jsPDF();
  const { url, risk, checks, timestamp } = lastScanRecord;

  doc.setFont("helvetica", "bold");
  doc.setFontSize(18);
  doc.text("PhishGuard AI — Scan Report", 14, 18);

  doc.setFont("helvetica", "normal");
  doc.setFontSize(11);
  doc.text(`URL: ${url}`, 14, 30);
  doc.text(`Scanned: ${new Date(timestamp * 1000).toLocaleString()}`, 14, 37);
  doc.text(`Verdict: ${risk.verdict.label}    Risk score: ${risk.score}%`, 14, 44);

  doc.setFont("helvetica", "bold");
  doc.text("AI Analysis", 14, 56);
  doc.setFont("helvetica", "normal");
  let y = 63;
  risk.reasons.forEach((reason) => {
    doc.text(`• ${reason}`, 16, y);
    y += 6;
  });
  y += 4;
  doc.text(`Recommendation: ${risk.recommendation}`, 14, y, { maxWidth: 180 });
  y += 14;

  doc.setFont("helvetica", "bold");
  doc.text("Detection Report", 14, y);
  y += 7;
  doc.setFont("helvetica", "normal");
  Object.entries(CHECK_LABELS).forEach(([key, label]) => {
    const result = checks[key] || { status: "unavailable", message: "No data." };
    if (y > 280) { doc.addPage(); y = 20; }
    doc.text(`${label}: ${result.status.toUpperCase()} — ${result.message || ""}`, 14, y, { maxWidth: 180 });
    y += 8;
  });

  doc.save(`phishguard-scan-${lastScanRecord.id}.pdf`);
});
