/* ==========================================================================
   PhishGuard AI — charts.js
   Owns: the circular risk gauge animation and the Chart.js detection timeline.
   ========================================================================== */

const GAUGE_CIRCUMFERENCE = 283; // matches the arc path length in index.html

function animateGauge(score) {
  const arc = document.getElementById("gaugeArc");
  const numberEl = document.getElementById("gaugeScore");
  const clamped = Math.max(0, Math.min(100, score));
  const offset = GAUGE_CIRCUMFERENCE - (GAUGE_CIRCUMFERENCE * clamped) / 100;

  requestAnimationFrame(() => {
    arc.style.strokeDashoffset = offset;
  });

  const duration = 1200;
  const start = performance.now();
  function tick(now) {
    const progress = Math.min(1, (now - start) / duration);
    numberEl.textContent = Math.round(progress * clamped);
    if (progress < 1) requestAnimationFrame(tick);
  }
  requestAnimationFrame(tick);
}

let timelineChartInstance = null;

function renderTimelineChart(record) {
  const ctx = document.getElementById("timelineChart");
  if (!ctx) return;

  const order = ["ssl", "dns", "whois", "redirects", "safe_browsing", "virustotal", "phishtank", "openphish", "heuristics"];
  const severityValue = { safe: 5, unavailable: 15, warning: 55, danger: 90 };
  const labels = order.map((k) => (CHECK_LABELS[k] || k));
  const data = order.map((k) => {
    const status = record.checks[k]?.status || "unavailable";
    return severityValue[status] ?? 15;
  });
  const colors = order.map((k) => {
    const status = record.checks[k]?.status || "unavailable";
    return { safe: "#1fe6a0", warning: "#ffb020", danger: "#ff4d6a", unavailable: "#3d4a6b" }[status];
  });

  if (timelineChartInstance) {
    timelineChartInstance.destroy();
  }

  timelineChartInstance = new Chart(ctx, {
    type: "line",
    data: {
      labels,
      datasets: [
        {
          label: "Signal severity",
          data,
          borderColor: "#22e8ff",
          borderWidth: 2,
          pointBackgroundColor: colors,
          pointBorderColor: colors,
          pointRadius: 5,
          tension: 0.35,
          fill: {
            target: "origin",
            above: "rgba(34,232,255,0.06)",
          },
        },
      ],
    },
    options: {
      responsive: true,
      plugins: { legend: { display: false } },
      scales: {
        x: { ticks: { color: "#7c8aad", font: { family: "JetBrains Mono", size: 10 } }, grid: { color: "rgba(255,255,255,0.04)" } },
        y: { min: 0, max: 100, ticks: { color: "#7c8aad", stepSize: 25 }, grid: { color: "rgba(255,255,255,0.04)" } },
      },
    },
  });
}
