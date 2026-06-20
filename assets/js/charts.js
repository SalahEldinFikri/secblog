// ============================================================
//  CHARTS.JS — Renders IOC & YARA statistics charts on the
//  homepage using Chart.js, sourced from REPORTS (reports-data.js)
// ============================================================

document.addEventListener('DOMContentLoaded', () => {
  if (typeof Chart === 'undefined' || typeof REPORTS === 'undefined') return;

  const css = getComputedStyle(document.documentElement);
  const colors = {
    green: css.getPropertyValue('--green').trim() || '#00ff9d',
    greenDim: css.getPropertyValue('--green-dim').trim() || '#00cc7d',
    red: css.getPropertyValue('--red').trim() || '#ff4d6d',
    amber: css.getPropertyValue('--amber').trim() || '#f59e0b',
    blue: css.getPropertyValue('--blue').trim() || '#38bdf8',
    text: css.getPropertyValue('--text').trim() || '#e2e8f0',
    muted: css.getPropertyValue('--muted').trim() || '#64748b',
    border: css.getPropertyValue('--border').trim() || '#1f2d45',
  };

  const palette = [colors.green, colors.blue, colors.amber, colors.red, colors.greenDim, '#a78bfa', '#fb923c'];

  Chart.defaults.color = colors.muted;
  Chart.defaults.font.family = "'Inter', 'Segoe UI', system-ui, sans-serif";
  Chart.defaults.font.size = 11;

  // Gather all IOCs across reports
  const allIocs = [];
  REPORTS.forEach(r => {
    if (r.iocs) r.iocs.forEach(i => allIocs.push({ ...i, reportSlug: r.slug }));
  });

  // ── Chart 1: IOC Types (doughnut) ──
  const typeCounts = {};
  allIocs.forEach(i => { typeCounts[i.type] = (typeCounts[i.type] || 0) + 1; });

  const ctxTypes = document.getElementById('chart-ioc-types');
  if (ctxTypes) {
    new Chart(ctxTypes, {
      type: 'doughnut',
      data: {
        labels: Object.keys(typeCounts),
        datasets: [{
          data: Object.values(typeCounts),
          backgroundColor: palette,
          borderColor: colors.border,
          borderWidth: 2,
        }],
      },
      options: {
        plugins: { legend: { position: 'bottom', labels: { boxWidth: 12, color: colors.text } } },
      },
    });
  }

  // ── Chart 2: Confidence Levels (bar) ──
  const confCounts = {};
  allIocs.forEach(i => {
    const c = i.confidence || 'UNKNOWN';
    confCounts[c] = (confCounts[c] || 0) + 1;
  });
  const confOrder = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN'];
  const confLabels = confOrder.filter(c => confCounts[c] !== undefined);
  const confColors = { CRITICAL: colors.red, HIGH: colors.amber, MEDIUM: colors.blue, LOW: colors.greenDim, UNKNOWN: colors.muted };

  const ctxConf = document.getElementById('chart-confidence');
  if (ctxConf) {
    new Chart(ctxConf, {
      type: 'bar',
      data: {
        labels: confLabels,
        datasets: [{
          label: 'IOCs',
          data: confLabels.map(c => confCounts[c]),
          backgroundColor: confLabels.map(c => confColors[c] || colors.green),
          borderRadius: 4,
        }],
      },
      options: {
        plugins: { legend: { display: false } },
        scales: {
          x: { grid: { color: colors.border } },
          y: { beginAtZero: true, ticks: { stepSize: 1 }, grid: { color: colors.border } },
        },
      },
    });
  }

  // ── Chart 3: IOCs by Malware Family (horizontal bar) ──
  const familyCounts = {};
  allIocs.forEach(i => {
    const f = i.family || 'Unknown';
    familyCounts[f] = (familyCounts[f] || 0) + 1;
  });
  const familyEntries = Object.entries(familyCounts).sort((a, b) => b[1] - a[1]);

  const ctxFam = document.getElementById('chart-families');
  if (ctxFam) {
    new Chart(ctxFam, {
      type: 'bar',
      data: {
        labels: familyEntries.map(e => e[0]),
        datasets: [{
          label: 'IOCs',
          data: familyEntries.map(e => e[1]),
          backgroundColor: colors.green,
          borderRadius: 4,
        }],
      },
      options: {
        indexAxis: 'y',
        plugins: { legend: { display: false } },
        scales: {
          x: { beginAtZero: true, ticks: { stepSize: 1 }, grid: { color: colors.border } },
          y: { grid: { color: colors.border } },
        },
      },
    });
  }

  // ── Chart 4: YARA Rules per Report (bar) ──
  const yaraData = REPORTS.filter(r => r.yara && r.yara.length)
    .map(r => ({ label: r.title.length > 20 ? r.title.slice(0, 20) + '…' : r.title, count: r.yara.length }));

  const ctxYara = document.getElementById('chart-yara');
  if (ctxYara) {
    new Chart(ctxYara, {
      type: 'bar',
      data: {
        labels: yaraData.map(d => d.label),
        datasets: [{
          label: 'YARA Rules',
          data: yaraData.map(d => d.count),
          backgroundColor: colors.blue,
          borderRadius: 4,
        }],
      },
      options: {
        plugins: { legend: { display: false } },
        scales: {
          x: { grid: { color: colors.border } },
          y: { beginAtZero: true, ticks: { stepSize: 1 }, grid: { color: colors.border } },
        },
      },
    });
  }
});
