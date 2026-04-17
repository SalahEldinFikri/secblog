(function () {
  const container = document.getElementById('ioc-container');
  const noIoc = document.getElementById('no-iocs');
  const dlBtn = document.getElementById('download-csv');

  const footerEl = document.getElementById('footer-links');
  if (footerEl) {
    const links = [];
    if (SITE_CONFIG.links.twitter) links.push(`<a href="${SITE_CONFIG.links.twitter}" target="_blank">X</a>`);
    if (SITE_CONFIG.links.github) links.push(`<a href="${SITE_CONFIG.links.github}"  target="_blank">GitHub</a>`);
    if (SITE_CONFIG.links.email) links.push(`<a href="${SITE_CONFIG.links.email}">Contact</a>`);
    footerEl.innerHTML = links.join('');
  }

  const reportsWithIocs = REPORTS.filter(r => r.iocs && r.iocs.length);

  if (!reportsWithIocs.length) {
    if (container) container.style.display = 'none';
    if (noIoc) noIoc.style.display = 'block';
    return;
  }

  function typeColor(t) { return t === 'IP' ? 'var(--amber)' : t === 'DOMAIN' ? 'var(--red)' : 'var(--blue)'; }
  function indicatorClass(t) { return t === 'IP' ? 'ioc-ip' : t === 'DOMAIN' ? 'ioc-domain' : 'ioc-hash'; }
  function sevColor(c) { return (c === 'HIGH' || c === 'CRITICAL') ? 'var(--red)' : 'var(--amber)'; }
  function tagClass(tag) { const m = { MALWARE: 'tag-malware', THREAT: 'tag-threat', VULN: 'tag-vuln', APT: 'tag-apt' }; return m[tag] || 'tag-malware'; }
  function sevClass(s) { const m = { CRITICAL: 'sev-crit', HIGH: 'sev-high', MEDIUM: 'sev-med', LOW: 'sev-med' }; return m[s] || 'sev-med'; }

  const sorted = [...reportsWithIocs].sort((a, b) => b.date.localeCompare(a.date));

  // Update total count
  const allIocs = sorted.reduce((acc, r) => acc + r.iocs.length, 0);
  const totalEl = document.getElementById('ioc-total');
  if (totalEl) totalEl.textContent = `${allIocs} indicators across ${sorted.length} reports`;

  // Render one block per report
  if (container) {
    container.innerHTML = sorted.map(r => `
      <div class="ioc-report-block" style="margin-bottom:2rem;">
        <div class="ioc-report-heading">
          <div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap;">
            <span class="tag-pill ${tagClass(r.tag)}" style="margin-bottom:0;">${r.tag}</span>
            <span class="sev ${sevClass(r.severity)}">${r.severity}</span>
            <a href="reports/${r.slug}.html" class="ioc-report-title">${r.title}</a>
          </div>
          <div style="display:flex;align-items:center;gap:12px;margin-top:6px;">
            <span style="font-family:var(--mono);font-size:11px;color:var(--muted);">${r.date}</span>
            <span style="font-family:var(--mono);font-size:11px;color:var(--muted);">${r.iocs.length} indicator${r.iocs.length !== 1 ? 's' : ''}</span>
          </div>
        </div>
        <div style="overflow-x:auto;">
          <table class="ioc-table">
            <thead><tr><th>TYPE</th><th>INDICATOR</th><th>MALWARE FAMILY</th><th>CONFIDENCE</th></tr></thead>
            <tbody>
              ${r.iocs.map(i => `
              <tr>
                <td style="color:${typeColor(i.type)}">${i.type}</td>
                <td class="${indicatorClass(i.type)}">${i.indicator}</td>
                <td>${i.family || '—'}</td>
                <td style="color:${sevColor(i.confidence)}">${i.confidence}</td>
              </tr>`).join('')}
            </tbody>
          </table>
        </div>
      </div>
    `).join('');
  }

  // CSV download — all IOCs combined
  if (dlBtn) {
    dlBtn.addEventListener('click', () => {
      const rows = [['TYPE', 'INDICATOR', 'FAMILY', 'CONFIDENCE', 'REPORT', 'DATE']];
      sorted.forEach(r => r.iocs.forEach(i =>
        rows.push([i.type, i.indicator, i.family || '', i.confidence, r.title, r.date])
      ));
      const csv = rows.map(r => r.map(v => `"${v}"`).join(',')).join('\n');
      const a = document.createElement('a');
      a.href = 'data:text/csv;charset=utf-8,' + encodeURIComponent(csv);
      a.download = 'secblog-iocs.csv';
      a.click();
    });
  }
})();
