(function () {
  const body = document.getElementById('ioc-body');
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

  // Collect all IOCs from REPORTS entries that have iocs array
  const allIocs = [];
  REPORTS.forEach(r => {
    if (r.iocs && Array.isArray(r.iocs)) {
      r.iocs.forEach(ioc => allIocs.push({ ...ioc, report: r.title, reportSlug: r.slug, date: r.date }));
    }
  });

  if (!allIocs.length) {
    if (body) body.innerHTML = '';
    if (noIoc) noIoc.style.display = 'block';
    return;
  }

  function typeColor(t) { return t === 'IP' ? 'var(--amber)' : t === 'DOMAIN' ? 'var(--red)' : 'var(--blue)'; }
  function sevColor(c) { return c === 'HIGH' || c === 'CRITICAL' ? 'var(--red)' : 'var(--amber)'; }
  function indicatorClass(t) { return t === 'IP' ? 'ioc-ip' : t === 'DOMAIN' ? 'ioc-domain' : 'ioc-hash'; }

  if (body) body.innerHTML = allIocs.map(i => `
    <tr>
      <td style="color:${typeColor(i.type)}">${i.type}</td>
      <td class="${indicatorClass(i.type)}">${i.indicator}</td>
      <td>${i.family || '—'}</td>
      <td style="color:${sevColor(i.confidence)}">${i.confidence}</td>
      <td><a href="reports/${i.reportSlug}.html" style="color:var(--muted);font-size:11px;">${i.report}</a></td>
      <td>${i.date}</td>
    </tr>`).join('');

  // CSV download
  if (dlBtn) {
    dlBtn.addEventListener('click', () => {
      const rows = [['TYPE', 'INDICATOR', 'FAMILY', 'CONFIDENCE', 'REPORT', 'DATE']];
      allIocs.forEach(i => rows.push([i.type, i.indicator, i.family || '', i.confidence, i.report, i.date]));
      const csv = rows.map(r => r.map(v => `"${v}"`).join(',')).join('\n');
      const a = document.createElement('a');
      a.href = 'data:text/csv;charset=utf-8,' + encodeURIComponent(csv);
      a.download = 'secblog-iocs.csv';
      a.click();
    });
  }
})();
