// Homepage logic

(function () {

  // Render ticker
  const tickerEl = document.getElementById('ticker-inner');
  if (tickerEl && SITE_CONFIG.tickerMessages.length) {
    const doubled = [...SITE_CONFIG.tickerMessages, ...SITE_CONFIG.tickerMessages];
    tickerEl.innerHTML = doubled.map(m =>
      `<span class="ticker-item"><span class="label">${m.label}</span>${m.text}</span>`
    ).join('');
  }

  // Render author about section
  const nameEl = document.getElementById('author-name');
  const bioEl = document.getElementById('author-bio');
  const avEl = document.getElementById('avatar-initials');
  if (nameEl) nameEl.textContent = SITE_CONFIG.authorName;
  if (bioEl) bioEl.textContent = SITE_CONFIG.bio;
  if (avEl) avEl.textContent = SITE_CONFIG.initials;

  const certEl = document.getElementById('cert-badges');
  if (certEl) certEl.innerHTML = SITE_CONFIG.certifications.map(c => `<span class="badge">${c}</span>`).join('');

  const skillEl = document.getElementById('skill-badges');
  if (skillEl) skillEl.innerHTML = SITE_CONFIG.skills.map(s => `<span class="badge">${s}</span>`).join('');

  // Footer links
  const footerEl = document.getElementById('footer-links');
  if (footerEl) {
    const links = [];
    if (SITE_CONFIG.links.twitter) links.push(`<a href="${SITE_CONFIG.links.twitter}" target="_blank">X</a>`);
    if (SITE_CONFIG.links.github) links.push(`<a href="${SITE_CONFIG.links.github}"  target="_blank">GitHub</a>`);
    if (SITE_CONFIG.links.linkedin) links.push(`<a href="${SITE_CONFIG.links.linkedin}" target="_blank">LinkedIn</a>`);
    if (SITE_CONFIG.links.email) links.push(`<a href="${SITE_CONFIG.links.email}">Contact</a>`);
    footerEl.innerHTML = links.join('');
  }

  // Render latest 6 reports
  const grid = document.getElementById('posts-grid');
  const noRep = document.getElementById('no-reports');
  const countEl = document.getElementById('report-count');

  if (countEl) countEl.textContent = REPORTS.length;

  if (!REPORTS.length) {
    if (grid) grid.style.display = 'none';
    if (noRep) noRep.style.display = 'block';
    return;
  }

  const sorted = [...REPORTS].sort((a, b) => b.date.localeCompare(a.date)).slice(0, 6);
  if (grid) grid.innerHTML = sorted.map(r => reportCard(r, '../')).join('');

})();

function tagClass(tag) {
  const m = { MALWARE: 'tag-malware', THREAT: 'tag-threat', VULN: 'tag-vuln', APT: 'tag-apt' };
  return m[tag] || 'tag-malware';
}

function sevClass(s) {
  const m = { CRITICAL: 'sev-crit', HIGH: 'sev-high', MEDIUM: 'sev-med', LOW: 'sev-med' };
  return m[s] || 'sev-med';
}

function reportCard(r, prefix = '') {
  prefix = prefix || '';
  return `
  <div class="post-card" onclick="window.location='${prefix}secblog/reports/${r.slug}.html'">
    <span class="tag-pill ${tagClass(r.tag)}">${r.tag}</span>
    <div class="post-meta">
      <span>${r.date}</span>
      <span>${r.readTime}</span>
      <span class="sev ${sevClass(r.severity)}">${r.severity}</span>
    </div>
    <div class="post-title">${r.title}</div>
    <div class="post-excerpt">${r.excerpt}</div>
    <div class="read-more">READ REPORT →</div>
  </div>`;
}
