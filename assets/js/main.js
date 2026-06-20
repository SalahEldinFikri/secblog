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
  const bioEl  = document.getElementById('author-bio');
  const avEl   = document.getElementById('avatar-initials');
  if (nameEl) nameEl.textContent = SITE_CONFIG.authorName;
  if (bioEl)  bioEl.textContent  = SITE_CONFIG.bio;
  if (avEl)   avEl.textContent   = SITE_CONFIG.initials;

  const certEl = document.getElementById('cert-badges');
  if (certEl) certEl.innerHTML = SITE_CONFIG.certifications.map(c => `<span class="badge">${c}</span>`).join('');

  const skillEl = document.getElementById('skill-badges');
  if (skillEl) skillEl.innerHTML = SITE_CONFIG.skills.map(s => `<span class="badge">${s}</span>`).join('');

  // Footer links
  const footerEl = document.getElementById('footer-links');
  if (footerEl) {
    const links = [];
    if (SITE_CONFIG.links.twitter)  links.push(`<a href="${SITE_CONFIG.links.twitter}"  target="_blank">X</a>`);
    if (SITE_CONFIG.links.github)   links.push(`<a href="${SITE_CONFIG.links.github}"   target="_blank">GitHub</a>`);
    if (SITE_CONFIG.links.linkedin) links.push(`<a href="${SITE_CONFIG.links.linkedin}" target="_blank">LinkedIn</a>`);
    if (SITE_CONFIG.links.email)    links.push(`<a href="${SITE_CONFIG.links.email}">Contact</a>`);
    footerEl.innerHTML = links.join('');
  }

  // ── Latest reports ────────────────────────────────────────
  const grid     = document.getElementById('posts-grid');
  const noRep    = document.getElementById('no-reports');
  const countEl  = document.getElementById('report-count');

  if (countEl) countEl.textContent = REPORTS.length;

  // Update IOC count in hero
  const iocCountEl = document.getElementById('ioc-count');
  if (iocCountEl) {
    const total = REPORTS.reduce((n, r) => n + (r.iocs ? r.iocs.length : 0), 0);
    iocCountEl.textContent = total || '0';
  }

  if (!REPORTS.length) {
    if (grid)  grid.style.display  = 'none';
    if (noRep) noRep.style.display = 'block';
  } else {
    const sorted = [...REPORTS].sort((a, b) => b.date.localeCompare(a.date)).slice(0, 6);
    if (grid) grid.innerHTML = sorted.map(r => reportCard(r, '')).join('');
  }

  // ── IOC preview (latest 8 IOCs across all reports) ────────
  const iocContainer = document.getElementById('home-ioc-container');
  const noIoc        = document.getElementById('home-no-iocs');

  const reportsWithIocs = REPORTS.filter(r => r.iocs && r.iocs.length)
                                  .sort((a, b) => b.date.localeCompare(a.date));

  if (!reportsWithIocs.length) {
    if (iocContainer) iocContainer.style.display = 'none';
    if (noIoc)        noIoc.style.display = 'block';
  } else {
    // Collect up to 8 latest IOCs, tagging each with its source report
    const preview = [];
    for (const r of reportsWithIocs) {
      for (const ioc of r.iocs) {
        if (preview.length >= 8) break;
        preview.push({ ...ioc, reportTitle: r.title, reportSlug: r.slug, reportTag: r.tag, reportSev: r.severity });
      }
      if (preview.length >= 8) break;
    }

    const totalIocs = reportsWithIocs.reduce((n, r) => n + r.iocs.length, 0);

    iocContainer.innerHTML = `
      <div style="overflow-x:auto;">
        <table class="ioc-table">
          <thead>
            <tr>
              <th>TYPE</th>
              <th>INDICATOR</th>
              <th>FAMILY</th>
              <th>CONFIDENCE</th>
              <th>SOURCE REPORT</th>
            </tr>
          </thead>
          <tbody>
            ${preview.map(i => `
            <tr>
              <td style="color:${typeColor(i.type)}">${i.type}</td>
              <td class="${indicatorClass(i.type)}">${i.indicator}</td>
              <td>${i.family || '—'}</td>
              <td style="color:${sevColor(i.confidence)}">${i.confidence}</td>
              <td style="font-size:11px;">
                <a href="reports/${i.reportSlug}.html"
                   style="color:var(--muted-bright);text-decoration:none;border-bottom:1px solid var(--border);"
                   onmouseover="this.style.color='var(--green)'"
                   onmouseout="this.style.color='var(--muted-bright)'"
                >${i.reportTitle.length > 55 ? i.reportTitle.slice(0, 55) + '…' : i.reportTitle}</a>
              </td>
            </tr>`).join('')}
          </tbody>
        </table>
      </div>
      <div style="margin-top:1rem;font-family:var(--mono);font-size:11px;color:var(--muted);">
        showing ${preview.length} of ${totalIocs} total indicators —
        <a href="ioc-feed.html" style="color:var(--green);border-bottom:1px solid;">view full feed →</a>
      </div>`;
  }

  // ── YARA preview (latest 3 rules) ─────────────────────────
  const yaraContainer = document.getElementById('home-yara-container');
  const noYara        = document.getElementById('home-no-yara');

  const reportsWithYara = REPORTS.filter(r => r.yara && r.yara.length)
                                   .sort((a, b) => b.date.localeCompare(a.date));

  if (!reportsWithYara.length) {
    if (yaraContainer) yaraContainer.style.display = 'none';
    if (noYara)        noYara.style.display = 'block';
  } else {
    // Collect up to 3 latest YARA rules
    const yaraPreview = [];
    for (const r of reportsWithYara) {
      for (const y of r.yara) {
        if (yaraPreview.length >= 3) break;
        yaraPreview.push({ ...y, reportTitle: r.title, reportSlug: r.slug });
      }
      if (yaraPreview.length >= 3) break;
    }

    const totalRules = reportsWithYara.reduce((n, r) => n + r.yara.length, 0);

    yaraContainer.innerHTML = `
      <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(300px,1fr));gap:1px;background:var(--border);">
        ${yaraPreview.map(y => `
        <div class="yara-home-card">
          <div class="yara-home-name">${y.name}</div>
          <div class="yara-home-desc">${y.description}</div>
          <div class="yara-home-meta">by ${y.author}</div>
          <div class="yara-home-footer">
            <a href="reports/${y.reportSlug}.html" class="yara-home-link">view report →</a>
            <button class="yara-copy-btn-home" data-rule="${encodeURIComponent(y.rule)}">COPY RULE</button>
          </div>
        </div>`).join('')}
      </div>
      <div style="margin-top:1rem;font-family:var(--mono);font-size:11px;color:var(--muted);">
        showing ${yaraPreview.length} of ${totalRules} total rules —
        <a href="yara-feed.html" style="color:var(--green);border-bottom:1px solid;">view full feed →</a>
      </div>`;

    // Wire up copy buttons
    document.querySelectorAll('.yara-copy-btn-home').forEach(btn => {
      btn.addEventListener('click', () => {
        const rule = decodeURIComponent(btn.dataset.rule);
        navigator.clipboard.writeText(rule).then(() => {
          btn.textContent = 'COPIED ✓';
          btn.style.color = 'var(--green)';
          setTimeout(() => { btn.textContent = 'COPY RULE'; btn.style.color = ''; }, 2000);
        });
      });
    });
  }

})();

// ── Shared helpers ─────────────────────────────────────────────

function tagClass(tag) {
  const m = { MALWARE: 'tag-malware', THREAT: 'tag-threat', VULN: 'tag-vuln', APT: 'tag-apt' };
  return m[tag] || 'tag-malware';
}

function sevClass(s) {
  const m = { CRITICAL: 'sev-crit', HIGH: 'sev-high', MEDIUM: 'sev-med', LOW: 'sev-med' };
  return m[s] || 'sev-med';
}

function typeColor(t)     { return t === 'IP' ? 'var(--amber)' : t === 'DOMAIN' ? 'var(--red)' : 'var(--blue)'; }
function indicatorClass(t){ return t === 'IP' ? 'ioc-ip' : t === 'DOMAIN' ? 'ioc-domain' : 'ioc-hash'; }
function sevColor(c)      { return (c === 'HIGH' || c === 'CRITICAL') ? 'var(--red)' : 'var(--amber)'; }

function reportCard(r, prefix) {
  prefix = prefix || '';
  return `
  <div class="post-card" onclick="window.location='${prefix}reports/${r.slug}.html'">
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
