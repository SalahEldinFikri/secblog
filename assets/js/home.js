// ============================================================
//  HOME.JS — Atlantean homepage extras: featured expedition card
//  and YARA rule count stat. Runs alongside main.js (which still
//  drives reports grid, IOC table, YARA preview, ticker, about, footer).
// ============================================================

document.addEventListener('DOMContentLoaded', () => {
  if (typeof REPORTS === 'undefined') return;

  // ── YARA rule count stat ──
  const yaraCountEl = document.getElementById('yara-count');
  if (yaraCountEl) {
    const total = REPORTS.reduce((n, r) => n + (r.yara ? r.yara.length : 0), 0);
    yaraCountEl.textContent = total || '0';
  }

  // ── Featured expedition: most recent report tagged LAB, or
  //    fall back to the most recent report overall ──
  const featuredEl = document.getElementById('featured-expedition');
  if (featuredEl) {
    const sorted = [...REPORTS].sort((a, b) => b.date.localeCompare(a.date));
    const featured = sorted.find(r => r.tag === 'LAB') || sorted[0];

    if (featured) {
      featuredEl.innerHTML = `
        <div class="atl-featured-eyebrow">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none"><circle cx="12" cy="8" r="6" stroke="currentColor" stroke-width="1.5"/><path d="M8.5 13.5L7 22l5-3 5 3-1.5-8.5" stroke="currentColor" stroke-width="1.5" stroke-linejoin="round"/></svg>
          Featured Expedition
        </div>
        <h3>${featured.title.length > 70 ? featured.title.slice(0, 70) + '…' : featured.title}</h3>
        <p>${featured.excerpt.length > 160 ? featured.excerpt.slice(0, 160) + '…' : featured.excerpt}</p>
        <a href="reports/${featured.slug}.html" class="atl-btn-outline">
          View Expedition
          <svg width="13" height="13" viewBox="0 0 24 24" fill="none"><path d="M5 12h14M13 6l6 6-6 6" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>
        </a>`;
    }
  }

  // ── New drop: a YARA rule + extractor published before its report ──
  //    (entries in extractors-data.js / saved extractors with report: "")
  const dropsEl = document.getElementById('unreported-drops');
  if (dropsEl) {
    const store = window.ExtractorStore;
    const esc = store ? store.esc : (s) => String(s);
    const cut = (s, n) => (s.length > n ? s.slice(0, n) + '…' : s);
    const arrow = '<svg width="13" height="13" viewBox="0 0 24 24" fill="none"><path d="M5 12h14M13 6l6 6-6 6" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>';
    const all = store ? store.all() : [];
    const pending = store ? store.unreported() : [];

    if (pending.length) {
      const e = pending[0];
      const ageDays = (Date.now() - new Date(e.date).getTime()) / 86400000;
      const isNew = ageDays <= 7;
      const nIocs = e.iocs ? e.iocs.length : 0;
      const desc = e.description || 'A YARA rule and config extractor, published ahead of the full write-up.';
      dropsEl.innerHTML = `
        <div class="atl-drops-eyebrow">
          <span class="atl-drops-dot"></span>
          New Drop · No Report Yet
          ${isNew ? '<span class="atl-drops-new">NEW</span>' : ''}
        </div>
        <h3>${esc(cut(e.name, 70))}</h3>
        <p>${esc(cut(desc, 160))}</p>
        <div class="atl-drops-chips">
          ${e.yara && e.yara.rule ? '<span class="atl-drops-chip">YARA ✓</span>' : ''}
          <span class="atl-drops-chip">EXTRACTOR ✓</span>
          ${nIocs ? `<span class="atl-drops-chip">${nIocs} IOC${nIocs !== 1 ? 's' : ''}</span>` : ''}
          <span class="atl-drops-chip atl-drops-chip-muted">${esc(e.family || '')}</span>
        </div>
        <a href="detections.html?tab=extractors#${esc(e.slug)}" class="atl-btn-outline atl-btn-amber">View Extractor ${arrow}</a>
        ${pending.length > 1 ? `<a href="detections.html?tab=extractors&filter=noreport" class="atl-drops-more">+${pending.length - 1} more without a report →</a>` : ''}`;
    } else {
      const none = !all.length;
      dropsEl.innerHTML = `
        <div class="atl-drops-eyebrow atl-drops-idle">
          <span class="atl-drops-dot"></span>
          Extractor Drops
        </div>
        <h3>${none ? 'No extractors yet' : 'All caught up'}</h3>
        <p>${none
          ? 'Config extractors and the YARA rules that find them will be announced here the moment they land.'
          : 'Every published extractor has a full report. When a YARA rule + extractor goes up before its write-up, it is announced right here.'}</p>
        <a href="detections.html?tab=extractors" class="atl-btn-outline atl-btn-amber">${none ? 'Open Extractors' : 'Browse Extractors'} ${arrow}</a>`;
    }
  }

});
