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
});
