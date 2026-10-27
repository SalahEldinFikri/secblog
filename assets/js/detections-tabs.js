// ============================================================
//  DETECTIONS-TABS.JS — YARA / Sigma / Extractors tabs
//  URL:  detections.html?tab=yara | sigma | extractors
//        (detections.html#sigma works too)
//  Load this BEFORE the panel scripts so the right tab is already
//  visible when a deep link (#slug) scrolls to an entry.
// ============================================================
(function () {
  var TABS = ['yara', 'sigma', 'extractors'];
  var TITLES = {
    yara: 'YARA Rules — Detections — SecBlog',
    sigma: 'Sigma Rules — Detections — SecBlog',
    extractors: 'Config Extractors — Detections — SecBlog'
  };

  var tabEls = Array.prototype.slice.call(document.querySelectorAll('.det-tab'));
  var panelEls = Array.prototype.slice.call(document.querySelectorAll('.det-panel'));
  if (!tabEls.length) return;

  function fromUrl() {
    var t = new URLSearchParams(location.search).get('tab');
    if (TABS.indexOf(t) !== -1) return t;
    var h = (location.hash || '').slice(1);
    if (TABS.indexOf(h) !== -1) return h;
    return 'yara';
  }

  function show(tab, opts) {
    opts = opts || {};
    tabEls.forEach(function (b) {
      var on = b.getAttribute('data-det-tab') === tab;
      b.classList.toggle('active', on);
      b.setAttribute('aria-selected', on ? 'true' : 'false');
      b.setAttribute('tabindex', on ? '0' : '-1');
    });
    panelEls.forEach(function (p) {
      p.classList.toggle('active', p.id === 'det-panel-' + tab);
    });
    document.title = TITLES[tab];
    if (opts.updateUrl) {
      try { history.replaceState(null, '', location.pathname + '?tab=' + tab); } catch (e) { }
    }
    if (opts.scrollTop) {
      var hero = document.querySelector('.det-hero');
      if (hero) {
        var y = hero.getBoundingClientRect().bottom + window.pageYOffset - 1;
        if (window.pageYOffset > y) window.scrollTo({ top: y });
      }
    }
  }

  tabEls.forEach(function (b, i) {
    b.addEventListener('click', function () {
      show(b.getAttribute('data-det-tab'), { updateUrl: true, scrollTop: true });
    });
    // arrow-key navigation (WAI-ARIA tabs pattern)
    b.addEventListener('keydown', function (e) {
      var next = null;
      if (e.key === 'ArrowRight') next = (i + 1) % tabEls.length;
      else if (e.key === 'ArrowLeft') next = (i - 1 + tabEls.length) % tabEls.length;
      else if (e.key === 'Home') next = 0;
      else if (e.key === 'End') next = tabEls.length - 1;
      if (next === null) return;
      e.preventDefault();
      tabEls[next].focus();
      show(tabEls[next].getAttribute('data-det-tab'), { updateUrl: true });
    });
  });

  window.addEventListener('hashchange', function () {
    var h = (location.hash || '').slice(1);
    if (TABS.indexOf(h) !== -1) show(h, { updateUrl: true, scrollTop: true });
  });

  // the right tab is visible before any panel script runs
  show(fromUrl(), { updateUrl: false });

  // ── live counts on the tabs ────────────────────────────────
  function yaraCount() {
    var n = 0;
    if (typeof REPORTS !== 'undefined') REPORTS.forEach(function (r) { n += (r.yara ? r.yara.length : 0); });
    try { n += JSON.parse(localStorage.getItem('secblog_standalone_yara') || '[]').length; } catch (e) { }
    return n;
  }

  function setCount(tab, n) {
    var el = document.getElementById('det-count-' + tab);
    if (el) el.textContent = n;
  }

  function refresh() {
    setCount('yara', yaraCount());
    setCount('sigma', window.SigmaPage ? window.SigmaPage.count() : 0);
    setCount('extractors', window.ExtractorStore ? window.ExtractorStore.all().length : 0);
  }

  window.addEventListener('det:changed', refresh);

  // once every panel script has run (DOMContentLoaded fires after all of them — a 0ms timer
  // can fire while the later scripts are still downloading): first count + hook the YARA
  // page's own stats refresh so standalone YARA rules update the badge too
  function afterLoad() {
    var orig = window._yaraUpdateStats;
    if (typeof orig === 'function' && !orig._detWrapped) {
      window._yaraUpdateStats = function () { orig.apply(this, arguments); refresh(); };
      window._yaraUpdateStats._detWrapped = true;
    }
    refresh();
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', afterLoad);
  else afterLoad();

  window.DetTabs = { show: show, refresh: refresh };
})();
