// ============================================================
//  EXTRACTORS-PAGE.JS — the "Extractors" tab on detections.html
//  Renders the extractor feed, the "add extractor" modal, the
//  IOC / config JSON import, and the export for publishing.
// ============================================================
(function () {
  var S = window.ExtractorStore;
  if (!S) return;
  var esc = S.esc;

  function $(id) { return document.getElementById(id); }
  function today() { return new Date().toISOString().slice(0, 10); }

  // ── footer links (same as the other pages) ─────────────────
  (function () {
    var el = $('footer-links');
    if (!el || typeof SITE_CONFIG === 'undefined') return;
    var links = [];
    if (SITE_CONFIG.links.twitter) links.push('<a href="' + SITE_CONFIG.links.twitter + '" target="_blank">X</a>');
    if (SITE_CONFIG.links.github) links.push('<a href="' + SITE_CONFIG.links.github + '" target="_blank">GitHub</a>');
    if (SITE_CONFIG.links.email) links.push('<a href="' + SITE_CONFIG.links.email + '">Contact</a>');
    el.innerHTML = links.join('');
  })();

  // ============================================================
  //  Syntax colouring (YARA / Python / JSON) — tokens styled in detections.css
  // ============================================================
  function escHtml(s) {
    return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  }

  var YARA_RE = /(\/\/[^\n]*|\/\*[\s\S]*?\*\/)|("(?:[^"\\\n]|\\.)*")|(\{\s*(?:[0-9A-Fa-f?]{2}|\[[0-9\-]+\]|\||\(|\)|\s)+\})|(\$[A-Za-z_][A-Za-z0-9_]*\*?|[#@!][A-Za-z_][A-Za-z0-9_]*)|(0x[0-9A-Fa-f]+)|\b(rule|meta|strings|condition|import|and|or|not|any|all|of|them|for|in|matches|contains|icontains|startswith|endswith|filesize|entrypoint|uint8|uint16|uint32|uint64|int8|int16|int32|true|false|private|global|ascii|wide|nocase|fullword|xor|base64)\b|\b(\d+)\b/g;

  var PY_RE = /("""[\s\S]*?"""|'''[\s\S]*?''')|(#[^\n]*)|((?:[rRbBfFuU]{1,2})?(?:"(?:[^"\\\n]|\\.)*"|'(?:[^'\\\n]|\\.)*'))|\b(False|None|True|and|as|assert|async|await|break|class|continue|def|del|elif|else|except|finally|for|from|global|if|import|in|is|lambda|nonlocal|not|or|pass|raise|return|try|while|with|yield|self)\b|\b(0x[0-9A-Fa-f]+|\d+(?:\.\d+)?)\b/g;

  var JSON_RE = /("(?:[^"\\]|\\.)*")(\s*:)?|\b(true|false|null)\b|(-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)/g;

  function colorYara(raw) {
    return escHtml(raw).replace(YARA_RE, function (m, cmt, str, hex, ref, hx, kw, num) {
      if (cmt) return '<span class="tok-comment">' + cmt + '</span>';
      if (str) return '<span class="tok-string">' + str + '</span>';
      if (hex) return '<span class="tok-num">' + hex + '</span>';
      if (ref) return '<span class="tok-var">' + ref + '</span>';
      if (hx) return '<span class="tok-num">' + hx + '</span>';
      if (kw) return '<span class="tok-kw">' + kw + '</span>';
      if (num) return '<span class="tok-num">' + num + '</span>';
      return m;
    });
  }

  function colorPython(raw) {
    return escHtml(raw).replace(PY_RE, function (m, tri, cmt, str, kw, num) {
      if (tri) return '<span class="tok-string">' + tri + '</span>';
      if (cmt) return '<span class="tok-comment">' + cmt + '</span>';
      if (str) return '<span class="tok-string">' + str + '</span>';
      if (kw) return '<span class="tok-kw">' + kw + '</span>';
      if (num) return '<span class="tok-num">' + num + '</span>';
      return m;
    });
  }

  function colorJson(raw) {
    return escHtml(raw).replace(JSON_RE, function (m, str, colon, lit, num) {
      if (str) return colon
        ? '<span class="tok-var">' + str + '</span>' + colon
        : '<span class="tok-string">' + str + '</span>';
      if (lit) return '<span class="tok-kw">' + lit + '</span>';
      if (num) return '<span class="tok-num">' + num + '</span>';
      return m;
    });
  }

  function colorCode(code, lang) {
    return (lang === 'python') ? colorPython(code) : escHtml(code);
  }

  // ============================================================
  //  JSON import — IOCs + config
  // ============================================================
  var URL_RE = /\bhttps?:\/\/[^\s"'<>\\]+/gi;
  var IP_RE = /\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b/g;
  var DOM_RE = /\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b/gi;
  var GENERIC_TLDS = ('com net org io co info biz xyz top site online club tech app dev cloud live shop store ' +
    'icu work vip pro mobi name link click space website fun stream download men win bid cyou cfd buzz lol one world today life').split(' ');
  var FILE_LIKE_CC = ['py', 'js', 'rs', 'go', 'md', 'so', 'sh', 'cs', 'vb', 'db', 'ps', 'ts'];

  function isDomainTld(tld) {
    tld = tld.toLowerCase();
    if (GENERIC_TLDS.indexOf(tld) !== -1) return true;
    return tld.length === 2 && FILE_LIKE_CC.indexOf(tld) === -1;
  }

  function guessType(v) {
    if (/^https?:\/\//i.test(v)) return 'URL';
    if (/^(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?$/.test(v)) return 'IP';
    if (/^[a-f0-9]{64}$/i.test(v)) return 'SHA256';
    if (/^[a-f0-9]{40}$/i.test(v)) return 'SHA1';
    if (/^[a-f0-9]{32}$/i.test(v)) return 'MD5';
    if (/^(?:[a-z0-9-]+\.)+[a-z]{2,24}$/i.test(v) && isDomainTld(v.split('.').pop())) return 'DOMAIN';
    return 'STRING';
  }

  function isIocLike(d) {
    if (typeof d === 'string') return true;
    return !!d && typeof d === 'object' && !Array.isArray(d) &&
      ('indicator' in d || 'value' in d || 'ioc' in d);
  }

  function normIoc(item, family, defConf) {
    var ind, type, fam, conf;
    if (typeof item === 'string') {
      ind = item;
    } else {
      ind = item.indicator != null ? item.indicator : (item.value != null ? item.value : item.ioc);
      type = item.type; fam = item.family; conf = item.confidence;
    }
    if (ind == null) return null;
    ind = (typeof ind === 'object') ? JSON.stringify(ind) : String(ind);
    ind = ind.trim();
    if (!ind) return null;
    type = (type ? String(type) : guessType(ind)).toUpperCase().trim().replace(/\s+/g, '_');
    return {
      type: type,
      indicator: ind,
      family: fam ? String(fam) : family,
      confidence: conf ? String(conf).toUpperCase() : defConf
    };
  }

  function walk(node, path, cb) {
    if (node == null) return;
    if (typeof node === 'string') { cb(node, path); return; }
    if (Array.isArray(node)) { node.forEach(function (v) { walk(v, path, cb); }); return; }
    if (typeof node === 'object') {
      Object.keys(node).forEach(function (k) { walk(node[k], path + '.' + k, cb); });
    }
  }

  function detectFromConfig(config, family) {
    var found = [], seen = {};
    function add(type, ind) {
      var key = type + '|' + ind.toLowerCase();
      if (seen[key] || found.length >= 300) return;
      seen[key] = true;
      found.push({ type: type, indicator: ind, family: family, confidence: 'MEDIUM' });
    }
    walk(config, '', function (str, path) {
      var s = str.trim();
      if (!s) return;
      var m, rest = s;

      // hashes only when the key name says so (a 32-hex AES key is not an MD5)
      if (/hash|md5|sha/i.test(path)) {
        if (/^[a-f0-9]{64}$/i.test(s)) { add('SHA256', s.toLowerCase()); return; }
        if (/^[a-f0-9]{40}$/i.test(s)) { add('SHA1', s.toLowerCase()); return; }
        if (/^[a-f0-9]{32}$/i.test(s)) { add('MD5', s.toLowerCase()); return; }
      }

      (rest.match(URL_RE) || []).forEach(function (u) { add('URL', u.replace(/[.,;)]+$/, '')); });
      rest = rest.replace(URL_RE, ' ');

      (rest.match(IP_RE) || []).forEach(function (ip) {
        if (/^(0|127|255)\./.test(ip)) return;
        add('IP', ip);
      });
      rest = rest.replace(IP_RE, ' ');

      (rest.match(DOM_RE) || []).forEach(function (d) {
        var tld = d.split('.').pop();
        if (isDomainTld(tld)) add('DOMAIN', d.toLowerCase());
      });
    });
    return found;
  }

  // returns { iocs, config, explicit, detected, error }
  function parseJsonInput(text, family, auto) {
    var out = { iocs: [], config: null, explicit: 0, detected: 0, error: null, empty: false };
    text = (text || '').trim();
    if (!text) { out.empty = true; return out; }

    var data;
    try { data = JSON.parse(text); }
    catch (e) { out.error = 'Invalid JSON — ' + e.message; return out; }

    var explicit = null, config = null;

    if (Array.isArray(data)) {
      if (data.length && data.every(isIocLike)) {
        explicit = data;                                           // bare list of IOCs
      } else if (data.length && data.every(function (d) { return d && d.result && typeof d.result === 'object'; })) {
        config = data.map(function (d) {                           // cfgx batch report
          return { sample: d.sample, status: d.result.status, config: d.result.config };
        });
      } else {
        config = data;
      }
    } else if (data && typeof data === 'object') {
      var arr = data.iocs || data.indicators;
      if (Array.isArray(arr)) explicit = arr;
      if ('config' in data) config = data.config;                  // {iocs:[], config:{}} or cfgx {status, config}
      else if ('configuration' in data) config = data.configuration;
      else if (!explicit) config = data;                           // a bare config object
    } else {
      out.error = 'The JSON file must contain an object or an array.';
      return out;
    }

    var seen = {};
    function push(i, isAuto) {
      if (!i) return;
      var key = i.type + '|' + i.indicator.toLowerCase();
      if (seen[key]) return;
      seen[key] = true;
      out.iocs.push(i);
      if (isAuto) out.detected++; else out.explicit++;
    }

    if (explicit) explicit.forEach(function (it) { push(normIoc(it, family, 'HIGH'), false); });
    if (auto && config != null && typeof config === 'object') {
      detectFromConfig(config, family).forEach(function (i) { push(i, true); });
    }
    out.config = (config == null) ? null : config;
    return out;
  }

  // ============================================================
  //  Downloads / clipboard
  // ============================================================
  function download(filename, text, mime) {
    var blob = new Blob([text], { type: (mime || 'text/plain') + ';charset=utf-8' });
    var a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    setTimeout(function () { URL.revokeObjectURL(a.href); a.remove(); }, 500);
  }

  function copyText(text) {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      return navigator.clipboard.writeText(text).catch(function () { return fallbackCopy(text); });
    }
    return Promise.resolve(fallbackCopy(text));
  }
  function fallbackCopy(text) {
    var ta = document.createElement('textarea');
    ta.value = text; ta.style.position = 'fixed'; ta.style.opacity = '0';
    document.body.appendChild(ta); ta.select();
    try { document.execCommand('copy'); } catch (e) { }
    ta.remove();
  }

  function toast(msg) {
    var el = $('ex-toast');
    if (!el) return;
    el.textContent = msg;
    el.classList.add('show');
    clearTimeout(toast._t);
    toast._t = setTimeout(function () { el.classList.remove('show'); }, 4200);
  }

  // ============================================================
  //  Rendering
  // ============================================================
  function typeColor(t) { return t === 'IP' ? 'var(--amber)' : t === 'DOMAIN' ? 'var(--red)' : 'var(--blue)'; }
  function indicatorClass(t) { return t === 'IP' ? 'ioc-ip' : t === 'DOMAIN' ? 'ioc-domain' : 'ioc-hash'; }
  function confColor(c) { return (c === 'HIGH' || c === 'CRITICAL') ? 'var(--red)' : 'var(--amber)'; }

  function rowHtml(e, what, title, meta, actions, bodyHtml) {
    var id = 'exb-' + e.slug + '-' + what;
    return '' +
      '<div class="yara-rule-card ex-row" data-row="' + id + '">' +
        '<div class="yara-rule-header" data-toggle="' + id + '">' +
          '<div>' +
            '<div class="yara-rule-name">' + title + '</div>' +
            '<div class="yara-rule-meta">' + meta + '</div>' +
          '</div>' +
          '<div class="yara-rule-actions">' + actions + '<span class="yara-chevron">▼</span></div>' +
        '</div>' +
        '<div class="yara-rule-body" id="' + id + '">' + bodyHtml + '</div>' +
      '</div>';
  }

  function btn(label, act, e, what) {
    return '<button class="yara-copy-btn" data-act="' + act + '" data-slug="' + esc(e.slug) + '" data-what="' + what + '">' + label + '</button>';
  }

  function blockHtml(e) {
    var iocs = e.iocs || [];
    var hasRep = S.hasReport(e);
    var statusPill = hasRep
      ? '<a class="ex-status report" href="reports/' + esc(e.report) + '.html">REPORT ↗</a>'
      : '<span class="ex-status noreport">NO REPORT YET</span>';
    var localPill = e._local ? '<span class="ex-status local" title="Saved in this browser only — export & commit to publish">LOCAL ONLY</span>' : '';

    var search = [e.name, e.family, e.author, e.description, e.report, e.slug,
      (e.yara && e.yara.name) || '', (e.extractor && e.extractor.filename) || '']
      .concat(iocs.map(function (i) { return i.indicator; })).join(' ').toLowerCase();

    var rows = '';

    if (e.yara && e.yara.rule) {
      rows += rowHtml(e, 'yara', esc(e.yara.name || 'YARA rule'), 'YARA RULE',
        btn('COPY', 'copy', e, 'yara') + btn('⬇ .yar', 'dl', e, 'yara'),
        '<pre>' + colorYara(e.yara.rule) + '</pre>');
    }

    if (e.extractor && e.extractor.code) {
      var fn = e.extractor.filename || (e.slug + '_extractor.py');
      rows += rowHtml(e, 'code', esc(fn), 'EXTRACTOR CODE · ' + e.extractor.code.split('\n').length + ' lines',
        btn('COPY', 'copy', e, 'code') + btn('⬇ file', 'dl', e, 'code'),
        '<pre>' + colorCode(e.extractor.code, e.extractor.language) + '</pre>');
    }

    if (iocs.length) {
      var table = '<div style="overflow-x:auto;"><table class="ioc-table"><thead><tr>' +
        '<th>TYPE</th><th>INDICATOR</th><th>MALWARE FAMILY</th><th>CONFIDENCE</th></tr></thead><tbody>' +
        iocs.map(function (i) {
          return '<tr><td style="color:' + typeColor(i.type) + '">' + esc(i.type) + '</td>' +
            '<td class="' + indicatorClass(i.type) + '">' + esc(i.indicator) + '</td>' +
            '<td>' + esc(i.family || e.family || '—') + '</td>' +
            '<td style="color:' + confColor(i.confidence) + '">' + esc(i.confidence || '—') + '</td></tr>';
        }).join('') + '</tbody></table></div>';
      rows += rowHtml(e, 'iocs', 'IOCs · ' + iocs.length, 'EXTRACTED INDICATORS — also listed on the <a href="ioc-feed.html" class="ex-inline-link">IOC feed</a>',
        btn('COPY', 'copy', e, 'iocs') + btn('⬇ .json', 'dl', e, 'iocs'), table);
    }

    if (e.config != null) {
      var cfgText = JSON.stringify(e.config, null, 2);
      rows += rowHtml(e, 'config', 'Extracted configuration', 'CONFIG · ' + cfgText.split('\n').length + ' lines of JSON',
        btn('COPY', 'copy', e, 'config') + btn('⬇ .json', 'dl', e, 'config'),
        '<pre>' + colorJson(cfgText) + '</pre>');
    }

    var del = e._local ? '<button class="yara-copy-btn sa-del" data-act="del" data-slug="' + esc(e.slug) + '">DELETE</button>' : '';

    return '' +
      '<div class="yara-block ex-block" id="ex-' + esc(e.slug) + '" data-search="' + esc(search) + '" data-report="' + (hasRep ? '1' : '0') + '" data-local="' + (e._local ? '1' : '0') + '">' +
        '<div class="yara-report-heading ex-heading">' +
          '<div class="ex-heading-top">' +
            '<div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap;">' +
              '<span class="tag-pill tag-extractor">EXTRACTOR</span>' +
              '<span class="ex-family">' + esc(e.family || '—') + '</span>' +
              statusPill + localPill +
              '<span class="yara-report-title" style="cursor:default">' + esc(e.name) + '</span>' +
            '</div>' + del +
          '</div>' +
          '<div class="ex-meta">' + esc(e.date || '') + ' &nbsp;·&nbsp; by ' + esc(e.author || 'SalahEldin Kamil (Mr_MaTriX)') +
            ' &nbsp;·&nbsp; ' + iocs.length + ' IOC' + (iocs.length !== 1 ? 's' : '') +
            (e.yara && e.yara.rule ? ' &nbsp;·&nbsp; YARA ✓' : '') + '</div>' +
          (e.description ? '<div class="ex-desc">' + esc(e.description) + '</div>' : '') +
        '</div>' +
        rows +
      '</div>';
  }

  var state = { q: '', filter: 'all' };

  function renderAll() {
    var list = S.all();
    var box = $('ex-container');
    var empty = $('ex-empty');
    if (box) box.innerHTML = list.map(blockHtml).join('');
    if (empty) empty.style.display = list.length ? 'none' : 'block';
    updateStats(list);
    updateLocalBanner(list);
    applyFilters();
  }

  function updateStats(list) {
    var el = $('ex-stats');
    if (!el) return;
    var yaraN = list.filter(function (e) { return e.yara && e.yara.rule; }).length;
    var iocN = list.reduce(function (n, e) { return n + (e.iocs ? e.iocs.length : 0); }, 0);
    var noRep = list.filter(function (e) { return !S.hasReport(e); }).length;
    var loc = list.filter(function (e) { return e._local; }).length;
    function stat(n, label, color) {
      return '<div class="stat-mini"><div class="stat-mini-num"' + (color ? ' style="color:' + color + '"' : '') + '>' + n + '</div><div class="stat-mini-label">' + label + '</div></div>';
    }
    el.innerHTML = stat(list.length, 'EXTRACTORS') + stat(yaraN, 'YARA RULES') + stat(iocN, 'IOCs EXTRACTED') +
      stat(noRep, 'NO REPORT YET', 'var(--amber)') + (loc ? stat(loc, 'LOCAL ONLY', 'var(--blue)') : '');
  }

  function updateLocalBanner(list) {
    var el = $('ex-local-banner');
    if (!el) return;
    var n = list.filter(function (e) { return e._local; }).length;
    if (!n) { el.style.display = 'none'; return; }
    $('ex-local-count').textContent = n + ' extractor' + (n !== 1 ? 's' : '');
    el.style.display = 'flex';
  }

  function applyFilters() {
    var q = state.q.trim().toLowerCase();
    var blocks = document.querySelectorAll('#ex-container .ex-block');
    var visible = 0;
    blocks.forEach(function (b) {
      var ok = true;
      if (q && (b.dataset.search || '').indexOf(q) === -1) ok = false;
      if (state.filter === 'noreport' && b.dataset.report !== '0') ok = false;
      if (state.filter === 'report' && b.dataset.report !== '1') ok = false;
      if (state.filter === 'local' && b.dataset.local !== '1') ok = false;
      b.style.display = ok ? '' : 'none';
      if (ok) visible++;
    });
    var nm = $('ex-no-match');
    if (nm) nm.style.display = (blocks.length && !visible) ? 'block' : 'none';
    document.querySelectorAll('.ex-chip').forEach(function (c) {
      c.classList.toggle('active', c.dataset.filter === state.filter);
    });
  }

  // ── row toggle + action buttons (event delegation) ─────────
  document.addEventListener('click', function (ev) {
    var actBtn = ev.target.closest('[data-act]');
    if (actBtn) {
      ev.stopPropagation();
      handleAction(actBtn);
      return;
    }
    var head = ev.target.closest('.yara-rule-header[data-toggle]');
    if (head && !ev.target.closest('a')) {
      var body = $(head.getAttribute('data-toggle'));
      if (!body) return;
      var open = body.classList.toggle('open');
      var chev = head.querySelector('.yara-chevron');
      if (chev) chev.style.transform = open ? 'rotate(180deg)' : '';
    }
  });

  function artifact(e, what) {
    if (what === 'yara') return { text: e.yara.rule, file: (e.yara.name || e.slug) + '.yar', mime: 'text/plain' };
    if (what === 'code') return { text: e.extractor.code, file: e.extractor.filename || (e.slug + '_extractor.py'), mime: 'text/plain' };
    if (what === 'iocs') return { text: JSON.stringify({ iocs: e.iocs }, null, 2), file: e.slug + '-iocs.json', mime: 'application/json' };
    if (what === 'config') return { text: JSON.stringify(e.config, null, 2), file: e.slug + '-config.json', mime: 'application/json' };
    return null;
  }

  function handleAction(b) {
    var act = b.getAttribute('data-act');
    var slug = b.getAttribute('data-slug');
    var e = S.all().filter(function (x) { return x.slug === slug; })[0];
    if (!e) return;

    if (act === 'del') {
      if (!confirm('Delete "' + e.name + '" from this browser?')) return;
      S.saveLocal(S.loadLocal().filter(function (x) { return x.slug !== slug; }));
      renderAll();
      window.dispatchEvent(new Event('det:changed'));
      toast('Deleted "' + e.name + '" from this browser.');
      return;
    }

    var a = artifact(e, b.getAttribute('data-what'));
    if (!a) return;
    if (act === 'copy') {
      Promise.resolve(copyText(a.text)).then(function () {
        var old = b.textContent;
        b.textContent = 'COPIED!'; b.classList.add('copied');
        setTimeout(function () { b.textContent = old; b.classList.remove('copied'); }, 1800);
      });
    } else if (act === 'dl') {
      download(a.file, a.text, a.mime);
    }
  }

  // ── search + filter chips ──────────────────────────────────
  var search = $('ex-search');
  if (search) search.addEventListener('input', function () { state.q = search.value; applyFilters(); });
  document.querySelectorAll('.ex-chip').forEach(function (c) {
    c.addEventListener('click', function () { state.filter = c.dataset.filter; applyFilters(); });
  });

  // ── export for publishing ──────────────────────────────────
  function doExport() {
    download('extractors-data.js', S.exportJs(), 'text/javascript');
    toast('Downloaded extractors-data.js — replace assets/js/extractors-data.js with it, then commit & push.');
  }
  var exBtn = $('ex-export'); if (exBtn) exBtn.addEventListener('click', doExport);
  var exBtn2 = $('ex-export-banner'); if (exBtn2) exBtn2.addEventListener('click', doExport);

  // ============================================================
  //  Add-extractor modal
  // ============================================================
  var overlay = $('x-modal');
  var errEl = $('x-err');
  var ui = {};
  ['name', 'family', 'author', 'date', 'report', 'desc', 'yara', 'yara-file', 'code', 'code-file', 'lang', 'filename', 'json', 'json-file', 'auto', 'json-summary']
    .forEach(function (k) { ui[k] = $('x-' + k); });

  function showErr(msg) { errEl.textContent = '⚠ ' + msg; errEl.classList.add('show'); }
  function clearErr() { errEl.textContent = ''; errEl.classList.remove('show'); }

  function openModal() {
    if (!ui.date.value) ui.date.value = today();
    overlay.classList.add('open');
    document.body.style.overflow = 'hidden';
    setTimeout(function () { ui.name.focus(); }, 50);
  }
  function closeModal() {
    overlay.classList.remove('open');
    document.body.style.overflow = '';
    clearErr();
  }
  function resetForm() {
    ['name', 'family', 'author', 'report', 'desc', 'yara', 'code', 'filename', 'json'].forEach(function (k) { ui[k].value = ''; });
    ['yara-file', 'code-file', 'json-file'].forEach(function (k) { ui[k].value = ''; });
    ui.date.value = today();
    ui.lang.value = 'python';
    ui.auto.checked = true;
    refreshSummary();
  }

  var openBtn = $('ex-open-modal'); if (openBtn) openBtn.addEventListener('click', openModal);
  $('x-close').addEventListener('click', closeModal);
  $('x-cancel').addEventListener('click', closeModal);
  overlay.addEventListener('click', function (e) { if (e.target === overlay) closeModal(); });
  document.addEventListener('keydown', function (e) {
    if (e.key === 'Escape' && overlay.classList.contains('open')) closeModal();
  });

  function readFile(input, cb) {
    var f = input.files && input.files[0];
    if (!f) return;
    if (f.size > 2 * 1024 * 1024) { showErr('"' + f.name + '" is larger than 2 MB.'); input.value = ''; return; }
    clearErr();
    var r = new FileReader();
    r.onload = function () { cb(String(r.result), f); };
    r.onerror = function () { showErr('Could not read "' + f.name + '".'); };
    r.readAsText(f);
  }

  ui['yara-file'].addEventListener('change', function () {
    readFile(ui['yara-file'], function (text) { ui.yara.value = text; });
  });
  ui['code-file'].addEventListener('change', function () {
    readFile(ui['code-file'], function (text, f) {
      ui.code.value = text;
      if (!ui.filename.value) ui.filename.value = f.name;
      ui.lang.value = /\.py$/i.test(f.name) ? 'python' : ui.lang.value;
    });
  });
  ui['json-file'].addEventListener('change', function () {
    readFile(ui['json-file'], function (text) { ui.json.value = text; refreshSummary(); });
  });

  function refreshSummary() {
    var el = ui['json-summary'];
    var res = parseJsonInput(ui.json.value, ui.family.value.trim() || 'Unknown', ui.auto.checked);
    el.className = 'x-summary';
    if (res.empty) { el.textContent = 'No JSON yet — optional. Attach the file you saved after extracting IOCs / config.'; return; }
    if (res.error) { el.classList.add('bad'); el.textContent = '✗ ' + res.error; return; }
    el.classList.add('ok');
    var parts = [];
    parts.push(res.iocs.length + ' IOC' + (res.iocs.length !== 1 ? 's' : '') +
      (res.detected ? ' (' + res.explicit + ' listed + ' + res.detected + ' auto-detected from config)' : ''));
    if (res.config != null) {
      var keys = (res.config && typeof res.config === 'object')
        ? (Array.isArray(res.config) ? res.config.length + ' item(s)' : Object.keys(res.config).length + ' key(s)') : 'value';
      parts.push('config: ' + keys);
    } else {
      parts.push('no config');
    }
    el.textContent = '✓ ' + parts.join(' · ') + (res.iocs.length ? ' — will be added to the IOC feed' : '');
  }
  ui.json.addEventListener('input', refreshSummary);
  ui.auto.addEventListener('change', refreshSummary);
  ui.family.addEventListener('input', refreshSummary);

  var tplBtn = $('x-template');
  if (tplBtn) tplBtn.addEventListener('click', function (e) {
    e.preventDefault();
    var tpl = {
      iocs: [
        { type: 'DOMAIN', indicator: 'c2.example.com', family: 'MyFamily', confidence: 'HIGH' },
        { type: 'IP', indicator: '203.0.113.7', family: 'MyFamily', confidence: 'HIGH' },
        { type: 'REGISTRY', indicator: 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater', family: 'MyFamily', confidence: 'MEDIUM' }
      ],
      config: { c2: ['c2.example.com:443'], mutex: 'Global\\example-mutex', campaign_id: 'test-01' }
    };
    download('extractor-iocs-template.json', JSON.stringify(tpl, null, 2), 'application/json');
  });

  $('x-save').addEventListener('click', function () {
    clearErr();
    var name = ui.name.value.trim();
    var family = ui.family.value.trim();
    var code = ui.code.value;
    var yaraText = ui.yara.value.trim();

    if (!name) { showErr('Extractor name is required'); ui.name.focus(); return; }
    if (!family) { showErr('Malware family is required'); ui.family.focus(); return; }
    if (!code.trim()) { showErr('Paste or attach the extractor code'); ui.code.focus(); return; }
    if (yaraText && yaraText.indexOf('condition:') === -1) { showErr('The YARA rule must contain a condition: block'); ui.yara.focus(); return; }

    var res = parseJsonInput(ui.json.value, family, ui.auto.checked);
    if (res.error) { showErr(res.error); ui.json.focus(); return; }

    var report = ui.report.value.trim().replace(/^.*\//, '').replace(/\.html$/i, '');
    if (report && !/^[A-Za-z0-9_.-]+$/.test(report)) { showErr('Report slug may only contain letters, numbers, dashes and underscores'); ui.report.focus(); return; }

    var slug = S.uniqueSlug(S.slugify(name));
    var ruleName = (yaraText.match(/\brule\s+([A-Za-z_][A-Za-z0-9_]*)/) || [])[1] || family;
    var filename = ui.filename.value.trim() || (S.slugify(name).replace(/-/g, '_') + (ui.lang.value === 'python' ? '.py' : '.txt'));

    var entry = {
      slug: slug,
      name: name,
      family: family,
      date: ui.date.value || today(),
      author: ui.author.value.trim() || 'SalahEldin Kamil (Mr_MaTriX)',
      description: ui.desc.value.trim(),
      report: report,
      yara: yaraText ? { name: ruleName, rule: yaraText } : null,
      extractor: { filename: filename, language: ui.lang.value, code: code },
      iocs: res.iocs,
      config: res.config
    };

    var local = S.loadLocal();
    local.unshift(entry);
    if (!S.saveLocal(local)) {
      showErr('Browser storage is full — export extractors-data.js and delete some local entries.');
      return;
    }

    closeModal();
    resetForm();
    state.q = ''; state.filter = 'all';
    if (search) search.value = '';
    renderAll();
    window.dispatchEvent(new Event('det:changed'));

    var msg = 'Saved "' + name + '" in this browser.';
    if (entry.iocs.length) msg += ' ' + entry.iocs.length + ' IOCs added to the IOC feed.';
    msg += ' Export & commit to publish it for visitors.';
    toast(msg);

    var el = $('ex-' + slug);
    if (el) el.scrollIntoView({ behavior: 'smooth', block: 'start' });
  });

  // ── init ───────────────────────────────────────────────────
  (function init() {
    var p = new URLSearchParams(location.search);
    var mine = !p.get('tab') || p.get('tab') === 'extractors';   // other tabs own their own deep links
    var f = mine ? p.get('filter') : null;
    if (f && ['noreport', 'report', 'local'].indexOf(f) !== -1) state.filter = f;
    renderAll();
    refreshSummary();

    var id = mine ? decodeURIComponent((location.hash || '').slice(1)) : '';
    if (id) {
      var el = $('ex-' + id) || $(id);
      if (el && el.classList.contains('ex-block')) {
        state.filter = 'all'; applyFilters();
        setTimeout(function () {
          el.scrollIntoView({ block: 'start' });
          el.classList.add('ex-flash');
        }, 80);
      }
    }
  })();
})();
