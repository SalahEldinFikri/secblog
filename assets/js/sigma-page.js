// ============================================================
//  SIGMA-PAGE.JS — the "Sigma Rules" tab on detections.html
//  Published rules (sigma-data.js) + rules attached to reports
//  (sigma: [...] in reports-data.js) + rules saved in this browser.
// ============================================================
(function () {
  var LS_KEY = 'secblog_local_sigma';
  function $(id) { return document.getElementById(id); }
  function today() { return new Date().toISOString().slice(0, 10); }

  function esc(s) {
    return String(s == null ? '' : s)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  }
  function escHtml(s) {
    return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  }
  function slugify(s) {
    return String(s || '').toLowerCase().trim().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 60) || 'sigma-rule';
  }

  // ============================================================
  //  Sigma YAML → metadata (no YAML library: the fields we show are simple)
  // ============================================================
  function unquote(v) {
    v = String(v).trim();
    if (v.length > 1 && ((v[0] === '"' && v[v.length - 1] === '"') || (v[0] === "'" && v[v.length - 1] === "'"))) {
      return v.slice(1, -1);
    }
    return v;
  }
  function stripComment(v) {
    v = String(v);
    if (/^\s*["']/.test(v)) return v;
    return v.replace(/\s+#.*$/, '');
  }

  function parseSigma(text) {
    var lines = String(text || '').replace(/\r\n?/g, '\n').split('\n');
    var meta = { tags: [], logsource: {}, hasLogsource: false, hasDetection: false, hasCondition: false };
    var seenTitle = false;

    for (var i = 0; i < lines.length; i++) {
      var line = lines[i];
      if (/^---\s*$/.test(line) && seenTitle) break;               // only the first document
      var m = /^([A-Za-z_][A-Za-z0-9_]*):\s*(.*)$/.exec(line);
      if (!m) continue;
      var key = m[1];
      var val = stripComment(m[2]).trim();

      if (/^[|>][+-]?$/.test(val)) {                               // block scalar (description: |)
        var buf = [], j = i + 1;
        while (j < lines.length && (/^\s+/.test(lines[j]) || lines[j].trim() === '')) { buf.push(lines[j].trim()); j++; }
        val = buf.join(' ').replace(/\s+/g, ' ').trim();
        i = j - 1;
      }

      if (key === 'title') { meta.title = unquote(val); seenTitle = true; }
      else if (key === 'id' || key === 'status' || key === 'description' || key === 'author' || key === 'date' || key === 'level') {
        meta[key] = unquote(val);
      } else if (key === 'tags') {
        if (/^\[.*\]$/.test(val)) {
          val.slice(1, -1).split(',').forEach(function (t) { t = unquote(t); if (t) meta.tags.push(t); });
        } else {
          var k = i + 1, tm;
          while (k < lines.length && (tm = /^\s*-\s*(.+?)\s*$/.exec(lines[k]))) { meta.tags.push(unquote(stripComment(tm[1]).trim())); k++; }
          i = k - 1;
        }
      } else if (key === 'logsource') {
        meta.hasLogsource = true;
        var q = i + 1, lm;
        while (q < lines.length && (/^\s+/.test(lines[q]) || lines[q].trim() === '')) {
          lm = /^\s+([A-Za-z_]+):\s*(.*)$/.exec(lines[q]);
          if (lm) meta.logsource[lm[1]] = unquote(stripComment(lm[2]).trim());
          q++;
        }
        i = q - 1;
      } else if (key === 'detection') {
        meta.hasDetection = true;
        var d = i + 1;
        while (d < lines.length && (/^\s+/.test(lines[d]) || lines[d].trim() === '')) {
          if (/^\s+condition\s*:/.test(lines[d])) meta.hasCondition = true;
          d++;
        }
        i = d - 1;
      }
    }
    return meta;
  }

  function normDate(d) {
    var m = /^(\d{4})[\/\-](\d{1,2})[\/\-](\d{1,2})/.exec(String(d || ''));
    if (!m) return '';
    return m[1] + '-' + ('0' + m[2]).slice(-2) + '-' + ('0' + m[3]).slice(-2);
  }

  function normLevel(l) {
    l = String(l || '').toLowerCase().trim();
    return ['informational', 'low', 'medium', 'high', 'critical'].indexOf(l) !== -1 ? l : 'medium';
  }

  function validate(meta) {
    if (!meta.title) return 'The rule needs a title: field';
    if (!meta.hasLogsource) return 'The rule needs a logsource: block';
    if (!meta.hasDetection) return 'The rule needs a detection: block';
    if (!meta.hasCondition) return 'The detection: block needs a condition:';
    return null;
  }

  function entryFromYaml(yaml, extra) {
    var m = parseSigma(yaml);
    return Object.assign({
      slug: slugify(m.title),
      title: m.title || 'Untitled Sigma rule',
      description: m.description || '',
      author: m.author || 'SalahEldin Kamil (Mr_MaTriX)',
      date: normDate(m.date) || today(),
      level: normLevel(m.level),
      status: m.status || '',
      logsource: {
        product: m.logsource.product || '', category: m.logsource.category || '', service: m.logsource.service || ''
      },
      tags: m.tags,
      report: '',
      rule: yaml
    }, extra || {});
  }

  // ============================================================
  //  Store
  // ============================================================
  function loadLocal() {
    try { var v = JSON.parse(localStorage.getItem(LS_KEY) || '[]'); return Array.isArray(v) ? v : []; }
    catch (e) { return []; }
  }
  function saveLocal(arr) {
    try { localStorage.setItem(LS_KEY, JSON.stringify(arr)); return true; } catch (e) { return false; }
  }
  function published() {
    return (typeof SIGMA_RULES !== 'undefined' && Array.isArray(SIGMA_RULES)) ? SIGMA_RULES : [];
  }
  function fromReports() {
    var out = [];
    if (typeof REPORTS === 'undefined') return out;
    REPORTS.forEach(function (r) {
      (r.sigma || []).forEach(function (s, i) {
        if (!s || !s.rule) return;
        out.push(entryFromYaml(s.rule, {
          slug: slugify(r.slug + '-sigma-' + (i + 1)),
          report: r.slug, date: r.date || '', _fromReport: true,
          author: s.author || undefined, description: s.description || undefined
        }));
        var e = out[out.length - 1];
        if (!e.author) e.author = 'SalahEldin Kamil (Mr_MaTriX)';
        if (!e.description) e.description = parseSigma(s.rule).description || '';
      });
    });
    return out;
  }
  function all() {
    var pub = published().map(function (e) { return Object.assign({}, e, { _local: false }); });
    var seen = {};
    pub.forEach(function (e) { seen[e.slug] = true; });
    var rep = fromReports().filter(function (e) { if (seen[e.slug]) return false; seen[e.slug] = true; return true; });
    var loc = loadLocal().filter(function (e) { return e && e.slug && !seen[e.slug]; })
      .map(function (e) { return Object.assign({}, e, { _local: true }); });
    return loc.concat(pub, rep).sort(function (a, b) { return (b.date || '').localeCompare(a.date || ''); });
  }
  function uniqueSlug(base) {
    var taken = {}; all().forEach(function (e) { taken[e.slug] = true; });
    var s = base, n = 2; while (taken[s]) s = base + '-' + n++;
    return s;
  }
  function changed() { window.dispatchEvent(new Event('det:changed')); }

  // ============================================================
  //  YAML colouring
  // ============================================================
  var VAL_RE = /(\s#.*$)|("(?:[^"\\]|\\.)*"|'(?:[^']|'')*')|\b(true|false|null)\b/g;
  var COND_RE = /\b(and|or|not|of|them|all|1)\b/g;

  function colorValue(v, isCond) {
    // a value that is purely a number (e.g. EventID: 4688) gets the number colour;
    // numbers inside ids / paths / commands are left alone
    if (!isCond && /^\s*-?\d+(?:\.\d+)?\s*$/.test(v)) return '<span class="tok-num">' + v + '</span>';
    var out = v.replace(VAL_RE, function (m, cmt, str, lit) {
      if (cmt) return '<span class="tok-comment">' + cmt + '</span>';
      if (str) return '<span class="tok-string">' + str + '</span>';
      if (lit) return '<span class="tok-kw">' + lit + '</span>';
      return m;
    });
    if (isCond) {
      // operators, but never inside an already-coloured span
      out = out.split(/(<span[^>]*>.*?<\/span>)/).map(function (part, idx) {
        return idx % 2 ? part : part.replace(COND_RE, '<span class="tok-op">$1</span>');
      }).join('');
    }
    return out;
  }

  function colorYaml(raw) {
    return escHtml(raw).split('\n').map(function (ln) {
      if (/^\s*#/.test(ln)) return '<span class="tok-comment">' + ln + '</span>';
      if (/^---\s*$/.test(ln)) return '<span class="tok-dash">' + ln + '</span>';
      var m = /^(\s*)(-\s+)?([A-Za-z_][\w.\-|\/]*)(:)(\s.*|)$/.exec(ln);
      if (m) {
        var isCond = m[3] === 'condition';
        return m[1] + (m[2] ? '<span class="tok-dash">' + m[2] + '</span>' : '') +
          '<span class="tok-key">' + m[3] + '</span>' + m[4] + colorValue(m[5], isCond);
      }
      var l = /^(\s*)(-\s+)(.*)$/.exec(ln);
      if (l) return l[1] + '<span class="tok-dash">' + l[2] + '</span>' + colorValue(l[3], false);
      return colorValue(ln, false);
    }).join('\n');
  }

  // ============================================================
  //  Helpers: download / copy / toast
  // ============================================================
  function download(filename, text, mime) {
    var blob = new Blob([text], { type: (mime || 'text/plain') + ';charset=utf-8' });
    var a = document.createElement('a');
    a.href = URL.createObjectURL(blob); a.download = filename;
    document.body.appendChild(a); a.click();
    setTimeout(function () { URL.revokeObjectURL(a.href); a.remove(); }, 500);
  }
  function copyText(text) {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      return navigator.clipboard.writeText(text).catch(function () { fallbackCopy(text); });
    }
    fallbackCopy(text); return Promise.resolve();
  }
  function fallbackCopy(text) {
    var ta = document.createElement('textarea');
    ta.value = text; ta.style.position = 'fixed'; ta.style.opacity = '0';
    document.body.appendChild(ta); ta.select();
    try { document.execCommand('copy'); } catch (e) { }
    ta.remove();
  }
  function toast(msg) {
    var el = $('ex-toast'); if (!el) return;
    el.textContent = msg; el.classList.add('show');
    clearTimeout(toast._t); toast._t = setTimeout(function () { el.classList.remove('show'); }, 4200);
  }

  // ============================================================
  //  Rendering
  // ============================================================
  function attackLink(tag) {
    var m = /^attack\.t(\d{4})(?:\.(\d{3}))?$/i.exec(tag);
    if (!m) return '<span class="sg-chip">' + esc(tag) + '</span>';
    var id = 'T' + m[1] + (m[2] ? '.' + m[2] : '');
    var path = 'T' + m[1] + (m[2] ? '/' + m[2] : '');
    return '<a class="sg-chip" href="https://attack.mitre.org/techniques/' + path + '/" target="_blank" rel="noopener">' + esc(id) + '</a>';
  }

  function logsrcText(ls) {
    return [ls.product, ls.category, ls.service].filter(Boolean).join(' · ');
  }

  function blockHtml(e) {
    var hasRep = !!e.report;
    var statusPill = hasRep
      ? '<a class="ex-status report" href="reports/' + esc(e.report) + '.html">REPORT ↗</a>'
      : '<span class="ex-status noreport">NO REPORT YET</span>';
    var localPill = e._local ? '<span class="ex-status local" title="Saved in this browser only — export & commit to publish">LOCAL ONLY</span>' : '';
    var ls = logsrcText(e.logsource || {});
    var search = [e.title, e.description, e.author, e.level, e.status, e.report, ls].concat(e.tags || []).join(' ').toLowerCase();
    var yaml = e.rule || '';
    var del = e._local ? '<button class="yara-copy-btn sa-del" data-sg-act="del" data-slug="' + esc(e.slug) + '">DELETE</button>' : '';
    var rowId = 'sgb-' + e.slug;

    var chips = '';
    if (ls) chips += '<span class="sg-chip logsrc">⌁ ' + esc(ls) + '</span>';
    if (e.status) chips += '<span class="sg-chip status">' + esc(e.status) + '</span>';
    (e.tags || []).forEach(function (t) { chips += attackLink(t); });

    return '' +
      '<div class="yara-block ex-block sg-block" id="sg-' + esc(e.slug) + '" data-search="' + esc(search) + '" data-report="' + (hasRep ? '1' : '0') + '" data-local="' + (e._local ? '1' : '0') + '">' +
        '<div class="yara-report-heading ex-heading">' +
          '<div class="ex-heading-top">' +
            '<div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap;">' +
              '<span class="tag-pill tag-sigma">SIGMA</span>' +
              '<span class="sg-level ' + esc(e.level) + '">' + esc(e.level) + '</span>' +
              statusPill + localPill +
              '<span class="yara-report-title" style="cursor:default">' + esc(e.title) + '</span>' +
            '</div>' + del +
          '</div>' +
          '<div class="ex-meta">' + esc(e.date || '') + ' &nbsp;·&nbsp; by ' + esc(e.author || '') + '</div>' +
          (e.description ? '<div class="ex-desc">' + esc(e.description) + '</div>' : '') +
          (chips ? '<div class="sg-chips">' + chips + '</div>' : '') +
        '</div>' +
        '<div class="yara-rule-card ex-row">' +
          '<div class="yara-rule-header" data-sg-toggle="' + rowId + '">' +
            '<div><div class="yara-rule-name">Sigma rule (YAML)</div>' +
            '<div class="yara-rule-meta">' + yaml.split('\n').length + ' lines</div></div>' +
            '<div class="yara-rule-actions">' +
              '<button class="yara-copy-btn" data-sg-act="copy" data-slug="' + esc(e.slug) + '">COPY</button>' +
              '<button class="yara-copy-btn" data-sg-act="dl" data-slug="' + esc(e.slug) + '">⬇ .yml</button>' +
              '<span class="yara-chevron">▼</span>' +
            '</div>' +
          '</div>' +
          '<div class="yara-rule-body" id="' + rowId + '"><pre>' + colorYaml(yaml) + '</pre></div>' +
        '</div>' +
      '</div>';
  }

  var state = { q: '', filter: 'all' };

  function renderAll() {
    var list = all();
    var box = $('sg-container');
    if (box) box.innerHTML = list.map(blockHtml).join('');
    if ($('sg-empty')) $('sg-empty').style.display = list.length ? 'none' : 'block';
    var dl = $('sg-dl-all'); if (dl) dl.style.display = list.length ? '' : 'none';
    updateStats(list);
    var n = list.filter(function (e) { return e._local; }).length;
    var bn = $('sg-local-banner');
    if (bn) { bn.style.display = n ? 'flex' : 'none'; if (n) $('sg-local-count').textContent = n + ' Sigma rule' + (n !== 1 ? 's' : ''); }
    applyFilters();
  }

  function updateStats(list) {
    var el = $('sg-stats'); if (!el) return;
    var noRep = list.filter(function (e) { return !e.report; }).length;
    var loc = list.filter(function (e) { return e._local; }).length;
    var high = list.filter(function (e) { return e.level === 'high' || e.level === 'critical'; }).length;
    function stat(n, label, color) {
      return '<div class="stat-mini"><div class="stat-mini-num"' + (color ? ' style="color:' + color + '"' : '') + '>' + n + '</div><div class="stat-mini-label">' + label + '</div></div>';
    }
    el.innerHTML = stat(list.length, 'SIGMA RULES') + stat(high, 'HIGH / CRITICAL', 'var(--red)') +
      stat(list.length - noRep, 'WITH REPORT') + stat(noRep, 'NO REPORT YET', 'var(--amber)') +
      (loc ? stat(loc, 'LOCAL ONLY', 'var(--blue)') : '');
  }

  function applyFilters() {
    var q = state.q.trim().toLowerCase();
    var blocks = document.querySelectorAll('#sg-container .sg-block');
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
    if ($('sg-no-match')) $('sg-no-match').style.display = (blocks.length && !visible) ? 'block' : 'none';
    document.querySelectorAll('.sg-chip-filter').forEach(function (c) { c.classList.toggle('active', c.dataset.filter === state.filter); });
  }

  // ── events (delegated, own attribute names so the other tabs don't react) ──
  document.addEventListener('click', function (ev) {
    var act = ev.target.closest('[data-sg-act]');
    if (act) { ev.stopPropagation(); handleAction(act); return; }
    var head = ev.target.closest('[data-sg-toggle]');
    if (head && !ev.target.closest('a')) {
      var body = $(head.getAttribute('data-sg-toggle'));
      if (!body) return;
      var open = body.classList.toggle('open');
      var chev = head.querySelector('.yara-chevron');
      if (chev) chev.style.transform = open ? 'rotate(180deg)' : '';
    }
  });

  function handleAction(b) {
    var slug = b.getAttribute('data-slug');
    var e = all().filter(function (x) { return x.slug === slug; })[0];
    if (!e) return;
    var act = b.getAttribute('data-sg-act');
    if (act === 'del') {
      if (!confirm('Delete "' + e.title + '" from this browser?')) return;
      saveLocal(loadLocal().filter(function (x) { return x.slug !== slug; }));
      renderAll(); changed();
      toast('Deleted "' + e.title + '" from this browser.');
    } else if (act === 'copy') {
      copyText(e.rule).then(function () {
        var old = b.textContent; b.textContent = 'COPIED!'; b.classList.add('copied');
        setTimeout(function () { b.textContent = old; b.classList.remove('copied'); }, 1800);
      });
    } else if (act === 'dl') {
      download(slug + '.yml', e.rule, 'text/yaml');
    }
  }

  var search = $('sg-search');
  if (search) search.addEventListener('input', function () { state.q = search.value; applyFilters(); });
  document.querySelectorAll('.sg-chip-filter').forEach(function (c) {
    c.addEventListener('click', function () { state.filter = c.dataset.filter; applyFilters(); });
  });

  // ── download all / export ──────────────────────────────────
  var dlAll = $('sg-dl-all');
  if (dlAll) dlAll.addEventListener('click', function () {
    var parts = ['# Sigma Rules — SecBlog by SalahEldin Kamil', '# Generated: ' + today(), ''];
    all().forEach(function (e) { parts.push('---'); parts.push(e.rule.trim()); });
    download('SalahEldin-Kamil-Sigma-Rules.yml', parts.join('\n') + '\n', 'text/yaml');
  });

  function exportJs() {
    var entries = all().filter(function (e) { return !e._fromReport; }).map(function (e) {
      var c = Object.assign({}, e); delete c._local; delete c._fromReport; return c;
    });
    var head = [
      '// ============================================================',
      '//  SIGMA-DATA.JS — generated by detections.html on ' + today(),
      '//  Replace assets/js/sigma-data.js with this file, then',
      '//  git add, git commit, git push.',
      '//  Set  report: "your-report-slug"  on a rule once its write-up exists.',
      '// ============================================================',
      '',
      'const SIGMA_RULES = '
    ].join('\n');
    return head + JSON.stringify(entries, null, 2) + ';\n';
  }
  function doExport() {
    download('sigma-data.js', exportJs(), 'text/javascript');
    toast('Downloaded sigma-data.js — replace assets/js/sigma-data.js with it, then commit & push.');
  }
  if ($('sg-export')) $('sg-export').addEventListener('click', doExport);
  if ($('sg-export-banner')) $('sg-export-banner').addEventListener('click', doExport);

  // ============================================================
  //  Add-Sigma-rule modal
  // ============================================================
  var overlay = $('sg-modal'), errEl = $('sg-err');
  var ui = { yaml: $('sg-yaml'), file: $('sg-file'), report: $('sg-report'), summary: $('sg-summary') };

  function showErr(m) { errEl.textContent = '⚠ ' + m; errEl.classList.add('show'); }
  function clearErr() { errEl.textContent = ''; errEl.classList.remove('show'); }
  function openModal() { overlay.classList.add('open'); document.body.style.overflow = 'hidden'; setTimeout(function () { ui.yaml.focus(); }, 50); }
  function closeModal() { overlay.classList.remove('open'); document.body.style.overflow = ''; clearErr(); }

  if ($('sg-open-modal')) $('sg-open-modal').addEventListener('click', openModal);
  $('sg-close').addEventListener('click', closeModal);
  $('sg-cancel').addEventListener('click', closeModal);
  overlay.addEventListener('click', function (e) { if (e.target === overlay) closeModal(); });
  document.addEventListener('keydown', function (e) { if (e.key === 'Escape' && overlay.classList.contains('open')) closeModal(); });

  ui.file.addEventListener('change', function () {
    var f = ui.file.files && ui.file.files[0]; if (!f) return;
    if (f.size > 1024 * 1024) { showErr('"' + f.name + '" is larger than 1 MB.'); ui.file.value = ''; return; }
    clearErr();
    var r = new FileReader();
    r.onload = function () { ui.yaml.value = String(r.result); refreshSummary(); };
    r.readAsText(f);
  });

  function refreshSummary() {
    var el = ui.summary; el.className = 'x-summary';
    var text = ui.yaml.value.trim();
    if (!text) { el.textContent = 'Paste the rule or attach a .yml file — title, level, log source and ATT&CK tags are read from it.'; return; }
    var meta = parseSigma(text), err = validate(meta);
    if (err) { el.classList.add('bad'); el.textContent = '✗ ' + err; return; }
    el.classList.add('ok');
    var ls = logsrcText(meta.logsource);
    var attack = meta.tags.filter(function (t) { return /^attack\.t\d{4}/i.test(t); }).length;
    el.textContent = '✓ ' + meta.title + ' · level: ' + normLevel(meta.level) + (ls ? ' · ' + ls : '') +
      (attack ? ' · ' + attack + ' ATT&CK technique' + (attack !== 1 ? 's' : '') : '');
  }
  ui.yaml.addEventListener('input', refreshSummary);

  $('sg-save').addEventListener('click', function () {
    clearErr();
    var text = ui.yaml.value.replace(/\r\n?/g, '\n').trim();
    if (!text) { showErr('Paste or attach the Sigma rule'); ui.yaml.focus(); return; }
    var meta = parseSigma(text), err = validate(meta);
    if (err) { showErr(err); ui.yaml.focus(); return; }
    var report = ui.report.value.trim().replace(/^.*\//, '').replace(/\.html$/i, '');
    if (report && !/^[A-Za-z0-9_.-]+$/.test(report)) { showErr('Report slug may only contain letters, numbers, dashes and underscores'); ui.report.focus(); return; }

    var entry = entryFromYaml(text, { report: report });
    entry.slug = uniqueSlug(entry.slug);

    var local = loadLocal(); local.unshift(entry);
    if (!saveLocal(local)) { showErr('Browser storage is full — export sigma-data.js and delete some local rules.'); return; }

    closeModal();
    ui.yaml.value = ''; ui.file.value = ''; ui.report.value = ''; refreshSummary();
    state.q = ''; state.filter = 'all'; if (search) search.value = '';
    renderAll(); changed();
    toast('Saved "' + entry.title + '" in this browser. Export & commit to publish it for visitors.');
    var el = $('sg-' + entry.slug); if (el) el.scrollIntoView({ behavior: 'smooth', block: 'start' });
  });

  // ── init ───────────────────────────────────────────────────
  (function init() {
    var p = new URLSearchParams(location.search), f = p.get('filter');
    if (p.get('tab') === 'sigma' && f && ['noreport', 'report', 'local'].indexOf(f) !== -1) state.filter = f;
    renderAll(); refreshSummary();
    var id = decodeURIComponent((location.hash || '').slice(1));
    if (id && p.get('tab') === 'sigma') {
      var el = $('sg-' + id);
      if (el) setTimeout(function () { el.scrollIntoView({ block: 'start' }); el.classList.add('ex-flash'); }, 120);
    }
  })();

  window.SigmaPage = { count: function () { return all().length; }, parse: parseSigma };
})();
