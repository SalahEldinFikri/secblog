// ============================================================
//  YARA-PAGE.JS — the "YARA Rules" tab on detections.html
//  Moved as-is from the old yara-feed.html (feed, reference tabs,
//  colouring, carousel, standalone rules). Nav toggle and
//  back-to-top now live once in detections.html.
// ============================================================

// ───── block 0 ─────
    (function () {
      const container = document.getElementById('yara-container');
      const noYara = document.getElementById('no-yara');
      const statsEl = document.getElementById('yara-stats');
      const dlAll = document.getElementById('dl-all');

      const footerEl = document.getElementById('footer-links');
      if (footerEl) {
        const links = [];
        if (SITE_CONFIG.links.twitter) links.push(`<a href="${SITE_CONFIG.links.twitter}" target="_blank">X</a>`);
        if (SITE_CONFIG.links.github) links.push(`<a href="${SITE_CONFIG.links.github}"  target="_blank">GitHub</a>`);
        if (SITE_CONFIG.links.email) links.push(`<a href="${SITE_CONFIG.links.email}">Contact</a>`);
        footerEl.innerHTML = links.join('');
      }

      const reportsWithYara = REPORTS.filter(r => r.yara && r.yara.length);
      if (!reportsWithYara.length) {
        if (container) container.style.display = 'none';
        if (noYara) noYara.style.display = 'block';
        if (dlAll) dlAll.style.display = 'none';
        return;
      }

      const totalRules = reportsWithYara.reduce((a, r) => a + r.yara.length, 0);

      function updateStats() {
        if (!statsEl) return;
        let saCount = 0;
        if (window.YaraStore) saCount = YaraStore.count();   // published (yara-data.js) + added in this browser
        else { try { saCount = JSON.parse(localStorage.getItem('secblog_standalone_yara') || '[]').length; } catch(e) {} }
        statsEl.innerHTML =
          '<div class="stat-mini"><div class="stat-mini-num">' + (totalRules + saCount) + '</div><div class="stat-mini-label">YARA RULES</div></div>' +
          '<div class="stat-mini"><div class="stat-mini-num">' + reportsWithYara.length + '</div><div class="stat-mini-label">REPORTS</div></div>' +
          (saCount ? '<div class="stat-mini"><div class="stat-mini-num" style="color:var(--amber)">' + saCount + '</div><div class="stat-mini-label">STANDALONE</div></div>' : '');
      }
      updateStats();
      window._yaraUpdateStats = updateStats;

      function sortAllByDate() {
        // collect all .yara-block elements from both containers
        var parent = document.getElementById('yara-feed-blocks');
        if (!parent) return;
        var blocks = Array.prototype.slice.call(parent.querySelectorAll(':scope > .yara-block-wrap'));
        blocks.sort(function(a, b) {
          var da = a.dataset.date || '';
          var db = b.dataset.date || '';
          return db.localeCompare(da);
        });
        blocks.forEach(function(b) { parent.appendChild(b); });
      }
      window._sortAllByDate = sortAllByDate;

      function tagClass(tag) { const m = { MALWARE: 'tag-malware', THREAT: 'tag-threat', VULN: 'tag-vuln', APT: 'tag-apt' }; return m[tag] || 'tag-malware'; }
      function sevClass(s) { const m = { CRITICAL: 'sev-crit', HIGH: 'sev-high', MEDIUM: 'sev-med', LOW: 'sev-med' }; return m[s] || 'sev-med'; }

      const sorted = [...reportsWithYara].sort((a, b) => b.date.localeCompare(a.date));

      if (container) {
        container.innerHTML = sorted.map((r, ri) => `
      <div class="yara-block" data-date="${r.date}" data-search="${(r.title + ' ' + r.tag + ' ' + r.severity + ' ' + r.yara.map(y => y.name + ' ' + y.description).join(' ')).toLowerCase().replace(/"/g, '&quot;')}">
        <div class="yara-report-heading">
          <div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap;">
            <span class="tag-pill ${tagClass(r.tag)}">${r.tag}</span>
            <span class="sev ${sevClass(r.severity)}">${r.severity}</span>
            <a href="reports/${r.slug}.html" class="yara-report-title">${r.title}</a>
          </div>
          <div style="margin-top:6px;font-family:var(--mono);font-size:11px;color:var(--muted);">
            ${r.date} &nbsp;·&nbsp; ${r.yara.length} rule${r.yara.length !== 1 ? 's' : ''}
          </div>
        </div>
        ${r.yara.map((y, yi) => `
          <div class="yara-rule-card">
            <div class="yara-rule-header" onclick="toggleRule('rule-${ri}-${yi}', this)">
              <div>
                <div class="yara-rule-name">${y.name}</div>
                <div class="yara-rule-meta">${y.description} &nbsp;·&nbsp; by ${y.author}</div>
              </div>
              <div class="yara-rule-actions">
                <button class="yara-copy-btn" onclick="copyRule(event, 'rule-${ri}-${yi}')">COPY</button>
                <span class="yara-chevron" id="chev-${ri}-${yi}">▼</span>
              </div>
            </div>
            <div class="yara-rule-body" id="rule-${ri}-${yi}">
              <pre>${escHtml(y.rule)}</pre>
            </div>
          </div>
        `).join('')}
      </div>
    `).join('');
      }

      // Live filter
      const searchInput = document.getElementById('yara-search');
      const noMatch = document.getElementById('yara-no-match');
      if (searchInput) {
        // after initial render, sort all blocks by date across both containers
        function sortFeed() {
          var feed = document.getElementById('yara-feed-combined');
          if (!feed) return;
          var blocks = Array.prototype.slice.call(feed.children);
          blocks.sort(function(a, b) {
            return (b.dataset.date || '').localeCompare(a.dataset.date || '');
          });
          blocks.forEach(function(b) { feed.appendChild(b); });
        }
        window._sortFeed = sortFeed;
        setTimeout(sortFeed, 0);

        searchInput.addEventListener('input', () => {
          const q = searchInput.value.trim().toLowerCase();
          // cover both report rules AND standalone rules
          const allBlocks = document.querySelectorAll('#yara-feed-combined .yara-block');
          let visible = 0;
          allBlocks.forEach(b => {
            const match = !q || (b.dataset.search || '').includes(q);
            b.style.display = match ? '' : 'none';
            if (match) visible++;
          });
          if (noMatch) noMatch.style.display = visible ? 'none' : 'block';
        });
      }

      // Download all as single .yar file
      if (dlAll) {
        dlAll.addEventListener('click', () => {
          const lines = ['// YARA Rules — SecBlog by SalahEldin Kamil', '// Generated: ' + new Date().toISOString().split('T')[0], ''];
          // standalone rules first
          try {
            const sa = window.YaraStore ? YaraStore.all() : JSON.parse(localStorage.getItem('secblog_standalone_yara') || '[]');
            if (sa.length) {
              lines.push('// ─────────────────────────────────────────────');
              lines.push('// STANDALONE RULES');
              lines.push('// ─────────────────────────────────────────────');
              sa.forEach(r => { lines.push(r.rule); lines.push(''); });
            }
          } catch(e) {}
          // report rules
          sorted.forEach(r => {
            lines.push('// ─────────────────────────────────────────────');
            lines.push('// Report: ' + r.title);
            lines.push('// Date:   ' + r.date);
            lines.push('// ─────────────────────────────────────────────');
            r.yara.forEach(y => { lines.push(y.rule); lines.push(''); });
          });
          const blob = new Blob([lines.join('\n')], { type: 'text/plain' });
          const a = document.createElement('a');
          a.href = URL.createObjectURL(blob);
          a.download = 'SalahEldin-Kamil-YARA-Rules.yar';
          a.click();
        });
      }

      function escHtml(str) {
        return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
      }

      window.toggleRule = function (id, header) {
        const body = document.getElementById(id);
        if (!body) return;
        const open = body.classList.toggle('open');
        let chevId;
        if (id.startsWith('sa-')) {
          chevId = 'chev-' + id;
        } else {
          const parts = id.split('-');
          chevId = 'chev-' + parts[1] + '-' + parts[2];
        }
        const chev = document.getElementById(chevId);
        if (chev) chev.style.transform = open ? 'rotate(180deg)' : '';
      };

      window.copyRule = function (e, id) {
        e.stopPropagation();
        const body = document.getElementById(id);
        const pre = body ? body.querySelector('pre') : null;
        if (!pre) return;
        navigator.clipboard.writeText(pre.textContent).then(() => {
          const btn = e.target;
          btn.textContent = 'COPIED!';
          btn.classList.add('copied');
          setTimeout(() => { btn.textContent = 'COPY'; btn.classList.remove('copied'); }, 2000);
        });
      };

    })();
  

// ───── block 1 ─────
    // Tab switching
    document.querySelectorAll('.ytab').forEach(function (tab) {
      tab.addEventListener('click', function () {
        document.querySelectorAll('.ytab').forEach(t => t.classList.remove('active'));
        document.querySelectorAll('.ytab-panel').forEach(p => p.classList.remove('active'));
        tab.classList.add('active');
        var panel = document.getElementById('tab-' + tab.dataset.tab);
        if (panel) panel.classList.add('active');
      });
    });
  

// ───── block 3 ─────
    (function () {
      function escapeHtml(s) {
        return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
      }

      function colorize(raw) {
        const escaped = escapeHtml(raw);
        const master = /(#[^\n]*|\/\/[^\n]*)|("(?:[^"\\]|\\.)*")|(\$[A-Za-z_][A-Za-z0-9_]*\b|\$)|(0x[0-9A-Fa-f]+)|(--?[A-Za-z][A-Za-z0-9_-]*)|\b(rule|meta|strings|condition|import|and|or|not|any|all|of|them|for|in|matches|filesize|uint8|uint16|uint32|uint64|int8|int16|int32|true|false|private|global|ascii|wide|nocase|fullword|entrypoint|do|done|then|fi|if)\b|\b(\d+)\b/g;

        return escaped.replace(master, function (m, comment, string, variable, hex, flag, kw, num) {
          if (comment) return '<span class="tok-comment">' + comment + '</span>';
          if (string) return '<span class="tok-string">' + string + '</span>';
          if (variable) return '<span class="tok-var">' + variable + '</span>';
          if (hex) return '<span class="tok-num">' + hex + '</span>';
          if (flag) return '<span class="tok-flag">' + flag + '</span>';
          if (kw) return '<span class="tok-kw">' + kw + '</span>';
          if (num) return '<span class="tok-num">' + num + '</span>';
          return m;
        });
      }

      document.querySelectorAll('.yref-code').forEach(function (el) {
        el.innerHTML = colorize(el.textContent);
      });

      document.querySelectorAll('.yara-rule-body pre').forEach(function (el) {
        el.innerHTML = colorize(el.textContent);
      });
    })();
  

// ───── block 5 ─────
    // ── Carousel logic: one box, two plain arrow buttons ───────────────────────
    document.querySelectorAll('.ytab-panel').forEach(function (panel) {
      var grid = panel.querySelector('.yref-grid');
      if (!grid) return;

      var cards = Array.from(grid.querySelectorAll('.yref-card'));
      var btnPrev = panel.querySelector('.cr-prev');
      var btnNext = panel.querySelector('.cr-next');
      var curEl = panel.querySelector('.cr-cur');
      var totEl = panel.querySelector('.cr-tot');
      if (!cards.length) return;

      var total = cards.length;
      var cur = 0;

      // Style grid as a plain block container — only one card box shows at a time
      grid.style.display = 'block';
      grid.style.transform = 'none';

      // Hide all cards, then reveal only the first
      cards.forEach(function (c) {
        c.style.display = 'none';
        c.style.width = '100%';
        c.style.flex = 'none';
        c.style.minWidth = '0';
        c.style.boxSizing = 'border-box';
      });
      cards[0].style.display = '';

      if (totEl) totEl.textContent = total;
      if (curEl) curEl.textContent = 1;

      function go(n) {
        n = Math.max(0, Math.min(n, total - 1));
        cards[cur].style.display = 'none';
        cur = n;
        cards[cur].style.display = '';
        if (curEl) curEl.textContent = cur + 1;
        if (btnPrev) btnPrev.disabled = cur === 0;
        if (btnNext) btnNext.disabled = cur === total - 1;
      }

      // Wire up the arrow buttons
      if (btnPrev) {
        btnPrev.disabled = true;
        btnPrev.addEventListener('click', function () { go(cur - 1); });
      }
      if (btnNext) {
        btnNext.disabled = (total <= 1);
        btnNext.addEventListener('click', function () { go(cur + 1); });
      }

      // Keyboard navigation
      panel.setAttribute('tabindex', '0');
      panel.addEventListener('keydown', function (e) {
        if (e.key === 'ArrowLeft') go(cur - 1);
        if (e.key === 'ArrowRight') go(cur + 1);
      });

      // Touch swipe
      var tx = 0;
      grid.addEventListener('touchstart', function (e) {
        tx = e.touches[0].clientX;
      }, { passive: true });
      grid.addEventListener('touchend', function (e) {
        var dx = e.changedTouches[0].clientX - tx;
        if (dx < -40) go(cur + 1);
        if (dx > 40) go(cur - 1);
      }, { passive: true });
    });
  

// ───── block 6 ─────
  /* ══ STANDALONE YARA RULES — ADD / DISPLAY / DELETE / EXPORT ══
     Published rules live in assets/js/yara-data.js, rules you add here live in
     this browser until you publish them. YaraStore (yara-lib.js) merges the two and
     is also what the homepage "YARA Rules Written" counter reads. */
  (function () {
    var Y = window.YaraStore;
    if (!Y) return;
    var AUTODL_KEY = 'secblog_yara_autodl';

    function esc(s) {
      return String(s == null ? '' : s)
        .replace(/&/g,'&amp;').replace(/</g,'&lt;')
        .replace(/>/g,'&gt;').replace(/"/g,'&quot;');
    }

    function colorize(raw) {
      var e = esc(raw);
      return e.replace(
        /(#[^\n]*|\/\/[^\n]*)|(\"(?:[^\"\\]|\\.)*\")|(\$[A-Za-z_][A-Za-z0-9_]*\b|\$)|(0x[0-9A-Fa-f]+)|\b(rule|meta|strings|condition|import|and|or|not|any|all|of|them|for|in|matches|filesize|uint8|uint16|uint32|uint64|int8|int16|int32|true|false|private|global|ascii|wide|nocase|fullword|entrypoint)\b|(\d+)/g,
        function(m, cmt, str, varr, hex, kw, num) {
          if (cmt)  return '<span class="tok-comment">'  + cmt  + '</span>';
          if (str)  return '<span class="tok-string">'   + str  + '</span>';
          if (varr) return '<span class="tok-var">'      + varr + '</span>';
          if (hex)  return '<span class="tok-num">'      + hex  + '</span>';
          if (kw)   return '<span class="tok-kw">'       + kw   + '</span>';
          if (num)  return '<span class="tok-num">'      + num  + '</span>';
          return m;
        }
      );
    }

    function tagCls(t) {
      return {MALWARE:'tag-malware',THREAT:'tag-threat',VULN:'tag-vuln',APT:'tag-apt'}[t] || 'tag-malware';
    }

    function download(filename, text) {
      var blob = new Blob([text], { type: 'text/javascript;charset=utf-8' });
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
      try { document.execCommand('copy'); } catch (e) {}
      ta.remove();
    }

    function toast(msg) {
      var el = document.getElementById('ex-toast'); if (!el) return;
      el.textContent = msg; el.classList.add('show');
      clearTimeout(toast._t); toast._t = setTimeout(function () { el.classList.remove('show'); }, 5200);
    }

    function refreshEverywhere() {
      if (window._yaraUpdateStats) window._yaraUpdateStats();
      window.dispatchEvent(new Event('det:changed'));
    }

    function updateBanner(rules) {
      var el = document.getElementById('yara-local-banner'); if (!el) return;
      var n = rules.filter(function (r) { return r._local; }).length;
      el.style.display = n ? 'flex' : 'none';
      var c = document.getElementById('yara-local-count');
      if (c && n) c.textContent = n + ' YARA rule' + (n !== 1 ? 's' : '');
    }

    function renderAll() {
      var wrap = document.getElementById('standalone-wrap');
      var rules = Y.all();
      updateBanner(rules);
      if (!wrap) return;
      if (!rules.length) { wrap.innerHTML = ''; return; }

      wrap.innerHTML = rules.map(function(r, i) {
        var uid = 'sa-' + i;
        var id = esc(r.id);
        var search = esc([r.name, r.description, r.tag, r.author].join(' ').toLowerCase());
        var del = r._local
          ? '<button class="yara-copy-btn sa-del" data-id="' + id + '" onclick="event.stopPropagation()" style="border-color:transparent">DELETE</button>'
          : '';
        return [
          '<div class="yara-block" id="yara-sa-' + id + '" data-date="' + esc(r.date || '2000-01-01') + '" data-sa="true" data-search="' + search + '">',
            '<div class="yara-report-heading">',
              '<div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap;">',
                '<span class="tag-pill ' + tagCls(r.tag) + '">' + esc(r.tag) + '</span>',
                '<span class="sa-standalone-label">STANDALONE</span>',
                (r._local ? '<span class="ex-status local" title="Added in this browser only — export yara-data.js & commit to publish">LOCAL ONLY</span>' : ''),
                '<span class="yara-report-title" style="cursor:default">' + esc(r.name) + '</span>',
              '</div>',
              '<div style="margin-top:6px;font-family:var(--mono);font-size:11px;color:var(--muted);">',
                esc(r.date || '') + ' &nbsp;·&nbsp; 1 rule',
              '</div>',
            '</div>',
            '<div class="yara-rule-card">',
              '<div class="yara-rule-header" onclick="toggleRule(\'' + uid + '\', this)">',
                '<div>',
                  '<div class="yara-rule-name">' + esc(r.name) + '</div>',
                  '<div class="yara-rule-meta">' + esc(r.description) + ' &nbsp;·&nbsp; by ' + esc(r.author || 'SalahEldin Kamil') + '</div>',
                '</div>',
                '<div class="yara-rule-actions">',
                  '<button class="yara-copy-btn sa-copy" data-id="' + id + '" onclick="event.stopPropagation()">COPY</button>',
                  del,
                  '<span class="yara-chevron" id="chev-' + uid + '">▼</span>',
                '</div>',
              '</div>',
              '<div class="yara-rule-body" id="' + uid + '">',
                '<pre>' + colorize(r.rule) + '</pre>',
              '</div>',
            '</div>',
          '</div>'
        ].join('');
      }).join('');

      /* wire copy buttons */
      wrap.querySelectorAll('.sa-copy').forEach(function(btn) {
        btn.addEventListener('click', function() {
          var r = Y.all().filter(function (x) { return x.id === btn.dataset.id; })[0];
          if (!r) return;
          copyText(r.rule).then(function() {
            btn.textContent = 'COPIED!'; btn.classList.add('copied');
            setTimeout(function() { btn.textContent = 'COPY'; btn.classList.remove('copied'); }, 2000);
          });
        });
      });

      /* wire delete buttons (only rules added in this browser can be deleted here) */
      wrap.querySelectorAll('.sa-del').forEach(function(btn) {
        btn.addEventListener('click', function() {
          var r = Y.all().filter(function (x) { return x.id === btn.dataset.id; })[0];
          if (!r) return;
          if (!confirm('Delete rule "' + r.name + '"?')) return;
          Y.removeLocal(r.id);
          renderAll();
          refreshEverywhere();
          toast('Deleted "' + r.name + '" from this browser.');
        });
      });
    }

    /* ── export for publishing ── */
    function doExport(autoMsg) {
      download('yara-data.js', Y.exportJs());
      toast((autoMsg || 'Downloaded yara-data.js') + ' — replace assets/js/yara-data.js with it, then commit & push. That is what adds it to the homepage counter for everyone.');
    }
    var exBtn  = document.getElementById('yara-export');         if (exBtn)  exBtn.addEventListener('click',  function () { doExport(); });
    var exBtn2 = document.getElementById('yara-export-banner');  if (exBtn2) exBtn2.addEventListener('click', function () { doExport(); });

    /* ── modal ── */
    var overlay    = document.getElementById('add-modal');
    var openBtn    = document.getElementById('open-add-modal');
    var xBtn       = document.getElementById('modal-x');
    var cancelBtn  = document.getElementById('modal-cancel');
    var saveBtn    = document.getElementById('modal-save');
    var errEl      = document.getElementById('modal-err');
    var autoDl     = document.getElementById('m-autodl');

    // remember the "also download yara-data.js" choice (on by default)
    if (autoDl) {
      var pref = null; try { pref = localStorage.getItem(AUTODL_KEY); } catch (e) {}
      autoDl.checked = pref !== '0';
      autoDl.addEventListener('change', function () { try { localStorage.setItem(AUTODL_KEY, autoDl.checked ? '1' : '0'); } catch (e) {} });
    }

    function openModal() {
      overlay.classList.add('open');
      document.body.style.overflow = 'hidden';
      setTimeout(function() { document.getElementById('m-name').focus(); }, 50);
    }
    function closeModal() {
      overlay.classList.remove('open');
      document.body.style.overflow = '';
      errEl.textContent = ''; errEl.classList.remove('show');
    }
    function showErr(msg) {
      errEl.textContent = '⚠ ' + msg;
      errEl.classList.add('show');
    }

    if (openBtn)   openBtn.addEventListener('click',   openModal);
    if (xBtn)      xBtn.addEventListener('click',      closeModal);
    if (cancelBtn) cancelBtn.addEventListener('click', closeModal);

    overlay.addEventListener('click', function(e) {
      if (e.target === overlay) closeModal();
    });
    document.addEventListener('keydown', function(e) {
      if (e.key === 'Escape' && overlay.classList.contains('open')) closeModal();
    });

    saveBtn.addEventListener('click', function() {
      errEl.textContent = ''; errEl.classList.remove('show');

      var name = document.getElementById('m-name').value.trim();
      var desc = document.getElementById('m-desc').value.trim();
      var rule = document.getElementById('m-rule').value.trim();
      var author = document.getElementById('m-author').value.trim();
      var tag  = document.getElementById('m-tag').value;
      var ref  = document.getElementById('m-ref').value.trim();

      if (!name) { showErr('Rule name is required'); document.getElementById('m-name').focus(); return; }
      if (!desc) { showErr('Description is required'); document.getElementById('m-desc').focus(); return; }
      if (!rule) { showErr('YARA rule body is required'); document.getElementById('m-rule').focus(); return; }
      if (rule.indexOf('condition:') === -1) {
        showErr('Rule must contain a condition: block');
        document.getElementById('m-rule').focus();
        return;
      }

      var entry = {
        id: Y.uniqueId(Y.slugify(name)),
        name: name,
        description: desc,
        author: author || 'SalahEldin Kamil (Mr_MaTriX)',
        tag: tag,
        rule: rule,
        reference: ref,
        date: new Date().toISOString().split('T')[0]
      };
      if (!Y.addLocal(entry)) {
        showErr('Browser storage is full — export yara-data.js and delete some local rules.');
        return;
      }

      renderAll();
      refreshEverywhere();
      if (window._sortFeed) window._sortFeed();
      closeModal();

      /* reset form */
      document.getElementById('m-name').value   = '';
      document.getElementById('m-desc').value   = '';
      document.getElementById('m-author').value = '';
      document.getElementById('m-rule').value   = '';
      document.getElementById('m-ref').value    = '';
      document.getElementById('m-tag').value    = 'MALWARE';

      /* write the rule into the data file (a fresh yara-data.js is downloaded) */
      if (autoDl && autoDl.checked) {
        doExport('Saved "' + entry.name + '" and downloaded yara-data.js');
      } else {
        toast('Saved "' + entry.name + '" in this browser and added to the counter. Click “export yara-data.js” to publish it for everyone.');
      }

      /* scroll to new card */
      var card = document.getElementById('yara-sa-' + entry.id);
      if (card) card.scrollIntoView({ behavior: 'smooth', block: 'start' });
    });

    /* init */
    renderAll();
    setTimeout(function(){ if(window._sortFeed) window._sortFeed(); }, 50);
  })();
