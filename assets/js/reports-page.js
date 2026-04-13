(function(){
  const grid    = document.getElementById('posts-grid');
  const noRep   = document.getElementById('no-reports');
  const totalEl = document.getElementById('report-total');
  const filterBar = document.getElementById('filter-bar');

  const footerEl = document.getElementById('footer-links');
  if(footerEl){
    const links = [];
    if(SITE_CONFIG.links.twitter)  links.push(`<a href="${SITE_CONFIG.links.twitter}" target="_blank">Twitter</a>`);
    if(SITE_CONFIG.links.github)   links.push(`<a href="${SITE_CONFIG.links.github}"  target="_blank">GitHub</a>`);
    if(SITE_CONFIG.links.email)    links.push(`<a href="${SITE_CONFIG.links.email}">Contact</a>`);
    footerEl.innerHTML = links.join('');
  }

  if(!REPORTS.length){
    if(grid) grid.style.display='none';
    if(noRep) noRep.style.display='block';
    if(totalEl) totalEl.textContent = '0 reports';
    return;
  }

  const sorted = [...REPORTS].sort((a,b)=>b.date.localeCompare(a.date));
  if(totalEl) totalEl.textContent = `${sorted.length} report${sorted.length!==1?'s':''}`;

  // Build filter buttons from unique tags
  const tags = ['ALL', ...new Set(sorted.map(r=>r.tag))];
  if(filterBar){
    filterBar.innerHTML = tags.map(t=>
      `<button class="filter-btn${t==='ALL'?' active':''}" data-tag="${t}">${t}</button>`
    ).join('');
    filterBar.addEventListener('click', e=>{
      if(!e.target.matches('.filter-btn')) return;
      filterBar.querySelectorAll('.filter-btn').forEach(b=>b.classList.remove('active'));
      e.target.classList.add('active');
      render(e.target.dataset.tag);
    });
  }

  render('ALL');

  function render(tag){
    const list = tag==='ALL' ? sorted : sorted.filter(r=>r.tag===tag);
    if(!list.length){ grid.style.display='none'; noRep.style.display='block'; return; }
    noRep.style.display='none';
    grid.style.display='';
    grid.innerHTML = list.map(r=>reportCard(r)).join('');
  }

  function tagClass(tag){ const m={MALWARE:'tag-malware',THREAT:'tag-threat',VULN:'tag-vuln',APT:'tag-apt'}; return m[tag]||'tag-malware'; }
  function sevClass(s){ const m={CRITICAL:'sev-crit',HIGH:'sev-high',MEDIUM:'sev-med',LOW:'sev-med'}; return m[s]||'sev-med'; }
  function reportCard(r){
    return `<div class="post-card" onclick="window.location='reports/${r.slug}.html'">
      <span class="tag-pill ${tagClass(r.tag)}">${r.tag}</span>
      <div class="post-meta"><span>${r.date}</span><span>${r.readTime}</span><span class="sev ${sevClass(r.severity)}">${r.severity}</span></div>
      <div class="post-title">${r.title}</div>
      <div class="post-excerpt">${r.excerpt}</div>
      <div class="read-more">READ REPORT →</div>
    </div>`;
  }
})();
