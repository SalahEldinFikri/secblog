(function(){
  const c = SITE_CONFIG;
  const set = (id, v) => { const e=document.getElementById(id); if(e) e.textContent=v; };

  set('author-name', c.authorName);
  set('author-bio',  c.bio);
  set('author-title', c.title);

  const avEl = document.getElementById('avatar-initials');
  if(avEl) avEl.textContent = c.initials;

  const certEl = document.getElementById('cert-badges');
  if(certEl) certEl.innerHTML = c.certifications.map(x=>`<span class="badge">${x}</span>`).join('');

  const skillEl = document.getElementById('skill-badges');
  if(skillEl) skillEl.innerHTML = c.skills.map(s=>`<span class="badge">${s}</span>`).join('');

  const contactEl = document.getElementById('contact-links');
  if(contactEl){
    const items = [];
    if(c.links.twitter)  items.push(`<a href="${c.links.twitter}"  target="_blank" style="color:var(--green);">&gt;_ Twitter / X</a>`);
    if(c.links.github)   items.push(`<a href="${c.links.github}"   target="_blank" style="color:var(--green);">&gt;_ GitHub</a>`);
    if(c.links.linkedin) items.push(`<a href="${c.links.linkedin}" target="_blank" style="color:var(--green);">&gt;_ LinkedIn</a>`);
    if(c.links.email)    items.push(`<a href="${c.links.email}"    style="color:var(--green);">&gt;_ Email</a>`);
    contactEl.innerHTML = items.join('');
  }

  const footerEl = document.getElementById('footer-links');
  if(footerEl){
    const links = [];
    if(c.links.twitter)  links.push(`<a href="${c.links.twitter}" target="_blank">Twitter</a>`);
    if(c.links.github)   links.push(`<a href="${c.links.github}"  target="_blank">GitHub</a>`);
    if(c.links.email)    links.push(`<a href="${c.links.email}">Contact</a>`);
    footerEl.innerHTML = links.join('');
  }
})();
