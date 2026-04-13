(function(){
  const footerEl = document.getElementById('footer-links');
  if(footerEl && typeof SITE_CONFIG !== 'undefined'){
    const links = [];
    if(SITE_CONFIG.links.twitter)  links.push(`<a href="${SITE_CONFIG.links.twitter}" target="_blank">Twitter</a>`);
    if(SITE_CONFIG.links.github)   links.push(`<a href="${SITE_CONFIG.links.github}"  target="_blank">GitHub</a>`);
    if(SITE_CONFIG.links.email)    links.push(`<a href="${SITE_CONFIG.links.email}">Contact</a>`);
    footerEl.innerHTML = links.join('');
  }
})();
