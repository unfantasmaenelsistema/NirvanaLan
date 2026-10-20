/* Tema e idioma guardados, antes de pintar (la CSP no permite scripts inline). */
(function () {
  var d = document.documentElement;
  try {
    var t = localStorage.getItem('nirvana-theme');
    if (t === 'light' || t === 'dark') d.setAttribute('data-theme', t);
    var l = localStorage.getItem('nirvana-lang');
    if (l !== 'es' && l !== 'en') l = /^es\b/i.test(navigator.language || '') ? 'es' : 'en';
    d.lang = l;
  } catch (e) { d.lang = 'es'; }
})();
