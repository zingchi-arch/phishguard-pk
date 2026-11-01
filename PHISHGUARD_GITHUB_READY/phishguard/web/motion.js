'use strict';
// Progressive enhancement only: analyzer works even if GSAP or Google Fonts is blocked.
(() => {
  const motionDisabled = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  const menu = document.getElementById('primary-nav');
  const toggle = document.getElementById('mobile-menu-toggle');
  const closeMenu = () => {
    if (!menu || !toggle) return;
    menu.classList.remove('is-open');
    toggle.setAttribute('aria-expanded', 'false');
    toggle.setAttribute('aria-label', 'Open menu');
  };
  toggle?.addEventListener('click', () => {
    const open = menu.classList.toggle('is-open');
    toggle.setAttribute('aria-expanded', String(open));
    toggle.setAttribute('aria-label', open ? 'Close menu' : 'Open menu');
  });
  menu?.querySelectorAll('a').forEach(a => a.addEventListener('click', closeMenu));
  document.addEventListener('keydown', e => { if (e.key === 'Escape') closeMenu(); });
  document.addEventListener('click', e => {
    if (menu?.classList.contains('is-open') && !menu.contains(e.target) && !toggle?.contains(e.target)) closeMenu();
  });
  // Animate only the final word. Its dedicated line and reserved width prevent layout shifts.
  const word = document.getElementById('typewriter');
  if (word && !motionDisabled) {
    const phrases = ['safely.', 'clearly.', 'quickly.', 'instantly.'];
    let index = 0;
    const update = (value) => { word.textContent = value; word.dataset.text = value; };
    const after = (ms, fn) => window.setTimeout(fn, ms);
    const glitch = (fn) => {
      word.classList.add('is-glitch');
      after(230, () => { word.classList.remove('is-glitch'); fn(); });
    };
    const cycle = () => glitch(() => {
      let pos = phrases[index].length;
      const next = (index + 1) % phrases.length;
      function erase() {
        if (pos > 0) { update(phrases[index].slice(0, --pos)); after(37, erase); }
        else { pos = 0; after(170, type); }
      }
      function type() {
        if (pos < phrases[next].length) { update(phrases[next].slice(0, ++pos)); after(74, type); }
        else { index = next; after(2500, cycle); }
      }
      erase();
    });
    after(2700, cycle);
  }
  const sections = Array.from(document.querySelectorAll('main section[id]'));
  if ('IntersectionObserver' in window) {
    const observer = new IntersectionObserver(entries => {
      entries.forEach(entry => {
        if (!entry.isIntersecting) return;
        menu?.querySelectorAll('a').forEach(a => a.classList.toggle('active', a.hash === '#' + entry.target.id));
      });
    }, {rootMargin:'-30% 0px -60% 0px'});
    sections.forEach(s => observer.observe(s));
  }
  if (motionDisabled || !window.gsap) return;
  const gsap = window.gsap;
  gsap.from('.hero-copy > *', {opacity:0, y:30, duration:.85, stagger:.105, ease:'power3.out', clearProps:'all'});
  gsap.from('.hero-visual .hero-art', {opacity:0, y:26, scale:.93, duration:1.2, delay:.2, ease:'power3.out', clearProps:'all'});
  gsap.to('.hero-visual .hero-art', {y:-12, duration:3.6, ease:'sine.inOut', yoyo:true, repeat:-1, delay:1.4});
  if (!window.ScrollTrigger) return;
  gsap.registerPlugin(window.ScrollTrigger);
  document.querySelectorAll('[data-reveal]').forEach(el => {
    gsap.from(el, {opacity:0, y:35, duration:.85, ease:'power3.out', scrollTrigger:{trigger:el,start:'top 93%',once:true}});
  });
  gsap.from('.steps .section-intro, .analyzer-intro', {opacity:0,y:25,stagger:.1,duration:.8,scrollTrigger:{trigger:'.steps',start:'top 86%',once:true}});
  gsap.to('.hero-glow', {y:62, scale:1.08, ease:'none', scrollTrigger:{trigger:'.hero',start:'top top',end:'bottom top',scrub:true}});
  gsap.to('.sample-dashboard', {rotation:0, y:-13, ease:'none', scrollTrigger:{trigger:'.features-art',start:'top bottom',end:'bottom 25%',scrub:true}});
})();
