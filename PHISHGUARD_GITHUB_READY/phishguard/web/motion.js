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
  // Typewriting is purely decorative. Keep a meaningful static phrase if JS or motion is disabled.
  const word = document.getElementById('typewriter');
  if (word && !motionDisabled) {
    const phrases = ['in seconds.', 'before you click.', 'with clarity.'];
    let index = 0;
    function cycle() {
      const next = (index + 1) % phrases.length;
      const from = phrases[index], to = phrases[next];
      let i = from.length;
      const erase = () => {
        if (i > 0) { word.textContent = from.slice(0, --i); setTimeout(erase, 40); }
        else { i = 0; setTimeout(type, 170); }
      };
      const type = () => {
        if (i < to.length) { word.textContent = to.slice(0, ++i); setTimeout(type, 73); }
        else { index = next; setTimeout(cycle, 3000); }
      };
      erase();
    }
    setTimeout(cycle, 3400);
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
  gsap.from('.hero-visual picture', {opacity:0, y:26, scale:.93, duration:1.2, delay:.2, ease:'power3.out', clearProps:'all'});
  gsap.to('.hero-visual picture', {y:-12, duration:3.6, ease:'sine.inOut', yoyo:true, repeat:-1, delay:1.4});
  if (!window.ScrollTrigger) return;
  gsap.registerPlugin(window.ScrollTrigger);
  document.querySelectorAll('[data-reveal]').forEach(el => {
    gsap.from(el, {opacity:0, y:35, duration:.85, ease:'power3.out', scrollTrigger:{trigger:el,start:'top 93%',once:true}});
  });
  gsap.from('.steps .section-intro, .analyzer-intro', {opacity:0,y:25,stagger:.1,duration:.8,scrollTrigger:{trigger:'.steps',start:'top 86%',once:true}});
  gsap.to('.hero-glow', {y:62, scale:1.08, ease:'none', scrollTrigger:{trigger:'.hero',start:'top top',end:'bottom top',scrub:true}});
  gsap.to('.sample-dashboard', {rotation:0, y:-13, ease:'none', scrollTrigger:{trigger:'.features-art',start:'top bottom',end:'bottom 25%',scrub:true}});
})();
