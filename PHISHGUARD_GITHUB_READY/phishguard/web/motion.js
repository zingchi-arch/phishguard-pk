"use strict";
// PhishGuard static layout: intentionally no animation, typing, scroll FX or third-party animation libraries.
(() => {
  const menu = document.getElementById('primary-nav');
  const toggle = document.getElementById('mobile-menu-toggle');
  if (!menu || !toggle) return;
  const close = () => {
    menu.classList.remove('is-open');
    toggle.setAttribute('aria-expanded', 'false');
    toggle.setAttribute('aria-label', 'Open menu');
  };
  toggle.addEventListener('click', () => {
    const open = menu.classList.toggle('is-open');
    toggle.setAttribute('aria-expanded', String(open));
    toggle.setAttribute('aria-label', open ? 'Close menu' : 'Open menu');
  });
  menu.querySelectorAll('a').forEach(link => link.addEventListener('click', close));
  document.addEventListener('keydown', event => {if (event.key === 'Escape') close();});
  document.addEventListener('click', event => {
    if (menu.classList.contains('is-open') && !menu.contains(event.target) && !toggle.contains(event.target)) close();
  });
})();
