"use strict";
(() => {
  // Navigation always works, whether or not third-party animations are available.
  const menu=document.getElementById('primary-nav');
  const toggle=document.getElementById('mobile-menu-toggle');
  if(menu && toggle){
    const close=()=>{menu.classList.remove('is-open');toggle.setAttribute('aria-expanded','false');toggle.setAttribute('aria-label','Open menu');};
    toggle.addEventListener('click',()=>{const open=menu.classList.toggle('is-open');toggle.setAttribute('aria-expanded',String(open));toggle.setAttribute('aria-label',open?'Close menu':'Open menu');});
    menu.querySelectorAll('a').forEach(link=>link.addEventListener('click',close));
    document.addEventListener('keydown',e=>{if(e.key==='Escape')close();});
    document.addEventListener('click',e=>{if(menu.classList.contains('is-open')&&!menu.contains(e.target)&&!toggle.contains(e.target))close();});
  }
  // Never hide UI at load time. Gracefully skip motion on reduced-motion and low-end devices.
  if(window.matchMedia('(prefers-reduced-motion: reduce)').matches)return;
  const gsap=window.gsap;
  const revealTargets=Array.from(document.querySelectorAll('[data-reveal]'));
  if(!gsap){
    // Fallback: native CSS transitions on existing visible elements, no blank page.
    const observer=new IntersectionObserver(items=>items.forEach(item=>{
      if(item.isIntersecting){item.target.classList.add('is-revealed');observer.unobserve(item.target);}
    }),{threshold:.13});
    revealTargets.forEach(el=>observer.observe(el));
    return;
  }
  const hero=document.querySelector('.hero');
  const t=gsap.timeline({defaults:{ease:'power3.out'},delay:.08});
  t.from('.hero .kicker',{autoAlpha:0,y:15,duration:.56})
   .from('.hero h1',{autoAlpha:0,y:24,duration:.8},'-=.28')
   .from('.hero p',{autoAlpha:0,y:16,duration:.66},'-=.48')
   .from('.hero-actions .btn',{autoAlpha:0,y:15,stagger:.105,duration:.6},'-=.46')
   .from('.hero-proof>div',{autoAlpha:0,y:14,stagger:.075,duration:.53},'-=.37');
  if(hero){
    // Subtle background parallax; animating background-position never changes layout dimensions.
    // Desktop only, keeps 1:1 mobile artwork perfectly stable.
    if(window.matchMedia('(min-width: 761px)').matches && window.ScrollTrigger){
      gsap.registerPlugin(window.ScrollTrigger);
      // Keep the layered hero background anchored while scroll reveals animate content.
    }
  }
  if(window.ScrollTrigger){
    gsap.registerPlugin(window.ScrollTrigger);
    revealTargets.forEach((el,i)=>gsap.from(el,{
      autoAlpha:0,y:30,duration:.8,ease:'power2.out',clearProps:'all',
      scrollTrigger:{trigger:el,start:'top 90%',once:true}
    }));
    gsap.from('.section-intro',{autoAlpha:0,y:18,stagger:.13,duration:.72,ease:'power2.out',clearProps:'all',scrollTrigger:{trigger:'.steps',start:'top 85%',once:true}});
  }else{
    const observer=new IntersectionObserver(items=>items.forEach(x=>{
      if(x.isIntersecting){gsap.fromTo(x.target,{autoAlpha:0,y:22},{autoAlpha:1,y:0,duration:.7,ease:'power2.out',clearProps:'all'});observer.unobserve(x.target)}
    }),{threshold:.1});
    revealTargets.forEach(el=>observer.observe(el));
  }
})();