(() => {
  const setup = () => {
    const banner = document.querySelector('.site-announcement[data-announcement]');
    if (!banner || banner.dataset.fixedReady === '1') return;
    banner.dataset.fixedReady = '1';
    const id = banner.dataset.announcementId || 'default';
    const key = 'avon-announcement-dismissed:' + id;
    try {
      if (sessionStorage.getItem(key) === '1') {
        banner.hidden = true;
        return;
      }
    } catch (_) {}
    const spacer = document.createElement('div');
    spacer.className = 'site-announcement-spacer';
    banner.parentNode.insertBefore(spacer, banner);
    const update = () => { spacer.style.height = banner.hidden ? '0px' : banner.offsetHeight + 'px'; };
    banner.style.display = 'block';
    update();
    window.addEventListener('resize', update, {passive:true});
    if ('ResizeObserver' in window) new ResizeObserver(update).observe(banner);
    const dismiss = banner.querySelector('.site-announcement__dismiss');
    if (dismiss) dismiss.addEventListener('click', () => {
      try { sessionStorage.setItem(key, '1'); } catch (_) {}
      banner.hidden = true;
      spacer.style.height = '0px';
    });
  };
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', setup);
  else setup();
})();
