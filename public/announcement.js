document.addEventListener('DOMContentLoaded', () => {
  const banner = document.querySelector('[data-announcement]');
  if (!banner) return;

  const id = banner.dataset.announcementId || 'default';
  const key = 'avon-announcement-dismissed:' + id;
  try {
    if (sessionStorage.getItem(key) === '1') {
      banner.hidden = true;
      return;
    }
  } catch (_) {}

  // Keep the announcement fixed directly underneath the sticky site navigation.
  // A spacer preserves its original place in the document and prevents a jump.
  const spacer = document.createElement('div');
  spacer.className = 'site-announcement-spacer';
  banner.parentNode.insertBefore(spacer, banner);

  const header = document.querySelector('.header');
  const updatePosition = () => {
    const headerBottom = header ? header.getBoundingClientRect().bottom : 0;
    banner.style.setProperty('--announcement-top', Math.max(0, headerBottom) + 'px');
    spacer.style.height = banner.hidden ? '0px' : banner.offsetHeight + 'px';
  };

  banner.classList.add('is-fixed');
  updatePosition();

  window.addEventListener('resize', updatePosition, { passive: true });
  window.addEventListener('orientationchange', updatePosition, { passive: true });
  if ('ResizeObserver' in window) {
    const observer = new ResizeObserver(updatePosition);
    if (header) observer.observe(header);
    observer.observe(banner);
  }

  const button = banner.querySelector('.site-announcement__dismiss');
  if (button) {
    button.addEventListener('click', () => {
      try { sessionStorage.setItem(key, '1'); } catch (_) {}
      banner.hidden = true;
      spacer.style.height = '0px';
    });
  }
});
