document.addEventListener('DOMContentLoaded', () => {
  const banner = document.querySelector('[data-announcement]');
  if (!banner) return;
  // Dismiss only for this browser tab session and this specific announcement.
  // A different announcement is always allowed to appear, and the banner returns
  // on the visitor's next fresh browser session.
  const id = banner.dataset.announcementId || 'default';
  const key = 'avon-announcement-dismissed:' + id;
  if (sessionStorage.getItem(key) === '1') {
    banner.hidden = true;
    return;
  }
  // Pin the banner to the viewport once its normal position has scrolled past.
  // A spacer preserves the page layout while the banner is fixed.
  const spacer = document.createElement('div');
  spacer.className = 'site-announcement-spacer';
  banner.parentNode.insertBefore(spacer, banner);
  const originalTop = banner.getBoundingClientRect().top + window.scrollY;
  let fixed = false;
  const updateSticky = () => {
    const shouldFix = window.scrollY >= originalTop;
    if (shouldFix === fixed) return;
    fixed = shouldFix;
    if (fixed) {
      spacer.style.height = banner.offsetHeight + 'px';
      banner.classList.add('is-fixed');
    } else {
      banner.classList.remove('is-fixed');
      spacer.style.height = '0px';
    }
  };
  window.addEventListener('scroll', updateSticky, { passive: true });
  window.addEventListener('resize', () => {
    if (fixed) spacer.style.height = banner.offsetHeight + 'px';
    updateSticky();
  });
  updateSticky();
  const button = banner.querySelector('.site-announcement__dismiss');
  if (button) {
    button.addEventListener('click', () => {
      sessionStorage.setItem(key, '1');
      banner.hidden = true;
    spacer.remove();
      window.removeEventListener('scroll', updateSticky);
    });
  }
});
