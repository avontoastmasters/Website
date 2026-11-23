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
  const button = banner.querySelector('.site-announcement__dismiss');
  if (button) {
    button.addEventListener('click', () => {
      sessionStorage.setItem(key, '1');
      banner.hidden = true;
    });
  }
});
