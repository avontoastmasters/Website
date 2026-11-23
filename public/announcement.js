document.addEventListener('DOMContentLoaded', () => {
  const banner = document.querySelector('[data-announcement]');
  if (!banner) return;
  const key = 'avon-announcement-dismissed';
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