document.addEventListener('DOMContentLoaded', () => {
  const form = document.getElementById('visit-contact-form');
  if (!form) return;

  const status = document.getElementById('contact-form-status');
  const submit = form.querySelector('button[type="submit"]');

  form.addEventListener('submit', async event => {
    event.preventDefault();
    status.textContent = '';
    status.className = 'contact-form-status';

    if (!form.reportValidity()) return;

    const data = new FormData(form);
    const token = data.get('cf-turnstile-response');
    if (!token) {
      status.textContent = 'Please complete the Cloudflare security check before sending.';
      status.classList.add('is-error');
      return;
    }

    const payload = Object.fromEntries(data.entries());
    submit.disabled = true;
    submit.textContent = 'Sending…';

    try {
      const response = await fetch('/api/contact', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
        credentials: 'same-origin'
      });
      const result = await response.json();

      if (!response.ok || !result.success) {
        throw new Error(result.message || 'We could not send your message. Please try again.');
      }

      form.reset();
      if (window.turnstile) window.turnstile.reset();
      status.textContent = result.message;
      status.classList.add('is-success');
    } catch (error) {
      status.textContent = error.message || 'Something went wrong. Please try again.';
      status.classList.add('is-error');
      if (window.turnstile) window.turnstile.reset();
    } finally {
      submit.disabled = false;
      submit.innerHTML = 'Send message <span aria-hidden="true">→</span>';
    }
  });
});