document.addEventListener('DOMContentLoaded', () => {
  const form = document.getElementById('announcement-form');
  if (!form) return;
  const fields = {
    type: document.getElementById('type'),
    title: document.getElementById('title'),
    message: document.getElementById('message'),
    buttonText: document.getElementById('buttonText')
  };
  const preview = document.getElementById('announcement-preview');
  const label = document.getElementById('preview-label');
  const title = document.getElementById('preview-title');
  const message = document.getElementById('preview-message');
  const button = document.getElementById('preview-button');
  const labels = { general: 'ANNOUNCEMENT', important: 'IMPORTANT', event: 'UPCOMING EVENT', urgent: 'URGENT' };
  function updatePreview() {
    const type = fields.type.value;
    preview.className = 'admin-preview site-announcement--' + type;
    label.textContent = labels[type] || labels.general;
    title.textContent = fields.title.value.trim() || 'Your announcement heading';
    message.textContent = fields.message.value.trim() || 'Your announcement message will appear here.';
    button.textContent = (fields.buttonText.value.trim() || 'Find out more') + ' →';
    button.hidden = !fields.buttonText.value.trim();
  }
  Object.values(fields).forEach(field => field.addEventListener('input', updatePreview));
  Object.values(fields).forEach(field => field.addEventListener('change', updatePreview));
  form.addEventListener('submit', event => {
    const start = document.getElementById('startDate').value;
    const end = document.getElementById('endDate').value;
    if (start && end && end < start) {
      event.preventDefault();
      window.alert('The expiry date must be on or after the start date.');
    }
  });
  updatePreview();
});