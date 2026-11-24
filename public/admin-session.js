(() => {
  const IDLE_MS = 45 * 60 * 1000;
  const WARNING_MS = 2 * 60 * 1000;
  const formKey = form => 'avon-admin-draft:' + location.pathname + ':' + (form.id || form.getAttribute('action') || 'form');
  const eligible = form => form.matches('.admin-form,[data-save-draft]') && !form.matches('[data-no-draft]');
  const persist = form => {
    const values = {};
    for (const field of form.elements) {
      if (!field.name || ['password','file','hidden','submit','button'].includes(field.type) || field.name === 'csrf') continue;
      if (field.type === 'checkbox' || field.type === 'radio') values[field.name] = field.checked;
      else values[field.name] = field.value;
    }
    try { localStorage.setItem(formKey(form), JSON.stringify(values)); } catch {}
  };
  document.querySelectorAll('form').forEach(form => {
    if (!eligible(form)) return;
    const key = formKey(form);
    if (new URLSearchParams(location.search).get('saved') === '1') {
      try { localStorage.removeItem(key); } catch {}
    } else {
      try {
        const saved = JSON.parse(localStorage.getItem(key) || 'null');
        if (saved) for (const field of form.elements) {
          if (!field.name || !(field.name in saved) || ['password','file','hidden','submit','button'].includes(field.type) || field.name === 'csrf') continue;
          if (field.type === 'checkbox' || field.type === 'radio') field.checked = Boolean(saved[field.name]);
          else field.value = saved[field.name];
        }
      } catch {}
    }
    form.addEventListener('input', () => persist(form));
    form.addEventListener('change', () => persist(form));
    form.addEventListener('submit', () => persist(form));
  });

  let lastActivity = Date.now();
  let warningShown = false;
  let pingBusy = false;
  const markActive = () => { lastActivity = Date.now(); warningShown = false; const warning = document.getElementById('admin-session-warning'); if (warning) warning.hidden = true; };
  ['pointerdown','keydown','input','change','scroll','touchstart'].forEach(type => document.addEventListener(type, markActive, { passive: true }));
  const warn = () => {
    let warning = document.getElementById('admin-session-warning');
    if (!warning) {
      warning = document.createElement('aside');
      warning.id = 'admin-session-warning';
      warning.className = 'admin-session-warning';
      warning.setAttribute('role','status');
      warning.innerHTML = '<span>Your admin session will expire soon due to inactivity.</span><button type="button">Stay signed in</button>';
      document.body.appendChild(warning);
      warning.querySelector('button').addEventListener('click', () => ping(true));
    }
    warning.hidden = false;
  };
  async function ping(force = false) {
    if (pingBusy || (!force && Date.now() - lastActivity > 2 * 60 * 1000)) return;
    pingBusy = true;
    try {
      const response = await fetch('/admin/activity', { credentials: 'same-origin', cache: 'no-store' });
      if (response.redirected || !response.ok || !(response.headers.get('content-type') || '').includes('application/json')) {
        location.href = '/admin?next=' + encodeURIComponent(location.pathname + location.search);
        return;
      }
      warningShown = false;
      const warning = document.getElementById('admin-session-warning');
      if (warning) warning.hidden = true;
    } catch {}
    finally { pingBusy = false; }
  }
  setInterval(() => {
    const idle = Date.now() - lastActivity;
    if (idle >= IDLE_MS) {
      location.href = '/admin?next=' + encodeURIComponent(location.pathname + location.search);
      return;
    }
    if (idle >= IDLE_MS - WARNING_MS && !warningShown) { warningShown = true; warn(); }
    if (idle < IDLE_MS) ping();
  }, 15000);
})();