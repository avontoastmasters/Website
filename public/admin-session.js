(() => {
  const IDLE_MS = 45 * 60 * 1000;
  const WARNING_MS = 2 * 60 * 1000;
  const formKey = form => 'avon-admin-draft:' + location.pathname + ':' + (form.id || form.getAttribute('action') || 'form');
  const eligible = form => form.matches('.admin-form,[data-save-draft]') && !form.matches('[data-no-draft]');
  const persist = form => {
    const values = {};
    for (const field of form.elements) {
      if (!field.name || ['password','file','hidden','submit','button'].includes(field.type) || field.name === 'csrf') continue;
      values[field.name] = field.type === 'checkbox' || field.type === 'radio' ? field.checked : field.value;
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
  let lastPing = 0;
  let pingTimer;
  let pingBusy = false;
  let warningShown = false;
  const warning = () => {
    let box = document.getElementById('admin-session-warning');
    if (!box) {
      box = document.createElement('aside');
      box.id = 'admin-session-warning';
      box.className = 'admin-session-warning';
      box.setAttribute('role','status');
      box.innerHTML = '<span>Your admin session will expire soon due to inactivity. Your saved draft will be available after you sign in again.</span><button type="button">Stay signed in</button>';
      document.body.appendChild(box);
      box.querySelector('button').addEventListener('click', () => ping(true));
    }
    box.hidden = false;
  };
  async function ping(force = false) {
    if (pingBusy || (!force && Date.now() - lastPing < 30000)) return;
    pingBusy = true;
    try {
      const response = await fetch('/admin/activity', { credentials: 'same-origin', cache: 'no-store' });
      if (response.redirected || !response.ok || !(response.headers.get('content-type') || '').includes('application/json')) {
        location.href = '/admin?next=' + encodeURIComponent(location.pathname + location.search);
        return;
      }
      lastPing = Date.now();
    } catch {}
    finally { pingBusy = false; }
  }
  const markActive = () => {
    lastActivity = Date.now();
    warningShown = false;
    const box = document.getElementById('admin-session-warning');
    if (box) box.hidden = true;
    clearTimeout(pingTimer);
    pingTimer = setTimeout(() => ping(), 1200);
  };
  ['pointerdown','keydown','input','change','scroll','touchstart'].forEach(type => document.addEventListener(type, markActive, { passive: true }));
  setInterval(() => {
    const idle = Date.now() - lastActivity;
    if (idle >= IDLE_MS) {
      location.href = '/admin?next=' + encodeURIComponent(location.pathname + location.search);
      return;
    }
    if (idle >= IDLE_MS - WARNING_MS && !warningShown) { warningShown = true; warning(); }
  }, 5000);
})();