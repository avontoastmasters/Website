require('dotenv').config();

const express = require('express');
const helmet = require('helmet');
const compression = require('compression');
const nodemailer = require('nodemailer');
const path = require('path');
const fs = require('node:fs');
const crypto = require('node:crypto');

const app = express();
const PORT = process.env.PORT || 3002;

app.disable('x-powered-by');
// The app is behind the site's Nginx reverse proxy.
app.set('trust proxy', 1);

app.use(helmet({
  contentSecurityPolicy: false,
  crossOriginEmbedderPolicy: false
}));

app.use(compression());
app.use(express.json({ limit: '12kb', type: 'application/json' }));
app.use(express.urlencoded({ extended: false, limit: '12kb' }));

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Small in-memory limiter: maximum 5 contact attempts per IP per 15 minutes.
const contactAttempts = new Map();
const RATE_WINDOW_MS = 15 * 60 * 1000;
const RATE_LIMIT = 5;

setInterval(() => {
  const now = Date.now();
  for (const [ip, record] of contactAttempts) {
    if (now - record.startedAt >= RATE_WINDOW_MS) contactAttempts.delete(ip);
  }
}, RATE_WINDOW_MS).unref();

function cleanText(value, maxLength) {
  if (typeof value !== 'string') return '';
  return value.replace(/[\x00-\x1F\x7F]/g, ' ').trim().slice(0, maxLength);
}

async function verifyTurnstile(token, remoteIp) {
  const secret = process.env.TURNSTILE_SECRET_KEY;
  if (!secret || !token) return false;

  const body = new URLSearchParams({
    secret,
    response: token
  });
  if (remoteIp) body.set('remoteip', remoteIp);

  try {
    const response = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body,
      signal: AbortSignal.timeout(8000)
    });
    if (!response.ok) return false;

    const result = await response.json();
    return result.success === true &&
      result.action === 'contact' &&
      ['toastmasters.net.nz', 'www.toastmasters.net.nz'].includes(result.hostname);
  } catch (error) {
    console.error('Turnstile verification failed:', error.message);
    return false;
  }
}


/* Simple Avon webmaster announcement administration. */
const announcementFile = path.join(__dirname, 'data', 'announcement.json');
const ADMIN_COOKIE = 'avon_admin_session';
const ADMIN_SESSION_MS = 8 * 60 * 60 * 1000;
const adminAttempts = new Map();

function readAnnouncement() {
  try {
    const value = JSON.parse(fs.readFileSync(announcementFile, 'utf8'));
    if (value && typeof value === 'object' && !Array.isArray(value)) return value;
  } catch {}
  return { enabled: false, type: 'general', title: '', message: '', buttonText: '', buttonLink: '', startDate: '', endDate: '' };
}

function writeAnnouncement(value) {
  fs.mkdirSync(path.dirname(announcementFile), { recursive: true, mode: 0o750 });
  const temporaryFile = announcementFile + '.tmp';
  fs.writeFileSync(temporaryFile, JSON.stringify(value, null, 2) + '\n', { mode: 0o640 });
  fs.renameSync(temporaryFile, announcementFile);
}

function getPublicAnnouncement() {
  const item = readAnnouncement();
  if (item.enabled !== true || !item.title || !item.message) return null;
  const today = new Intl.DateTimeFormat('en-CA', { timeZone: 'Pacific/Auckland', year: 'numeric', month: '2-digit', day: '2-digit' }).format(new Date());
  if ((item.startDate && today < item.startDate) || (item.endDate && today > item.endDate)) return null;
  return item;
}

function getCookie(req, name) {
  for (const cookie of (req.headers.cookie || '').split(';')) {
    const separator = cookie.indexOf('=');
    if (separator >= 0 && cookie.slice(0, separator).trim() === name) return cookie.slice(separator + 1).trim();
  }
  return '';
}

function createAdminToken(payload) {
  const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const signature = crypto.createHmac('sha256', process.env.ADMIN_SESSION_SECRET).update(body).digest('base64url');
  return body + '.' + signature;
}

function getAdminSession(req) {
  const token = getCookie(req, ADMIN_COOKIE);
  const separator = token.lastIndexOf('.');
  if (separator < 1 || !process.env.ADMIN_SESSION_SECRET) return null;
  const body = token.slice(0, separator);
  const supplied = Buffer.from(token.slice(separator + 1));
  const expected = Buffer.from(crypto.createHmac('sha256', process.env.ADMIN_SESSION_SECRET).update(body).digest('base64url'));
  if (supplied.length !== expected.length || !crypto.timingSafeEqual(supplied, expected)) return null;
  try {
    const payload = JSON.parse(Buffer.from(body, 'base64url').toString('utf8'));
    return payload && payload.expiresAt > Date.now() && payload.username && payload.csrf ? payload : null;
  } catch { return null; }
}

function setAdminCookie(res, payload) {
  res.setHeader('Set-Cookie', ADMIN_COOKIE + '=' + createAdminToken(payload) + '; Path=/admin; HttpOnly; Secure; SameSite=Strict; Max-Age=28800');
}
function clearAdminCookie(res) {
  res.setHeader('Set-Cookie', ADMIN_COOKIE + '=; Path=/admin; HttpOnly; Secure; SameSite=Strict; Max-Age=0');
}
function adminReady() {
  return Boolean(process.env.ADMIN_PASSWORD_HASH && process.env.ADMIN_SESSION_SECRET && process.env.ADMIN_SESSION_SECRET.length >= 32);
}
function requireAdmin(req, res, next) {
  const session = getAdminSession(req);
  if (!session) return res.redirect(303, '/admin');
  req.adminSession = session;
  next();
}
function validCsrf(req, res) {
  const session = getAdminSession(req);
  if (!session || typeof req.body.csrf !== 'string' || req.body.csrf !== session.csrf) {
    res.status(403).send('Your session expired. Please sign in again.');
    return false;
  }
  return true;
}
function safeAnnouncementLink(value) {
  const link = cleanText(value, 500);
  if (!link) return '';
  if (link.startsWith('/') && !link.startsWith('//') && !link.includes('\\')) return link;
  try {
    const parsed = new URL(link);
    return parsed.protocol === 'https:' ? parsed.toString() : null;
  } catch { return null; }
}
function verifyAdminPassword(password) {
  const parts = (process.env.ADMIN_PASSWORD_HASH || '').split('
  res.type('text/plain').sendFile(path.join(__dirname, 'robots.txt'));
});

app.get('/sitemap.xml', (req, res) => {
  res.type('application/xml').sendFile(path.join(__dirname, 'sitemap.xml'));
});

app.get(['/health', '/healthz'], (req, res) => {
  res.json({
    status: 'ok',
    application: 'Avon Toastmasters',
    version: '3.1.0'
  });
});

// Contact form submission. The secret key and SMTP credentials stay server-side.
app.post('/api/contact', async (req, res) => {
  const ip = req.ip || req.socket.remoteAddress || 'unknown';
  const now = Date.now();
  let record = contactAttempts.get(ip);

  if (!record || now - record.startedAt >= RATE_WINDOW_MS) {
    record = { startedAt: now, count: 0 };
  }
  record.count += 1;
  contactAttempts.set(ip, record);

  if (record.count > RATE_LIMIT) {
    return res.status(429).json({
      success: false,
      message: 'Too many messages have been sent. Please try again in 15 minutes.'
    });
  }

  const body = req.body && typeof req.body === 'object' ? req.body : {};

  // Honeypot: bots often fill every field. Return a quiet success without sending.
  if (cleanText(body.website_url, 200)) {
    return res.json({ success: true, message: 'Thank you. Your message has been received.' });
  }

  const name = cleanText(body.name, 100);
  const email = cleanText(body.email, 254).toLowerCase();
  const phone = cleanText(body.phone, 40);
  const subject = cleanText(body.subject, 120);
  const message = cleanText(body.message, 5000);
  const token = cleanText(body['cf-turnstile-response'], 4096);

  const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!name || name.length < 2 || !emailPattern.test(email) ||
      !subject || subject.length < 3 || !message || message.length < 10) {
    return res.status(400).json({
      success: false,
      message: 'Please check your name, email address, subject and message, then try again.'
    });
  }

  if (!process.env.TURNSTILE_SECRET_KEY) {
    console.error('Contact form unavailable: TURNSTILE_SECRET_KEY is not configured.');
    return res.status(503).json({
      success: false,
      message: 'The contact form is temporarily unavailable. Please email hello@toastmasters.net.nz.'
    });
  }

  const verified = await verifyTurnstile(token, ip);
  if (!verified) {
    return res.status(400).json({
      success: false,
      message: 'Please complete the security check and try again.'
    });
  }

  const smtpUser = process.env.SMTP_USER;
  const smtpPass = process.env.SMTP_PASS;
  const recipient = process.env.CONTACT_TO || 'hello@toastmasters.net.nz';

  if (!smtpUser || !smtpPass) {
    console.error('Contact form unavailable: SMTP_USER or SMTP_PASS is not configured.');
    return res.status(503).json({
      success: false,
      message: 'The contact form is temporarily unavailable. Please email hello@toastmasters.net.nz.'
    });
  }

  try {
    const transporter = nodemailer.createTransport({
      host: process.env.SMTP_HOST || 'smtp.fastmail.com',
      port: Number(process.env.SMTP_PORT || 465),
      secure: true,
      auth: { user: smtpUser, pass: smtpPass },
      connectionTimeout: 10000,
      greetingTimeout: 10000,
      socketTimeout: 15000
    });

    await transporter.sendMail({
      from: { name: 'Avon Toastmasters Website', address: smtpUser },
      to: recipient,
      replyTo: { name, address: email },
      subject: `Website enquiry: ${subject}`,
      text: [
        'A new message was sent using the Avon Toastmasters Visit Us page.',
        '',
        `Name: ${name}`,
        `Email: ${email}`,
        `Phone: ${phone || 'Not provided'}`,
        `Subject: ${subject}`,
        '',
        'Message:',
        message,
        '',
        `Sender IP: ${ip}`
      ].join('\n')
    });

    await transporter.close();
    return res.json({
      success: true,
      message: 'Thank you! Your message has been sent to Avon Toastmasters.'
    });
  } catch (error) {
    console.error('Contact email delivery failed:', error.message);
    return res.status(502).json({
      success: false,
      message: 'We could not send your message just now. Please try again or email hello@toastmasters.net.nz.'
    });
  }
});


/* Private webmaster dashboard: deliberately excluded from the public sitemap. */
app.use('/admin', (req, res, next) => {
  res.setHeader('X-Robots-Tag', 'noindex, nofollow, noarchive');
  res.setHeader('Cache-Control', 'no-store');
  next();
});

app.get('/admin', (req, res) => {
  if (!adminReady()) return res.status(503).send('Webmaster login has not been configured yet.');
  const session = getAdminSession(req);
  if (!session) return res.render('admin/login', { error: '', username: process.env.ADMIN_USERNAME || 'webmaster' });
  res.render('admin/dashboard', { username: session.username, csrf: session.csrf, announcement: readAnnouncement(), saved: req.query.saved === '1' });
});

app.post('/admin/login', async (req, res) => {
  if (!adminReady()) return res.status(503).send('Webmaster login has not been configured yet.');
  const ip = req.ip || req.socket.remoteAddress || 'unknown';
  if (!limitAdminLogin(ip)) return res.status(429).render('admin/login', { error: 'Too many sign-in attempts. Please wait 15 minutes and try again.', username: process.env.ADMIN_USERNAME || 'webmaster' });
  const username = cleanText(req.body.username, 80);
  const password = typeof req.body.password === 'string' ? req.body.password : '';
  const expectedUsername = process.env.ADMIN_USERNAME || 'webmaster';
  const suppliedUser = Buffer.from(username);
  const expectedUser = Buffer.from(expectedUsername);
  const usernameMatches = suppliedUser.length === expectedUser.length && crypto.timingSafeEqual(suppliedUser, expectedUser);
  let passwordMatches = false;
  try { passwordMatches = await verifyAdminPassword(password); }
  catch (error) { console.error('Webmaster password verification failed:', error.message); }
  if (!usernameMatches || !passwordMatches) return res.status(401).render('admin/login', { error: 'The username or password was incorrect.', username: '' });
  adminAttempts.delete(ip);
  const csrf = crypto.randomBytes(24).toString('hex');
  setAdminCookie(res, { username: expectedUsername, csrf, expiresAt: Date.now() + ADMIN_SESSION_MS });
  res.redirect(303, '/admin');
});

app.post('/admin/save', requireAdmin, (req, res) => {
  if (!validCsrf(req, res)) return;
  const title = cleanText(req.body.title, 100);
  const message = cleanText(req.body.message, 500);
  const buttonText = cleanText(req.body.buttonText, 40);
  const buttonLink = safeAnnouncementLink(req.body.buttonLink);
  const type = ['general', 'important', 'event', 'urgent'].includes(req.body.type) ? req.body.type : 'general';
  const startDate = /^\\d{4}-\\d{2}-\\d{2}$/.test(req.body.startDate || '') ? req.body.startDate : '';
  const endDate = /^\\d{4}-\\d{2}-\\d{2}$/.test(req.body.endDate || '') ? req.body.endDate : '';
  if (!title || !message) return res.status(400).send('Please enter both an announcement heading and message.');
  if (buttonLink === null) return res.status(400).send('Use a local page path or a secure https:// button link.');
  if (startDate && endDate && endDate < startDate) return res.status(400).send('The expiry date must be on or after the start date.');
  writeAnnouncement({ enabled: req.body.enabled === 'on', type, title, message, buttonText: buttonLink ? buttonText : '', buttonLink, startDate, endDate, updatedAt: new Date().toISOString() });
  res.redirect(303, '/admin?saved=1');
});

app.post('/admin/logout', requireAdmin, (req, res) => {
  if (!validCsrf(req, res)) return;
  clearAdminCookie(res);
  res.redirect(303, '/admin');
});

app.use(express.static(path.join(__dirname, 'public'), {
  index: false,
  dotfiles: 'deny'
}));

app.get('/index.html', (req, res) => res.redirect(301, '/'));

const pages = {
  '/': 'index',
  '/about.html': 'about',
  '/benefits.html': 'benefits',
  '/experience.html': 'experience',
  '/faq.html': 'faq',
  '/join.html': 'join',
  '/meetings.html': 'meetings',
  '/visit.html': 'visit'
};

for (const [url, pageName] of Object.entries(pages)) {
  app.get(url, (req, res, next) => {
    res.render('layout', {
      pageName,
      currentPage: pageName,
      announcement: getPublicAnnouncement()
    }, (err, html) => {
      if (err) return next(err);
      res.type('html').send(html);
    });
  });
}

app.use((req, res) => {
  res.status(404).send('Page not found');
});

app.use((err, req, res, next) => {
  console.error(err);
  if (err.type === 'entity.too.large') {
    return res.status(413).json({ success: false, message: 'Your message is too large.' });
  }
  res.status(500).send('An internal server error occurred.');
});

app.listen(PORT, '127.0.0.1', () => {
  console.log(`Avon Toastmasters server running on http://127.0.0.1:${PORT}`);
});
);
  if (parts.length !== 3 || parts[0] !== 'scrypt' || !/^[a-f0-9]{32,}$/.test(parts[1]) || !/^[a-f0-9]{128}$/.test(parts[2])) return Promise.resolve(false);
  return new Promise((resolve, reject) => {
    crypto.scrypt(password, Buffer.from(parts[1], 'hex'), 64, (error, derived) => {
      if (error) return reject(error);
      const expected = Buffer.from(parts[2], 'hex');
      resolve(derived.length === expected.length && crypto.timingSafeEqual(derived, expected));
    });
  });
}
function limitAdminLogin(ip) {
  const now = Date.now();
  let record = adminAttempts.get(ip);
  if (!record || now - record.startedAt >= RATE_WINDOW_MS) record = { startedAt: now, count: 0 };
  record.count += 1;
  adminAttempts.set(ip, record);
  return record.count <= 5;
}

app.get('/robots.txt', (req, res) => {
  res.type('text/plain').sendFile(path.join(__dirname, 'robots.txt'));
});

app.get('/sitemap.xml', (req, res) => {
  res.type('application/xml').sendFile(path.join(__dirname, 'sitemap.xml'));
});

app.get(['/health', '/healthz'], (req, res) => {
  res.json({
    status: 'ok',
    application: 'Avon Toastmasters',
    version: '3.1.0'
  });
});

// Contact form submission. The secret key and SMTP credentials stay server-side.
app.post('/api/contact', async (req, res) => {
  const ip = req.ip || req.socket.remoteAddress || 'unknown';
  const now = Date.now();
  let record = contactAttempts.get(ip);

  if (!record || now - record.startedAt >= RATE_WINDOW_MS) {
    record = { startedAt: now, count: 0 };
  }
  record.count += 1;
  contactAttempts.set(ip, record);

  if (record.count > RATE_LIMIT) {
    return res.status(429).json({
      success: false,
      message: 'Too many messages have been sent. Please try again in 15 minutes.'
    });
  }

  const body = req.body && typeof req.body === 'object' ? req.body : {};

  // Honeypot: bots often fill every field. Return a quiet success without sending.
  if (cleanText(body.website_url, 200)) {
    return res.json({ success: true, message: 'Thank you. Your message has been received.' });
  }

  const name = cleanText(body.name, 100);
  const email = cleanText(body.email, 254).toLowerCase();
  const phone = cleanText(body.phone, 40);
  const subject = cleanText(body.subject, 120);
  const message = cleanText(body.message, 5000);
  const token = cleanText(body['cf-turnstile-response'], 4096);

  const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!name || name.length < 2 || !emailPattern.test(email) ||
      !subject || subject.length < 3 || !message || message.length < 10) {
    return res.status(400).json({
      success: false,
      message: 'Please check your name, email address, subject and message, then try again.'
    });
  }

  if (!process.env.TURNSTILE_SECRET_KEY) {
    console.error('Contact form unavailable: TURNSTILE_SECRET_KEY is not configured.');
    return res.status(503).json({
      success: false,
      message: 'The contact form is temporarily unavailable. Please email hello@toastmasters.net.nz.'
    });
  }

  const verified = await verifyTurnstile(token, ip);
  if (!verified) {
    return res.status(400).json({
      success: false,
      message: 'Please complete the security check and try again.'
    });
  }

  const smtpUser = process.env.SMTP_USER;
  const smtpPass = process.env.SMTP_PASS;
  const recipient = process.env.CONTACT_TO || 'hello@toastmasters.net.nz';

  if (!smtpUser || !smtpPass) {
    console.error('Contact form unavailable: SMTP_USER or SMTP_PASS is not configured.');
    return res.status(503).json({
      success: false,
      message: 'The contact form is temporarily unavailable. Please email hello@toastmasters.net.nz.'
    });
  }

  try {
    const transporter = nodemailer.createTransport({
      host: process.env.SMTP_HOST || 'smtp.fastmail.com',
      port: Number(process.env.SMTP_PORT || 465),
      secure: true,
      auth: { user: smtpUser, pass: smtpPass },
      connectionTimeout: 10000,
      greetingTimeout: 10000,
      socketTimeout: 15000
    });

    await transporter.sendMail({
      from: { name: 'Avon Toastmasters Website', address: smtpUser },
      to: recipient,
      replyTo: { name, address: email },
      subject: `Website enquiry: ${subject}`,
      text: [
        'A new message was sent using the Avon Toastmasters Visit Us page.',
        '',
        `Name: ${name}`,
        `Email: ${email}`,
        `Phone: ${phone || 'Not provided'}`,
        `Subject: ${subject}`,
        '',
        'Message:',
        message,
        '',
        `Sender IP: ${ip}`
      ].join('\n')
    });

    await transporter.close();
    return res.json({
      success: true,
      message: 'Thank you! Your message has been sent to Avon Toastmasters.'
    });
  } catch (error) {
    console.error('Contact email delivery failed:', error.message);
    return res.status(502).json({
      success: false,
      message: 'We could not send your message just now. Please try again or email hello@toastmasters.net.nz.'
    });
  }
});

app.use(express.static(path.join(__dirname, 'public'), {
  index: false,
  dotfiles: 'deny'
}));

app.get('/index.html', (req, res) => res.redirect(301, '/'));

const pages = {
  '/': 'index',
  '/about.html': 'about',
  '/benefits.html': 'benefits',
  '/experience.html': 'experience',
  '/faq.html': 'faq',
  '/join.html': 'join',
  '/meetings.html': 'meetings',
  '/visit.html': 'visit'
};

for (const [url, pageName] of Object.entries(pages)) {
  app.get(url, (req, res, next) => {
    res.render('layout', {
      pageName,
      currentPage: pageName
    }, (err, html) => {
      if (err) return next(err);
      res.type('html').send(html);
    });
  });
}

app.use((req, res) => {
  res.status(404).send('Page not found');
});

app.use((err, req, res, next) => {
  console.error(err);
  if (err.type === 'entity.too.large') {
    return res.status(413).json({ success: false, message: 'Your message is too large.' });
  }
  res.status(500).send('An internal server error occurred.');
});

app.listen(PORT, '127.0.0.1', () => {
  console.log(`Avon Toastmasters server running on http://127.0.0.1:${PORT}`);
});
