require('dotenv').config();

const express = require('express');
const helmet = require('helmet');
const compression = require('compression');
const nodemailer = require('nodemailer');
const path = require('path');
const fs = require('node:fs');
const crypto = require('node:crypto');
const multer = require('multer');
const sharp = require('sharp');
const heicConvert = require('heic-convert');

const app = express();
const PORT = process.env.PORT || 3002;

app.disable('x-powered-by');
// The app is behind the site's Nginx reverse proxy.
app.set('trust proxy', 1);

// Redirect the alternate www hostname to the canonical non-www domain.
app.use((req, res, next) => {
  if (req.hostname === 'www.toastmasters.net.nz') return res.redirect(301, 'https://toastmasters.net.nz' + req.originalUrl);
  next();
});

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
const announcementUploadDir = path.join(__dirname, 'public', 'uploads', 'announcements');
const announcementUpload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 8 * 1024 * 1024, files: 1 } });
function safeAnnouncementImage(value) {
  const image = cleanText(value, 240);
  return /^\/uploads\/(?:announcements|media)\/[a-f0-9-]{36}\.webp$/.test(image) ? image : '';
}

const eventFile = path.join(__dirname, 'data', 'events.json');

function readEvents() {
  try {
    const value = JSON.parse(fs.readFileSync(eventFile, 'utf8'));
    return Array.isArray(value) ? value : [];
  } catch { return []; }
}
function writeEvents(items) {
  fs.mkdirSync(path.dirname(eventFile), { recursive: true, mode: 0o750 });
  const temporaryFile = eventFile + '.tmp';
  fs.writeFileSync(temporaryFile, JSON.stringify(items, null, 2) + '\n', { mode: 0o640 });
  fs.renameSync(temporaryFile, eventFile);
}
function eventDateTime(item) {
  return (item.date || '9999-12-31') + 'T' + (item.startTime || '00:00');
}
function eventEndDateTime(item) {
  return (item.date || '9999-12-31') + 'T' + (item.endTime || item.startTime || '23:59');
}
function eventHasFinished(item, now = nzDateTime()) {
  return eventEndDateTime(item) <= now;
}
function getPublicEvents() {
  const now = nzDateTime();
  return readEvents()
    .filter(item => item.enabled === true && item.title && item.description && item.date && !eventHasFinished(item, now))
    .sort((a, b) => eventDateTime(a).localeCompare(eventDateTime(b)));
}

function readAnnouncements() {
  try {
    const value = JSON.parse(fs.readFileSync(announcementFile, 'utf8'));
    if (Array.isArray(value)) return value;
    if (value && typeof value === 'object' && value.title) return [{ ...value, id: value.id || 'legacy-' + crypto.createHash('sha256').update(JSON.stringify(value)).digest('hex').slice(0, 24) }];
  } catch {}
  return [];
}
function writeAnnouncements(items) {
  fs.mkdirSync(path.dirname(announcementFile), { recursive: true, mode: 0o750 });
  const temporaryFile = announcementFile + '.tmp';
  fs.writeFileSync(temporaryFile, JSON.stringify(items, null, 2) + '\n', { mode: 0o640 });
  fs.renameSync(temporaryFile, announcementFile);
}
function nzDateTime(date = new Date()) {
  const parts = new Intl.DateTimeFormat('en-CA', {
    timeZone: 'Pacific/Auckland', year: 'numeric', month: '2-digit', day: '2-digit',
    hour: '2-digit', minute: '2-digit', hourCycle: 'h23'
  }).formatToParts(date);
  const value = Object.fromEntries(parts.map(part => [part.type, part.value]));
  return value.year + '-' + value.month + '-' + value.day + 'T' + value.hour + ':' + value.minute;
}
function announcementStart(item) {
  if (item.startDate) return item.startDate + 'T' + (item.startTime || '00:00');
  return '0000-01-01T00:00';
}
function announcementEnd(item) {
  if (!item.endDate) return null;
  return item.endDate + 'T' + (item.endTime || '23:59');
}
function announcementsOverlap(first, second) {
  const firstStart = announcementStart(first);
  const secondStart = announcementStart(second);
  const firstEnd = announcementEnd(first) || '9999-12-31T23:59';
  const secondEnd = announcementEnd(second) || '9999-12-31T23:59';
  return firstStart < secondEnd && secondStart < firstEnd;
}
function findAnnouncementConflict(items, candidate) {
  return items.find(item => item.enabled && item.id !== candidate.id && announcementsOverlap(item, candidate));
}
function expireAnnouncements(items, now = nzDateTime()) {
  let changed = false;
  for (const item of items) {
    const end = announcementEnd(item);
    if (item.enabled === true && end && now >= end) {
      item.enabled = false;
      item.expiredAt = new Date().toISOString();
      changed = true;
    }
  }
  if (changed) writeAnnouncements(items);
  return items;
}
function getPublicAnnouncement() {
  const now = nzDateTime();
  return readAnnouncements().find(item => item.enabled === true && item.title && item.message &&
    announcementStart(item) <= now && (!announcementEnd(item) || now < announcementEnd(item))) || null;
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
  const parts = (process.env.ADMIN_PASSWORD_HASH || '').split('$');
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
  const sitemapPath = path.join(__dirname, 'sitemap.xml');
  let xml = fs.readFileSync(sitemapPath, 'utf8');
  const eventUrls = getPublicEvents().map(item => [
    '  <url>',
    '    <loc>' + escapeXml(eventUrl(item)) + '</loc>',
    '    <lastmod>' + escapeXml((item.updatedAt || new Date().toISOString()).slice(0, 10)) + '</lastmod>',
    '    <changefreq>weekly</changefreq>',
    '    <priority>0.6</priority>',
    '  </url>'
  ].join('\\n')).join('\\n');
  if (eventUrls) xml = xml.replace('</urlset>', eventUrls + '\\n</urlset>');
  res.type('application/xml').send(xml);
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


/* Private webmaster dashboard. It is not linked publicly or listed in the sitemap. */
app.use('/admin', (req, res, next) => {
  res.setHeader('X-Robots-Tag', 'noindex, nofollow, noarchive');
  res.setHeader('Cache-Control', 'no-store');
  next();
});
app.get('/admin', (req, res) => {
  if (!adminReady()) return res.status(503).send('Webmaster login has not been configured yet.');
  const session = getAdminSession(req);
  if (!session) return res.render('admin/login', { error: '', username: process.env.ADMIN_USERNAME || 'webmaster' });
  const announcements = expireAnnouncements(readAnnouncements());
  res.render('admin/dashboard', { username: session.username, csrf: session.csrf, announcements, editing: announcements.find(item => item.id === req.query.edit) || null, saved: req.query.saved === '1', uploadedImage: safeAnnouncementImage(req.query.image), nowNZ: nzDateTime(), error: '' });
});
app.get('/admin/events', requireAdmin, (req, res) => {
  const events = readEvents().sort((a, b) => eventDateTime(a).localeCompare(eventDateTime(b)));
  res.render('admin/events', {
    username: req.adminSession.username,
    csrf: req.adminSession.csrf,
    events,
    editing: events.find(item => item.id === req.query.edit) || null,
    saved: req.query.saved === '1',
    error: ''
  });
});

app.post('/admin/events/save', requireAdmin, (req, res) => {
  if (!validCsrf(req, res)) return;
  const items = readEvents();
  const id = cleanText(req.body.id, 80) || crypto.randomUUID();
  const title = cleanText(req.body.title, 120);
  const description = cleanText(req.body.description, 2000);
  const category = ['competition', 'open-house', 'workshop', 'social', 'special', 'other'].includes(req.body.category) ? req.body.category : 'other';
  const date = cleanText(req.body.date, 10);
  const startTime = cleanText(req.body.startTime, 5);
  const endTime = cleanText(req.body.endTime, 5);
  const location = cleanText(req.body.location, 180);
  const bookingLink = safeAnnouncementLink(req.body.bookingLink);
  const imageUrl = safeAnnouncementImage(req.body.imageUrl);
  const datePattern = /^\d{4}-\d{2}-\d{2}$/;
  const timePattern = /^(?:[01]\d|2[0-3]):[0-5]\d$/;
  const validDate = value => datePattern.test(value) && !Number.isNaN(Date.parse(value + 'T00:00:00Z')) && new Date(value + 'T00:00:00Z').toISOString().slice(0, 10) === value;
  if (!title || title.length < 3 || !description || description.length < 10) return res.status(400).send('Please enter an event title and a description of at least 10 characters.');
  if (!validDate(date) || !timePattern.test(startTime) || (endTime && !timePattern.test(endTime))) return res.status(400).send('Please enter a valid New Zealand event date and time.');
  if (endTime && endTime <= startTime) return res.status(400).send('The event end time must be later than its start time.');
  if (!location) return res.status(400).send('Please enter an event location.');
  if (bookingLink === null) return res.status(400).send('Use a local page path or a secure https:// booking link.');
  const item = { id, enabled: req.body.enabled === 'on', title, description, category, date, startTime, endTime, location, bookingLink, imageUrl, updatedAt: new Date().toISOString() };
  const index = items.findIndex(entry => entry.id === id);
  if (index >= 0) items[index] = item; else items.unshift(item);
  writeEvents(items);
  res.redirect(303, '/admin/events?saved=1');
});

app.post('/admin/events/toggle', requireAdmin, (req, res) => {
  if (!validCsrf(req, res)) return;
  const items = readEvents();
  const item = items.find(entry => entry.id === req.body.id);
  if (!item) return res.status(404).send('Event not found.');
  item.enabled = req.body.enabled === 'on';
  item.updatedAt = new Date().toISOString();
  writeEvents(items);
  res.redirect(303, '/admin/events?saved=1');
});

app.post('/admin/events/delete', requireAdmin, (req, res) => {
  if (!validCsrf(req, res)) return;
  writeEvents(readEvents().filter(item => item.id !== req.body.id));
  res.redirect(303, '/admin/events?saved=1');
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


const mediaUploadDir = path.join(__dirname, 'public', 'uploads', 'media');
async function getProcessableImageBuffer(file) {
  const extension = path.extname(file.originalname || '').toLowerCase();
  const mimeType = (file.mimetype || '').toLowerCase();
  const isHeic = ['.heic', '.heif'].includes(extension) || ['image/heic', 'image/heif', 'image/heic-sequence', 'image/heif-sequence'].includes(mimeType);
  if (!isHeic) return file.buffer;
  // Decode HEIC first because Sharp's standard prebuilt binaries do not decode HEVC.
  return Buffer.from(await heicConvert({ buffer: file.buffer, format: 'JPEG', quality: 0.92 }));
}
function listMediaFiles() {
  try {
    return fs.readdirSync(mediaUploadDir, { withFileTypes: true })
      .filter(entry => entry.isFile() && /^[a-f0-9-]{36}\.webp$/.test(entry.name))
      .map(entry => {
        const filename = entry.name;
        const fullPath = path.join(mediaUploadDir, filename);
        const stat = fs.statSync(fullPath);
        return { filename, url: '/uploads/media/' + filename, bytes: stat.size, modified: stat.mtime.toISOString() };
      }).sort((a,b) => b.modified.localeCompare(a.modified));
  } catch { return []; }
}
app.get('/admin/media', requireAdmin, (req, res) => {
  res.render('admin/media', {
    username: req.adminSession.username,
    csrf: req.adminSession.csrf,
    files: listMediaFiles(),
    uploaded: req.query.uploaded === '1',
    error: ''
  });
});
app.post('/admin/media/upload', requireAdmin, (req, res, next) => {
  announcementUpload.single('mediaImage')(req, res, error => {
    if (error) {
      if (error.code === 'LIMIT_FILE_SIZE') return res.status(413).send('Image is too large. Please choose an image under 8 MB.');
      return res.status(400).send('Please choose one valid image file.');
    }
    next();
  });
}, async (req, res) => {
  if (!validCsrf(req, res)) return;
  if (!req.file) return res.status(400).send('Please choose an image to upload.');
  try {
    const imageBuffer = await getProcessableImageBuffer(req.file);
    const metadata = await sharp(imageBuffer, { limitInputPixels: 40000000 }).metadata();
    if (!['jpeg', 'png', 'webp', 'avif'].includes(metadata.format)) {
      return res.status(400).send('Please upload a JPEG, PNG, WebP, AVIF or HEIC image.');
    }
    const filename = crypto.randomUUID() + '.webp';
    fs.mkdirSync(mediaUploadDir, { recursive: true, mode: 0o750 });
    await sharp(imageBuffer, { limitInputPixels: 40000000 })
      .rotate()
      .resize({ width: 2000, height: 2000, fit: 'inside', withoutEnlargement: true })
      .webp({ quality: 80, effort: 4 })
      .toFile(path.join(mediaUploadDir, filename));
    return res.redirect(303, '/admin/media?uploaded=1');
  } catch (error) {
    console.error('Media image processing failed:', error.message);
    return res.status(400).send('That image could not be processed. Please try a JPEG, PNG, WebP, AVIF or HEIC image.');
  }
});
app.post('/admin/media/delete', requireAdmin, (req, res) => {
  if (!validCsrf(req, res)) return;
  const filename = cleanText(req.body.filename, 60);
  if (!/^[a-f0-9-]{36}\.webp$/.test(filename)) return res.status(400).send('Invalid image filename.');
  const filePath = path.join(mediaUploadDir, filename);
  try { fs.unlinkSync(filePath); } catch (error) {
    if (error.code === 'ENOENT') return res.status(404).send('Image not found.');
    throw error;
  }
  res.redirect(303, '/admin/media');
});

app.post('/admin/upload-image', requireAdmin, (req, res, next) => {
  announcementUpload.single('announcementImage')(req, res, error => {
    if (error) {
      if (error.code === 'LIMIT_FILE_SIZE') return res.status(413).send('Image is too large. Please choose an image under 8 MB.');
      return res.status(400).send('Please choose one valid image file.');
    }
    next();
  });
}, async (req, res) => {
  if (!validCsrf(req, res)) return;
  if (!req.file) return res.status(400).send('Please choose an image to upload.');
  try {
    const imageBuffer = await getProcessableImageBuffer(req.file);
    const metadata = await sharp(imageBuffer, { limitInputPixels: 40000000 }).metadata();
    if (!['jpeg', 'png', 'webp', 'avif'].includes(metadata.format)) {
      return res.status(400).send('Please upload a JPEG, PNG, WebP, AVIF or HEIC image.');
    }
    const filename = crypto.randomUUID() + '.webp';
    fs.mkdirSync(mediaUploadDir, { recursive: true, mode: 0o750 });
    await sharp(imageBuffer, { limitInputPixels: 40000000 })
      .rotate()
      .resize({ width: 1600, height: 1000, fit: 'inside', withoutEnlargement: true })
      .webp({ quality: 78, effort: 4 })
      .toFile(path.join(mediaUploadDir, filename));
    const imageUrl = '/uploads/media/' + filename;
    return res.redirect(303, '/admin?image=' + encodeURIComponent(imageUrl));
  } catch (error) {
    console.error('Announcement image processing failed:', error.message);
    return res.status(400).send('That image could not be processed. Please try a JPEG, PNG, WebP, AVIF or HEIC image.');
  }
});
app.post('/admin/save', requireAdmin, (req, res) => {
  if (!validCsrf(req, res)) return;
  const items = readAnnouncements();
  const id = cleanText(req.body.id, 80) || crypto.randomUUID();
  const title = cleanText(req.body.title, 100);
  const message = cleanText(req.body.message, 500);
  const buttonText = cleanText(req.body.buttonText, 40);
  const buttonLink = safeAnnouncementLink(req.body.buttonLink);
  const imageUrl = safeAnnouncementImage(req.body.imageUrl);
  const type = ['general', 'important', 'event', 'urgent'].includes(req.body.type) ? req.body.type : 'general';
  const nowNZ = nzDateTime();
  const datePattern = /^\d{4}-\d{2}-\d{2}$/;
  const timePattern = /^(?:[01]\d|2[0-3]):[0-5]\d$/;
  const validDate = value => datePattern.test(value) && !Number.isNaN(Date.parse(value + 'T00:00:00Z')) && new Date(value + 'T00:00:00Z').toISOString().slice(0, 10) === value;
  const suppliedStartDate = cleanText(req.body.startDate, 10);
  const suppliedStartTime = cleanText(req.body.startTime, 5);
  if ((suppliedStartDate && !validDate(suppliedStartDate)) || (suppliedStartTime && !timePattern.test(suppliedStartTime))) {
    return res.status(400).send('Please enter a valid New Zealand start date and time.');
  }
  const startDate = validDate(suppliedStartDate) ? suppliedStartDate : nowNZ.slice(0, 10);
  const startTime = timePattern.test(suppliedStartTime) ? suppliedStartTime : (startDate === nowNZ.slice(0, 10) ? nowNZ.slice(11, 16) : '00:00');
  const suppliedEndDate = cleanText(req.body.endDate, 10);
  const suppliedEndTime = cleanText(req.body.endTime, 5);
  if ((suppliedEndDate && !validDate(suppliedEndDate)) || (suppliedEndTime && !timePattern.test(suppliedEndTime))) {
    return res.status(400).send('Please enter a valid New Zealand end date and time.');
  }
  const endDate = validDate(suppliedEndDate) ? suppliedEndDate : (timePattern.test(suppliedEndTime) ? startDate : '');
  const endTime = endDate ? (timePattern.test(suppliedEndTime) ? suppliedEndTime : '23:59') : '';
  if (!title || !message) return res.status(400).send('Please enter both an announcement heading and message.');
  if (buttonLink === null) return res.status(400).send('Use a local page path or a secure https:// button link.');
  if (!validDate(startDate) || !timePattern.test(startTime) || (endDate && (!validDate(endDate) || !timePattern.test(endTime)))) {
    return res.status(400).send('Please enter valid New Zealand start and end dates and times.');
  }
  if (endDate && endDate + 'T' + endTime < startDate + 'T' + startTime) {
    return res.status(400).send('The end date and time must be after the start date and time.');
  }
  const enabled = req.body.enabled === 'on';
  const item = { id, enabled, type, title, message, imageUrl, buttonText: buttonLink ? buttonText : '', buttonLink, startDate, startTime, endDate, endTime, updatedAt: new Date().toISOString() };
  const index = items.findIndex(entry => entry.id === id);
  if (enabled) {
    const conflict = findAnnouncementConflict(items, item);
    if (conflict) return res.status(409).render('admin/dashboard', {
      username: req.adminSession.username, csrf: req.adminSession.csrf, announcements: items,
      editing: item, saved: false, nowNZ: nzDateTime(),
      error: 'Schedule conflict: "' + cleanText(conflict.title, 100) + '" is already scheduled during this time. Change the start or end date/time before saving.'
    });
  }
  if (index >= 0) items[index] = item; else items.unshift(item);
  writeAnnouncements(items);
  res.redirect(303, '/admin?saved=1');
});
app.post('/admin/toggle', requireAdmin, (req, res) => {
  if (!validCsrf(req, res)) return;
  const items = readAnnouncements();
  const item = items.find(entry => entry.id === req.body.id);
  if (!item) return res.status(404).send('Announcement not found.');
  const shouldEnable = req.body.enabled === 'on';
  if (shouldEnable) {
    const conflict = findAnnouncementConflict(items, item);
    if (conflict) return res.status(409).render('admin/dashboard', {
      username: req.adminSession.username, csrf: req.adminSession.csrf, announcements: items,
      editing: item, saved: false, nowNZ: nzDateTime(),
      error: 'Schedule conflict: "' + cleanText(conflict.title, 100) + '" is already scheduled during this time. Edit the schedule before publishing.'
    });
  }
  item.enabled = shouldEnable;
  writeAnnouncements(items);
  res.redirect(303, '/admin?saved=1');
});
app.post('/admin/delete', requireAdmin, (req, res) => {
  if (!validCsrf(req, res)) return;
  writeAnnouncements(readAnnouncements().filter(entry => entry.id !== req.body.id));
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

// Short, memorable link for visitors to leave an Avon Toastmasters Google review.
app.get('/review', (req, res) => res.redirect(302, 'https://search.google.com/local/writereview?placeid=ChIJm5X6pmiLMW0R_nscPejQJ5Q'));

app.get('/events.html', (req, res, next) => {
  const events = getPublicEvents();
  res.render('layout', {
    pageName: 'events',
    currentPage: 'events',
    announcement: getPublicAnnouncement(),
    events
  }, (err, html) => {
    if (err) return next(err);
    res.type('html').send(html);
  });
});

const pages = {
  '/': 'index',
  '/about.html': 'about',
  '/benefits.html': 'benefits',
  '/experience.html': 'experience',
  '/faq.html': 'faq',
  '/join.html': 'join',
  '/meetings.html': 'meetings',
  '/visit.html': 'visit',
  '/public-speaking-christchurch.html': 'public-speaking-christchurch'
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
