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

function cleanMultilineText(value, maxLength) {
  if (typeof value !== 'string') return '';
  return value
    .replace(/\r\n?/g, '\n')
    .replace(/[\x00-\x09\x0B-\x1F\x7F]/g, '')
    .trim()
    .slice(0, maxLength);
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
const ADMIN_SESSION_MS = 45 * 60 * 1000;
const ADMIN_TURNSTILE_SITE_KEY = '0x4AAAAAAGOdEcQMTT3VMD9-';
const adminAttempts = new Map();

const adminUsersFile=path.join(__dirname,'data','admin-users.json'),adminSettingsFile=path.join(__dirname,'data','admin-settings.json');
function readAdminUsers(){try{const v=JSON.parse(fs.readFileSync(adminUsersFile,'utf8'));return Array.isArray(v)?v:[]}catch{return[]}}
function writeAdminUsers(users){fs.mkdirSync(path.dirname(adminUsersFile),{recursive:true,mode:0o750});const t=adminUsersFile+'.tmp';fs.writeFileSync(t,JSON.stringify(users,null,2)+'\n',{mode:0o600});fs.renameSync(t,adminUsersFile)}
function readAdminSettings(){const defaults={sessionMinutes:45,maintenance:{enabled:false,title:'We’ll be back shortly',message:'We’re carrying out scheduled maintenance to improve the Avon Toastmasters website. Please check back soon.',startAt:'',endAt:''}};try{const v=JSON.parse(fs.readFileSync(adminSettingsFile,'utf8'));const m=v.maintenance&&typeof v.maintenance==='object'?v.maintenance:{};return{...defaults,...v,sessionMinutes:[30,45,60].includes(Number(v.sessionMinutes))?Number(v.sessionMinutes):45,maintenance:{...defaults.maintenance,...m,enabled:m.enabled===true,title:cleanText(m.title,100)||defaults.maintenance.title,message:cleanMultilineText(m.message,1000)||defaults.maintenance.message,startAt:typeof m.startAt==='string'?m.startAt:'',endAt:typeof m.endAt==='string'?m.endAt:''}}}catch{return defaults}}
function maintenanceStatus(){const m=readAdminSettings().maintenance,now=Date.now();if(!m.enabled)return 'disabled';if(m.startAt&&Date.parse(m.startAt)>now)return 'scheduled';if(m.endAt&&Date.parse(m.endAt)<=now)return 'ended';return 'active'}
function isMaintenanceActive(){return maintenanceStatus()==='active'}
function formatNZDateTimeInput(value){if(!value)return '';const date=new Date(value);if(Number.isNaN(date.getTime()))return '';const parts=new Intl.DateTimeFormat('en-CA',{timeZone:'Pacific/Auckland',year:'numeric',month:'2-digit',day:'2-digit',hour:'2-digit',minute:'2-digit',hourCycle:'h23'}).formatToParts(date);const p=Object.fromEntries(parts.map(x=>[x.type,x.value]));return p.year+'-'+p.month+'-'+p.day+'T'+p.hour+':'+p.minute}
function writeAdminSettings(v){fs.mkdirSync(path.dirname(adminSettingsFile),{recursive:true,mode:0o750});const t=adminSettingsFile+'.tmp';fs.writeFileSync(t,JSON.stringify(v,null,2)+'\n',{mode:0o600});fs.renameSync(t,adminSettingsFile)}
function hashAdminPassword(p){return new Promise((resolve,reject)=>{const salt=crypto.randomBytes(24);crypto.scrypt(p,salt,64,(e,d)=>e?reject(e):resolve('scrypt$'+salt.toString('hex')+'$'+d.toString('hex')))})}
function verifyPasswordHash(p,h){const a=String(h||'').split('$');if(a.length!==3||a[0]!=='scrypt'||!/^[a-f0-9]{32,}$/.test(a[1])||!/^[a-f0-9]{128}$/.test(a[2]))return Promise.resolve(false);return new Promise((resolve,reject)=>crypto.scrypt(p,Buffer.from(a[1],'hex'),64,(e,d)=>{if(e)return reject(e);const x=Buffer.from(a[2],'hex');resolve(d.length===x.length&&crypto.timingSafeEqual(d,x))}))}
function ensureInitialAdmin(){if(fs.existsSync(adminUsersFile))return;const username=cleanText(process.env.ADMIN_USERNAME||'webmaster',80),passwordHash=process.env.ADMIN_PASSWORD_HASH||'';if(username&&passwordHash)writeAdminUsers([{id:crypto.randomUUID(),username,passwordHash,role:'administrator',enabled:true,createdAt:new Date().toISOString(),updatedAt:new Date().toISOString(),sessionVersion:1}])}
ensureInitialAdmin();

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
function slugifyEvent(value) {
  return String(value || '')
    .normalize('NFKD')
    .replace(/[\u0300-\u036f]/g, '')
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 80)
    .replace(/-+$/g, '');
}

function eventSlug(item) {
  return item.slug || slugifyEvent(item.title) || item.id;
}

function eventUrl(item) {
  return 'https://toastmasters.net.nz/events/' + encodeURIComponent(eventSlug(item));
}

function escapeXml(value) {
  return String(value || '').replace(/[&<>"']/g, character => ({
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&apos;'
  })[character]);
}

function eventEndDateTime(item) {
  return (item.date || '9999-12-31') + 'T' + (item.endTime || '23:59');
}

function eventHasFinished(item, now = nzDateTime()) {
  return eventEndDateTime(item) <= now;
}

function getPublicEvents() {
  const now = nzDateTime();
  return readEvents()
    .filter(item =>
      item.enabled === true &&
      item.title &&
      item.description &&
      item.date &&
      !eventHasFinished(item, now)
    )
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
function createAdminToken(p){const body=Buffer.from(JSON.stringify(p)).toString('base64url');const sig=crypto.createHmac('sha256',process.env.ADMIN_SESSION_SECRET).update(body).digest('base64url');return body+'.'+sig}
function getAdminSession(req){const t=getCookie(req,ADMIN_COOKIE),i=t.lastIndexOf('.');if(i<1||!process.env.ADMIN_SESSION_SECRET)return null;const b=t.slice(0,i),s=Buffer.from(t.slice(i+1)),e=Buffer.from(crypto.createHmac('sha256',process.env.ADMIN_SESSION_SECRET).update(b).digest('base64url'));if(s.length!==e.length||!crypto.timingSafeEqual(s,e))return null;try{const p=JSON.parse(Buffer.from(b,'base64url').toString('utf8'));if(!p||p.expiresAt<=Date.now()||!p.userId||!p.csrf)return null;const u=readAdminUsers().find(x=>x.id===p.userId&&x.enabled&&Number(x.sessionVersion||1)===Number(p.sessionVersion));return u?{...p,username:u.username,role:u.role}:null}catch{return null}}
function setAdminCookie(res,p){const value=ADMIN_COOKIE+'='+createAdminToken(p)+'; HttpOnly; Secure; SameSite=Strict; Max-Age='+(readAdminSettings().sessionMinutes*60);res.setHeader('Set-Cookie',[value+'; Path=/',''+ADMIN_COOKIE+'=; Path=/admin; HttpOnly; Secure; SameSite=Strict; Max-Age=0'])}
function clearAdminCookie(res){res.setHeader('Set-Cookie',[ADMIN_COOKIE+'=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0',ADMIN_COOKIE+'=; Path=/admin; HttpOnly; Secure; SameSite=Strict; Max-Age=0'])}
function adminReady(){ensureInitialAdmin();return Boolean(readAdminUsers().some(x=>x.enabled&&x.role==='administrator')&&process.env.ADMIN_SESSION_SECRET&&process.env.ADMIN_SESSION_SECRET.length>=32)}
function requireAdmin(req,res,next){const session=req.adminSession||getAdminSession(req);if(!session){let back='/admin';if(req.method==='GET')back=safeAdminReturnPath(req.originalUrl);else{try{const u=new URL(req.get('referer')||'');if(u.host===req.get('host'))back=safeAdminReturnPath(u.pathname+u.search)}catch{}}return res.redirect(303,'/admin?next='+encodeURIComponent(back))}req.adminSession=session;next()}
function requireAdministrator(req,res,next){requireAdmin(req,res,()=>{if(req.adminSession.role!=='administrator')return res.status(403).send('Administrator access is required for this page.');next()})}
function validCsrf(req,res){const p=req.adminSession||getAdminSession(req);if(!p||typeof req.body.csrf!=='string'||req.body.csrf!==p.csrf){res.status(403).send('Your session expired. Please sign in again.');return false}return true}
function safeAnnouncementLink(value){const link=cleanText(value,500);if(!link)return '';if(link.startsWith('/')&&!link.startsWith('//')&&!link.includes('\\'))return link;try{const u=new URL(link);return u.protocol==='https:'?u.toString():null}catch{return null}}
async function verifyAdminTurnstile(token, remoteIp) {
  const secret = process.env.TURNSTILE_SECRET_KEY;
  if (!secret || !(process.env.TURNSTILE_SITE_KEY || ADMIN_TURNSTILE_SITE_KEY) || !token) return false;
  const body = new URLSearchParams({ secret, response: token });
  if (remoteIp) body.set('remoteip', remoteIp);
  try {
    const response = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
      method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body, signal: AbortSignal.timeout(8000)
    });
    if (!response.ok) return false;
    const result = await response.json();
    return result.success === true && result.action === 'admin_login' &&
      ['toastmasters.net.nz', 'www.toastmasters.net.nz'].includes(result.hostname);
  } catch (error) {
    console.error('Admin Turnstile verification failed:', error.message);
    return false;
  }
}


const adminRecoveryAttempts = new Map();

async function verifyAdminRecoveryTurnstile(token, remoteIp) {
  const secret = process.env.TURNSTILE_SECRET_KEY;
  if (!secret || !(process.env.TURNSTILE_SITE_KEY || ADMIN_TURNSTILE_SITE_KEY) || !token) return false;
  const body = new URLSearchParams({ secret, response: token });
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
    return result.success === true && result.action === 'admin_recovery' &&
      ['toastmasters.net.nz', 'www.toastmasters.net.nz'].includes(result.hostname);
  } catch (error) {
    console.error('Admin recovery Turnstile verification failed:', error.message);
    return false;
  }
}

function limitAdminRecovery(ip) {
  const now = Date.now();
  const key = String(ip || 'unknown').slice(0, 100);
  const record = adminRecoveryAttempts.get(key);
  if (record && now - record.startedAt < 15 * 60 * 1000) {
    if (record.count >= 3) return false;
    record.count++;
    return true;
  }
  adminRecoveryAttempts.set(key, { startedAt: now, count: 1 });
  if (adminRecoveryAttempts.size > 1000) {
    for (const [k, v] of adminRecoveryAttempts) {
      if (now - v.startedAt >= 15 * 60 * 1000) adminRecoveryAttempts.delete(k);
    }
  }
  return true;
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
  if (isMaintenanceActive()) return res.set('Retry-After','3600').status(503).type('text/plain').send('Website temporarily unavailable for scheduled maintenance.');
  res.type('text/plain').sendFile(path.join(__dirname, 'robots.txt'));
});

app.get('/sitemap.xml', (req, res) => {
  if (isMaintenanceActive()) return res.set('Retry-After','3600').status(503).type('text/plain').send('Sitemap temporarily unavailable during maintenance.');
  try {
    const sitemapFile = path.join(__dirname, 'sitemap.xml');
    let xml = fs.readFileSync(sitemapFile, 'utf8');

    const eventUrls = getPublicEvents().map(item => {
      const lastmod = item.updatedAt
        ? String(item.updatedAt).slice(0, 10)
        : item.date;

      return [
        '  <url>',
        `    <loc>${escapeXml(eventUrl(item))}</loc>`,
        `    <lastmod>${escapeXml(lastmod)}</lastmod>`,
        '    <changefreq>weekly</changefreq>',
        '    <priority>0.6</priority>',
        '  </url>'
      ].join('\n');
    });

    if (eventUrls.length && xml.includes('</urlset>')) {
      xml = xml.replace('</urlset>', eventUrls.join('\n') + '\n</urlset>');
    }

    res.set('Cache-Control', 'no-store');
    res.type('application/xml').send(xml);
  } catch (error) {
    console.error('Sitemap generation failed:', error);
    res.status(500).type('text/plain').send('Unable to generate sitemap.');
  }
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
  if (isMaintenanceActive()) return res.status(503).json({ success:false, message:'The website is temporarily unavailable for maintenance. Please try again later.' });
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
  res.locals.adminSessionMinutes = readAdminSettings().sessionMinutes;
  next();
});
app.use('/admin', (req,res,next)=>{const session=getAdminSession(req);if(session){session.expiresAt=Date.now()+readAdminSettings().sessionMinutes*60000;setAdminCookie(res,session);req.adminSession=session;res.locals.adminUserKey=session.userId;const path=req.originalUrl.split('?')[0];if(readAdminUsers().some(u=>u.id===session.userId&&u.mustChangePassword)&&!['/admin/first-login','/admin/logout'].includes(path))return res.redirect(303,'/admin/first-login')}next()});

function renderAdminForgotPassword(res, status = 200, error = '', sent = false) {
  return res.status(status).render('admin/forgot-password', {
    error,
    sent,
    turnstileSiteKey: process.env.TURNSTILE_SITE_KEY || ADMIN_TURNSTILE_SITE_KEY || ''
  });
}

function findAdminResetUser(token, users) {
  if (typeof token !== 'string' || token.length < 32 || token.length > 200) return null;
  const supplied = crypto.createHash('sha256').update(token).digest();
  for (const user of users) {
    const stored = user.resetTokenHash;
    if (!/^[a-f0-9]{64}$/i.test(String(stored || ''))) continue;
    const expected = Buffer.from(stored, 'hex');
    if (expected.length === supplied.length &&
        crypto.timingSafeEqual(expected, supplied) &&
        Number(user.resetTokenExpiresAt) > Date.now() &&
        user.enabled) return user;
  }
  return null;
}

app.get('/admin/forgot-password', (req, res) => {
  renderAdminForgotPassword(res);
});

app.post('/admin/forgot-password', async (req, res) => {
  const ip = req.ip || req.socket.remoteAddress || 'unknown';

  if (!limitAdminRecovery(ip)) {
    return renderAdminForgotPassword(res, 200, '', true);
  }

  const challenge = cleanText(req.body['cf-turnstile-response'], 4096);
  if (!await verifyAdminRecoveryTurnstile(challenge, ip)) {
    return renderAdminForgotPassword(res, 400, 'Please complete the security check and try again.');
  }

  const email = cleanText(req.body.email, 254).toLowerCase();
  const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

  if (!emailPattern.test(email)) {
    return renderAdminForgotPassword(res, 400, 'Please enter a valid email address.');
  }

  if (emailPattern.test(email)) {
    const users = readAdminUsers();
    const user = users.find(u =>
      u.enabled && String(u.email || '').toLowerCase() === email
    );

    if (user) {
      const token = crypto.randomBytes(32).toString('base64url');
      user.resetTokenHash = crypto.createHash('sha256').update(token).digest('hex');
      user.resetTokenExpiresAt = Date.now() + 30 * 60 * 1000;
      writeAdminUsers(users);

      const smtpUser = process.env.SMTP_USER;
      const smtpPass = process.env.SMTP_PASS;

      if (smtpUser && smtpPass) {
        let transporter;
        try {
          transporter = nodemailer.createTransport({
            host: process.env.SMTP_HOST || 'smtp.fastmail.com',
            port: Number(process.env.SMTP_PORT || 465),
            secure: true,
            auth: { user: smtpUser, pass: smtpPass },
            connectionTimeout: 10000,
            greetingTimeout: 10000,
            socketTimeout: 15000
          });

          const resetUrl = 'https://toastmasters.net.nz/admin/reset-password?token=' +
            encodeURIComponent(token);

          await transporter.sendMail({
            from: { name: 'Avon Toastmasters Website', address: 'noreply@toastmasters.net.nz' },
            to: user.email,
            subject: 'Reset your Avon Toastmasters website password',
            text: [
              'A password reset was requested for your Avon Toastmasters website administrator account.',
              '',
              'Use the following link to choose a new password:',
              resetUrl,
              '',
              'This link expires in 30 minutes and can only be used once.',
              'If you did not request this reset, you can safely ignore this email.',
              '',
              'For security, no password is included in this email.'
            ].join('\n')
          });
        } catch (error) {
          console.error('Admin password recovery email failed:', error.message);
          delete user.resetTokenHash;
          delete user.resetTokenExpiresAt;
          writeAdminUsers(users);
        } finally {
          if (transporter) {
            try { transporter.close(); } catch {}
          }
        }
      } else {
        console.error('Admin password recovery unavailable: SMTP credentials are not configured.');
        delete user.resetTokenHash;
        delete user.resetTokenExpiresAt;
        writeAdminUsers(users);
      }
    }
  }

  // Identical response for existing and non-existing email addresses.
  return renderAdminForgotPassword(res, 200, '', true);
});

app.get('/admin/reset-password', (req, res) => {
  const token = typeof req.query.token === 'string' ? req.query.token : '';
  const user = findAdminResetUser(token, readAdminUsers());

  if (!user) {
    return res.status(400).render('admin/reset-password', {
      token: '',
      error: 'This password reset link is invalid or has expired. Please request a new one.',
      invalid: true
    });
  }

  return res.render('admin/reset-password', {
    token,
    error: '',
    invalid: false
  });
});

app.post('/admin/reset-password', async (req, res) => {
  const token = typeof req.body.token === 'string' ? req.body.token : '';
  const users = readAdminUsers();
  const user = findAdminResetUser(token, users);

  const fail = message => res.status(400).render('admin/reset-password', {
    token: user ? token : '',
    error: message,
    invalid: !user
  });

  if (!user) {
    return fail('This password reset link is invalid or has expired. Please request a new one.');
  }

  const password = typeof req.body.newPassword === 'string' ? req.body.newPassword : '';
  const confirmation = typeof req.body.confirmPassword === 'string' ? req.body.confirmPassword : '';

  if (password.length < 12) {
    return fail('Your new password must be at least 12 characters long.');
  }
  if (password !== confirmation) {
    return fail('The new passwords do not match.');
  }

  user.passwordHash = await hashAdminPassword(password);
  user.sessionVersion = Number(user.sessionVersion || 1) + 1;
  user.updatedAt = new Date().toISOString();
  delete user.resetTokenHash;
  delete user.resetTokenExpiresAt;
  writeAdminUsers(users);

  return res.redirect(303, '/admin?reset=1');
});

function safeAdminReturnPath(value) {
  const candidate = typeof value === 'string' ? value : '';
  return (candidate === '/admin' || candidate.startsWith('/admin?') || candidate.startsWith('/admin/')) && !candidate.startsWith('//') && !candidate.includes('\\') && !candidate.startsWith('/admin/login') ? candidate : '/admin';
}

app.get('/admin',(req,res)=>{if(!adminReady())return res.status(503).send('Admin accounts are not configured. Check the initial administrator environment settings.');const u=req.adminSession||getAdminSession(req);if(!u)return res.render('admin/login',{error:'',next:safeAdminReturnPath(req.query.next),turnstileSiteKey:process.env.TURNSTILE_SITE_KEY||'',resetSuccess:req.query.reset==='1'});res.render('admin/dashboard-home',{username:u.username,role:u.role,csrf:u.csrf,announcementCount:expireAnnouncements(readAnnouncements()).length,eventCount:readEvents().length,mediaCount:listMediaFiles().length,userCount:u.role==='administrator'?readAdminUsers().length:null,maintenanceStatus:maintenanceStatus()})});
app.get('/admin/announcements',requireAdmin,(req,res)=>{const u=req.adminSession,announcements=expireAnnouncements(readAnnouncements());res.render('admin/dashboard',{username:u.username,role:u.role,csrf:u.csrf,announcements,editing:announcements.find(x=>x.id===req.query.edit)||null,saved:req.query.saved==='1',uploadedImage:safeAnnouncementImage(req.query.image),nowNZ:nzDateTime(),error:''})});

app.get('/admin/account',requireAdmin,(req,res)=>res.render('admin/account',{username:req.adminSession.username,role:req.adminSession.role,csrf:req.adminSession.csrf,saved:req.query.saved==='1',error:''}));
app.post('/admin/account/password',requireAdmin,async(req,res)=>{if(!validCsrf(req,res))return;const users=readAdminUsers(),u=users.find(x=>x.id===req.adminSession.userId),cur=typeof req.body.currentPassword==='string'?req.body.currentPassword:'',pw=typeof req.body.newPassword==='string'?req.body.newPassword:'',confirm=typeof req.body.confirmPassword==='string'?req.body.confirmPassword:'';const fail=error=>res.status(400).render('admin/account',{username:req.adminSession.username,role:req.adminSession.role,csrf:req.adminSession.csrf,saved:false,error});if(!u||!await verifyPasswordHash(cur,u.passwordHash))return fail('Your current password was incorrect.');if(pw.length<12)return fail('Your new password must be at least 12 characters long.');if(pw!==confirm)return fail('The new passwords do not match.');u.passwordHash=await hashAdminPassword(pw);u.sessionVersion=Number(u.sessionVersion||1)+1;u.updatedAt=new Date().toISOString();writeAdminUsers(users);clearAdminCookie(res);res.redirect(303,'/admin')});
app.get('/admin/users',requireAdministrator,(req,res)=>res.render('admin/users',{username:req.adminSession.username,role:req.adminSession.role,csrf:req.adminSession.csrf,users:readAdminUsers().sort((a,b)=>a.createdAt.localeCompare(b.createdAt)),error:'',saved:req.query.saved==='1'}));
app.post('/admin/users/create',requireAdministrator,async(req,res)=>{if(!validCsrf(req,res))return;const username=cleanText(req.body.username,40),email=cleanText(req.body.email,254).toLowerCase(),password=typeof req.body.password==='string'?req.body.password:'',role=req.body.role==='administrator'?'administrator':'editor',users=readAdminUsers(),fail=error=>res.status(400).render('admin/users',{username:req.adminSession.username,role:req.adminSession.role,csrf:req.adminSession.csrf,users,error,saved:false});if(!/^[a-zA-Z0-9._-]{3,40}$/.test(username))return fail('Usernames must be 3–40 characters and use letters, numbers, dots, underscores or hyphens.');if(users.some(x=>x.username.toLowerCase()===username.toLowerCase()))return fail('That username is already in use.');if(email&&!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))return fail('Enter a valid email address or leave the field blank.');if(email&&users.some(x=>String(x.email||'').toLowerCase()===email))return fail('That email address is already in use.');if(password.length<12)return fail('Passwords must be at least 12 characters long.');users.push({id:crypto.randomUUID(),username,email,passwordHash:await hashAdminPassword(password),role,enabled:true,mustChangePassword:true,createdAt:new Date().toISOString(),updatedAt:new Date().toISOString(),sessionVersion:1});writeAdminUsers(users);res.redirect(303,'/admin/users?saved=1')});
app.post('/admin/users/update',requireAdministrator,(req,res)=>{if(!validCsrf(req,res))return;const users=readAdminUsers(),u=users.find(x=>x.id===req.body.id);if(!u)return res.status(404).send('Account not found.');if(String(u.username||'').toLowerCase()==='webmaster')return res.status(403).send('The protected webmaster account cannot be changed here.');const role=req.body.role==='administrator'?'administrator':'editor',enabled=req.body.enabled==='on';if(u.id===req.adminSession.userId&&(!enabled||role!=='administrator'))return res.status(400).send('You cannot disable or demote your own administrator account.');if(u.role==='administrator'&&u.enabled&&(!enabled||role!=='administrator')&&users.filter(x=>x.role==='administrator'&&x.enabled).length<=1)return res.status(400).send('The last active administrator cannot be disabled or demoted.');u.role=role;u.enabled=enabled;u.sessionVersion=Number(u.sessionVersion||1)+1;u.updatedAt=new Date().toISOString();writeAdminUsers(users);res.redirect(303,'/admin/users?saved=1')});
app.post('/admin/users/password',requireAdministrator,async(req,res)=>{if(!validCsrf(req,res))return;const users=readAdminUsers(),u=users.find(x=>x.id===req.body.id),pw=typeof req.body.newPassword==='string'?req.body.newPassword:'';if(!u)return res.status(404).send('Account not found.');if(String(u.username||'').toLowerCase()==='webmaster')return res.status(403).send('The protected webmaster account password cannot be reset by another administrator.');if(pw.length<12)return res.status(400).send('Passwords must be at least 12 characters long.');u.passwordHash=await hashAdminPassword(pw);u.sessionVersion=Number(u.sessionVersion||1)+1;u.updatedAt=new Date().toISOString();writeAdminUsers(users);res.redirect(303,'/admin/users?saved=1')});
app.post('/admin/users/delete',requireAdministrator,(req,res)=>{if(!validCsrf(req,res))return;const users=readAdminUsers(),u=users.find(x=>x.id===req.body.id);if(!u)return res.status(404).send('Account not found.');if(String(u.username||'').toLowerCase()==='webmaster')return res.status(403).send('The protected webmaster account cannot be removed.');if(u.id===req.adminSession.userId)return res.status(400).send('You cannot remove your own account.');if(u.role==='administrator'&&u.enabled&&users.filter(x=>x.role==='administrator'&&x.enabled).length<=1)return res.status(400).send('The last active administrator cannot be removed.');writeAdminUsers(users.filter(x=>x.id!==u.id));res.redirect(303,'/admin/users?saved=1')});
app.get('/admin/settings',requireAdministrator,(req,res)=>res.render('admin/settings',{username:req.adminSession.username,role:req.adminSession.role,csrf:req.adminSession.csrf,settings:readAdminSettings(),saved:req.query.saved==='1'}));
app.post('/admin/settings',requireAdministrator,(req,res)=>{if(!validCsrf(req,res))return;const sessionMinutes=[30,45,60].includes(Number(req.body.sessionMinutes))?Number(req.body.sessionMinutes):45;writeAdminSettings({...readAdminSettings(),sessionMinutes});res.redirect(303,'/admin/settings?saved=1')});
app.get('/admin/maintenance',requireAdministrator,(req,res)=>{const settings=readAdminSettings().maintenance;res.render('admin/maintenance',{username:req.adminSession.username,role:req.adminSession.role,csrf:req.adminSession.csrf,maintenance:settings,status:maintenanceStatus(),startInput:formatNZDateTimeInput(settings.startAt),endInput:formatNZDateTimeInput(settings.endAt),saved:req.query.saved==='1',error:''})});
app.post('/admin/maintenance',requireAdministrator,(req,res)=>{if(!validCsrf(req,res))return;const old=readAdminSettings(),enabled=req.body.enabled==='on',title=cleanText(req.body.title,100)||'We’ll be back shortly',message=cleanMultilineText(req.body.message,1000)||'We’re carrying out scheduled maintenance to improve the Avon Toastmasters website. Please check back soon.',startValue=cleanText(req.body.startAt,16),endValue=cleanText(req.body.endAt,16);const parseLocal=value=>{if(!value)return '';if(!/^\d{4}-\d{2}-\d{2}T(?:[01]\d|2[0-3]):[0-5]\d$/.test(value))throw new Error('Enter valid New Zealand date and time values.');const [date,time]=value.split('T');return eventLocalDateTimeToUtc(date,time).toISOString()};let startAt='',endAt='';try{startAt=parseLocal(startValue);endAt=parseLocal(endValue)}catch(error){return res.status(400).render('admin/maintenance',{username:req.adminSession.username,role:req.adminSession.role,csrf:req.adminSession.csrf,maintenance:{...old.maintenance,enabled,title,message},status:maintenanceStatus(),startInput:startValue,endInput:endValue,saved:false,error:error.message})}if(startAt&&endAt&&Date.parse(endAt)<=Date.parse(startAt))return res.status(400).render('admin/maintenance',{username:req.adminSession.username,role:req.adminSession.role,csrf:req.adminSession.csrf,maintenance:{...old.maintenance,enabled,title,message},status:maintenanceStatus(),startInput:startValue,endInput:endValue,saved:false,error:'The maintenance end time must be after the start time.'});writeAdminSettings({...old,maintenance:{enabled,title,message,startAt,endAt,updatedAt:new Date().toISOString(),updatedBy:req.adminSession.username}});res.redirect(303,'/admin/maintenance?saved=1')});
app.get('/admin/activity', requireAdmin, (req, res) => {
  res.json({ ok: true, expiresAt: req.adminSession.expiresAt });
});

app.get('/admin/events', requireAdmin, (req, res) => {
  const events = readEvents().sort((a, b) => eventDateTime(a).localeCompare(eventDateTime(b)));
  res.render('admin/events', {
    username: req.adminSession.username,
    role: req.adminSession.role,
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
  const requestedSlug = cleanText(req.body.slug, 80);
  const slug = slugifyEvent(requestedSlug || title);
  const description = cleanMultilineText(req.body.description, 2000);
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
  if (!slug || slug.length < 3 || !/^[a-z0-9]+(?:-[a-z0-9]+)*$/.test(slug)) return res.status(400).send('Please enter a valid event URL using letters, numbers and hyphens.');
  if (items.some(entry => entry.id !== id && eventSlug(entry) === slug)) return res.status(400).send('That event URL is already in use. Please choose a different custom URL.');
  if (!validDate(date) || !timePattern.test(startTime) || (endTime && !timePattern.test(endTime))) return res.status(400).send('Please enter a valid New Zealand event date and time.');
  if (endTime && endTime <= startTime) return res.status(400).send('The event end time must be later than its start time.');
  if (!location) return res.status(400).send('Please enter an event location.');
  if (bookingLink === null) return res.status(400).send('Use a local page path or a secure https:// booking link.');
  const item = { id, slug, enabled: req.body.enabled === 'on', title, description, category, date, startTime, endTime, location, bookingLink, imageUrl, updatedAt: new Date().toISOString() };
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


app.get('/admin/first-login',(req,res)=>{
  const session=req.adminSession;
  if(!session)return res.redirect(303,'/admin');
  const user=readAdminUsers().find(x=>x.id===session.userId);
  if(!user||!user.mustChangePassword)return res.redirect(303,'/admin');
  res.render('admin/first-login',{username:user.username,csrf:session.csrf,error:''});
});

app.post('/admin/first-login',async(req,res)=>{
  const session=req.adminSession;
  if(!session)return res.redirect(303,'/admin');
  if(!validCsrf(req,res))return;

  const users=readAdminUsers();
  const user=users.find(x=>x.id===session.userId);
  const email=cleanText(req.body.email,254).toLowerCase();
  const password=typeof req.body.newPassword==='string'?req.body.newPassword:'';
  const confirm=typeof req.body.confirmPassword==='string'?req.body.confirmPassword:'';

  const fail=error=>res.status(400).render('admin/first-login',{
    username:session.username,csrf:session.csrf,error
  });

  if(!user||!user.mustChangePassword)return res.redirect(303,'/admin');
  if(!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))return fail('Enter a valid email address.');
  if(users.some(x=>x.id!==user.id&&String(x.email||'').toLowerCase()===email))
    return fail('That email address is already in use.');
  if(password.length<12)return fail('Your new password must be at least 12 characters long.');
  if(password!==confirm)return fail('The passwords do not match.');

  user.email=email;
  user.passwordHash=await hashAdminPassword(password);
  user.mustChangePassword=false;
  user.sessionVersion=Number(user.sessionVersion||1)+1;
  user.updatedAt=new Date().toISOString();

  writeAdminUsers(users);
  clearAdminCookie(res);
  res.redirect(303,'/admin');
});

app.post('/admin/login',async(req,res)=>{if(!adminReady())return res.status(503).send('Admin accounts are not configured. Check the initial administrator environment settings.');const ip=req.ip||req.socket.remoteAddress||'unknown',next=safeAdminReturnPath(req.body.next),render=(status,error)=>res.status(status).render('admin/login',{error,next,turnstileSiteKey:process.env.TURNSTILE_SITE_KEY||''});if(!limitAdminLogin(ip))return render(429,'Too many sign-in attempts. Please wait 15 minutes and try again.');if(!await verifyAdminTurnstile(cleanText(req.body['cf-turnstile-response'],4096),ip))return render(400,'Please complete the security check and try again.');const username=cleanText(req.body.username,254),password=typeof req.body.password==='string'?req.body.password:'',user=readAdminUsers().find(x=>x.enabled&&(x.username.toLowerCase()===username.toLowerCase()||(x.email&&x.email.toLowerCase()===username.toLowerCase())));let ok=false;try{ok=Boolean(user&&await verifyPasswordHash(password,user.passwordHash))}catch(e){console.error('Admin password verification failed:',e.message)}if(!user||!ok)return render(401,'The username or password was incorrect.');adminAttempts.delete(ip);const csrf=crypto.randomBytes(24).toString('hex'),minutes=readAdminSettings().sessionMinutes;setAdminCookie(res,{userId:user.id,username:user.username,role:user.role,sessionVersion:Number(user.sessionVersion||1),csrf,expiresAt:Date.now()+minutes*60000});res.redirect(303,user.mustChangePassword?'/admin/first-login':next)});



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
    role: req.adminSession.role,
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
    return res.redirect(303, '/admin/announcements?image=' + encodeURIComponent(imageUrl));
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
      username: req.adminSession.username, role: req.adminSession.role, csrf: req.adminSession.csrf, announcements: items,
      editing: item, saved: false, nowNZ: nzDateTime(),
      error: 'Schedule conflict: "' + cleanText(conflict.title, 100) + '" is already scheduled during this time. Change the start or end date/time before saving.'
    });
  }
  if (index >= 0) items[index] = item; else items.unshift(item);
  writeAnnouncements(items);
  res.redirect(303, '/admin/announcements?saved=1');
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
  res.redirect(303, '/admin/announcements?saved=1');
});
app.post('/admin/delete', requireAdmin, (req, res) => {
  if (!validCsrf(req, res)) return;
  writeAnnouncements(readAnnouncements().filter(entry => entry.id !== req.body.id));
  res.redirect(303, '/admin/announcements?saved=1');
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

// Public maintenance gate. Static assets and admin routes remain available; authenticated
// administrators can browse the real site while everyone else receives HTTP 503.
app.use((req,res,next)=>{
  if(!isMaintenanceActive())return next();
  if(req.path==='/health'||req.path==='/healthz'||req.path.startsWith('/admin'))return next();
  const session=getAdminSession(req);
  if(session){res.locals.maintenancePreview=true;return next();}
  const maintenance=readAdminSettings().maintenance;
  res.set('Retry-After','3600').set('X-Robots-Tag','noindex, nofollow').set('Cache-Control','no-store');
  if(req.path.startsWith('/api/'))return res.status(503).json({success:false,message:'The website is temporarily unavailable for maintenance.'});
  if(req.method!=='GET'&&req.method!=='HEAD')return res.status(503).type('text/plain').send('The website is temporarily unavailable for maintenance.');
  return res.status(503).render('maintenance',{maintenance});
});

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


function eventLocalDateTimeToUtc(dateValue, timeValue) {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(String(dateValue || '')) ||
      !/^\d{2}:\d{2}$/.test(String(timeValue || ''))) {
    throw new Error('Invalid event date or time');
  }

  const [year, month, day] = dateValue.split('-').map(Number);
  const [hour, minute] = timeValue.split(':').map(Number);

  if (month < 1 || month > 12 || day < 1 || day > 31 ||
      hour > 23 || minute > 59) {
    throw new Error('Invalid event date or time');
  }

  const target = Date.UTC(year, month - 1, day, hour, minute);
  const formatter = new Intl.DateTimeFormat('en-NZ', {
    timeZone: 'Pacific/Auckland',
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hourCycle: 'h23'
  });

  let result = target;

  for (let i = 0; i < 3; i++) {
    const parts = Object.fromEntries(
      formatter.formatToParts(new Date(result))
        .filter(part => part.type !== 'literal')
        .map(part => [part.type, Number(part.value)])
    );

    const representedAsUtc = Date.UTC(
      parts.year, parts.month - 1, parts.day,
      parts.hour, parts.minute, parts.second
    );

    result = target - (representedAsUtc - result);
  }

  return new Date(result);
}

function getEventCalendarTimes(event) {
  const start = eventLocalDateTimeToUtc(event.date, event.startTime || '19:00');
  const end = event.endTime
    ? eventLocalDateTimeToUtc(event.date, event.endTime)
    : new Date(start.getTime() + 90 * 60 * 1000);

  if (end <= start) throw new Error('Event end time must be after its start time');

  return { start, end };
}

function calendarUtcDate(date) {
  return date.toISOString().replace(/[-:]/g, '').replace(/\.\d{3}/, '');
}

function escapeCalendarText(value) {
  return String(value || '')
    .replace(/\\/g, '\\\\')
    .replace(/\r?\n/g, '\\n')
    .replace(/,/g, '\\,')
    .replace(/;/g, '\\;');
}

function makeGoogleCalendarUrl(event) {
  const { start, end } = getEventCalendarTimes(event);
  const params = new URLSearchParams({
    action: 'TEMPLATE',
    text: event.title,
    dates: calendarUtcDate(start) + '/' + calendarUtcDate(end),
    details: String(event.description || '') + '\n\nEvent information: ' + eventUrl(event),
    location: event.location || 'St Albans Community Centre, Christchurch',
    ctz: 'Pacific/Auckland'
  });

  return 'https://calendar.google.com/calendar/render?' + params.toString();
}

function makeEventIcs(event) {
  const { start, end } = getEventCalendarTimes(event);
  const uid = (event.id || eventSlug(event)) + '@toastmasters.net.nz';
  const description = String(event.description || '') +
    '\n\nEvent information: ' + eventUrl(event);

  const lines = [
    'BEGIN:VCALENDAR',
    'VERSION:2.0',
    'PRODID:-//Avon Toastmasters//Event Calendar//EN',
    'CALSCALE:GREGORIAN',
    'METHOD:PUBLISH',
    'BEGIN:VEVENT',
    'UID:' + escapeCalendarText(uid),
    'DTSTAMP:' + calendarUtcDate(new Date()),
    'DTSTART:' + calendarUtcDate(start),
    'DTEND:' + calendarUtcDate(end),
    'SUMMARY:' + escapeCalendarText(event.title),
    'DESCRIPTION:' + escapeCalendarText(description),
    'LOCATION:' + escapeCalendarText(event.location || ''),
    'URL:' + eventUrl(event),
    'END:VEVENT',
    'END:VCALENDAR'
  ];

  return lines.join('\r\n') + '\r\n';
}

app.get('/events/:slug/calendar.ics', (req, res) => {
  const requestedSlug = String(req.params.slug || '');
  const event = getPublicEvents().find(item =>
    eventSlug(item) === requestedSlug
  );

  if (!event) {
    return res.status(404).send('This event could not be found.');
  }

  try {
    const filename = eventSlug(event) + '.ics';
    const calendar = makeEventIcs(event);

    res.set({
      'Content-Type': 'text/calendar; charset=utf-8',
      'Content-Disposition': 'attachment; filename="' + filename + '"',
      'Cache-Control': 'no-store'
    });

    return res.send(calendar);
  } catch (error) {
    console.error('Unable to generate event calendar file:', error);
    return res.status(400).send('This event does not have valid calendar date and time details.');
  }
});

app.get('/events/:slug', (req, res, next) => {
  const requestedSlug = String(req.params.slug || '');

  const event = getPublicEvents().find(item =>
    eventSlug(item) === requestedSlug
  );

  if (!event) {
    return res.status(404).send('This event could not be found. It may have been unpublished or removed.');
  }

  const categoryLabels = {
    competition: 'Speech competition',
    'open-house': 'Open house',
    workshop: 'Workshop',
    social: 'Club social',
    special: 'Special event',
    other: 'Club event'
  };

  const eventUrlValue = eventUrl(event);
  const descriptionParagraphs = String(event.description || '')
    .split(/\n{2,}/)
    .map(paragraph => paragraph.trim())
    .filter(Boolean);

  res.render('layout', {
    pageName: 'event',
    currentPage: 'events',
    announcement: getPublicAnnouncement(),
    event,
    eventUrl: eventUrlValue,
    googleCalendarUrl: makeGoogleCalendarUrl(event),
    calendarDownloadUrl: '/events/' + encodeURIComponent(eventSlug(event)) + '/calendar.ics',
    categoryLabel: categoryLabels[event.category] || 'Club event',
    descriptionParagraphs
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
