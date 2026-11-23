const express = require('express');
const helmet = require('helmet');
const compression = require('compression');
const nodemailer = require('nodemailer');
const path = require('path');

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
  return value.replace(/[\\u0000-\\u001f\\u007f]/g, ' ').trim().slice(0, maxLength);
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

  const emailPattern = /^[^\\s@]+@[^\\s@]+\\.[^\\s@]+$/;
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
      ].join('\\n')
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
