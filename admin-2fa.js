'use strict';

const crypto = require('node:crypto');
const OTPAuth = require('otpauth');
const QRCode = require('qrcode');

function getEncryptionKey() {
  const value = process.env.ADMIN_2FA_ENCRYPTION_KEY || '';

  if (!/^[a-f0-9]{64}$/i.test(value)) {
    throw new Error('ADMIN_2FA_ENCRYPTION_KEY is missing or invalid.');
  }

  return Buffer.from(value, 'hex');
}

function encryptSecret(secret) {
  const key = getEncryptionKey();
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);

  const encrypted = Buffer.concat([
    cipher.update(secret, 'utf8'),
    cipher.final()
  ]);

  return {
    version: 1,
    iv: iv.toString('base64'),
    tag: cipher.getAuthTag().toString('base64'),
    data: encrypted.toString('base64')
  };
}

function decryptSecret(record) {
  if (!record || record.version !== 1) {
    throw new Error('Invalid encrypted authenticator secret.');
  }

  const decipher = crypto.createDecipheriv(
    'aes-256-gcm',
    getEncryptionKey(),
    Buffer.from(record.iv, 'base64')
  );

  decipher.setAuthTag(Buffer.from(record.tag, 'base64'));

  return Buffer.concat([
    decipher.update(Buffer.from(record.data, 'base64')),
    decipher.final()
  ]).toString('utf8');
}

function createTotp(username, secret) {
  return new OTPAuth.TOTP({
    issuer: 'Avon Toastmasters',
    label: username,
    algorithm: 'SHA1',
    digits: 6,
    period: 30,
    secret: OTPAuth.Secret.fromHex(secret)
  });
}

function generateAuthenticator(username) {
  const secret = crypto.randomBytes(20).toString('hex');
  const totp = createTotp(username, secret);

  return {
    secret,
    uri: totp.toString()
  };
}

async function createQrCode(uri) {
  return QRCode.toDataURL(uri, {
    errorCorrectionLevel: 'M',
    margin: 2,
    width: 260
  });
}

function verifyAuthenticator(secret, suppliedCode) {
  const code = String(suppliedCode || '').replace(/\s/g, '');

  if (!/^\d{6}$/.test(code)) return false;

  try {
    const totp = createTotp('Avon Toastmasters', secret);

    return totp.validate({
      token: code,
      window: 1
    }) !== null;
  } catch {
    return false;
  }
}

function generateRecoveryCodes(count = 10) {
  return Array.from({ length: count }, () => {
    const value = crypto.randomBytes(8).toString('hex').toUpperCase();
    return value.match(/.{1,4}/g).join('-');
  });
}

function hashRecoveryCode(code) {
  const normalized = String(code || '')
    .replace(/[^a-f0-9]/gi, '')
    .toUpperCase();

  return crypto.createHash('sha256')
    .update(normalized)
    .digest('hex');
}

function verifyRecoveryCode(code, storedHashes) {
  const supplied = Buffer.from(hashRecoveryCode(code), 'hex');

  if (!Array.isArray(storedHashes)) return -1;

  return storedHashes.findIndex(hash => {
    if (!/^[a-f0-9]{64}$/i.test(String(hash))) return false;

    const expected = Buffer.from(hash, 'hex');

    return expected.length === supplied.length &&
      crypto.timingSafeEqual(expected, supplied);
  });
}

module.exports = {
  encryptSecret,
  decryptSecret,
  generateAuthenticator,
  createQrCode,
  verifyAuthenticator,
  generateRecoveryCodes,
  hashRecoveryCode,
  verifyRecoveryCode
};
