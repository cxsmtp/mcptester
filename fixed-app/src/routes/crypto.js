'use strict';

// A02 remediated: bcrypt for passwords, AES-256-GCM with random IV, CSPRNG tokens,
// TLS verification always on.

const express = require('express');
const router = express.Router();
const crypto = require('crypto');
const bcrypt = require('bcrypt');
const https = require('https');

// Password hashing with bcrypt (adaptive, salted).
router.post('/hash', async (req, res, next) => {
  try {
    const hash = await bcrypt.hash(String(req.body.password || ''), 12);
    res.json({ hash });
  } catch (e) { next(e); }
});

// Authenticated encryption: AES-256-GCM, key from env, random per-message IV.
function getKey() {
  const b64 = process.env.ENCRYPTION_KEY_B64;
  if (!b64) throw new Error('ENCRYPTION_KEY_B64 not set');
  const key = Buffer.from(b64, 'base64');
  if (key.length !== 32) throw new Error('ENCRYPTION_KEY_B64 must decode to 32 bytes');
  return key;
}

router.post('/encrypt', (req, res, next) => {
  try {
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', getKey(), iv);
    const ct = Buffer.concat([cipher.update(String(req.body.text || ''), 'utf8'), cipher.final()]);
    const tag = cipher.getAuthTag();
    res.json({ iv: iv.toString('base64'), ct: ct.toString('base64'), tag: tag.toString('base64') });
  } catch (e) { next(e); }
});

// Cryptographically secure random tokens.
router.get('/token', (req, res) => {
  res.json({ token: crypto.randomBytes(32).toString('hex') });
});

router.get('/otp', (req, res) => {
  res.json({ otp: crypto.randomInt(0, 1000000).toString().padStart(6, '0') });
});

// Outbound HTTPS with certificate validation left ON (the default).
router.get('/fetch', (req, res, next) => {
  const url = new URL(String(req.query.url));
  if (url.protocol !== 'https:') return res.status(400).send('https only');
  https.get(url, r => {
    let data = '';
    r.on('data', c => (data += c));
    r.on('end', () => res.send(data));
  }).on('error', next);
});

module.exports = router;
