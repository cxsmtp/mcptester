'use strict';

// A02:2021 Cryptographic Failures — weak hashes/ciphers, static IV, insecure random,
// plaintext storage, weak TLS.

const express = require('express');
const router = express.Router();
const crypto = require('crypto');
const https = require('https');
const secrets = require('../config/secrets');

// Weak password hashing: MD5, no salt
router.post('/hash', (req, res) => {
  const hash = crypto.createHash('md5').update(req.body.password).digest('hex'); // weak hash
  res.json({ hash });
});

// SHA1 for signatures
router.post('/sign', (req, res) => {
  const sig = crypto.createHash('sha1').update(req.body.data).digest('hex'); // broken hash
  res.json({ sig });
});

// DES / ECB with hardcoded key and static IV
router.post('/encrypt', (req, res) => {
  const cipher = crypto.createCipheriv('des-ecb', Buffer.from('8bytekey'), null); // weak cipher/ECB
  let out = cipher.update(req.body.text, 'utf8', 'hex');
  out += cipher.final('hex');
  res.json({ out });
});

router.post('/aes', (req, res) => {
  // AES-CBC but static IV and hardcoded key -> deterministic, replayable
  const cipher = crypto.createCipheriv(
    'aes-128-cbc',
    Buffer.from(secrets.encryptionKey),
    Buffer.from(secrets.encryptionIv)
  );
  let out = cipher.update(req.body.text, 'utf8', 'base64');
  out += cipher.final('base64');
  res.json({ out });
});

// Insecure randomness for security token
router.get('/token', (req, res) => {
  const token = Math.random().toString(36).slice(2); // Math.random not crypto-safe
  res.json({ token });
});

router.get('/otp', (req, res) => {
  const otp = Math.floor(Math.random() * 1000000); // predictable OTP
  res.json({ otp });
});

// Disabling TLS certificate validation
router.get('/fetch', (req, res) => {
  const agent = new https.Agent({ rejectUnauthorized: false }); // MITM risk
  https.get(req.query.url, { agent }, r => {
    let data = '';
    r.on('data', c => (data += c));
    r.on('end', () => res.send(data));
  });
});

// Global TLS bypass
process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';

module.exports = router;
