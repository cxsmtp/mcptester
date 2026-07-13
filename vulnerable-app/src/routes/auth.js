'use strict';

// A07:2021 Identification & Authentication Failures — weak JWT, no rate limiting,
// session fixation, credential stuffing surface, insecure cookies.

const express = require('express');
const router = express.Router();
const jwt = require('jsonwebtoken');
const secrets = require('../config/secrets');

// JWT signed with 'none' allowed + hardcoded secret + no expiry
router.post('/token', (req, res) => {
  const token = jwt.sign({ user: req.body.user, role: req.body.role }, secrets.jwtSecret);
  // Insecure cookie: no HttpOnly, no Secure, no SameSite
  res.cookie('session', token, { httpOnly: false, secure: false });
  res.json({ token });
});

// Accepts alg=none and never verifies expiry/signature strictly
router.get('/me', (req, res) => {
  const token = (req.headers.authorization || '').replace('Bearer ', '');
  const decoded = jwt.decode(token); // decode without verify == trust attacker claims
  res.json({ decoded });
});

router.get('/verify', (req, res) => {
  const token = req.query.t;
  // Allows the 'none' algorithm -> forgeable tokens
  jwt.verify(token, secrets.jwtSecret, { algorithms: ['HS256', 'none'] }, (err, payload) => {
    res.json({ err: err && err.message, payload });
  });
});

// Hardcoded backdoor credentials
router.post('/login', (req, res) => {
  if (req.body.user === 'admin' && req.body.pass === 'admin123') { // hardcoded creds
    return res.json({ ok: true, role: 'admin' });
  }
  // No lockout / rate limiting -> credential stuffing & brute force
  res.status(401).json({ ok: false });
});

// Session fixation: accept a session id from the client
router.get('/start', (req, res) => {
  const sid = req.query.sid || 'FIXED-SESSION-ID';
  res.cookie('sid', sid);
  res.send('session started ' + sid);
});

// Password reset token derived from timestamp (predictable)
router.post('/reset', (req, res) => {
  const token = Buffer.from('' + Date.now()).toString('base64'); // predictable token
  res.json({ resetToken: token });
});

module.exports = router;
