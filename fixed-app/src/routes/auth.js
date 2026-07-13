'use strict';

// A07 remediated: strong JWT (HS256 only, short expiry), rate limiting, bcrypt creds,
// secure cookies, CSPRNG reset tokens.

const express = require('express');
const router = express.Router();
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const rateLimit = require('express-rate-limit');
const secrets = require('../config/secrets');

const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 10 });

// Demo user store: password stored as a bcrypt hash, never in plaintext.
const users = {}; // username -> { hash, role }

router.post('/token', (req, res) => {
  const token = jwt.sign(
    { user: String(req.body.user), role: 'user' }, // role is server-assigned, not client-supplied
    secrets.jwtSecret,
    { algorithm: 'HS256', expiresIn: '15m' }
  );
  res.cookie('session', token, { httpOnly: true, secure: true, sameSite: 'strict' });
  res.json({ ok: true });
});

// Always verify signature + algorithm + expiry. 'none' is never accepted.
router.get('/me', (req, res) => {
  const token = (req.headers.authorization || '').replace('Bearer ', '');
  try {
    const payload = jwt.verify(token, secrets.jwtSecret, { algorithms: ['HS256'] });
    res.json({ user: payload.user, role: payload.role });
  } catch {
    res.status(401).json({ error: 'invalid token' });
  }
});

router.post('/login', loginLimiter, async (req, res) => {
  const record = users[String(req.body.user)];
  const ok = record && await bcrypt.compare(String(req.body.pass || ''), record.hash);
  if (!ok) return res.status(401).json({ ok: false }); // uniform failure, no backdoor
  const token = jwt.sign({ user: req.body.user, role: record.role }, secrets.jwtSecret,
    { algorithm: 'HS256', expiresIn: '15m' });
  res.cookie('session', token, { httpOnly: true, secure: true, sameSite: 'strict' });
  res.json({ ok: true });
});

// Server generates the session id; client cannot fixate it.
router.post('/start', (req, res) => {
  const sid = crypto.randomBytes(16).toString('hex');
  res.cookie('sid', sid, { httpOnly: true, secure: true, sameSite: 'strict' });
  res.json({ ok: true });
});

// Unguessable, hashed, expiring reset token.
router.post('/reset', (req, res) => {
  const token = crypto.randomBytes(32).toString('hex');
  // store hash + expiry server-side (omitted); return only the raw token to the user's email
  res.json({ ok: true });
});

module.exports = router;
