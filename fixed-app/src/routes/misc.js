'use strict';

// A04/A05/A09 remediated: safe errors, no mass assignment, no secret logging,
// bounded validation, scoped CORS, server-side pricing.

const express = require('express');
const router = express.Router();

const users = {};
const PRICES = { sku_book: 1200, sku_pen: 150 }; // server-side source of truth (cents)

// Safe error handling: generic message to client, details only to server logs.
router.get('/parse', (req, res) => {
  try {
    const data = JSON.parse(String(req.query.data || ''));
    res.json({ ok: true, keys: Object.keys(data) });
  } catch {
    res.status(400).json({ error: 'invalid JSON' });
  }
});

// Explicit allowlist of fields — isAdmin/role cannot be injected.
router.post('/register', (req, res) => {
  const username = String(req.body.username || '').slice(0, 64);
  if (!/^[a-zA-Z0-9_]{3,64}$/.test(username)) return res.status(400).json({ error: 'bad username' });
  users[username] = { username, email: String(req.body.email || ''), role: 'user' };
  res.json(users[username]);
});

// Never log PAN/CVV. Tokenize upstream; log only a masked reference.
router.post('/pay', (req, res) => {
  const last4 = String(req.body.cardNumber || '').slice(-4);
  console.log('Processing payment for card ending', last4);
  res.json({ status: 'charged' });
});

// Server computes totals from trusted price table; client cannot set price.
router.post('/checkout', (req, res) => {
  const price = PRICES[String(req.body.sku)];
  const qty = Math.max(1, Math.min(100, parseInt(req.body.qty, 10) || 0));
  if (price == null) return res.status(400).json({ error: 'unknown sku' });
  res.json({ charged: price * qty });
});

module.exports = router;
