'use strict';

// A01 remediated: ownership checks, role enforcement, path traversal prevention.

const express = require('express');
const router = express.Router();
const fs = require('fs');
const path = require('path');

const accounts = {
  '1': { id: 1, owner: 'alice', balance: 100 },
  '2': { id: 2, owner: 'bob', balance: 5000 }
};

// Minimal auth middleware: resolves the caller from a verified session (set upstream).
function requireUser(req, res, next) {
  if (!req.user) return res.status(401).json({ error: 'authentication required' });
  next();
}
function requireRole(role) {
  return (req, res, next) =>
    req.user && req.user.role === role ? next() : res.status(403).json({ error: 'forbidden' });
}

// Ownership enforced: a user can only read their own account.
router.get('/account/:id', requireUser, (req, res) => {
  const acct = accounts[req.params.id];
  if (!acct) return res.status(404).end();
  if (acct.owner !== req.user.username) return res.status(403).json({ error: 'forbidden' });
  res.json({ id: acct.id, owner: acct.owner, balance: acct.balance }); // no SSN exposed
});

router.post('/account/:id/withdraw', requireUser, (req, res) => {
  const acct = accounts[req.params.id];
  if (!acct) return res.status(404).end();
  if (acct.owner !== req.user.username) return res.status(403).json({ error: 'forbidden' });
  const amount = Number(req.body.amount);
  if (!(amount > 0) || amount > acct.balance) return res.status(400).json({ error: 'bad amount' });
  acct.balance -= amount;
  res.json({ id: acct.id, balance: acct.balance });
});

// Admin action now requires a server-verified admin role (not a client header).
router.post('/admin/delete-user', requireUser, requireRole('admin'), (req, res) => {
  res.json({ deleted: String(req.body.username) });
});

// Path traversal prevented: resolve within a base dir and verify containment.
const FILES_ROOT = path.resolve('/var/www/files');
router.get('/download', (req, res) => {
  const full = path.resolve(FILES_ROOT, path.normalize('.' + path.sep + String(req.query.file || '')));
  if (!full.startsWith(FILES_ROOT + path.sep)) return res.status(400).send('invalid path');
  fs.readFile(full, (e, data) => (e ? res.status(404).end() : res.send(data)));
});

module.exports = router;
