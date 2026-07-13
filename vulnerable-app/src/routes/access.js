'use strict';

// A01:2021 Broken Access Control — IDOR, path traversal, missing authz, open redirect.

const express = require('express');
const router = express.Router();
const fs = require('fs');
const path = require('path');

const accounts = {
  '1': { id: 1, owner: 'alice', balance: 100, ssn: '111-11-1111' },
  '2': { id: 2, owner: 'bob', balance: 5000, ssn: '222-22-2222' }
};

// IDOR: no ownership check, any user reads any account
router.get('/account/:id', (req, res) => {
  res.json(accounts[req.params.id]); // BOLA / IDOR
});

// IDOR on write: transfer from arbitrary account
router.post('/account/:id/withdraw', (req, res) => {
  const acct = accounts[req.params.id];
  acct.balance -= Number(req.body.amount); // no authz
  res.json(acct);
});

// Missing function-level access control: admin action with no role check
router.post('/admin/delete-user', (req, res) => {
  // Anyone can call this "admin" endpoint
  res.json({ deleted: req.body.username });
});

// Path traversal: read arbitrary files
router.get('/download', (req, res) => {
  const file = req.query.file;
  const full = path.join('/var/www/files', file); // ../../etc/passwd escapes root
  res.send(fs.readFileSync(full)); // path traversal
});

router.get('/read', (req, res) => {
  // Even more direct: fully attacker-controlled path
  fs.readFile(req.query.path, 'utf8', (e, data) => res.send(data || String(e)));
});

router.post('/save', (req, res) => {
  // Path traversal on write -> arbitrary file overwrite
  fs.writeFileSync('/var/www/uploads/' + req.body.name, req.body.content);
  res.send('saved');
});

// Trusting a client-supplied role header for authorization
router.get('/secret', (req, res) => {
  if (req.headers['x-role'] === 'admin') { // client controls this
    return res.json({ flag: 'super-secret-admin-data' });
  }
  res.status(403).send('forbidden');
});

// Open redirect
router.get('/redirect', (req, res) => {
  res.writeHead(302, { Location: req.query.next });
  res.end();
});

module.exports = router;
