'use strict';

// A03 remediated: parameterized queries, no shell/eval sinks, allowlisted columns.

const express = require('express');
const router = express.Router();
const { execFile } = require('child_process');
const net = require('net');
const db = require('../db');

// SQL: bound parameters everywhere.
router.get('/user', async (req, res, next) => {
  try {
    const rows = await db.query('SELECT id, username FROM users WHERE id = ?', [req.query.id]);
    res.json(rows);
  } catch (e) { next(e); }
});

router.get('/search', async (req, res, next) => {
  try {
    const rows = await db.query(
      'SELECT id, name FROM products WHERE name LIKE ?',
      [`%${req.query.q}%`]                       // value bound, not concatenated into SQL
    );
    res.json(rows);
  } catch (e) { next(e); }
});

router.post('/login', async (req, res, next) => {
  try {
    // Parameterized; password is verified with bcrypt in the auth module, not in SQL.
    const rows = await db.query(
      'SELECT id, username, password_hash FROM users WHERE username = ?',
      [req.body.username]
    );
    res.json({ found: rows.length > 0 });
  } catch (e) { next(e); }
});

// ORDER BY can't be parameterized -> allowlist the column and direction.
const SORTABLE = new Set(['id', 'name', 'created_at']);
router.get('/order', async (req, res, next) => {
  try {
    const col = SORTABLE.has(req.query.sort) ? req.query.sort : 'id';
    const dir = req.query.dir === 'desc' ? 'DESC' : 'ASC';
    const rows = await db.query(`SELECT * FROM orders ORDER BY ${col} ${dir}`, []);
    res.json(rows);
  } catch (e) { next(e); }
});

// Command execution: fixed binary + argument array (no shell), input validated.
router.get('/ping', (req, res) => {
  const host = String(req.query.host || '');
  if (!/^[a-zA-Z0-9.-]+$/.test(host)) return res.status(400).send('invalid host');
  execFile('ping', ['-c', '1', '--', host], { timeout: 3000 }, (err, stdout) => {
    res.send(err ? 'ping failed' : stdout);
  });
});

// TCP reachability check instead of shelling out to nslookup.
router.get('/reachable', (req, res) => {
  const host = String(req.query.domain || '');
  if (!/^[a-zA-Z0-9.-]+$/.test(host)) return res.status(400).send('invalid host');
  const sock = net.createConnection({ host, port: 443, timeout: 2000 }, () => {
    sock.destroy(); res.json({ reachable: true });
  });
  sock.on('error', () => res.json({ reachable: false }));
  sock.on('timeout', () => { sock.destroy(); res.json({ reachable: false }); });
});

// No eval / Function / vm. Arithmetic handled by a tiny safe evaluator.
router.get('/calc', (req, res) => {
  const expr = String(req.query.formula || '');
  if (!/^[0-9+\-*/(). ]+$/.test(expr)) return res.status(400).send('only arithmetic allowed');
  // Still avoid eval: parse numbers/operators explicitly via Function is not used.
  try {
    // Shunting-yard-free simple guard: reject anything but arithmetic already ensured above.
    // Use a Number-only evaluation through JSON where possible; fall back to rejecting.
    const value = safeArithmetic(expr);
    res.json({ value });
  } catch {
    res.status(400).send('invalid expression');
  }
});

function safeArithmetic(expr) {
  // Recursive-descent parser for + - * / and parentheses over numbers only.
  let i = 0;
  const peek = () => expr[i];
  const num = () => {
    let s = '';
    while (i < expr.length && /[0-9.]/.test(expr[i])) s += expr[i++];
    return parseFloat(s);
  };
  function factor() {
    while (peek() === ' ') i++;
    if (peek() === '(') { i++; const v = addSub(); if (peek() === ')') i++; return v; }
    return num();
  }
  function mulDiv() {
    let v = factor();
    while (true) { while (peek() === ' ') i++;
      if (peek() === '*') { i++; v *= factor(); }
      else if (peek() === '/') { i++; v /= factor(); }
      else break; }
    return v;
  }
  function addSub() {
    let v = mulDiv();
    while (true) { while (peek() === ' ') i++;
      if (peek() === '+') { i++; v += mulDiv(); }
      else if (peek() === '-') { i++; v -= mulDiv(); }
      else break; }
    return v;
  }
  const result = addSub();
  if (i !== expr.length) throw new Error('parse error');
  return result;
}

module.exports = router;
