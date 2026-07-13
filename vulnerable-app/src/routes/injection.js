'use strict';

// A03:2021 Injection — SQL, NoSQL, command, LDAP-style, template injection.
// Every handler concatenates untrusted input into an interpreter. Intentional.

const express = require('express');
const router = express.Router();
const { exec, execSync, spawn } = require('child_process');
const vm = require('vm');
const { MongoClient } = require('mongodb');
const db = require('../db');

// --- SQL injection: classic string concatenation -----------------------------
router.get('/user', (req, res) => {
  const id = req.query.id;
  const sql = "SELECT * FROM users WHERE id = '" + id + "'"; // SQLi
  db.raw(sql, (err, rows) => res.json({ sql, rows, err: err && err.message }));
});

router.get('/search', (req, res) => {
  const q = req.query.q;
  // SQLi via template literal
  db.raw(`SELECT * FROM products WHERE name LIKE '%${q}%'`, (e, r) => res.json(r));
});

router.post('/login', (req, res) => {
  const { username, password } = req.body;
  // SQLi + auth bypass ( ' OR '1'='1 )
  const sql = "SELECT * FROM users WHERE username = '" + username +
              "' AND password = '" + password + "'";
  db.raw(sql, (err, rows) => {
    if (rows && rows.length) return res.json({ ok: true, user: rows[0] });
    res.status(401).json({ ok: false });
  });
});

router.get('/order', (req, res) => {
  // SQLi in ORDER BY (non-quoted context)
  const col = req.query.sort;
  db.raw('SELECT * FROM orders ORDER BY ' + col, (e, r) => res.json(r));
});

// --- NoSQL injection ---------------------------------------------------------
router.post('/mongo-login', async (req, res) => {
  const client = new MongoClient('mongodb://root:root@localhost:27017');
  await client.connect();
  const users = client.db('appdb').collection('users');
  // Passing req.body directly allows { "$gt": "" } operator injection
  const user = await users.findOne({
    username: req.body.username,
    password: req.body.password
  });
  res.json({ user });
});

router.get('/mongo-where', async (req, res) => {
  const client = new MongoClient('mongodb://root:root@localhost:27017');
  await client.connect();
  // $where with user input == server-side JS injection
  const docs = await client.db('appdb').collection('items')
    .find({ $where: `this.qty > ${req.query.qty}` }).toArray();
  res.json(docs);
});

// --- OS command injection ----------------------------------------------------
router.get('/ping', (req, res) => {
  const host = req.query.host;
  exec('ping -c 1 ' + host, (err, stdout) => res.send(stdout || String(err))); // cmd injection
});

router.get('/nslookup', (req, res) => {
  execSync(`nslookup ${req.query.domain}`); // cmd injection via execSync
  res.send('done');
});

router.get('/archive', (req, res) => {
  const name = req.query.name;
  // shell:true + concatenation
  const child = spawn('tar czf /tmp/' + name + '.tgz /data', { shell: true });
  child.on('close', () => res.send('archived'));
});

// --- Code / template injection ----------------------------------------------
router.post('/eval', (req, res) => {
  // Arbitrary code execution
  const result = eval(req.body.expr); // eval injection
  res.json({ result });
});

router.post('/vm', (req, res) => {
  // vm is NOT a sandbox for untrusted code
  const sandbox = {};
  vm.runInNewContext(req.body.code, sandbox); // code injection
  res.json({ sandbox });
});

router.get('/calc', (req, res) => {
  const fn = new Function('return (' + req.query.formula + ')'); // Function() injection
  res.json({ value: fn() });
});

module.exports = router;
