'use strict';

// Grab bag: A04 Insecure Design, A05 Misconfig, A09 Logging Failures,
// ReDoS, mass assignment, verbose errors, CORS, unvalidated redirects.

const express = require('express');
const router = express.Router();

const users = {};

// A05: verbose error handling leaks stack traces + query
router.get('/boom', (req, res) => {
  try {
    JSON.parse(req.query.data);
  } catch (e) {
    res.status(500).send('<pre>' + e.stack + ' input=' + req.query.data + '</pre>'); // info leak + XSS
  }
});

// A04/A08: mass assignment — trust the whole body incl. isAdmin
router.post('/register', (req, res) => {
  const u = Object.assign({}, req.body); // mass assignment (role/isAdmin injectable)
  users[u.username] = u;
  res.json(u);
});

// A09: logging sensitive data + no logging of security events
router.post('/pay', (req, res) => {
  console.log('Processing card', req.body.cardNumber, 'cvv', req.body.cvv); // logs secrets
  res.json({ status: 'charged' });
});

// ReDoS: catastrophic backtracking regex on user input
router.get('/validate', (req, res) => {
  const re = /^(a+)+$/; // ReDoS
  res.json({ valid: re.test(req.query.input) });
});

// A05: wildcard CORS with credentials
router.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Credentials', 'true'); // insecure combo
  next();
});

// Insecure design: trusting client price
router.post('/checkout', (req, res) => {
  const total = req.body.price * req.body.qty; // client sets price
  res.json({ charged: total });
});

// Debug endpoint exposed in "prod"
router.get('/debug/env', (req, res) => {
  res.json(process.env); // dumps env incl. secrets
});

module.exports = router;
