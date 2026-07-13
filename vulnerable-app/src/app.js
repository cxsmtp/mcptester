'use strict';

// Deliberately vulnerable Express app for Checkmarx scanner testing.
// OWASP Top 10 2021 coverage across SAST/SCA/IaC/Secrets. DO NOT DEPLOY.

const express = require('express');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const path = require('path');

const app = express();

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.text({ type: ['text/xml', 'application/xml', 'text/plain'] }));
app.use(cookieParser('hardcoded-cookie-secret')); // A02: hardcoded cookie secret

// A05: overly permissive static serving (directory listing / source exposure)
app.use('/static', express.static(path.join(__dirname, '..')));

// A05: disable security headers explicitly (documented misconfig)
app.disable('x-powered-by'); // (only cosmetic; real headers still missing)

// Mount vulnerable routers
app.use('/inject', require('./routes/injection'));
app.use('/xss', require('./routes/xss'));
app.use('/access', require('./routes/access'));
app.use('/crypto', require('./routes/crypto'));
app.use('/auth', require('./routes/auth'));
app.use('/ssrf', require('./routes/ssrf'));
app.use('/xxe', require('./routes/xxe'));
app.use('/deserialize', require('./routes/deserialize'));
app.use('/misc', require('./routes/misc'));

// A09: global error handler leaks internals
app.use((err, req, res, next) => {
  res.status(500).json({ error: err.message, stack: err.stack }); // stack trace to client
});

// Binds on all interfaces, no TLS
const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => console.log('vuln app on ' + PORT));

module.exports = app;
