'use strict';

// Remediated Express app. Security headers on, scoped CORS, safe errors,
// no source/secret exposure. AFTER state.

const express = require('express');
const cookieParser = require('cookie-parser');
const helmet = require('helmet');
const secrets = require('../config/secrets');

const app = express();

app.use(helmet()); // sets CSP, HSTS, X-Content-Type-Options, frameguard, etc.
app.use(express.json({ limit: '100kb' }));
app.use(express.urlencoded({ extended: false, limit: '100kb' }));
app.use(express.text({ type: ['text/xml', 'application/xml'], limit: '100kb' }));
app.use(cookieParser(secrets.cookieSecret));

// Scoped CORS: explicit origin allowlist, credentials only for those origins.
const ALLOWED_ORIGINS = new Set((process.env.ALLOWED_ORIGINS || '').split(',').filter(Boolean));
app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (origin && ALLOWED_ORIGINS.has(origin)) {
    res.header('Access-Control-Allow-Origin', origin);
    res.header('Vary', 'Origin');
    res.header('Access-Control-Allow-Credentials', 'true');
  }
  next();
});

app.use('/inject', require('./routes/injection'));
app.use('/xss', require('./routes/xss'));
app.use('/access', require('./routes/access'));
app.use('/crypto', require('./routes/crypto'));
app.use('/auth', require('./routes/auth'));
app.use('/ssrf', require('./routes/ssrf'));
app.use('/xxe', require('./routes/xxe'));
app.use('/deserialize', require('./routes/deserialize'));
app.use('/misc', require('./routes/misc'));

// Error handler: no stack traces or internals to the client.
// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
  console.error(err); // detail stays server-side
  res.status(500).json({ error: 'internal server error' });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log('app listening on ' + PORT));

module.exports = app;
