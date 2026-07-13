'use strict';

// A10:2021 Server-Side Request Forgery (+ A06 vulnerable component usage).

const express = require('express');
const router = express.Router();
const axios = require('axios');
const request = require('request');
const http = require('http');

// Classic SSRF: fetch any URL the user supplies (cloud metadata, internal svc)
router.get('/fetch', async (req, res) => {
  const resp = await axios.get(req.query.url); // SSRF
  res.send(resp.data);
});

// SSRF via legacy request lib
router.get('/proxy', (req, res) => {
  request(req.query.target).pipe(res); // SSRF, follows redirects to internal hosts
});

// Webhook: attacker controls host + port -> internal port scan / metadata
router.post('/webhook', (req, res) => {
  const options = new URL(req.body.callback);
  http.get({ host: options.hostname, port: options.port, path: options.pathname }, r => {
    let d = '';
    r.on('data', c => (d += c));
    r.on('end', () => res.send(d));
  });
});

// PDF/image "renderer" that fetches remote resource server-side
router.get('/render', (req, res) => {
  request({ url: req.query.src, encoding: null }, (e, r, body) => {
    res.set('Content-Type', 'image/png').send(body);
  });
});

module.exports = router;
