'use strict';

// A10 remediated: strict host allowlist, https-only, no redirects, no internal ranges.

const express = require('express');
const router = express.Router();
const axios = require('axios');
const dns = require('dns').promises;
const net = require('net');

const ALLOWED_HOSTS = new Set(
  (process.env.ALLOWED_FETCH_HOSTS || '').split(',').map(s => s.trim()).filter(Boolean)
);

function isPrivate(ip) {
  if (net.isIPv4(ip)) {
    const [a, b] = ip.split('.').map(Number);
    return a === 10 || a === 127 || (a === 172 && b >= 16 && b <= 31) ||
           (a === 192 && b === 168) || (a === 169 && b === 254) || a === 0;
  }
  return ip === '::1' || ip.startsWith('fc') || ip.startsWith('fd') || ip.startsWith('fe80');
}

async function assertSafeUrl(raw) {
  const url = new URL(raw);
  if (url.protocol !== 'https:') throw new Error('https only');
  if (!ALLOWED_HOSTS.has(url.hostname)) throw new Error('host not allowed');
  const { address } = await dns.lookup(url.hostname);
  if (isPrivate(address)) throw new Error('resolves to private address');
  return url;
}

router.get('/fetch', async (req, res, next) => {
  try {
    const url = await assertSafeUrl(String(req.query.url));
    const resp = await axios.get(url.toString(), { maxRedirects: 0, timeout: 5000 });
    res.send(resp.data);
  } catch (e) { res.status(400).send(e.message); }
});

router.post('/webhook', async (req, res, next) => {
  try {
    const url = await assertSafeUrl(String(req.body.callback));
    await axios.post(url.toString(), req.body.payload || {}, { maxRedirects: 0, timeout: 5000 });
    res.json({ ok: true });
  } catch (e) { res.status(400).send(e.message); }
});

module.exports = router;
