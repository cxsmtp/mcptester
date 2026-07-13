'use strict';

// A08 remediated: JSON only (no code-executing deserializers), pollution-safe merge,
// safe YAML, safe archive extraction with path containment.

const express = require('express');
const router = express.Router();
const yaml = require('js-yaml');
const path = require('path');

const BLOCKED_KEYS = new Set(['__proto__', 'constructor', 'prototype']);

// Replaces node-serialize.unserialize with plain JSON.parse (no code execution).
router.post('/load', (req, res) => {
  try {
    res.json({ obj: JSON.parse(String(req.body.data || '{}')) });
  } catch {
    res.status(400).send('invalid json');
  }
});

// Pollution-safe deep merge that refuses dangerous keys.
function safeMerge(target, source) {
  for (const key of Object.keys(source)) {
    if (BLOCKED_KEYS.has(key)) continue;
    if (source[key] && typeof source[key] === 'object' && !Array.isArray(source[key])) {
      target[key] = safeMerge(target[key] && typeof target[key] === 'object' ? target[key] : {}, source[key]);
    } else {
      target[key] = source[key];
    }
  }
  return target;
}

router.post('/merge', (req, res) => {
  res.json({ target: safeMerge({}, req.body || {}) });
});

// js-yaml v4 load() is safe by default (no !!js/function). Still guard type.
router.post('/yaml', (req, res) => {
  try {
    res.json({ data: yaml.load(String(req.body.yaml || ''), { schema: yaml.JSON_SCHEMA }) });
  } catch {
    res.status(400).send('invalid yaml');
  }
});

// Archive extraction with zip-slip containment (validates each resolved entry path).
const EXTRACT_ROOT = path.resolve('/tmp/extract');
function safeJoin(name) {
  const dest = path.resolve(EXTRACT_ROOT, path.normalize(name));
  if (!dest.startsWith(EXTRACT_ROOT + path.sep)) throw new Error('zip slip blocked');
  return dest;
}
router.post('/unzip', (req, res) => {
  try {
    const entries = Array.isArray(req.body.entries) ? req.body.entries : [];
    const written = entries.map(e => safeJoin(String(e.name)));
    res.json({ ok: true, written });
  } catch (e) {
    res.status(400).send(e.message);
  }
});

module.exports = router;
