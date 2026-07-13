'use strict';

// A05 (XXE) remediated: external entities and DTDs disabled; prefer JSON where possible.

const express = require('express');
const router = express.Router();
const { XMLParser } = require('fast-xml-parser');

// fast-xml-parser does not resolve external entities or DTDs at all -> XXE-safe by design.
const parser = new XMLParser({ ignoreAttributes: false, processEntities: false });

router.post('/parse', (req, res) => {
  try {
    const body = String(req.body || '');
    if (/<!DOCTYPE/i.test(body) || /<!ENTITY/i.test(body)) {
      return res.status(400).send('DTD/entities not allowed');
    }
    res.json(parser.parse(body));
  } catch {
    res.status(400).send('invalid xml');
  }
});

module.exports = router;
