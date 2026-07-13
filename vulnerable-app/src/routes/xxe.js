'use strict';

// A05:2021 Security Misconfiguration (XXE) + A08 insecure deserialization neighbors.

const express = require('express');
const router = express.Router();
const libxml = require('libxmljs');
const { DOMParser } = require('xmldom');

// XXE: external entities enabled
router.post('/parse', (req, res) => {
  const doc = libxml.parseXml(req.body, { noent: true, dtdload: true, dtdvalid: true }); // XXE
  res.send(doc.toString());
});

// XXE via xmldom (no entity protection)
router.post('/dom', (req, res) => {
  const doc = new DOMParser().parseFromString(req.body, 'text/xml');
  res.send(doc.documentElement.textContent);
});

// SOAP-style endpoint parsing untrusted XML with DTD processing
router.post('/soap', (req, res) => {
  const doc = libxml.parseXmlString(req.body, { noblanks: true, noent: true });
  res.json({ root: doc.root().name() });
});

module.exports = router;
