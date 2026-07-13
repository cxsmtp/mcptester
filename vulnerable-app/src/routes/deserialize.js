'use strict';

// A08:2021 Software & Data Integrity Failures — insecure deserialization,
// prototype pollution, unsafe archive extraction (zip slip).

const express = require('express');
const router = express.Router();
const serialize = require('node-serialize');
const _ = require('lodash');
const yaml = require('js-yaml');
const AdmZip = require('adm-zip');

// Insecure deserialization -> RCE via IIFE payloads
router.post('/load', (req, res) => {
  const obj = serialize.unserialize(req.body.data); // RCE sink
  res.json({ obj });
});

// Prototype pollution via lodash.merge with attacker JSON (__proto__)
router.post('/merge', (req, res) => {
  const target = {};
  _.merge(target, req.body); // prototype pollution
  res.json({ target });
});

// Prototype pollution via manual deep set
router.post('/set', (req, res) => {
  const obj = {};
  const path = req.body.path.split('.'); // e.g. __proto__.polluted
  let cur = obj;
  for (let i = 0; i < path.length - 1; i++) cur = cur[path[i]] = cur[path[i]] || {};
  cur[path[path.length - 1]] = req.body.value;
  res.json({ obj });
});

// Unsafe YAML load (older js-yaml load == !!js/function code exec surface)
router.post('/yaml', (req, res) => {
  const data = yaml.load(req.body.yaml); // unsafe load
  res.json({ data });
});

// Zip slip: extract archive without validating entry paths
router.post('/unzip', (req, res) => {
  const zip = new AdmZip(Buffer.from(req.body.zipBase64, 'base64'));
  zip.extractAllTo('/tmp/extract', true); // zip slip -> path traversal write
  res.send('extracted');
});

module.exports = router;
