'use strict';

// A03 (XSS) remediated: output encoding, sanitized markdown, redirect allowlist.

const express = require('express');
const router = express.Router();
const escapeHtml = require('escape-html');
const { marked } = require('marked');
const createDOMPurify = require('dompurify');
const { JSDOM } = require('jsdom');

const DOMPurify = createDOMPurify(new JSDOM('').window);
const comments = [];

router.get('/hello', (req, res) => {
  res.type('html').send('<h1>Hello ' + escapeHtml(String(req.query.name || '')) + '</h1>');
});

router.get('/search', (req, res) => {
  res.type('html').send('<p>You searched for: ' + escapeHtml(String(req.query.q || '')) + '</p>');
});

router.post('/comment', (req, res) => {
  comments.push(String(req.body.text || ''));
  res.redirect('/xss/comments');
});

router.get('/comments', (req, res) => {
  const html = comments.map(c => '<li>' + escapeHtml(c) + '</li>').join('');
  res.type('html').send('<ul>' + html + '</ul>');
});

// Markdown sanitized through DOMPurify.
router.post('/markdown', (req, res) => {
  const dirty = marked.parse(String(req.body.md || ''));
  res.type('html').send(DOMPurify.sanitize(dirty));
});

// Redirect only to a vetted allowlist of internal paths.
const ALLOWED_REDIRECTS = new Set(['/', '/dashboard', '/profile']);
router.get('/go', (req, res) => {
  const target = String(req.query.url || '/');
  res.redirect(ALLOWED_REDIRECTS.has(target) ? target : '/');
});

module.exports = router;
