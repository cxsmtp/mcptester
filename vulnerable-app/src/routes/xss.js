'use strict';

// A03:2021 Injection (Cross-Site Scripting) — reflected, stored, DOM, template.

const express = require('express');
const router = express.Router();
const handlebars = require('handlebars');
const ejs = require('ejs');
const marked = require('marked');

const comments = []; // in-memory "stored" sink

// Reflected XSS: raw interpolation into HTML response
router.get('/hello', (req, res) => {
  const name = req.query.name;
  res.send('<h1>Hello ' + name + '</h1>'); // reflected XSS
});

router.get('/search', (req, res) => {
  res.set('Content-Type', 'text/html');
  res.end(`<p>You searched for: ${req.query.q}</p>`); // reflected XSS
});

// Stored XSS: persist then render unescaped
router.post('/comment', (req, res) => {
  comments.push(req.body.text);
  res.redirect('/xss/comments');
});

router.get('/comments', (req, res) => {
  const html = comments.map(c => `<li>${c}</li>`).join(''); // stored XSS
  res.send('<ul>' + html + '</ul>');
});

// XSS via disabled escaping in template engines
router.get('/hbs', (req, res) => {
  const tpl = handlebars.compile('<div>{{{body}}}</div>'); // triple-stache = no escaping
  res.send(tpl({ body: req.query.body }));
});

router.get('/ejs', (req, res) => {
  // <%- %> outputs unescaped; also template injection since template is user-controlled
  res.send(ejs.render('<%- user %>', { user: req.query.user }));
});

// Markdown rendered with sanitize disabled -> XSS
router.post('/markdown', (req, res) => {
  res.send(marked(req.body.md, { sanitize: false }));
});

// Open redirect + reflected in Location (A01)
router.get('/go', (req, res) => {
  res.redirect(req.query.url); // open redirect
});

// Reflected XSS via header
router.get('/setname', (req, res) => {
  res.set('X-Greeting', req.query.name); // header injection / response splitting
  res.send('ok');
});

module.exports = router;
