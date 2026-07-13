'use strict';

// Remediated client script. No secrets; all untrusted input goes through textContent
// (never innerHTML/document.write/eval), redirects are allowlisted, postMessage
// checks the origin.

(function () {
  var params = new URLSearchParams(location.search);

  // Safe text rendering — textContent does not parse HTML.
  var content = document.getElementById('content');
  content.textContent = 'Welcome ' + (params.get('user') || 'guest');

  // Redirect/href only to same-origin allowlisted paths.
  var ALLOWED = ['/', '/dashboard', '/profile'];
  var next = params.get('next') || '/';
  document.getElementById('link').setAttribute('href', ALLOWED.indexOf(next) >= 0 ? next : '/');

  // postMessage with strict origin check.
  window.addEventListener('message', function (e) {
    if (e.origin !== location.origin) return; // reject cross-origin messages
    var msg = document.createElement('div');
    msg.textContent = String(e.data);
    document.body.appendChild(msg);
  });
})();
