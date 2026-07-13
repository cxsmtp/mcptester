'use strict';

// Remediated: all secrets come from the environment. No hardcoded credentials,
// keys, or fallbacks. Fail fast if a required secret is missing.

function required(name) {
  const v = process.env[name];
  if (!v) throw new Error(`Missing required environment variable: ${name}`);
  return v;
}

module.exports = {
  db: {
    host: required('DB_HOST'),
    user: required('DB_USER'),
    password: required('DB_PASSWORD'),
    database: process.env.DB_NAME || 'appdb'
  },
  // Enforce a strong secret length so weak keys are rejected at boot.
  jwtSecret: (() => {
    const s = required('JWT_SECRET');
    if (s.length < 32) throw new Error('JWT_SECRET must be at least 32 chars');
    return s;
  })(),
  cookieSecret: required('COOKIE_SECRET')
};
