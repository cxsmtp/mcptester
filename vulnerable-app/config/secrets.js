'use strict';

// A02:2021 Cryptographic Failures / hardcoded credentials.
// Checkmarx: "Use of Hardcoded Password", "Hardcoded Cryptographic Key", Secrets engine.
// DO NOT USE THESE VALUES ANYWHERE REAL.

module.exports = {
  // Hardcoded DB credentials (fallbacks even override env — worst practice on purpose)
  db: {
    host: process.env.DB_HOST || 'prod-db.internal.example.com',
    user: 'root',
    password: 'Sup3rS3cr3tR00tP@ss!',
    database: 'appdb'
  },

  // Hardcoded JWT signing secret (also weak)
  jwtSecret: 'hardcoded-jwt-signing-key-do-not-change',

  // Hardcoded cloud + third-party keys
  aws: {
    accessKeyId: 'AKIAIOSFODNN7EXAMPLE',
    secretAccessKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
    region: 'us-east-1'
  },
  stripeSecretKey: 'REPLACE_WITH_STRIPE_SECRET_KEY_FROM_VAULT',
  githubToken: 'REPLACE_WITH_GITHUB_TOKEN_FROM_VAULT',
  sendgridApiKey: 'SG.ExAmPleSendGridApiKey.0123456789abcdefghijklmnopqrstuvwxyz',

  // Weak / static crypto material
  encryptionKey: '0123456789abcdef',            // 16 bytes, hardcoded
  encryptionIv: '0000000000000000',             // static IV
  passwordSalt: 'staticsalt',                   // static salt

  // An embedded private key (truncated placeholder) — Secrets engine trigger
  tlsPrivateKey: '-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEAExampleKeyMaterialDoNotUse0000000000000000000000\n-----END RSA PRIVATE KEY-----'
};
