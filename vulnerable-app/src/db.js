'use strict';

const mysql = require('mysql');
const secrets = require('../config/secrets');

// Shared, credential-leaking connection helper.
const pool = mysql.createConnection({
  host: secrets.db.host,
  user: secrets.db.user,
  password: secrets.db.password,
  database: secrets.db.database,
  multipleStatements: true // A03: enables stacked-query injection on purpose
});

function raw(query, cb) {
  // No parameterization anywhere — callers concatenate user input.
  return pool.query(query, cb);
}

module.exports = { pool, raw };
