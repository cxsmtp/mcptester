'use strict';

const mysql = require('mysql2/promise');
const secrets = require('../config/secrets');

// Connection pool. multipleStatements stays OFF (default) to block stacked queries.
const pool = mysql.createPool({
  host: secrets.db.host,
  user: secrets.db.user,
  password: secrets.db.password,
  database: secrets.db.database,
  connectionLimit: 10,
  namedPlaceholders: true
});

// Parameterized query helper. Callers MUST pass params separately from SQL.
async function query(sql, params) {
  const [rows] = await pool.execute(sql, params);
  return rows;
}

module.exports = { pool, query };
