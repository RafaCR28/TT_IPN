const mysql = require('mysql2/promise');

const pool = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASS,
  database: process.env.DB_NAME,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
  timezone: 'Z',
});

async function testDbConnection() {
  const conn = await pool.getConnection();
  try {
    await conn.ping();
    const [rows] = await conn.query('SELECT DATABASE() AS db, NOW() AS now');
    console.log('MySQL connected:', rows[0]);
  } finally {
    conn.release();
  }
}

module.exports = { pool, testDbConnection };