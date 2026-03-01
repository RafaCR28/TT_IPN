const express = require('express');
const cors = require('cors');

const { testDbConnection } = require('./config/db');
const authRoutes = require('./routes/auth.routes');

const app = express();

app.use(cors());
app.use(express.json());

// Probar conexión al arrancar (si falla, lo verás en consola)
testDbConnection().catch((err) => {
  console.error('MySQL connection failed:', err.message);
  process.exit(1);
});

app.use('/auth', authRoutes);

app.get('/', (req, res) => {
  res.json({ message: 'PQC Wallet API running' });
});

const { authenticate, authorize } = require('./middlewares/auth.middleware');

app.get('/admin/test', authenticate, authorize('admin'), (req, res) => {
  res.json({ ok: true, message: 'Admin access granted', user: req.user });
});

module.exports = app;