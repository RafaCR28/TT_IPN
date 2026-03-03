const argon2 = require('argon2');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const { pool } = require('../config/db');

exports.register = async (req, res) => {
  const conn = await pool.getConnection();
  try {
    const { email, password } = req.body;
    const rol = req.body.rol === 'admin' ? 'admin' : 'usuario';

    const cleanEmail = String(email || '').trim().toLowerCase();
    const plain = String(password || '');

    if (!cleanEmail || !plain) {
      return res.status(400).json({ message: 'Email y password requeridos' });
    }
    if (plain.length < 8) {
      return res.status(400).json({ message: 'La contraseña debe tener mínimo 8 caracteres' });
    }

    const [existing] = await conn.query(
      'SELECT 1 FROM usuario WHERE email = ? LIMIT 1',
      [cleanEmail]
    );
    if (existing.length > 0) {
      return res.status(400).json({ message: 'Usuario ya existe' });
    }

    const hashStr = await argon2.hash(plain, {
      type: argon2.argon2id,
      memoryCost: 19456,
      timeCost: 2,
      parallelism: 1,
    });

    const hashBin = Buffer.from(hashStr, 'utf8');

    await conn.beginTransaction();

    const [ins] = await conn.query(
      `INSERT INTO usuario (uuid, email, password_hash, rol, estado, creado_en, actualizado_en, intentos_fallidos, bloqueado_hasta)
       VALUES (?, ?, ?, ?, 'activo', NOW(), NOW(), 0, NULL)`,
      [uuidv4(), cleanEmail, hashBin, rol]
    );

    const userId = ins.insertId;

    await conn.query(
      `INSERT INTO billetera (usuario_id, moneda, saldo_actual, estado, creado_en, actualizado_en)
       VALUES (?, 'MXN', 0.00, 'activa', NOW(), NOW())`,
      [userId]
    );

    await registrarLog(conn, userId, 'AUTH', 'INFO', 'Registro de cuenta');

    const accessToken = jwt.sign(
      { usuario_id: userId, rol },
      process.env.JWT_SECRET,
      { expiresIn: '15m' }
    );

    const refreshToken = crypto.randomBytes(64).toString('hex');
    const refreshHash = crypto.createHash('sha256').update(refreshToken).digest();

    await conn.query(
      `INSERT INTO token_sesion
       (usuario_id, tipo, token_hash, expira_en, estado, emitido_en, ultimo_uso_en)
       VALUES (?, 'refresh', ?, DATE_ADD(NOW(), INTERVAL 7 DAY), 'vigente', NOW(), NOW())`,
      [userId, refreshHash]
    );

    await conn.commit();

    return res.status(201).json({
      message: 'Usuario registrado',
      access_token: accessToken,
      refresh_token: refreshToken,
      user: { usuario_id: userId, email: cleanEmail, rol }
    });
  } catch (err) {
    try { await conn.rollback(); } catch (_) {}
    console.error(err);
    return res.status(500).json({ message: 'Error en registro' });
  } finally {
    conn.release();
  }
};

exports.login = async (req, res) => {
  try {
    const { email, password } = req.body;
    const cleanEmail = String(email || '').trim().toLowerCase();

    const [rows] = await pool.query(
      `SELECT usuario_id, email, rol, password_hash, estado,
              intentos_fallidos, bloqueado_hasta
       FROM usuario WHERE email = ?`,
      [cleanEmail]
    );

    if (rows.length === 0) {
      return res.status(401).json({ message: 'Credenciales inválidas' });
    }

    const user = rows[0];

    if (user.bloqueado_hasta && new Date(user.bloqueado_hasta) > new Date()) {
      return res.status(403).json({ message: 'Cuenta bloqueada temporalmente' });
    }

    const stored = Buffer.isBuffer(user.password_hash)
      ? user.password_hash.toString('utf8')
      : String(user.password_hash || '');

    const valid = await argon2.verify(stored, String(password || ''));

    if (!valid) {
      const nuevosIntentos = (user.intentos_fallidos || 0) + 1;

      if (nuevosIntentos >= 3) {
        await pool.query(
          `UPDATE usuario
          SET intentos_fallidos = ?,
              bloqueado_hasta = DATE_ADD(NOW(), INTERVAL 10 MINUTE)
          WHERE usuario_id = ?`,
          [nuevosIntentos, user.usuario_id] // o 3 si quieres fijo
        );

        await registrarLog(user.usuario_id, 'AUTH', 'WARN', 'Usuario bloqueado por intentos fallidos');

        return res.status(403).json({ message: 'Cuenta bloqueada por 10 minutos' });
      }

      await pool.query(
        `UPDATE usuario SET intentos_fallidos = ? WHERE usuario_id = ?`,
        [nuevosIntentos, user.usuario_id]
      );

      await registrarLog(user.usuario_id, 'AUTH', 'WARN', 'Intento fallido de login');

      return res.status(401).json({ message: 'Credenciales inválidas' });
    }

    await pool.query(
      `UPDATE usuario
       SET intentos_fallidos = 0,
           bloqueado_hasta = NULL
       WHERE usuario_id = ?`,
      [user.usuario_id]
    );

    const accessToken = jwt.sign(
      { usuario_id: user.usuario_id, rol: user.rol },
      process.env.JWT_SECRET,
      { expiresIn: '15m' }
    );

    const refreshToken = crypto.randomBytes(64).toString('hex');
    const refreshHash = crypto.createHash('sha256').update(refreshToken).digest();

    await pool.query(
      `INSERT INTO token_sesion
       (usuario_id, tipo, token_hash, expira_en, estado, emitido_en, ultimo_uso_en)
       VALUES (?, 'refresh', ?, DATE_ADD(NOW(), INTERVAL 7 DAY), 'vigente', NOW(), NOW())`,
      [user.usuario_id, refreshHash]
    );

    await registrarLog(user.usuario_id, 'AUTH', 'INFO', 'Login exitoso');

    return res.json({
      access_token: accessToken,
      refresh_token: refreshToken,
      user: {
        usuario_id: user.usuario_id,
        email: user.email,
        rol: user.rol
      }
    });

  } catch (err) {
    console.error(err);
    return res.status(500).json({ message: 'Error en login' });
  }
};

exports.me = async (req, res) => {
  try {
    const userId = req.user?.usuario_id;
    if (!userId) return res.status(401).json({ message: 'No autenticado' });

    const [rows] = await pool.query(
      `SELECT usuario_id, uuid, email, rol, estado, creado_en, actualizado_en
       FROM usuario WHERE usuario_id = ? LIMIT 1`,
      [userId]
    );

    if (rows.length === 0) return res.status(404).json({ message: 'Usuario no encontrado' });

    return res.json({ user: rows[0] });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ message: 'Error en /me' });
  }
};

async function registrarLog(a, b, c, d, e) {
  const hasConn = a && typeof a.query === 'function';

  const conn = hasConn ? a : pool;
  const usuario_id = hasConn ? b : a;
  const categoria  = hasConn ? c : b;
  const nivel      = hasConn ? d : c;
  const mensaje    = hasConn ? e : d;

  await conn.query(
    `INSERT INTO log_aplicacion (usuario_id, categoria, nivel, mensaje)
     VALUES (?, ?, ?, ?)`,
    [usuario_id, categoria, nivel, mensaje]
  );
}