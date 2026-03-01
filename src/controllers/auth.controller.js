const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const { pool } = require('../config/db');

exports.register = async (req, res) => {
  try {
    const { email, password, rol } = req.body;

    if (!email || !password) {
      return res.status(400).json({ message: 'Email y password requeridos' });
    }

    const [existing] = await pool.query('SELECT 1 FROM usuario WHERE email = ? LIMIT 1', [email]);
    if (existing.length > 0) {
      return res.status(400).json({ message: 'Usuario ya existe' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    // Si tu BD usa 'admin'/'user', usa minúsculas aquí:
    const role = (rol || 'user').toLowerCase();

    await pool.query(
      `INSERT INTO usuario (uuid, email, password_hash, rol, estado, creado_en, actualizado_en)
       VALUES (?, ?, ?, ?, 'activo', NOW(), NOW())`,
      [uuidv4(), email, hashedPassword, role]
    );

    return res.status(201).json({ message: 'Usuario registrado' });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ message: 'Error en registro' });
  }
};

exports.login = async (req, res) => {
  try {
    const { email, password } = req.body;

    const [rows] = await pool.query('SELECT usuario_id, email, rol, password_hash, estado FROM usuario WHERE email = ?', [email]);
    if (rows.length === 0) return res.status(401).json({ message: 'Credenciales inválidas' });

    const user = rows[0];

    if ((user.estado || '').toLowerCase() !== 'activo') {
      return res.status(403).json({ message: 'Usuario inactivo' });
    }

    // Asegurar que ambos sean string (porque MySQL puede devolver Buffer)
    const plain = String(password ?? '');

    const hash = Buffer.isBuffer(user.password_hash)
    ? user.password_hash.toString('utf8')
    : String(user.password_hash ?? '');

    if (!plain || !hash) {
    return res.status(401).json({ message: 'Credenciales inválidas' });
    }

    const ok = await bcrypt.compare(plain, hash);
    if (!ok) return res.status(401).json({ message: 'Credenciales inválidas' });

    const token = jwt.sign(
      { usuario_id: user.usuario_id, rol: user.rol },
      process.env.JWT_SECRET,
      { expiresIn: process.env.JWT_EXPIRES || '1h' }
    );

    return res.json({
      token,
      user: {
        usuario_id: user.usuario_id,
        email: user.email,
        rol: user.rol,
      },
    });
  } catch (err) {
        console.error(err);
        return res.status(500).json({
            message: 'Error en login',
            detail: err.message, // temporal para debug
        });
    }
};

// /auth/me
exports.me = async (req, res) => {
  try {
    const userId = req.user.usuario_id;

    const [rows] = await pool.query(
      'SELECT usuario_id, uuid, email, rol, estado, creado_en, actualizado_en FROM usuario WHERE usuario_id = ?',
      [userId]
    );

    if (rows.length === 0) return res.status(404).json({ message: 'Usuario no encontrado' });

    return res.json({ user: rows[0] });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ message: 'Error en /me' });
  }
};