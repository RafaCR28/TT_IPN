const jwt = require('jsonwebtoken');

function authenticate(req, res, next) {
  const auth = req.headers.authorization || '';
  const [type, token] = auth.split(' ');

  if (type !== 'Bearer' || !token) {
    return res.status(401).json({ message: 'Token requerido (Bearer)' });
  }

  try {
    const payload = jwt.verify(token, process.env.JWT_SECRET);
    req.user = payload; // { usuario_id, rol, iat, exp }
    return next();
  } catch (err) {
    return res.status(401).json({ message: 'Token inválido o expirado' });
  }
}

function authorize(...allowedRoles) {
  return (req, res, next) => {
    const rol = req.user?.rol;
    if (!rol) return res.status(401).json({ message: 'No autenticado' });

    if (!allowedRoles.includes(String(rol).toLowerCase())) {
      return res.status(403).json({ message: 'No autorizado' });
    }
    return next();
  };
}

module.exports = { authenticate, authorize };