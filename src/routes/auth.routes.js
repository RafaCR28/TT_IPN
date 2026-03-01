const express = require('express');
const router = express.Router();

const { register, login, me } = require('../controllers/auth.controller');
const { authenticate } = require('../middlewares/auth.middleware');

router.post('/register', register);
router.post('/login', login);

// protegido: requiere token
router.get('/me', authenticate, me);

module.exports = router;