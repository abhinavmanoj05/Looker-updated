// backend/auth.js – JWT helpers
const jwt = require('jsonwebtoken');
const secret = process.env.JWT_SECRET || 'change_this_secret';

function generateToken(payload) {
  return jwt.sign(payload, secret, { expiresIn: '12h' });
}

function verifyToken(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ success: false, error: 'Missing token' });
  }
  const token = authHeader.split(' ')[1];
  try {
    req.user = jwt.verify(token, secret);
    next();
  } catch (err) {
    return res.status(401).json({ success: false, error: 'Invalid token' });
  }
}

module.exports = { generateToken, verifyToken };
