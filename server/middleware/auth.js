// WARDKEY Auth Middleware
const jwt = require('jsonwebtoken');
const { getDB } = require('../models/db');

if (!process.env.JWT_SECRET) {
  throw new Error('FATAL: JWT_SECRET environment variable is required.');
}
const JWT_SECRET = process.env.JWT_SECRET;

function authenticate(req, res, next) {
  const header = req.headers.authorization;
  if (!header || !header.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Authentication required' });
  }

  const token = header.split(' ')[1];
  try {
    const decoded = jwt.verify(token, JWT_SECRET, { algorithms: ['HS256'] });

    // Validate session is not revoked/expired (if JWT contains sid)
    if (decoded.sid) {
      const db = getDB();
      const session = db.prepare('SELECT id, revoked, expires_at FROM sessions WHERE id = ?').get(decoded.sid);
      if (!session || session.revoked || new Date(session.expires_at) < new Date()) {
        return res.status(401).json({ error: 'Session revoked or expired', code: 'SESSION_REVOKED' });
      }
    }

    req.user = decoded;
    next();
  } catch (err) {
    if (err.name === 'TokenExpiredError') {
      return res.status(401).json({ error: 'Token expired', code: 'TOKEN_EXPIRED' });
    }
    return res.status(401).json({ error: 'Invalid token' });
  }
}

function optionalAuth(req, res, next) {
  const header = req.headers.authorization;
  if (header && header.startsWith('Bearer ')) {
    try {
      const decoded = jwt.verify(header.split(' ')[1], JWT_SECRET, { algorithms: ['HS256'] });
      if (decoded.sid) {
        const db = getDB();
        const session = db.prepare('SELECT id, revoked, expires_at FROM sessions WHERE id = ?').get(decoded.sid);
        if (session && !session.revoked && new Date(session.expires_at) >= new Date()) {
          req.user = decoded;
        }
      } else {
        req.user = decoded;
      }
    } catch {}
  }
  next();
}

module.exports = { authenticate, optionalAuth };
