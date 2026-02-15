// WARDKEY Auth Routes
const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { v4: uuid } = require('uuid');
const { authenticator } = require('otplib');
const QRCode = require('qrcode');
const rateLimit = require('express-rate-limit');
const { getDB, auditLog } = require('../models/db');
const { authenticate } = require('../middleware/auth');

const crypto = require('crypto');

const sensitiveAuthLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: { error: 'Too many attempts, try again later' }
});

const router = express.Router();
if (!process.env.JWT_SECRET) {
  throw new Error('FATAL: JWT_SECRET environment variable is required. Set it before starting the server.');
}
const JWT_SECRET = process.env.JWT_SECRET;

// ═══════ MFA SECRET ENCRYPTION ═══════
// Encrypt MFA secrets at rest using AES-256-GCM
// Uses separate MFA_ENC_KEY env var when available for key isolation
const MFA_ENC_KEY_RAW = process.env.MFA_ENC_KEY || JWT_SECRET;
if (!process.env.MFA_ENC_KEY) {
  console.warn('⚠ MFA_ENC_KEY not set — falling back to JWT_SECRET. Set a separate MFA_ENC_KEY for better key isolation.');
}
const MFA_ENC_KEY = crypto.createHash('sha256').update(MFA_ENC_KEY_RAW + ':mfa-encryption-key').digest();

function encryptMfaSecret(plaintext) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', MFA_ENC_KEY, iv);
  let encrypted = cipher.update(plaintext, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  const tag = cipher.getAuthTag().toString('hex');
  return iv.toString('hex') + ':' + tag + ':' + encrypted;
}

function decryptMfaSecret(ciphertext) {
  // Reject legacy plaintext secrets — must be migrated to encrypted format
  if (!ciphertext.includes(':')) {
    throw new Error('Legacy plaintext MFA secret detected - migration required');
  }
  const [ivHex, tagHex, encrypted] = ciphertext.split(':');
  if (!ivHex || !tagHex || !encrypted) throw new Error('Malformed encrypted MFA secret');
  const iv = Buffer.from(ivHex, 'hex');
  const tag = Buffer.from(tagHex, 'hex');
  const decipher = crypto.createDecipheriv('aes-256-gcm', MFA_ENC_KEY, iv);
  decipher.setAuthTag(tag);
  let decrypted = decipher.update(encrypted, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  return decrypted;
}
const JWT_EXPIRES = process.env.JWT_EXPIRES_IN || '7d';
const BCRYPT_ROUNDS = parseInt(process.env.BCRYPT_ROUNDS) || 12;

// Parse JWT_EXPIRES to milliseconds for session expiry sync
function parseExpiresMs(val) {
  const m = /^(\d+)\s*(s|m|h|d|w)$/.exec(val);
  if (!m) return 7 * 24 * 60 * 60 * 1000; // default 7d
  const n = parseInt(m[1]);
  const unit = { s: 1000, m: 60000, h: 3600000, d: 86400000, w: 604800000 }[m[2]];
  return n * unit;
}
const SESSION_EXPIRES_MS = parseExpiresMs(JWT_EXPIRES);

// TOTP replay protection — reject codes used within the same 30s window
function checkTotpReplay(userId) {
  const db = getDB();
  const user = db.prepare('SELECT last_totp_at FROM users WHERE id = ?').get(userId);
  const now = Math.floor(Date.now() / 1000);
  const window = 30; // TOTP time step
  if (user?.last_totp_at && Math.floor(user.last_totp_at / window) >= Math.floor(now / window)) {
    return false; // replay — same time window
  }
  return true;
}
function markTotpUsed(userId) {
  const db = getDB();
  db.prepare('UPDATE users SET last_totp_at = ? WHERE id = ?').run(Math.floor(Date.now() / 1000), userId);
}

// ═══════ INPUT VALIDATION ═══════
function isValidEmail(email) {
  if (!email || typeof email !== 'string') return false;
  if (email.length > 254) return false;
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function sanitizeName(name) {
  if (!name || typeof name !== 'string') return null;
  // Strip control characters and limit length
  return name.replace(/[\x00-\x1F\x7F]/g, '').substring(0, 100).trim() || null;
}

// ═══════ REGISTER ═══════
router.post('/register', async (req, res) => {
  try {
    const { email, password, name } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
    if (!isValidEmail(email)) return res.status(400).json({ error: 'Invalid email format' });
    if (typeof password !== 'string') return res.status(400).json({ error: 'Email and password required' });
    if (password.length < 12) return res.status(400).json({ error: 'Password must be at least 12 characters' });
    if (password.length > 128) return res.status(400).json({ error: 'Password must be 128 characters or less' });
    if (!/[A-Z]/.test(password) || !/[a-z]/.test(password) || !/[0-9]/.test(password)) return res.status(400).json({ error: 'Password must contain uppercase, lowercase, and a number' });

    const safeName = sanitizeName(name);
    const db = getDB();
    const existing = db.prepare('SELECT id FROM users WHERE email = ?').get(email.toLowerCase());
    if (existing) return res.status(409).json({ error: 'Email already registered' });

    const id = uuid();
    const hash = await bcrypt.hash(password, BCRYPT_ROUNDS);
    db.prepare('INSERT INTO users (id, email, password_hash, name) VALUES (?, ?, ?, ?)').run(id, email.toLowerCase(), hash, safeName);

    // Create session and bind to JWT
    const sessionId = uuid();
    const expiresAt = new Date(Date.now() + SESSION_EXPIRES_MS).toISOString();
    db.prepare('INSERT INTO sessions (id, user_id, device_name, ip_address, expires_at) VALUES (?, ?, ?, ?, ?)')
      .run(sessionId, id, req.headers['user-agent']?.substring(0, 100), req.ip, expiresAt);

    const token = jwt.sign({ id, email: email.toLowerCase(), plan: 'free', sid: sessionId }, JWT_SECRET, { expiresIn: JWT_EXPIRES });

    auditLog(id, 'register', null, req);

    res.status(201).json({
      token,
      user: { id, email: email.toLowerCase(), name: safeName, plan: 'free', mfa_enabled: 0 }
    });
  } catch (err) {
    res.status(500).json({ error: 'Registration failed' });
  }
});

// ═══════ LOGIN ═══════
router.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password || typeof password !== 'string') return res.status(400).json({ error: 'Email and password required' });
    if (!isValidEmail(email)) return res.status(400).json({ error: 'Invalid email format' });

    const db = getDB();
    const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email.toLowerCase());
    if (!user) {
      console.log(`[AUTH] Failed login attempt for ${email.replace(/(.{2}).*(@.*)/, '$1***$2')} at ${new Date().toISOString()} from ${req.ip}`);
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const valid = await bcrypt.compare(password, user.password_hash);
    if (!valid) {
      console.log(`[AUTH] Failed login attempt for ${email.replace(/(.{2}).*(@.*)/, '$1***$2')} at ${new Date().toISOString()} from ${req.ip}`);
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Update last login
    db.prepare('UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?').run(user.id);

    // If 2FA is enabled, return a temporary token instead of a full session
    if (user.mfa_enabled) {
      const tempToken = jwt.sign(
        { id: user.id, email: user.email, plan: user.plan, purpose: '2fa-verify' },
        JWT_SECRET,
        { expiresIn: '5m' }
      );
      return res.json({ requires2fa: true, tempToken });
    }

    // Create session and bind to JWT
    const sessionId = uuid();
    const expiresAt = new Date(Date.now() + SESSION_EXPIRES_MS).toISOString();
    db.prepare('INSERT INTO sessions (id, user_id, device_name, ip_address, expires_at) VALUES (?, ?, ?, ?, ?)')
      .run(sessionId, user.id, req.headers['user-agent']?.substring(0, 100), req.ip, expiresAt);

    const token = jwt.sign({ id: user.id, email: user.email, plan: user.plan, sid: sessionId }, JWT_SECRET, { expiresIn: JWT_EXPIRES });

    auditLog(user.id, 'login', null, req);

    res.json({
      token,
      user: { id: user.id, email: user.email, name: user.name, plan: user.plan, mfa_enabled: user.mfa_enabled }
    });
  } catch (err) {
    res.status(500).json({ error: 'Login failed' });
  }
});

// ═══════ 2FA: SETUP ═══════
router.post('/2fa/setup', authenticate, async (req, res) => {
  try {
    const { currentPassword } = req.body;
    if (!currentPassword || typeof currentPassword !== 'string') return res.status(400).json({ error: 'Current password required' });
    const db = getDB();
    const user = db.prepare('SELECT email, password_hash, mfa_enabled FROM users WHERE id = ?').get(req.user.id);
    if (!user) return res.status(404).json({ error: 'User not found' });
    const valid = await bcrypt.compare(currentPassword, user.password_hash);
    if (!valid) return res.status(401).json({ error: 'Wrong password' });

    const secret = authenticator.generateSecret();
    const otpauthUri = authenticator.keyuri(user.email, 'WARDKEY', secret);
    const qrDataUri = await QRCode.toDataURL(otpauthUri);

    // Store secret encrypted, keep mfa_enabled=0 until confirmed
    db.prepare('UPDATE users SET mfa_secret = ? WHERE id = ?').run(encryptMfaSecret(secret), req.user.id);

    auditLog(req.user.id, '2fa_setup', null, req);
    res.json({ secret, qrDataUri });
  } catch (err) {
    res.status(500).json({ error: '2FA setup failed' });
  }
});

// ═══════ 2FA: CONFIRM (enable after scanning QR) ═══════
router.post('/2fa/confirm', authenticate, async (req, res) => {
  try {
    const { totpCode } = req.body;
    if (!totpCode || typeof totpCode !== 'string' || !/^\d{6}$/.test(totpCode)) return res.status(400).json({ error: 'TOTP code must be 6 digits' });

    const db = getDB();
    const user = db.prepare('SELECT mfa_secret FROM users WHERE id = ?').get(req.user.id);
    if (!user || !user.mfa_secret) return res.status(400).json({ error: '2FA not set up — call /2fa/setup first' });

    const decryptedSecret = decryptMfaSecret(user.mfa_secret);
    const isValid = authenticator.check(totpCode, decryptedSecret);
    if (!isValid) return res.status(400).json({ error: 'Invalid code — please try again' });
    if (!checkTotpReplay(req.user.id)) return res.status(429).json({ error: 'Code already used — wait for a new code' });
    markTotpUsed(req.user.id);

    db.prepare('UPDATE users SET mfa_enabled = 1 WHERE id = ?').run(req.user.id);
    auditLog(req.user.id, '2fa_enabled', null, req);
    res.json({ success: true, message: '2FA enabled successfully' });
  } catch (err) {
    res.status(500).json({ error: '2FA confirmation failed' });
  }
});

// ═══════ 2FA: VERIFY LOGIN (complete login after 2FA) ═══════
router.post('/2fa/verify-login', async (req, res) => {
  try {
    const { tempToken, totpCode } = req.body;
    if (!tempToken || !totpCode || typeof totpCode !== 'string' || !/^\d{6}$/.test(totpCode)) return res.status(400).json({ error: 'TOTP code must be 6 digits' });

    let decoded;
    try {
      decoded = jwt.verify(tempToken, JWT_SECRET, { algorithms: ['HS256'] });
    } catch (err) {
      return res.status(401).json({ error: 'Token expired or invalid — please log in again' });
    }

    if (decoded.purpose !== '2fa-verify') {
      return res.status(401).json({ error: 'Invalid token purpose' });
    }

    const db = getDB();
    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(decoded.id);
    if (!user || !user.mfa_secret) return res.status(401).json({ error: 'Invalid user or 2FA not configured' });

    const decryptedSecret = decryptMfaSecret(user.mfa_secret);
    const isValid = authenticator.check(totpCode, decryptedSecret);
    if (!isValid) {
      console.log(`[AUTH] Failed 2FA attempt for ${user.email.replace(/(.{2}).*(@.*)/, '$1***$2')} at ${new Date().toISOString()} from ${req.ip}`);
      return res.status(401).json({ error: 'Invalid 2FA code' });
    }
    if (!checkTotpReplay(decoded.id)) return res.status(429).json({ error: 'Code already used — wait for a new code' });
    markTotpUsed(decoded.id);

    // Issue full token and create session (bound to JWT)
    const sessionId = uuid();
    const expiresAt = new Date(Date.now() + SESSION_EXPIRES_MS).toISOString();
    db.prepare('INSERT INTO sessions (id, user_id, device_name, ip_address, expires_at) VALUES (?, ?, ?, ?, ?)')
      .run(sessionId, user.id, req.headers['user-agent']?.substring(0, 100), req.ip, expiresAt);

    const token = jwt.sign({ id: user.id, email: user.email, plan: user.plan, sid: sessionId }, JWT_SECRET, { expiresIn: JWT_EXPIRES });

    auditLog(user.id, 'login', null, req, { method: '2fa' });

    res.json({
      token,
      user: { id: user.id, email: user.email, name: user.name, plan: user.plan, mfa_enabled: user.mfa_enabled }
    });
  } catch (err) {
    res.status(500).json({ error: '2FA verification failed' });
  }
});

// ═══════ 2FA: DISABLE ═══════
router.post('/2fa/disable', authenticate, async (req, res) => {
  try {
    const { totpCode } = req.body;
    if (!totpCode || typeof totpCode !== 'string' || !/^\d{6}$/.test(totpCode)) return res.status(400).json({ error: 'TOTP code must be 6 digits' });

    const db = getDB();
    const user = db.prepare('SELECT mfa_secret, mfa_enabled FROM users WHERE id = ?').get(req.user.id);
    if (!user || !user.mfa_enabled) return res.status(400).json({ error: '2FA is not enabled' });

    const decryptedSecret = decryptMfaSecret(user.mfa_secret);
    const isValid = authenticator.check(totpCode, decryptedSecret);
    if (!isValid) return res.status(400).json({ error: 'Invalid code — please try again' });
    if (!checkTotpReplay(req.user.id)) return res.status(429).json({ error: 'Code already used — wait for a new code' });
    markTotpUsed(req.user.id);

    db.prepare('UPDATE users SET mfa_enabled = 0, mfa_secret = NULL WHERE id = ?').run(req.user.id);

    // Revoke all other sessions for security
    const currentSid = req.user.sid;
    if (currentSid) {
      db.prepare('UPDATE sessions SET revoked = 1 WHERE user_id = ? AND id != ?').run(req.user.id, currentSid);
    } else {
      db.prepare('UPDATE sessions SET revoked = 1 WHERE user_id = ?').run(req.user.id);
    }

    auditLog(req.user.id, '2fa_disabled', null, req);
    res.json({ success: true, message: '2FA disabled' });
  } catch (err) {
    res.status(500).json({ error: '2FA disable failed' });
  }
});

// ═══════ PROFILE ═══════
router.get('/me', authenticate, (req, res) => {
  const db = getDB();
  const user = db.prepare('SELECT id, email, name, plan, created_at, last_login, mfa_enabled FROM users WHERE id = ?').get(req.user.id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  res.json({ user });
});

router.patch('/me', authenticate, sensitiveAuthLimiter, async (req, res) => {
  const { name, currentPassword, newPassword } = req.body;
  const db = getDB();

  if (name !== undefined) {
    const safeName = sanitizeName(name);
    db.prepare('UPDATE users SET name = ? WHERE id = ?').run(safeName, req.user.id);
  }

  if (newPassword) {
    if (!currentPassword || typeof currentPassword !== 'string') return res.status(400).json({ error: 'Current password required' });
    if (typeof newPassword !== 'string') return res.status(400).json({ error: 'New password must be a string' });
    if (newPassword.length < 12) return res.status(400).json({ error: 'New password must be at least 12 characters' });
    if (newPassword.length > 128) return res.status(400).json({ error: 'New password must be 128 characters or less' });
    if (!/[A-Z]/.test(newPassword) || !/[a-z]/.test(newPassword) || !/[0-9]/.test(newPassword)) return res.status(400).json({ error: 'New password must contain uppercase, lowercase, and a number' });
    const user = db.prepare('SELECT password_hash FROM users WHERE id = ?').get(req.user.id);
    const valid = await bcrypt.compare(currentPassword, user.password_hash);
    if (!valid) return res.status(401).json({ error: 'Current password incorrect' });

    const hash = await bcrypt.hash(newPassword, BCRYPT_ROUNDS);
    db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(hash, req.user.id);

    // Revoke all other sessions (force re-login on other devices)
    const currentSid = req.user.sid;
    if (currentSid) {
      db.prepare('UPDATE sessions SET revoked = 1 WHERE user_id = ? AND id != ?').run(req.user.id, currentSid);
    } else {
      db.prepare('UPDATE sessions SET revoked = 1 WHERE user_id = ?').run(req.user.id);
    }

    auditLog(req.user.id, 'password_changed', null, req);
  }

  res.json({ success: true });
});

// ═══════ SESSIONS ═══════
router.get('/sessions', authenticate, (req, res) => {
  const db = getDB();
  const sessions = db.prepare('SELECT id, device_name, ip_address, created_at FROM sessions WHERE user_id = ? AND revoked = 0 ORDER BY created_at DESC').all(req.user.id);
  res.json({ sessions });
});

router.delete('/sessions/:id', authenticate, (req, res) => {
  const db = getDB();
  db.prepare('UPDATE sessions SET revoked = 1 WHERE id = ? AND user_id = ?').run(req.params.id, req.user.id);
  auditLog(req.user.id, 'session_revoked', req.params.id, req);
  res.json({ success: true });
});

// ═══════ DELETE ACCOUNT ═══════
router.delete('/me', authenticate, sensitiveAuthLimiter, async (req, res) => {
  const { password } = req.body;
  if (!password || typeof password !== 'string') return res.status(400).json({ error: 'Password required for account deletion' });

  const db = getDB();
  const user = db.prepare('SELECT password_hash FROM users WHERE id = ?').get(req.user.id);
  const valid = await bcrypt.compare(password, user.password_hash);
  if (!valid) return res.status(401).json({ error: 'Invalid password' });

  // Explicitly delete all user data in a transaction (don't rely solely on CASCADE)
  const deleteAccount = db.transaction(() => {
    db.prepare('DELETE FROM vaults WHERE user_id = ?').run(req.user.id);
    db.prepare('DELETE FROM shares WHERE user_id = ?').run(req.user.id);
    db.prepare('DELETE FROM sync_log WHERE user_id = ?').run(req.user.id);
    db.prepare('DELETE FROM sessions WHERE user_id = ?').run(req.user.id);
    db.prepare('DELETE FROM emergency_contacts WHERE grantor_id = ? OR grantee_id = ?').run(req.user.id, req.user.id);
    db.prepare('DELETE FROM audit_log WHERE user_id = ?').run(req.user.id);
    db.prepare('DELETE FROM users WHERE id = ?').run(req.user.id);
  });
  deleteAccount();
  res.json({ success: true, message: 'Account and all data permanently deleted' });
});

module.exports = router;
module.exports.isValidEmail = isValidEmail;
