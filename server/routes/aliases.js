// WARDKEY Email Alias Routes
const express = require('express');
const { v4: uuid } = require('uuid');
const crypto = require('crypto');
const { getDB, auditLog } = require('../models/db');
const { authenticate } = require('../middleware/auth');
const { isValidEmail } = require('./auth');

const router = express.Router();
const ALIAS_DOMAIN = process.env.ALIAS_DOMAIN || 'wardkey.email';

// ═══════ LIST ALIASES ═══════
router.get('/', authenticate, (req, res) => {
  const db = getDB();
  const aliases = db.prepare('SELECT * FROM aliases WHERE user_id = ? ORDER BY created_at DESC').all(req.user.id);
  res.json({ aliases });
});

// ═══════ CREATE ALIAS ═══════
router.post('/', authenticate, (req, res) => {
  const { label, targetEmail } = req.body;
  const db = getDB();

  // Validate label
  let safeLabel = label;
  if (label !== undefined && label !== null) {
    if (typeof label !== 'string' || label.length > 100) {
      return res.status(400).json({ error: 'Label must be a string of 100 characters or less' });
    }
    safeLabel = label.replace(/[\x00-\x1F\x7F]/g, '').trim() || null;
  }

  // Validate targetEmail
  if (targetEmail && !isValidEmail(targetEmail)) {
    return res.status(400).json({ error: 'Invalid target email format' });
  }

  // Check plan limits (free: 3, pro: unlimited)
  const user = db.prepare('SELECT plan, email FROM users WHERE id = ?').get(req.user.id);
  if (user?.plan === 'free') {
    const count = db.prepare('SELECT COUNT(*) as count FROM aliases WHERE user_id = ?').get(req.user.id);
    if (count.count >= 3) {
      return res.status(403).json({ error: 'Free plan limited to 3 aliases. Upgrade to Pro for unlimited.' });
    }
  }

  // Generate random alias
  const random = crypto.randomBytes(4).toString('hex');
  const prefix = (user?.email?.split('@')[0] || 'user').substring(0, 10).replace(/[^a-z0-9]/gi, '');
  const alias = `${prefix}.${random}@${ALIAS_DOMAIN}`;
  const target = targetEmail || user?.email;

  if (!target) return res.status(400).json({ error: 'Target email required' });

  const id = uuid();
  db.prepare('INSERT INTO aliases (id, user_id, alias, target_email, label) VALUES (?, ?, ?, ?, ?)')
    .run(id, req.user.id, alias, target, safeLabel || null);

  auditLog(req.user.id, 'alias_created', alias, req);

  res.status(201).json({
    id,
    alias,
    targetEmail: target,
    label: safeLabel,
    active: true,
    forwardedCount: 0
  });
});

// ═══════ TOGGLE ALIAS ═══════
router.patch('/:id', authenticate, (req, res) => {
  const { active, label } = req.body;
  const db = getDB();

  const alias = db.prepare('SELECT * FROM aliases WHERE id = ? AND user_id = ?').get(req.params.id, req.user.id);
  if (!alias) return res.status(404).json({ error: 'Alias not found' });

  if (active !== undefined) {
    db.prepare('UPDATE aliases SET active = ? WHERE id = ?').run(active ? 1 : 0, req.params.id);
  }
  if (label !== undefined) {
    if (label !== null && (typeof label !== 'string' || label.length > 100)) {
      return res.status(400).json({ error: 'Label must be a string of 100 characters or less' });
    }
    const safeLabel = label ? label.replace(/[\x00-\x1F\x7F]/g, '').trim() || null : null;
    db.prepare('UPDATE aliases SET label = ? WHERE id = ?').run(safeLabel, req.params.id);
  }

  res.json({ success: true });
});

// ═══════ DELETE ALIAS ═══════
router.delete('/:id', authenticate, (req, res) => {
  const db = getDB();
  const result = db.prepare('DELETE FROM aliases WHERE id = ? AND user_id = ?').run(req.params.id, req.user.id);
  if (result.changes === 0) return res.status(404).json({ error: 'Alias not found' });
  auditLog(req.user.id, 'alias_deleted', req.params.id, req);
  res.json({ success: true });
});

// ═══════ INCOMING EMAIL WEBHOOK ═══════
// This endpoint receives forwarded emails from your mail server (Cloudflare Email Routing, Postfix, etc.)
router.post('/incoming', async (req, res) => {
  // Authenticate webhook requests — timing-safe comparison to prevent timing attacks
  const expected = process.env.WEBHOOK_SECRET || '';
  const provided = req.headers['x-webhook-secret'] || '';
  const expectedBuf = Buffer.from(expected.padEnd(64, '\0'));
  const providedBuf = Buffer.from(provided.padEnd(64, '\0'));
  if (!expected || !crypto.timingSafeEqual(expectedBuf, providedBuf)) {
    return res.status(401).json({ error: 'Unauthorized webhook request' });
  }

  const { to, from, subject } = req.body;
  if (!to) return res.status(400).json({ error: 'Missing recipient' });

  const db = getDB();
  const alias = db.prepare('SELECT * FROM aliases WHERE alias = ? AND active = 1').get(to.toLowerCase());

  if (!alias) {
    return res.status(404).json({ error: 'Alias not found or inactive', bounce: true });
  }

  // Increment counter
  db.prepare('UPDATE aliases SET forwarded_count = forwarded_count + 1 WHERE id = ?').run(alias.id);

  // In production: use nodemailer to forward the email to alias.target_email
  // For now, just acknowledge
  res.json({
    forward: true,
    target: alias.target_email,
    aliasId: alias.id
  });
});

module.exports = router;
