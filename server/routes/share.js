// WARDKEY Share Routes — One-time secure links
const express = require('express');
const crypto = require('crypto');
const { getDB, auditLog } = require('../models/db');
const { authenticate, optionalAuth } = require('../middleware/auth');

const router = express.Router();

// ═══════ CREATE SHARE LINK ═══════
router.post('/', authenticate, (req, res) => {
  const { encryptedData, iv, maxViews, expiresInHours } = req.body;
  if (!encryptedData || !iv || typeof encryptedData !== 'string' || typeof iv !== 'string') {
    return res.status(400).json({ error: 'Missing encrypted data' });
  }
  if (encryptedData.length > 1048576) {
    return res.status(413).json({ error: 'Share data exceeds maximum size (1MB)' });
  }

  const db = getDB();

  const id = crypto.randomBytes(16).toString('hex');
  const safeExpiresInHours = typeof expiresInHours === 'number' && expiresInHours > 0 ? expiresInHours : 24;
  const hours = Math.min(safeExpiresInHours, 30 * 24); // Max 30 days
  const expiresAt = new Date(Date.now() + hours * 60 * 60 * 1000).toISOString();
  const views = Math.min(maxViews || 1, 100);

  // Atomic plan check + insert in a transaction to prevent race conditions
  const createShare = db.transaction(() => {
    const user = db.prepare('SELECT plan FROM users WHERE id = ?').get(req.user.id);
    if (user?.plan === 'free') {
      const activeShares = db.prepare("SELECT COUNT(*) as count FROM shares WHERE user_id = ? AND revoked = 0 AND expires_at > datetime('now')").get(req.user.id);
      if (activeShares.count >= 5) {
        return { error: 'Free plan limited to 5 active share links. Upgrade to Pro for unlimited.' };
      }
    }

    db.prepare('INSERT INTO shares (id, user_id, encrypted_data, iv, max_views, expires_at) VALUES (?, ?, ?, ?, ?, ?)')
      .run(id, req.user.id, encryptedData, iv, views, expiresAt);
    return null;
  });

  const err = createShare();
  if (err) return res.status(403).json(err);

  const baseUrl = process.env.SHARE_BASE_URL || 'https://wardkey.io/s';

  auditLog(req.user.id, 'share_created', id, req);

  res.status(201).json({
    id,
    url: `${baseUrl}/${id}`,
    expiresAt,
    maxViews: views
  });
});

// ═══════ VIEW SHARE (PUBLIC) ═══════
router.get('/:id', (req, res) => {
  const db = getDB();

  // Atomic view: transaction prevents race condition on concurrent requests
  const viewShare = db.transaction(() => {
    const share = db.prepare('SELECT * FROM shares WHERE id = ?').get(req.params.id);
    if (!share) return { status: 404, error: 'Share link not found or no longer available' };
    if (share.revoked || new Date(share.expires_at) < new Date() || share.current_views >= share.max_views) {
      return { status: 404, error: 'Share link not found or no longer available' };
    }

    db.prepare('UPDATE shares SET current_views = current_views + 1 WHERE id = ?').run(share.id);
    return { share };
  });

  const result = viewShare();
  if (result.error) return res.status(result.status).json({ error: result.error });

  const share = result.share;
  res.json({
    data: share.encrypted_data,
    iv: share.iv,
    viewsRemaining: share.max_views - share.current_views - 1,
    expiresAt: share.expires_at
  });
});

// ═══════ LIST MY SHARES ═══════
router.get('/', authenticate, (req, res) => {
  const db = getDB();
  const shares = db.prepare(`
    SELECT id, max_views, current_views, expires_at, created_at, revoked,
           CASE WHEN revoked = 1 THEN 'revoked'
                WHEN expires_at < datetime('now') THEN 'expired'
                WHEN current_views >= max_views THEN 'exhausted'
                ELSE 'active' END as status
    FROM shares WHERE user_id = ? ORDER BY created_at DESC LIMIT 50
  `).all(req.user.id);

  res.json({ shares });
});

// ═══════ REVOKE SHARE ═══════
router.delete('/:id', authenticate, (req, res) => {
  const db = getDB();
  const result = db.prepare('UPDATE shares SET revoked = 1 WHERE id = ? AND user_id = ?').run(req.params.id, req.user.id);
  if (result.changes === 0) return res.status(404).json({ error: 'Share not found' });
  auditLog(req.user.id, 'share_revoked', req.params.id, req);
  res.json({ success: true });
});

module.exports = router;
