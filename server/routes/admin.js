// WARDKEY Admin API — Mission Control Backend
const express = require('express');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const { getDB, auditLog } = require('../models/db');
const path = require('path');
const fs = require('fs');

const router = express.Router();

// Admin CORS handled in server.js — no duplicate needed here

// ═══════ ADMIN AUTH ═══════
function requireAdmin(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Missing admin token' });
  }
  try {
    const decoded = jwt.verify(auth.slice(7), process.env.JWT_SECRET, { algorithms: ['HS256'] });
    if (decoded.role !== 'admin') {
      return res.status(403).json({ error: 'Not an admin token' });
    }
    req.admin = decoded;
    next();
  } catch {
    return res.status(401).json({ error: 'Invalid or expired admin token' });
  }
}

// Whitelist for sort/order validation
const VALID_SORT = ['created_at', 'last_login', 'email', 'name', 'plan'];
const VALID_ORDER = ['asc', 'desc'];

// ═══════ AUTH ═══════

// POST /api/admin/login
router.post('/login', (req, res) => {
  const { secret } = req.body || {};
  const adminSecret = process.env.ADMIN_SECRET;

  if (!adminSecret) {
    return res.status(403).json({ error: 'Admin access is not configured' });
  }
  if (!secret || typeof secret !== 'string') {
    return res.status(400).json({ error: 'Secret is required' });
  }

  // Constant-time comparison via SHA-256 (fixed-length hashes prevent length leaks)
  const aHash = crypto.createHash('sha256').update(secret).digest();
  const bHash = crypto.createHash('sha256').update(adminSecret).digest();
  if (!crypto.timingSafeEqual(aHash, bHash)) {
    return res.status(401).json({ error: 'Invalid secret' });
  }

  const { v4: adminJti } = require('uuid');
  const token = jwt.sign({ role: 'admin', jti: adminJti() }, process.env.JWT_SECRET, { expiresIn: '15m' });
  auditLog(null, 'admin_login', null, req);
  res.json({ token });
});

// ═══════ OVERVIEW ═══════

// GET /api/admin/overview?days=30
router.get('/overview', requireAdmin, (req, res) => {
  try {
    const db = getDB();
    const days = Math.min(Math.max(parseInt(req.query.days) || 30, 1), 365);

    // KPIs
    const totalUsers = db.prepare('SELECT COUNT(*) as c FROM users').get().c;
    const activeToday = db.prepare(
      "SELECT COUNT(*) as c FROM users WHERE date(last_login) = date('now')"
    ).get().c;
    const proSubscribers = db.prepare("SELECT COUNT(*) as c FROM users WHERE plan = 'pro'").get().c;
    const totalVaults = db.prepare('SELECT COUNT(*) as c FROM vaults').get().c;
    const totalSyncs = db.prepare('SELECT COUNT(*) as c FROM sync_log').get().c;
    const totalShares = db.prepare('SELECT COUNT(*) as c FROM shares').get().c;
    const activeShares = db.prepare(
      "SELECT COUNT(*) as c FROM shares WHERE revoked = 0 AND expires_at > datetime('now') AND current_views < max_views"
    ).get().c;
    const totalAliases = db.prepare('SELECT COUNT(*) as c FROM aliases').get().c;
    const activeAliases = db.prepare('SELECT COUNT(*) as c FROM aliases WHERE active = 1').get().c;
    const mfaEnabled = db.prepare('SELECT COUNT(*) as c FROM users WHERE mfa_enabled = 1').get().c;

    // Signups by day
    const signups = db.prepare(`
      SELECT date(created_at) as day, COUNT(*) as count
      FROM users
      WHERE created_at >= datetime('now', '-' || ? || ' days')
      GROUP BY date(created_at)
      ORDER BY day ASC
    `).all(days);

    // Recent activity
    const activity = db.prepare(`
      SELECT a.id, a.user_id, a.action, a.target, a.ip_address, a.created_at,
             u.email
      FROM audit_log a
      LEFT JOIN users u ON a.user_id = u.id
      ORDER BY a.created_at DESC
      LIMIT 20
    `).all();

    res.json({
      kpis: {
        totalUsers, activeToday, proSubscribers, totalVaults, totalSyncs,
        totalShares, activeShares, totalAliases, activeAliases, mfaEnabled
      },
      signups,
      activity
    });
  } catch (err) {
    console.error('Admin overview error:', err.message);
    res.status(500).json({ error: 'Failed to load overview' });
  }
});

// ═══════ USERS ═══════

// GET /api/admin/users
router.get('/users', requireAdmin, (req, res) => {
  try {
    const db = getDB();
    const search = req.query.search || '';
    // SECURITY REVIEW: sort and order are strictly validated against whitelists before interpolation
    // This is safe because the values can only be one of the predefined constants
    const sort = VALID_SORT.includes(req.query.sort) ? req.query.sort : 'created_at';
    const order = VALID_ORDER.includes((req.query.order || '').toLowerCase()) ? req.query.order.toLowerCase() : 'desc';
    const page = Math.max(parseInt(req.query.page) || 1, 1);
    const limit = Math.min(Math.max(parseInt(req.query.limit) || 25, 1), 100);
    const offset = (page - 1) * limit;

    let where = '';
    const params = [];
    if (search) {
      where = "WHERE u.email LIKE ? OR u.name LIKE ?";
      params.push(`%${search}%`, `%${search}%`);
    }

    const total = db.prepare(`SELECT COUNT(*) as c FROM users u ${where}`).get(...params).c;

    const users = db.prepare(`
      SELECT u.id, u.email, u.name, u.plan, u.mfa_enabled, u.created_at, u.last_login,
             COALESCE(v.size_bytes, 0) as vault_size,
             (SELECT COUNT(*) FROM sessions s WHERE s.user_id = u.id AND s.revoked = 0) as session_count
      FROM users u
      LEFT JOIN vaults v ON v.user_id = u.id
      ${where}
      ORDER BY u.${sort} ${order}
      LIMIT ? OFFSET ?
    `).all(...params, limit, offset);

    res.json({ users, total, page, limit, pages: Math.ceil(total / limit) });
  } catch (err) {
    console.error('Admin users list error:', err.message);
    res.status(500).json({ error: 'Failed to load users' });
  }
});

// GET /api/admin/users/:id
router.get('/users/:id', requireAdmin, (req, res) => {
  try {
    const db = getDB();
    const user = db.prepare(
      'SELECT id, email, name, plan, mfa_enabled, created_at, last_login FROM users WHERE id = ?'
    ).get(req.params.id);

    if (!user) return res.status(404).json({ error: 'User not found' });

    const vault = db.prepare(
      'SELECT id, version, size_bytes, updated_at FROM vaults WHERE user_id = ?'
    ).get(user.id);

    const sessions = db.prepare(
      'SELECT id, device_name, ip_address, created_at, expires_at, revoked FROM sessions WHERE user_id = ? ORDER BY created_at DESC'
    ).all(user.id);

    const sharesCount = db.prepare('SELECT COUNT(*) as c FROM shares WHERE user_id = ?').get(user.id).c;
    const aliasesCount = db.prepare('SELECT COUNT(*) as c FROM aliases WHERE user_id = ?').get(user.id).c;

    const recentAudit = db.prepare(
      'SELECT id, action, target, ip_address, created_at FROM audit_log WHERE user_id = ? ORDER BY created_at DESC LIMIT 10'
    ).all(user.id);

    res.json({ user, vault, sessions, sharesCount, aliasesCount, recentAudit });
  } catch (err) {
    console.error('Admin user detail error:', err.message);
    res.status(500).json({ error: 'Failed to load user detail' });
  }
});

// PATCH /api/admin/users/:id/plan
router.patch('/users/:id/plan', requireAdmin, (req, res) => {
  try {
    const db = getDB();
    const { plan } = req.body || {};
    if (!['free', 'pro'].includes(plan)) {
      return res.status(400).json({ error: 'Plan must be "free" or "pro"' });
    }

    const user = db.prepare('SELECT id, email, plan as oldPlan FROM users WHERE id = ?').get(req.params.id);
    if (!user) return res.status(404).json({ error: 'User not found' });

    db.prepare('UPDATE users SET plan = ? WHERE id = ?').run(plan, user.id);
    auditLog(null, 'admin_plan_change', user.id, req, { email: user.email, from: user.oldPlan, to: plan });

    res.json({ success: true, plan });
  } catch (err) {
    console.error('Admin plan change error:', err.message);
    res.status(500).json({ error: 'Failed to update plan' });
  }
});

// DELETE /api/admin/users/:id/sessions/:sid — Revoke single session
router.delete('/users/:id/sessions/:sid', requireAdmin, (req, res) => {
  try {
    const db = getDB();
    const result = db.prepare(
      'UPDATE sessions SET revoked = 1 WHERE id = ? AND user_id = ?'
    ).run(req.params.sid, req.params.id);

    if (result.changes === 0) return res.status(404).json({ error: 'Session not found' });
    auditLog(null, 'admin_session_revoked', req.params.sid, req, { userId: req.params.id });
    res.json({ success: true });
  } catch (err) {
    console.error('Admin revoke session error:', err.message);
    res.status(500).json({ error: 'Failed to revoke session' });
  }
});

// DELETE /api/admin/users/:id/sessions — Revoke ALL sessions
router.delete('/users/:id/sessions', requireAdmin, (req, res) => {
  try {
    const db = getDB();
    const result = db.prepare(
      'UPDATE sessions SET revoked = 1 WHERE user_id = ? AND revoked = 0'
    ).run(req.params.id);

    auditLog(null, 'admin_all_sessions_revoked', req.params.id, req, { count: result.changes });
    res.json({ success: true, revoked: result.changes });
  } catch (err) {
    console.error('Admin revoke all sessions error:', err.message);
    res.status(500).json({ error: 'Failed to revoke sessions' });
  }
});

// DELETE /api/admin/users/:id — Delete user + cascade
router.delete('/users/:id', requireAdmin, (req, res) => {
  try {
    const db = getDB();
    const user = db.prepare('SELECT id, email FROM users WHERE id = ?').get(req.params.id);
    if (!user) return res.status(404).json({ error: 'User not found' });

    // Explicitly delete all user data in a transaction (don't rely solely on CASCADE)
    const deleteUser = db.transaction(() => {
      db.prepare('DELETE FROM vaults WHERE user_id = ?').run(user.id);
      db.prepare('DELETE FROM shares WHERE user_id = ?').run(user.id);
      db.prepare('DELETE FROM aliases WHERE user_id = ?').run(user.id);
      db.prepare('DELETE FROM sync_log WHERE user_id = ?').run(user.id);
      db.prepare('DELETE FROM sessions WHERE user_id = ?').run(user.id);
      db.prepare('DELETE FROM emergency_contacts WHERE grantor_id = ? OR grantee_id = ?').run(user.id, user.id);
      db.prepare('DELETE FROM audit_log WHERE user_id = ?').run(user.id);
      db.prepare('DELETE FROM users WHERE id = ?').run(user.id);
    });
    deleteUser();
    auditLog(null, 'admin_user_deleted', user.id, req, { email: user.email });
    res.json({ success: true });
  } catch (err) {
    console.error('Admin delete user error:', err.message);
    res.status(500).json({ error: 'Failed to delete user' });
  }
});

// ═══════ AUDIT ═══════

// GET /api/admin/audit
router.get('/audit', requireAdmin, (req, res) => {
  try {
    const db = getDB();
    const page = Math.max(parseInt(req.query.page) || 1, 1);
    const limit = Math.min(Math.max(parseInt(req.query.limit) || 50, 1), 200);
    const offset = (page - 1) * limit;

    const conditions = [];
    const params = [];

    if (req.query.action) {
      conditions.push('a.action = ?');
      params.push(req.query.action);
    }
    if (req.query.user) {
      conditions.push('(u.email LIKE ? OR a.user_id = ?)');
      params.push(`%${req.query.user}%`, req.query.user);
    }
    if (req.query.ip) {
      conditions.push('a.ip_address LIKE ?');
      params.push(`%${req.query.ip}%`);
    }
    if (req.query.from) {
      conditions.push('a.created_at >= ?');
      params.push(req.query.from);
    }
    if (req.query.to) {
      conditions.push('a.created_at <= ?');
      params.push(req.query.to + ' 23:59:59');
    }

    const where = conditions.length ? 'WHERE ' + conditions.join(' AND ') : '';

    const total = db.prepare(`
      SELECT COUNT(*) as c FROM audit_log a LEFT JOIN users u ON a.user_id = u.id ${where}
    `).get(...params).c;

    const entries = db.prepare(`
      SELECT a.id, a.user_id, a.action, a.target, a.ip_address, a.user_agent, a.metadata, a.created_at,
             u.email
      FROM audit_log a
      LEFT JOIN users u ON a.user_id = u.id
      ${where}
      ORDER BY a.created_at DESC
      LIMIT ? OFFSET ?
    `).all(...params, limit, offset);

    res.json({ entries, total, page, limit, pages: Math.ceil(total / limit) });
  } catch (err) {
    console.error('Admin audit error:', err.message);
    res.status(500).json({ error: 'Failed to load audit log' });
  }
});

// GET /api/admin/audit/actions — distinct action types
router.get('/audit/actions', requireAdmin, (req, res) => {
  try {
    const db = getDB();
    const actions = db.prepare('SELECT DISTINCT action FROM audit_log ORDER BY action').all();
    res.json(actions.map(a => a.action));
  } catch (err) {
    console.error('Admin audit actions error:', err.message);
    res.status(500).json({ error: 'Failed to load action types' });
  }
});

// ═══════ SHARES ═══════

// GET /api/admin/shares
router.get('/shares', requireAdmin, (req, res) => {
  try {
    const db = getDB();
    const page = Math.max(parseInt(req.query.page) || 1, 1);
    const limit = Math.min(Math.max(parseInt(req.query.limit) || 25, 1), 100);
    const offset = (page - 1) * limit;
    const status = req.query.status || '';
    const search = req.query.search || '';

    const conditions = [];
    const params = [];

    if (status === 'active') {
      conditions.push("s.revoked = 0 AND s.expires_at > datetime('now') AND s.current_views < s.max_views");
    } else if (status === 'revoked') {
      conditions.push('s.revoked = 1');
    } else if (status === 'expired') {
      conditions.push("s.revoked = 0 AND (s.expires_at <= datetime('now') OR s.current_views >= s.max_views)");
    }
    if (search) {
      conditions.push('u.email LIKE ?');
      params.push(`%${search}%`);
    }

    const where = conditions.length ? 'WHERE ' + conditions.join(' AND ') : '';

    const total = db.prepare(`SELECT COUNT(*) as c FROM shares s LEFT JOIN users u ON s.user_id = u.id ${where}`).get(...params).c;

    const shares = db.prepare(`
      SELECT s.id, s.user_id, s.max_views, s.current_views, s.expires_at, s.created_at, s.revoked,
             LENGTH(s.encrypted_data) as data_size, u.email
      FROM shares s
      LEFT JOIN users u ON s.user_id = u.id
      ${where}
      ORDER BY s.created_at DESC
      LIMIT ? OFFSET ?
    `).all(...params, limit, offset);

    res.json({ shares, total, page, limit, pages: Math.ceil(total / limit) });
  } catch (err) {
    console.error('Admin shares error:', err.message);
    res.status(500).json({ error: 'Failed to load shares' });
  }
});

// DELETE /api/admin/shares/:id — Revoke a share
router.delete('/shares/:id', requireAdmin, (req, res) => {
  try {
    const db = getDB();
    const result = db.prepare('UPDATE shares SET revoked = 1 WHERE id = ? AND revoked = 0').run(req.params.id);
    if (result.changes === 0) return res.status(404).json({ error: 'Share not found or already revoked' });
    auditLog(null, 'admin_share_revoked', req.params.id, req);
    res.json({ success: true });
  } catch (err) {
    console.error('Admin revoke share error:', err.message);
    res.status(500).json({ error: 'Failed to revoke share' });
  }
});

// ═══════ ALIASES ═══════

// GET /api/admin/aliases
router.get('/aliases', requireAdmin, (req, res) => {
  try {
    const db = getDB();
    const page = Math.max(parseInt(req.query.page) || 1, 1);
    const limit = Math.min(Math.max(parseInt(req.query.limit) || 25, 1), 100);
    const offset = (page - 1) * limit;
    const status = req.query.status || '';
    const search = req.query.search || '';

    const conditions = [];
    const params = [];

    if (status === 'active') {
      conditions.push('a.active = 1');
    } else if (status === 'inactive') {
      conditions.push('a.active = 0');
    }
    if (search) {
      conditions.push('(a.alias LIKE ? OR a.target_email LIKE ? OR u.email LIKE ?)');
      params.push(`%${search}%`, `%${search}%`, `%${search}%`);
    }

    const where = conditions.length ? 'WHERE ' + conditions.join(' AND ') : '';

    const total = db.prepare(`SELECT COUNT(*) as c FROM aliases a LEFT JOIN users u ON a.user_id = u.id ${where}`).get(...params).c;

    const aliases = db.prepare(`
      SELECT a.id, a.user_id, a.alias, a.target_email, a.label, a.active, a.forwarded_count, a.created_at,
             u.email as owner_email
      FROM aliases a
      LEFT JOIN users u ON a.user_id = u.id
      ${where}
      ORDER BY a.created_at DESC
      LIMIT ? OFFSET ?
    `).all(...params, limit, offset);

    res.json({ aliases, total, page, limit, pages: Math.ceil(total / limit) });
  } catch (err) {
    console.error('Admin aliases error:', err.message);
    res.status(500).json({ error: 'Failed to load aliases' });
  }
});

// PATCH /api/admin/aliases/:id — Toggle active status
router.patch('/aliases/:id', requireAdmin, (req, res) => {
  try {
    const db = getDB();
    const alias = db.prepare('SELECT id, alias, active, user_id FROM aliases WHERE id = ?').get(req.params.id);
    if (!alias) return res.status(404).json({ error: 'Alias not found' });

    const newActive = alias.active ? 0 : 1;
    db.prepare('UPDATE aliases SET active = ? WHERE id = ?').run(newActive, alias.id);
    auditLog(null, 'admin_alias_toggled', alias.id, req, { alias: alias.alias, active: newActive });
    res.json({ success: true, active: newActive });
  } catch (err) {
    console.error('Admin toggle alias error:', err.message);
    res.status(500).json({ error: 'Failed to toggle alias' });
  }
});

// DELETE /api/admin/aliases/:id — Delete an alias
router.delete('/aliases/:id', requireAdmin, (req, res) => {
  try {
    const db = getDB();
    const alias = db.prepare('SELECT id, alias FROM aliases WHERE id = ?').get(req.params.id);
    if (!alias) return res.status(404).json({ error: 'Alias not found' });

    db.prepare('DELETE FROM aliases WHERE id = ?').run(alias.id);
    auditLog(null, 'admin_alias_deleted', alias.id, req, { alias: alias.alias });
    res.json({ success: true });
  } catch (err) {
    console.error('Admin delete alias error:', err.message);
    res.status(500).json({ error: 'Failed to delete alias' });
  }
});

// ═══════ SYNC LOG ═══════

// GET /api/admin/syncs
router.get('/syncs', requireAdmin, (req, res) => {
  try {
    const db = getDB();
    const page = Math.max(parseInt(req.query.page) || 1, 1);
    const limit = Math.min(Math.max(parseInt(req.query.limit) || 50, 1), 200);
    const offset = (page - 1) * limit;
    const search = req.query.search || '';
    const action = req.query.action || '';

    const conditions = [];
    const params = [];

    if (search) {
      conditions.push('u.email LIKE ?');
      params.push(`%${search}%`);
    }
    if (action) {
      conditions.push('sl.action = ?');
      params.push(action);
    }

    const where = conditions.length ? 'WHERE ' + conditions.join(' AND ') : '';

    const total = db.prepare(`SELECT COUNT(*) as c FROM sync_log sl LEFT JOIN users u ON sl.user_id = u.id ${where}`).get(...params).c;

    const syncs = db.prepare(`
      SELECT sl.id, sl.user_id, sl.device_id, sl.action, sl.timestamp,
             u.email
      FROM sync_log sl
      LEFT JOIN users u ON sl.user_id = u.id
      ${where}
      ORDER BY sl.timestamp DESC
      LIMIT ? OFFSET ?
    `).all(...params, limit, offset);

    // Distinct sync actions for filter
    const actions = db.prepare('SELECT DISTINCT action FROM sync_log ORDER BY action').all().map(a => a.action);

    res.json({ syncs, actions, total, page, limit, pages: Math.ceil(total / limit) });
  } catch (err) {
    console.error('Admin syncs error:', err.message);
    res.status(500).json({ error: 'Failed to load sync log' });
  }
});

// ═══════ SYSTEM HEALTH ═══════

// GET /api/admin/health
router.get('/health', requireAdmin, (req, res) => {
  try {
    const db = getDB();
    const dbPath = process.env.DB_PATH || './data/wardkey.db';
    let dbSize = 0;
    try {
      const resolved = path.resolve(dbPath);
      dbSize = fs.statSync(resolved).size;
    } catch { /* file might not exist */ }

    const mem = process.memoryUsage();

    const sessionsTotal = db.prepare('SELECT COUNT(*) as c FROM sessions').get().c;
    const sessionsActive = db.prepare(
      "SELECT COUNT(*) as c FROM sessions WHERE revoked = 0 AND expires_at > datetime('now')"
    ).get().c;
    const sessionsRevoked = db.prepare('SELECT COUNT(*) as c FROM sessions WHERE revoked = 1').get().c;

    const sharesTotal = db.prepare('SELECT COUNT(*) as c FROM shares').get().c;
    const sharesActive = db.prepare(
      "SELECT COUNT(*) as c FROM shares WHERE revoked = 0 AND expires_at > datetime('now') AND current_views < max_views"
    ).get().c;

    const aliasesTotal = db.prepare('SELECT COUNT(*) as c FROM aliases').get().c;
    const aliasesActive = db.prepare('SELECT COUNT(*) as c FROM aliases WHERE active = 1').get().c;

    const syncsToday = db.prepare(
      "SELECT COUNT(*) as c FROM sync_log WHERE date(timestamp) = date('now')"
    ).get().c;

    res.json({
      uptime: process.uptime(),
      nodeVersion: process.version,
      platform: process.platform,
      memory: {
        rss: mem.rss,
        heapUsed: mem.heapUsed,
        heapTotal: mem.heapTotal
      },
      database: {
        configured: true,
        sizeBytes: dbSize
      },
      sessions: { total: sessionsTotal, active: sessionsActive, revoked: sessionsRevoked },
      shares: { total: sharesTotal, active: sharesActive },
      aliases: { total: aliasesTotal, active: aliasesActive },
      syncsToday
    });
  } catch (err) {
    console.error('Admin health error:', err.message);
    res.status(500).json({ error: 'Failed to load health data' });
  }
});

module.exports = router;
