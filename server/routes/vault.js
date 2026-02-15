// WARDKEY Vault Sync Routes
// IMPORTANT: Server NEVER sees decrypted data. All encryption is client-side.
const express = require('express');
const { v4: uuid } = require('uuid');
const { getDB, auditLog } = require('../models/db');
const { authenticate } = require('../middleware/auth');

const router = express.Router();

// ═══════ GET VAULT ═══════
// Download encrypted vault blob (v4 format)
router.get('/', authenticate, (req, res) => {
  const db = getDB();
  const vault = db.prepare('SELECT id, encrypted_data, version, updated_at FROM vaults WHERE user_id = ? ORDER BY updated_at DESC LIMIT 1').get(req.user.id);

  if (!vault) {
    return res.json({ vault: null, message: 'No vault found. Upload to create one.' });
  }

  // Safely parse and re-serialize to prevent JSON injection
  try {
    const parsed = JSON.parse(vault.encrypted_data);
    res.json({ vault: parsed });
  } catch (e) {
    res.status(500).json({ error: 'Vault data corrupted' });
  }
});

// ═══════ SYNC VAULT ═══════
// Upload encrypted vault blob (v4 format — full replace)
router.put('/', authenticate, (req, res) => {
  const body = req.body;
  if (!body.data || !body.salt) {
    return res.status(400).json({ error: 'Missing encrypted data or salt' });
  }
  if (typeof body.data !== 'object' || !Array.isArray(body.data.iv) || !Array.isArray(body.data.ct)) {
    return res.status(400).json({ error: 'Invalid vault data structure' });
  }
  if (!Array.isArray(body.salt)) {
    return res.status(400).json({ error: 'Invalid salt format' });
  }

  const blob = JSON.stringify(body);
  const deviceId = body.deviceId;

  const db = getDB();
  const sizeBytes = Buffer.byteLength(blob, 'utf8');

  // Extract salt for DB column (NOT NULL constraint), iv stored inside blob
  const saltStr = JSON.stringify(body.salt || []);
  const ivStr = body.data?.iv ? JSON.stringify(body.data.iv) : '[]';
  const clientVersion = body.version || body.v || 0;

  // Atomic: conflict detection + plan check + upsert in a transaction
  const syncVault = db.transaction(() => {
    const existing = db.prepare('SELECT id, version FROM vaults WHERE user_id = ?').get(req.user.id);

    if (existing && !clientVersion) {
      return { status: 400, error: 'Version required for vault updates' };
    }

    if (existing && clientVersion && existing.version > clientVersion) {
      return { status: 409, error: 'Conflict: server has newer version', serverVersion: existing.version, clientVersion };
    }

    const user = db.prepare('SELECT plan FROM users WHERE id = ?').get(req.user.id);
    const maxSize = user?.plan === 'pro' ? 1073741824 : 10485760;
    if (sizeBytes > maxSize) {
      return { status: 413, error: 'Vault exceeds plan storage limit', maxBytes: maxSize };
    }

    const id = existing?.id || uuid();
    const newVersion = (existing?.version || 0) + 1;

    if (existing) {
      db.prepare('UPDATE vaults SET encrypted_data = ?, iv = ?, salt = ?, version = ?, updated_at = CURRENT_TIMESTAMP, size_bytes = ? WHERE id = ?')
        .run(blob, ivStr, saltStr, newVersion, sizeBytes, id);
    } else {
      db.prepare('INSERT INTO vaults (id, user_id, encrypted_data, iv, salt, version, size_bytes) VALUES (?, ?, ?, ?, ?, ?, ?)')
        .run(id, req.user.id, blob, ivStr, saltStr, newVersion, sizeBytes);
    }

    db.prepare('INSERT INTO sync_log (user_id, device_id, action) VALUES (?, ?, ?)')
      .run(req.user.id, deviceId || 'unknown', 'sync_upload');

    return { success: true, version: newVersion };
  });

  const result = syncVault();
  if (result.error) {
    return res.status(result.status).json({ error: result.error, ...(result.serverVersion ? { serverVersion: result.serverVersion, clientVersion: result.clientVersion } : {}), ...(result.maxBytes ? { maxBytes: result.maxBytes } : {}) });
  }

  auditLog(req.user.id, 'vault_sync', null, req);

  res.json({
    success: true,
    version: result.version,
    updatedAt: new Date().toISOString()
  });
});

// ═══════ SYNC STATUS ═══════
router.get('/status', authenticate, (req, res) => {
  const db = getDB();
  const vault = db.prepare('SELECT version, updated_at, size_bytes FROM vaults WHERE user_id = ?').get(req.user.id);
  const lastSync = db.prepare('SELECT timestamp, device_id FROM sync_log WHERE user_id = ? ORDER BY timestamp DESC LIMIT 1').get(req.user.id);

  res.json({
    hasVault: !!vault,
    version: vault?.version || 0,
    lastUpdated: vault?.updated_at,
    sizeBytes: vault?.size_bytes || 0,
    lastSync: lastSync?.timestamp,
    lastDevice: lastSync?.device_id
  });
});

// ═══════ DELETE VAULT ═══════
router.delete('/', authenticate, (req, res) => {
  const db = getDB();
  db.prepare('DELETE FROM vaults WHERE user_id = ?').run(req.user.id);
  db.prepare('INSERT INTO sync_log (user_id, action) VALUES (?, ?)').run(req.user.id, 'vault_deleted');
  auditLog(req.user.id, 'vault_deleted', null, req);
  res.json({ success: true, message: 'Vault deleted from server' });
});

module.exports = router;
