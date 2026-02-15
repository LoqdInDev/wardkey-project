// WARDKEY Database Layer — SQLite
const Database = require('better-sqlite3');
const path = require('path');

const DB_PATH = process.env.DB_PATH || './data/wardkey.db';
let db;

function initDB() {
  db = new Database(DB_PATH);
  db.pragma('journal_mode = WAL');
  db.pragma('foreign_keys = ON');

  db.exec(`
    -- Users
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      name TEXT,
      plan TEXT DEFAULT 'free',
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      last_login DATETIME,
      mfa_secret TEXT,
      mfa_enabled INTEGER DEFAULT 0,
      last_totp_at INTEGER DEFAULT 0
    );

    -- Encrypted vault blobs (server never sees decrypted data)
    CREATE TABLE IF NOT EXISTS vaults (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      encrypted_data TEXT NOT NULL,
      iv TEXT NOT NULL,
      salt TEXT NOT NULL,
      version INTEGER DEFAULT 1,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      size_bytes INTEGER DEFAULT 0
    );

    -- Sync metadata
    CREATE TABLE IF NOT EXISTS sync_log (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      device_id TEXT,
      action TEXT NOT NULL,
      timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    -- Share links
    CREATE TABLE IF NOT EXISTS shares (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      encrypted_data TEXT NOT NULL,
      iv TEXT NOT NULL,
      max_views INTEGER DEFAULT 1,
      current_views INTEGER DEFAULT 0,
      expires_at DATETIME NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      revoked INTEGER DEFAULT 0
    );

    -- Emergency contacts
    CREATE TABLE IF NOT EXISTS emergency_contacts (
      id TEXT PRIMARY KEY,
      grantor_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      grantee_email TEXT NOT NULL,
      grantee_id TEXT REFERENCES users(id),
      waiting_hours INTEGER NOT NULL DEFAULT 48,
      status TEXT NOT NULL DEFAULT 'invited',
      request_at DATETIME,
      invite_token TEXT UNIQUE,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    -- Sessions / refresh tokens
    CREATE TABLE IF NOT EXISTS sessions (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      device_name TEXT,
      ip_address TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      expires_at DATETIME NOT NULL,
      revoked INTEGER DEFAULT 0
    );

    -- Audit log
    CREATE TABLE IF NOT EXISTS audit_log (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id TEXT,
      action TEXT NOT NULL,
      target TEXT,
      ip_address TEXT,
      user_agent TEXT,
      metadata TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    -- Indexes
    CREATE INDEX IF NOT EXISTS idx_vaults_user ON vaults(user_id);
    CREATE INDEX IF NOT EXISTS idx_shares_user ON shares(user_id);
    CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
    CREATE INDEX IF NOT EXISTS idx_sync_user ON sync_log(user_id);
    CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_log(user_id);
    CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_log(action);
    CREATE INDEX IF NOT EXISTS idx_ec_grantor ON emergency_contacts(grantor_id);
    CREATE INDEX IF NOT EXISTS idx_ec_grantee ON emergency_contacts(grantee_id);
  `);

  // Migrations for existing databases
  try { db.exec('ALTER TABLE users ADD COLUMN last_totp_at INTEGER DEFAULT 0'); } catch {}

  // Restrict database file permissions (owner read/write only)
  try { require('fs').chmodSync(DB_PATH, 0o600); } catch(e) {}

  // Periodic cleanup of stale data (every 6 hours)
  setInterval(() => {
    try {
      db.prepare("DELETE FROM sessions WHERE revoked = 1 OR expires_at < datetime('now', '-7 days')").run();
      db.prepare("DELETE FROM sync_log WHERE timestamp < datetime('now', '-90 days')").run();
      db.prepare("DELETE FROM shares WHERE expires_at < datetime('now', '-30 days')").run();
    } catch (err) {
      console.error('Cleanup error:', err.message);
    }
  }, 6 * 60 * 60 * 1000);

  console.log('✓ Database initialized');
  return db;
}

function getDB() {
  if (!db) initDB();
  return db;
}

function auditLog(userId, action, target, req, metadata) {
  try {
    const db = getDB();
    db.prepare(
      'INSERT INTO audit_log (user_id, action, target, ip_address, user_agent, metadata) VALUES (?, ?, ?, ?, ?, ?)'
    ).run(
      userId || null,
      action,
      target || null,
      req?.ip || null,
      req?.headers?.['user-agent']?.substring(0, 200) || null,
      metadata ? JSON.stringify(metadata) : null
    );
  } catch (err) {
    console.error('Audit log write failed:', err.message);
  }
}

module.exports = { initDB, getDB, auditLog };
