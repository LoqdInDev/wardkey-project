// WARDKEY Emergency Access Routes
const express = require('express');
const crypto = require('crypto');
const { getDB, auditLog } = require('../models/db');
const { authenticate } = require('../middleware/auth');
const email = require('../services/email');

const router = express.Router();

const APP_URL = process.env.APP_ORIGIN || 'https://wardkey.io';

// ═══════ ADD EMERGENCY CONTACT (grantor) ═══════
router.post('/', authenticate, (req, res) => {
  const { contactEmail, contactName, waitingHours } = req.body;
  if (!contactEmail || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(contactEmail) || contactEmail.length > 254) {
    return res.status(400).json({ error: 'Valid email required' });
  }

  const db = getDB();
  const hours = [24, 48, 168].includes(waitingHours) ? waitingHours : 48;

  // Check if already added
  const existing = db.prepare(
    'SELECT id FROM emergency_contacts WHERE grantor_id = ? AND grantee_email = ? AND status != ?'
  ).get(req.user.id, contactEmail.toLowerCase(), 'denied');
  if (existing) {
    return res.status(409).json({ error: 'This contact is already added' });
  }

  const contactCount = db.prepare('SELECT COUNT(*) as count FROM emergency_contacts WHERE grantor_id = ?').get(req.user.id);
  if (contactCount.count >= 10) {
    return res.status(403).json({ error: 'Maximum 10 emergency contacts allowed' });
  }

  const id = crypto.randomBytes(12).toString('hex');
  const inviteToken = crypto.randomBytes(24).toString('hex');

  db.prepare(
    'INSERT INTO emergency_contacts (id, grantor_id, grantee_email, waiting_hours, invite_token) VALUES (?, ?, ?, ?, ?)'
  ).run(id, req.user.id, contactEmail.toLowerCase(), hours, inviteToken);

  // Get grantor info for email
  const grantor = db.prepare('SELECT name, email FROM users WHERE id = ?').get(req.user.id);
  const confirmUrl = `${APP_URL}/app.html#emergency-confirm=${inviteToken}`;
  const tpl = email.emergencyInvite(grantor.name || grantor.email, confirmUrl);
  email.send(contactEmail, tpl.subject, tpl.html).catch(err => {
    console.error('Failed to send emergency invite:', err.message);
  });

  auditLog(req.user.id, 'emergency_invite', contactEmail, req);

  res.status(201).json({ id, status: 'invited' });
});

// ═══════ LIST MY CONTACTS (grantor view) ═══════
router.get('/', authenticate, (req, res) => {
  const db = getDB();
  const contacts = db.prepare(
    `SELECT id, grantee_email, waiting_hours, status, request_at, created_at
     FROM emergency_contacts WHERE grantor_id = ? ORDER BY created_at DESC`
  ).all(req.user.id);
  res.json({ contacts });
});

// ═══════ LIST INCOMING (grantee view) ═══════
router.get('/incoming', authenticate, (req, res) => {
  const db = getDB();
  const userEmail = db.prepare('SELECT email FROM users WHERE id = ?').get(req.user.id)?.email;
  if (!userEmail) return res.json({ contacts: [] });

  const contacts = db.prepare(
    `SELECT ec.id, ec.grantor_id, u.name as grantor_name, u.email as grantor_email,
            ec.waiting_hours, ec.status, ec.request_at, ec.created_at
     FROM emergency_contacts ec
     JOIN users u ON u.id = ec.grantor_id
     WHERE ec.grantee_email = ? AND ec.status IN ('confirmed', 'requesting', 'approved')
     ORDER BY ec.created_at DESC`
  ).all(userEmail.toLowerCase());
  res.json({ contacts });
});

// ═══════ CONFIRM INVITATION (public, token-based) ═══════
router.post('/confirm/:token', (req, res) => {
  if (!/^[0-9a-f]{48}$/.test(req.params.token)) return res.status(400).json({ error: 'Invalid token format' });
  const db = getDB();
  const contact = db.prepare(
    'SELECT * FROM emergency_contacts WHERE invite_token = ? AND status = ?'
  ).get(req.params.token, 'invited');

  if (!contact) {
    return res.status(404).json({ error: 'Invalid or already used invitation link' });
  }

  // Link grantee_id if the confirming user is authenticated
  const authHeader = req.headers.authorization;
  let granteeId = null;
  if (authHeader && authHeader.startsWith('Bearer ')) {
    try {
      const jwt = require('jsonwebtoken');
      const decoded = jwt.verify(authHeader.split(' ')[1], process.env.JWT_SECRET, { algorithms: ['HS256'] });
      if (decoded.id && !decoded.purpose) granteeId = decoded.id;
    } catch {}
  }

  const updates = granteeId
    ? db.prepare('UPDATE emergency_contacts SET status = ?, grantee_id = ?, invite_token = NULL WHERE id = ?')
    : db.prepare('UPDATE emergency_contacts SET status = ?, invite_token = NULL WHERE id = ?');

  if (granteeId) updates.run('confirmed', granteeId, contact.id);
  else updates.run('confirmed', contact.id);

  auditLog(contact.grantor_id, 'emergency_confirmed', contact.grantee_email, req);

  res.json({ success: true, status: 'confirmed' });
});

// ═══════ REQUEST ACCESS (grantee) ═══════
router.post('/:id/request', authenticate, (req, res) => {
  const db = getDB();
  const userEmail = db.prepare('SELECT email FROM users WHERE id = ?').get(req.user.id)?.email;

  const contact = db.prepare(
    'SELECT * FROM emergency_contacts WHERE id = ? AND (grantee_id = ? OR grantee_email = ?) AND status = ?'
  ).get(req.params.id, req.user.id, userEmail?.toLowerCase(), 'confirmed');

  if (!contact) {
    return res.status(404).json({ error: 'Contact not found or not in confirmed state' });
  }

  db.prepare(
    "UPDATE emergency_contacts SET status = 'requesting', request_at = datetime('now'), grantee_id = ? WHERE id = ?"
  ).run(req.user.id, contact.id);

  // Notify grantor
  const grantor = db.prepare('SELECT name, email FROM users WHERE id = ?').get(contact.grantor_id);
  if (grantor) {
    const denyUrl = `${APP_URL}/app.html#emergency-deny=${contact.id}`;
    const approveUrl = `${APP_URL}/app.html#emergency-approve=${contact.id}`;
    const tpl = email.emergencyRequest(userEmail || contact.grantee_email, contact.waiting_hours, denyUrl, approveUrl);
    email.send(grantor.email, tpl.subject, tpl.html).catch(err => {
      console.error('Failed to send emergency request email:', err.message);
    });
  }

  auditLog(contact.grantor_id, 'emergency_requested', contact.grantee_email, req);

  res.json({ success: true, status: 'requesting' });
});

// ═══════ APPROVE (grantor) ═══════
router.post('/:id/approve', authenticate, (req, res) => {
  const db = getDB();
  const contact = db.prepare(
    'SELECT * FROM emergency_contacts WHERE id = ? AND grantor_id = ? AND status = ?'
  ).get(req.params.id, req.user.id, 'requesting');

  if (!contact) {
    return res.status(404).json({ error: 'No pending request found' });
  }

  db.prepare("UPDATE emergency_contacts SET status = 'approved' WHERE id = ?").run(contact.id);

  // Notify grantee
  const grantor = db.prepare('SELECT name, email FROM users WHERE id = ?').get(req.user.id);
  const tpl = email.emergencyApproved(grantor?.email || 'the vault owner');
  email.send(contact.grantee_email, tpl.subject, tpl.html).catch(err => {
    console.error('Failed to send approval email:', err.message);
  });

  auditLog(req.user.id, 'emergency_approved', contact.grantee_email, req);

  res.json({ success: true, status: 'approved' });
});

// ═══════ DENY (grantor) ═══════
router.post('/:id/deny', authenticate, (req, res) => {
  const db = getDB();
  const contact = db.prepare(
    'SELECT * FROM emergency_contacts WHERE id = ? AND grantor_id = ? AND status = ?'
  ).get(req.params.id, req.user.id, 'requesting');

  if (!contact) {
    return res.status(404).json({ error: 'No pending request found' });
  }

  db.prepare("UPDATE emergency_contacts SET status = 'denied' WHERE id = ?").run(contact.id);

  // Notify grantee
  const grantor = db.prepare('SELECT name FROM users WHERE id = ?').get(req.user.id);
  const tpl = email.emergencyDenied(grantor?.name || 'the vault owner');
  email.send(contact.grantee_email, tpl.subject, tpl.html).catch(err => {
    console.error('Failed to send denial email:', err.message);
  });

  auditLog(req.user.id, 'emergency_denied', contact.grantee_email, req);

  res.json({ success: true, status: 'denied' });
});

// ═══════ REMOVE CONTACT (grantor) ═══════
router.delete('/:id', authenticate, (req, res) => {
  const db = getDB();
  const result = db.prepare(
    'DELETE FROM emergency_contacts WHERE id = ? AND grantor_id = ?'
  ).run(req.params.id, req.user.id);

  if (result.changes === 0) {
    return res.status(404).json({ error: 'Contact not found' });
  }

  auditLog(req.user.id, 'emergency_removed', req.params.id, req);
  res.json({ success: true });
});

module.exports = router;
