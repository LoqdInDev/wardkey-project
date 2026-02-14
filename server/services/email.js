// WARDKEY Email Service — Nodemailer with SMTP
const nodemailer = require('nodemailer');

let transporter = null;
let configured = false;

function init() {
  if (process.env.SMTP_HOST && process.env.SMTP_USER && process.env.SMTP_PASS) {
    transporter = nodemailer.createTransport({
      host: process.env.SMTP_HOST,
      port: parseInt(process.env.SMTP_PORT) || 587,
      secure: (parseInt(process.env.SMTP_PORT) || 587) === 465,
      auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASS
      }
    });
    configured = true;
    console.log('✓ Email service configured');
  } else {
    console.log('⚠ SMTP not configured — emails will be logged to console');
  }
}

async function send(to, subject, html) {
  const from = process.env.SMTP_FROM || process.env.SMTP_USER || 'noreply@wardkey.io';

  if (!configured) {
    console.log(`[EMAIL] To: ${to} | Subject: ${subject}\n${html.replace(/<[^>]+>/g, '')}\n`);
    return { messageId: 'console-' + Date.now() };
  }

  return transporter.sendMail({ from: `WARDKEY <${from}>`, to, subject, html });
}

// ═══════ EMAIL TEMPLATES ═══════

function emergencyInvite(grantorName, confirmUrl) {
  return {
    subject: `WARDKEY: You've been added as an emergency contact`,
    html: `<div style="font-family:system-ui,sans-serif;max-width:480px;margin:0 auto;padding:24px">
      <h2 style="color:#6c5ce7">WARDKEY Emergency Access</h2>
      <p>You've been added as an emergency contact for <strong>${esc(grantorName)}</strong>'s WARDKEY vault.</p>
      <p>If they become unavailable, you'll be able to request access to their vault after a waiting period.</p>
      <p><a href="${esc(confirmUrl)}" style="display:inline-block;padding:12px 24px;background:#6c5ce7;color:#fff;text-decoration:none;border-radius:8px;font-weight:600">Confirm as Emergency Contact</a></p>
      <p style="color:#888;font-size:12px">If you don't recognize this request, you can safely ignore this email.</p>
    </div>`
  };
}

function emergencyRequest(granteeEmail, waitHours, denyUrl, approveUrl) {
  return {
    subject: `WARDKEY: Emergency access requested`,
    html: `<div style="font-family:system-ui,sans-serif;max-width:480px;margin:0 auto;padding:24px">
      <h2 style="color:#e74c3c">Emergency Access Request</h2>
      <p><strong>${esc(granteeEmail)}</strong> has requested emergency access to your WARDKEY vault.</p>
      <p>You have <strong>${waitHours} hours</strong> to deny this request. If you don't respond, access will be granted automatically.</p>
      <div style="display:flex;gap:12px;margin:20px 0">
        <a href="${esc(denyUrl)}" style="display:inline-block;padding:12px 24px;background:#e74c3c;color:#fff;text-decoration:none;border-radius:8px;font-weight:600">Deny Access</a>
        <a href="${esc(approveUrl)}" style="display:inline-block;padding:12px 24px;background:#27ae60;color:#fff;text-decoration:none;border-radius:8px;font-weight:600">Approve Now</a>
      </div>
      <p style="color:#888;font-size:12px">This is an automated notification from WARDKEY.</p>
    </div>`
  };
}

function emergencyApproved(grantorEmail) {
  return {
    subject: `WARDKEY: Emergency access approved`,
    html: `<div style="font-family:system-ui,sans-serif;max-width:480px;margin:0 auto;padding:24px">
      <h2 style="color:#27ae60">Emergency Access Approved</h2>
      <p>Your emergency access request has been approved.</p>
      <p>Contact <strong>${esc(grantorEmail)}</strong> to receive their vault export, or log in to WARDKEY to view the status.</p>
      <p style="color:#888;font-size:12px">This is an automated notification from WARDKEY.</p>
    </div>`
  };
}

function emergencyDenied(grantorName) {
  return {
    subject: `WARDKEY: Emergency access denied`,
    html: `<div style="font-family:system-ui,sans-serif;max-width:480px;margin:0 auto;padding:24px">
      <h2 style="color:#e74c3c">Emergency Access Denied</h2>
      <p>Your emergency access request was denied by <strong>${esc(grantorName)}</strong>.</p>
      <p style="color:#888;font-size:12px">This is an automated notification from WARDKEY.</p>
    </div>`
  };
}

function esc(s) {
  return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

init();

module.exports = { send, emergencyInvite, emergencyRequest, emergencyApproved, emergencyDenied };
