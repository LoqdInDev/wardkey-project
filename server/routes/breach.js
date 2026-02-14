// WARDKEY Breach Scanner — HIBP Pwned Passwords proxy (k-anonymity)
const express = require('express');
const { authenticate } = require('../middleware/auth');
const { auditLog } = require('../models/db');

const router = express.Router();

// POST /api/breach/check — Check password prefixes against HIBP
router.post('/check', authenticate, async (req, res) => {
  const { prefixes } = req.body;
  if (!Array.isArray(prefixes) || prefixes.length === 0) {
    return res.status(400).json({ error: 'Missing prefixes array' });
  }

  // Validate prefixes: must be 5-char hex strings
  const validPrefixes = [...new Set(prefixes.filter(p =>
    typeof p === 'string' && /^[0-9a-fA-F]{5}$/.test(p)
  ))];

  if (validPrefixes.length === 0) {
    return res.status(400).json({ error: 'No valid prefixes provided' });
  }

  // Cap at 100 unique prefixes per request
  if (validPrefixes.length > 100) {
    return res.status(400).json({ error: 'Too many prefixes (max 100)' });
  }

  try {
    const results = {};
    // Fetch in batches of 3 to respect HIBP rate limits
    for (let i = 0; i < validPrefixes.length; i += 3) {
      const batch = validPrefixes.slice(i, i + 3);
      const fetches = batch.map(async (prefix) => {
        const resp = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`, {
          headers: { 'User-Agent': 'WARDKEY-PasswordManager' }
        });
        if (!resp.ok) throw new Error(`HIBP returned ${resp.status} for prefix ${prefix}`);
        const text = await resp.text();
        return { prefix, text };
      });
      const batchResults = await Promise.all(fetches);
      for (const { prefix, text } of batchResults) {
        results[prefix.toUpperCase()] = text;
      }
      // Small delay between batches to be polite to HIBP
      if (i + 3 < validPrefixes.length) {
        await new Promise(r => setTimeout(r, 200));
      }
    }

    auditLog(req.user.id, 'breach_scan', `${validPrefixes.length} prefixes`, req);
    res.json({ results });
  } catch (err) {
    console.error('Breach check error:', err.message);
    res.status(502).json({ error: 'Failed to check breach database. Try again later.' });
  }
});

module.exports = router;
