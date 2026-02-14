# 🔐 WARDKEY — AI-Enhanced Password Manager

A local-first, zero-knowledge password manager with AES-256-GCM encryption, built as a single-file PWA with a Chrome extension and backend API.

## Project Structure

```
wardkey-project/
├── app/                        # Frontend PWA (static files)
│   ├── wardkey.html            # Main app — single-file PWA (1600+ lines)
│   ├── landing.html            # Marketing landing page
│   ├── wardkey-manifest.json   # PWA manifest
│   └── wardkey-sw.js           # Service worker (offline support)
│
├── extension/                  # Chrome Extension (Manifest V3)
│   ├── manifest.json           # Extension manifest
│   ├── popup.html              # Extension popup UI
│   ├── popup.js                # Popup logic (vault, generator, autofill)
│   ├── content.js              # Content script (form detection, autofill injection)
│   ├── content.css             # Content script styles
│   ├── background.js           # Service worker (context menu, auto-lock, badge)
│   └── icons/                  # Extension icons (16/32/48/128px PNGs + SVG)
│
├── server/                     # Backend API (Node.js/Express)
│   ├── server.js               # Express app entry point
│   ├── package.json            # Dependencies
│   ├── routes/
│   │   ├── auth.js             # Registration, login, sessions, profile
│   │   ├── vault.js            # Encrypted vault sync (upload/download)
│   │   ├── share.js            # One-time share links
│   │   ├── breach.js           # Breach scanner (HIBP proxy)
│   │   └── emergency.js        # Emergency access
│   ├── middleware/
│   │   └── auth.js             # JWT authentication middleware
│   ├── models/
│   │   └── db.js               # SQLite schema + initialization
│   ├── Dockerfile              # Production container
│   ├── docker-compose.yml      # Docker deployment
│   ├── .env.example            # Environment variables reference
│   └── README.md               # API documentation
│
├── docs/
│   └── DEPLOY.md               # Step-by-step deployment guide (9 phases)
│
├── README.md                   # This file
└── CLAUDE.md                   # Claude Code instructions
```

## Architecture

### Security Model
- **Encryption:** AES-256-GCM (authenticated encryption)
- **Key Derivation:** PBKDF2 with 600,000 iterations + SHA-256
- **Verification:** Separate SHA-512 hash (310K iterations) for password validation without exposing encryption key
- **Zero-knowledge:** Server only stores encrypted blobs — cannot read vault contents
- **Memory protection:** Keys wiped from memory on lock, clipboard auto-clears after 30s
- **Brute force:** 5 attempts max, 60-second lockout, remaining attempts counter
- **Browser hardening:** CSP, frame-ancestors:none, no-referrer, X-Content-Type-Options

### Vault Format (v4)
```json
{
  "v": 4,
  "salt": [16 bytes],
  "verify": "base64 SHA-512 hash",
  "data": {
    "iv": [12 bytes],
    "ct": [AES-256-GCM ciphertext]
  }
}
```

### App Features
- **Vault types:** Passwords, Credit Cards, Secure Notes, TOTP 2FA, API Keys, Software Licenses, Passkeys
- **Password Generator:** Configurable length/charset, passphrase mode, strength meter
- **Security Monitor:** Breach monitoring dashboard with severity ratings
- **Security Audit:** Weak/reused/aging password detection with actionable recommendations
- **Credential Map:** Interactive graph visualization of password/email reuse connections
- **Password Decay Timeline:** GPU advancement projections showing when passwords become crackable
- **Auto-Rotate:** Scheduled automatic password rotation with configurable intervals (7-365 days)
- **Travel Mode:** Hide sensitive items when crossing borders
- **PWA:** Installable, offline-capable, iOS/Android home screen support
- **Dark/Light mode:** Full theme toggle with system preference detection
- **Activity log:** Full audit trail of all vault actions

### Pricing Tiers
- **Free ($0):** 50 passwords, 5 share links, basic breach alerts
- **Pro ($3.99/mo):** Unlimited everything, AI analysis, cloud sync, priority support
- **Family ($6.99/mo):** 6 users, shared vaults, family dashboard
- **Enterprise ($8.99/user/mo):** SSO/SCIM, admin console, compliance reports

### Tech Stack
- **Frontend:** Vanilla JS, CSS custom properties, no framework dependencies
- **Backend:** Node.js 18+, Express 4.18, better-sqlite3, bcryptjs, jsonwebtoken
- **Extension:** Chrome Manifest V3, Web Crypto API
- **Deployment:** Vercel (frontend) + Railway (backend) + Cloudflare (DNS/email)

## Quick Start

### Run the app locally
Just open `app/wardkey.html` in any browser. Enter any 4+ character password to access the demo vault.

### Run the server locally
```bash
cd server
npm install
cp .env.example .env  # Edit with your JWT_SECRET
node server.js
```

### Load the Chrome extension
1. Open `chrome://extensions`
2. Enable "Developer mode"
3. Click "Load unpacked" → select the `extension/` folder

## Key Implementation Details

### Single-File Architecture
The main app (`wardkey.html`) is a self-contained ~170KB HTML file with all CSS and JS inline. This is intentional — it maximizes portability (works offline, no build step, no CDN dependencies for core functionality) and simplifies the security audit surface.

### Encryption Flow
1. User enters master password
2. PBKDF2 derives 256-bit encryption key from password + salt (600K iterations)
3. Separate PBKDF2 derives verification hash (SHA-512, 310K iterations)
4. AES-256-GCM encrypts the entire vault object with a unique 12-byte IV
5. Salt + verify hash + encrypted blob stored in localStorage
6. On unlock: verify hash checked first (fast rejection), then decrypt

### Auto-Rotate System
- Each password can have `rotate: { enabled, days, lastRotated }` in its data
- On unlock, `checkRotations()` scans all passwords — overdue ones get auto-rotated
- New password generated matching original complexity (length, charset)
- Old password saved to history with timestamp
- User notified to update password on the actual site
- "Rotate & Launch" opens the site immediately after rotation
