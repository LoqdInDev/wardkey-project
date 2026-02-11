# 🔐 WARDKEY — AI-Powered Password Manager

> Local-first, zero-knowledge, AI-powered password security. Free forever.

## 🚀 Quick Start

### Web App (PWA)
```bash
# Just open wardkey.html in any browser — it works offline!
# Or serve it:
npx serve . -p 5173
```
Visit `http://localhost:5173/wardkey.html` and install as PWA.

### Backend API
```bash
cd wardkey-server
cp .env.example .env     # Edit with your secrets
npm install
npm start                # http://localhost:3000
```

Or with Docker:
```bash
cd wardkey-server
docker compose up -d
```

### Chrome Extension
1. Open `chrome://extensions`
2. Enable "Developer mode"
3. Click "Load unpacked"
4. Select the `wardkey-extension` folder
5. Pin WARDKEY to toolbar

---

## 📦 Project Structure

```
wardkey/
├── wardkey.html              # Main PWA (single file, works offline)
├── wardkey-manifest.json     # PWA manifest
├── wardkey-sw.js             # Service worker (offline caching)
├── wardkey-landing.html      # Marketing landing page
│
├── wardkey-extension/        # Chrome Extension
│   ├── manifest.json         # Extension manifest v3
│   ├── popup.html/js         # Extension popup UI
│   ├── content.js/css        # Page injection & autofill
│   ├── background.js         # Service worker
│   └── icons/                # Extension icons
│
└── wardkey-server/           # Backend API
    ├── server.js             # Express entry point
    ├── package.json
    ├── Dockerfile
    ├── docker-compose.yml
    ├── .env.example
    ├── routes/
    │   ├── auth.js           # Register, login, sessions
    │   ├── vault.js          # Encrypted vault sync
    │   ├── share.js          # One-time share links
    │   └── aliases.js        # Email alias management
    ├── models/
    │   └── db.js             # SQLite schema & queries
    └── middleware/
        └── auth.js           # JWT authentication
```

---

## 🔒 Security Architecture

| Layer | Technology |
|-------|-----------|
| Encryption | AES-256-GCM (client-side) |
| Key Derivation | PBKDF2 with 600,000 iterations |
| Zero-Knowledge | Server never sees decrypted data |
| Auth | bcrypt (12 rounds) + JWT |
| Transport | HTTPS/TLS 1.3 |
| Storage | Encrypted blobs only |

**The server NEVER has access to your passwords.** All encryption and decryption happens in the browser using the Web Crypto API. The server only stores encrypted blobs that are useless without your master password.

---

## 🌐 API Reference

### Auth
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/auth/register` | Create account |
| POST | `/api/auth/login` | Login |
| GET | `/api/auth/me` | Get profile |
| PATCH | `/api/auth/me` | Update profile |
| DELETE | `/api/auth/me` | Delete account |
| GET | `/api/auth/sessions` | List sessions |

### Vault Sync
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/vault` | Download encrypted vault |
| PUT | `/api/vault` | Upload encrypted vault |
| GET | `/api/vault/status` | Sync status |
| DELETE | `/api/vault` | Delete server vault |

### Sharing
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/share` | Create share link |
| GET | `/api/share/:id` | View shared item (public) |
| GET | `/api/share` | List my shares |
| DELETE | `/api/share/:id` | Revoke share |

### Email Aliases
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/aliases` | List aliases |
| POST | `/api/aliases` | Create alias |
| PATCH | `/api/aliases/:id` | Toggle/update |
| DELETE | `/api/aliases/:id` | Delete alias |

---

## 📱 Features

### Core Vault
- ✅ Passwords with strength scoring
- ✅ Credit cards & IDs
- ✅ Secure notes
- ✅ API keys with environment tagging
- ✅ Software licenses
- ✅ Passkeys (FIDO2/WebAuthn)

### Security
- ✅ Watchtower security dashboard
- ✅ Security audit (weak, reused, aging)
- ✅ Breach scanner
- ✅ Credential Map (network graph)
- ✅ Password Decay Timeline
- ✅ Travel Mode
- ✅ Clipboard auto-clear (30s)
- ✅ Auto-lock (5 min)
- ✅ Password history tracking

### AI-Powered (Claude)
- ✅ Password analyzer
- ✅ Security report generator
- ✅ Phishing detector

### Tools
- ✅ Password generator (passwords + passphrases)
- ✅ TOTP authenticator
- ✅ One-time share links
- ✅ Email alias generator
- ✅ Emergency access
- ✅ Import/Export (JSON, CSV)
- ✅ Quick Launch (open site + copy password)

### Platform
- ✅ PWA (installable)
- ✅ Chrome extension with autofill
- ✅ Cloud sync (optional)
- ✅ Dark & Light mode
- ✅ Mobile responsive
- ✅ Keyboard shortcuts
- ✅ Offline-first

---

## 🚢 Deployment

### Railway / Render / Fly.io
```bash
cd wardkey-server
# Set environment variables in dashboard
# Deploy with Git push
```

### VPS (Ubuntu)
```bash
git clone https://github.com/your/wardkey.git
cd wardkey/wardkey-server
cp .env.example .env
nano .env  # Set JWT_SECRET and other vars
docker compose up -d
```

### Vercel / Netlify (Static)
Just deploy the HTML files:
- `wardkey.html` → Main app
- `wardkey-landing.html` → Marketing page
- `wardkey-manifest.json` → PWA manifest
- `wardkey-sw.js` → Service worker

### Email Aliases Setup
To enable real email forwarding:
1. Register your domain (e.g., `wardkey.email`)
2. Set up Cloudflare Email Routing or Postfix
3. Configure catch-all to forward to `/api/aliases/incoming`
4. Update `ALIAS_DOMAIN` in `.env`

---

## 📄 License

MIT — Free to use, modify, and distribute.

---

Built with 🔐 by WARDKEY
