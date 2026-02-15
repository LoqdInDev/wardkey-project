# CLAUDE.md — Instructions for Claude Code

## Project Overview
WARDKEY is a local-first password manager with zero-knowledge vault encryption. The main app is a single HTML file (`app/wardkey.html`) containing all CSS and JS inline (~170KB, 1600+ lines). There is also a Chrome extension and a Node.js backend API.

## Critical Rules

### Security — DO NOT BREAK
- **Never downgrade encryption.** The vault uses AES-256-GCM with PBKDF2 (600K iterations). Do not reduce iterations, change algorithms, or weaken key derivation.
- **Never log or expose plaintext passwords.** No `console.log` of vault contents, passwords, or master keys.
- **Never store plaintext.** All vault data must be encrypted before writing to localStorage or server.
- **Never remove re-authentication gates.** Export and vault wipe require re-entering the master password.
- **Never remove brute force protection.** The 5-attempt lockout with 60s cooldown must stay.
- **Keep `secureClear()` comprehensive.** On lock: null the master key, vault salt, verify hash; wipe the vault object; clear DOM password fields; empty clipboard.

### Architecture — Single-File PWA
- `app/wardkey.html` is the ENTIRE frontend app in one file. CSS is in `<style>`, JS is in `<script>`. This is intentional for portability and security audit simplicity.
- Do NOT split it into separate files unless explicitly asked.
- The app works fully offline with no external JS dependencies. Only external resource is Google Fonts (optional, falls back gracefully).

### Code Style
- The codebase uses compact/minified-style JS. Variable names are short (`V` = vault, `mk` = master key, `pg` = current page, etc.).
- Key function names: `saveV()`, `loadV()`, `encrypt()`, `decrypt()`, `deriveKey()`, `render()`, `showD()`, `vI()`, `nav()`, `str()` (password strength), `genPw()` (generate password).
- Helper: `$()` = `document.getElementById()`, `F()` = detail field renderer, `IC` = icon constants.
- CSS uses custom properties defined in `:root` (dark) and `[data-theme="light"]` (light mode).
- Color vars: `--ac` (accent blue), `--gn` (green), `--rd` (red), `--og` (orange), `--yl` (yellow), `--pp` (purple), `--cy` (cyan). Background variants: `--gnb`, `--rdb`, etc.

### Vault Data Structure
```javascript
V = {
  passwords: [{ id, name, username, password, url, cat, tags, notes, created, modified, history, icon, fav, sens, fields, rotate? }],
  cards: [{ id, name, number, holder, exp, cvv, pin, type, billing, icon }],
  notes: [{ id, name, content, created, modified, icon }],
  totp: [{ id, name, secret, issuer, icon }],
  apikeys: [{ id, name, svc, key, env, url, notes, icon }],
  licenses: [{ id, name, product, key, email, seats, icon }],
  passkeys: [{ id, name, rpId, username, credId, alg, created, lastUsed, icon }],
  aliases: [{ id, alias, target, label, active }],
  breaches: [{ id, site, date, data, resolved, severity }],
  trash: [{ ...item, deletedAt, origType }],
  activity: [{ action, item, type, time }]
}
```

### Auto-Rotate System
Passwords can have: `rotate: { enabled: boolean, days: number, lastRotated: timestamp }`
- `checkRotations()` runs on unlock, auto-generates new passwords for overdue items
- `doRotate(id)` generates new password matching original complexity, saves old to history
- `getRotateStatus(p)` returns `{ daysLeft, overdue, soon, label, color }`

### Navigation Pages
`dashboard`, `passwords`, `cards`, `notes`, `totp`, `apikeys`, `licenses`, `passkeys`, `watchtower`, `audit`, `generator`, `share`, `credmap`, `decay`, `activity`, `trash`, `pricing`, `settings`

### Crypto Format (v4)
```
localStorage key: 'wardkey_v4'
{
  v: 4,
  salt: Uint8Array(16) as array,
  verify: base64 string (SHA-512 PBKDF2, 310K iterations),
  data: {
    iv: Uint8Array(12) as array,
    ct: AES-256-GCM ciphertext as array
  }
}
```

## File Locations

| File | Purpose | Size |
|------|---------|------|
| `app/wardkey.html` | Main PWA app (CSS + JS inline) | ~170KB |
| `app/landing.html` | Marketing page | ~52KB |
| `app/wardkey-manifest.json` | PWA manifest (icons, shortcuts) | ~2.5KB |
| `app/wardkey-sw.js` | Service worker (cache-first) | ~2.5KB |
| `extension/manifest.json` | Chrome Manifest V3 | ~1KB |
| `extension/popup.html` | Extension popup | ~11KB |
| `extension/popup.js` | Popup logic | ~13KB |
| `extension/content.js` | Form detection + autofill | ~7KB |
| `extension/background.js` | Service worker | ~4KB |
| `server/server.js` | Express entry point | ~2KB |
| `server/routes/auth.js` | Auth endpoints | ~5KB |
| `server/routes/vault.js` | Vault sync endpoints | ~3KB |
| `server/routes/share.js` | Share link endpoints | ~4KB |
| `server/models/db.js` | SQLite schema | ~3KB |

## Common Tasks

### Adding a new vault type
1. Add array to `V` in `seed()` function
2. Add to `loadV()` fallback: `['...'].forEach(k => { if(!V[k]) V[k]=[]; })`
3. Add nav entry in `NAV` array
4. Add render function `rNewType(el)` 
5. Add to page router in `render()` switch
6. Add to `showD()` detail panel
7. Add to vault stats in `rSet()` settings
8. Add to `updC()` counter updates

### Adding a new setting toggle
1. Add state variable (e.g., `let myToggle = true;`)
2. Add `sRow()` in `rSet()` function with `tgl()` toggle

### Modifying encryption
- Key derivation: `deriveKey()` function
- Verification: `deriveVerifyHash()` function
- Encrypt/decrypt: `encrypt()` and `decrypt()` functions
- Save/load: `saveV()` and `loadV()` functions
- Memory wipe: `secureClear()` function

## Testing
- Open `app/wardkey.html` in browser, enter any 4+ char password
- Demo data auto-populates on first run
- Check browser console for errors
- Test lock/unlock cycle to verify encryption round-trip
- Verify auto-lock fires after 5 min inactivity
