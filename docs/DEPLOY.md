# 🔐 WARDKEY — Complete Launch Guide

> Step-by-step instructions to take WARDKEY from files on your computer to a live product people can install, use, and pay for.

---

## Overview — What We're Deploying

| Component | What it is | Where it goes |
|-----------|-----------|---------------|
| **Web App (PWA)** | wardkey.html + manifest + service worker | Vercel / Netlify / Cloudflare Pages |
| **Landing Page** | wardkey-landing.html | Same hosting |
| **Backend API** | Express.js server | Railway / Render / VPS |
| **Chrome Extension** | wardkey-extension.zip | Chrome Web Store |
| **Domain** | wardkey.io (or similar) | Namecheap / Cloudflare |

**Estimated time:** 2-3 hours for everything.

---

## PHASE 1: Domain & DNS (15 min)

### Step 1.1 — Buy your domain

Go to one of these registrars and search for your preferred domain:

- **Cloudflare Registrar** (recommended — cheapest, no markup): https://dash.cloudflare.com
- **Namecheap**: https://namecheap.com
- **Porkbun**: https://porkbun.com

Buy a domain:
1. **wardkey.io** (or wardkeyapp.com, getwardkey.io — whatever is available) — for the app

> 💡 If you use Cloudflare for registration, DNS is already configured. Otherwise, point your domain's nameservers to Cloudflare (free plan works fine).

### Step 1.2 — Add domains to Cloudflare

1. Go to https://dash.cloudflare.com → **Add a Site**
2. Enter your domain → Select **Free** plan
3. Cloudflare will scan existing DNS records
4. If your registrar isn't Cloudflare, update nameservers at your registrar to the ones Cloudflare provides
5. Wait for propagation (usually 5-30 minutes)

---

## PHASE 2: Deploy the Web App + Landing Page (20 min)

### Option A: Vercel (Recommended — Easiest)

#### Step 2A.1 — Create a GitHub repo

1. Go to https://github.com/new
2. Name it `wardkey` (public or private)
3. On your computer, create a project folder and add these files:

```
wardkey/
├── index.html              ← rename wardkey-landing.html to this
├── app.html                ← rename wardkey.html to this
├── wardkey-manifest.json
├── wardkey-sw.js
└── vercel.json
```

4. Create `vercel.json` with this content:

```json
{
  "rewrites": [
    { "source": "/app", "destination": "/app.html" },
    { "source": "/s/:id", "destination": "/app.html" }
  ],
  "headers": [
    {
      "source": "/wardkey-sw.js",
      "headers": [
        { "key": "Service-Worker-Allowed", "value": "/" },
        { "key": "Cache-Control", "value": "no-cache" }
      ]
    },
    {
      "source": "/(.*)",
      "headers": [
        { "key": "X-Content-Type-Options", "value": "nosniff" },
        { "key": "X-Frame-Options", "value": "DENY" },
        { "key": "Referrer-Policy", "value": "strict-origin-when-cross-origin" }
      ]
    }
  ]
}
```

5. Push to GitHub:

```bash
cd wardkey
git init
git add .
git commit -m "Initial WARDKEY launch"
git branch -M main
git remote add origin https://github.com/YOUR_USER/wardkey.git
git push -u origin main
```

#### Step 2A.2 — Deploy on Vercel

1. Go to https://vercel.com → Sign in with GitHub
2. Click **"Add New Project"**
3. Import your `wardkey` repository
4. Framework: **Other** (it's static HTML)
5. Click **Deploy**
6. Wait ~30 seconds — your site is live at `wardkey-xxxxx.vercel.app`

#### Step 2A.3 — Connect your domain

1. In Vercel dashboard → your project → **Settings** → **Domains**
2. Add `wardkey.io` (or your domain)
3. Vercel will show you DNS records to add
4. Go to Cloudflare DNS → Add the records Vercel shows (usually a CNAME)
5. Wait a few minutes → Vercel auto-provisions SSL
6. Your site is now live at `https://wardkey.io`

#### Step 2A.4 — Update landing page links

Open your landing page HTML file and find/replace any placeholder URLs:

- `#download` buttons → link to `/app` (your app URL)
- Any `wardkey.io` references → your actual domain

Push the changes:

```bash
git add .
git commit -m "Update links to production domain"
git push
```

Vercel auto-deploys on every push.

### Option B: Netlify (Alternative)

1. Go to https://app.netlify.com → **Add new site** → **Import from Git**
2. Connect GitHub → Select your repo
3. Build command: leave blank
4. Publish directory: `.`
5. Deploy → Add custom domain in settings
6. Add Netlify's DNS records to Cloudflare

### Option C: Cloudflare Pages (Free, fastest CDN)

1. Go to Cloudflare Dashboard → **Pages** → **Create a project**
2. Connect to Git → Select repo
3. Build settings: leave blank, output directory: `.`
4. Deploy → Custom domain is instant since DNS is already on Cloudflare

---

## PHASE 3: Deploy the Backend API (30 min)

### Option A: Railway (Recommended — Easiest)

#### Step 3A.1 — Prepare the server repo

1. Unzip `wardkey-server.zip`
2. Create a new GitHub repo called `wardkey-server`
3. Push the server code:

```bash
cd wardkey-server
git init
git add .
git commit -m "WARDKEY API v1.0"
git branch -M main
git remote add origin https://github.com/YOUR_USER/wardkey-server.git
git push -u origin main
```

#### Step 3A.2 — Deploy on Railway

1. Go to https://railway.app → Sign in with GitHub
2. Click **"New Project"** → **"Deploy from GitHub Repo"**
3. Select `wardkey-server`
4. Railway auto-detects Node.js

#### Step 3A.3 — Set environment variables

In Railway dashboard → your service → **Variables** tab, add:

```
PORT=3000
NODE_ENV=production
JWT_SECRET=<generate a 64-char random string — use: openssl rand -hex 32>
DB_PATH=/app/data/wardkey.db
ALLOWED_ORIGINS=https://wardkey.io
BCRYPT_ROUNDS=12
SHARE_BASE_URL=https://wardkey.io/s
```

> ⚠️ The JWT_SECRET must be random and secret. Generate one:
> Run `openssl rand -hex 32` in your terminal, or use https://generate-random.org/api-key-generator

#### Step 3A.4 — Add persistent storage

1. In Railway → your service → **Settings** → **Volumes**
2. Add a volume: Mount path = `/app/data`
3. This ensures your SQLite database survives redeploys

#### Step 3A.5 — Generate a domain

1. In Railway → your service → **Settings** → **Networking**
2. Click **"Generate Domain"** → You get something like `wardkey-server-production.up.railway.app`
3. OR add a custom domain: `api.wardkey.io`
   - Add a CNAME record in Cloudflare: `api` → Railway's provided value

#### Step 3A.6 — Verify it works

```bash
curl https://api.wardkey.io/api/health
```

Should return:
```json
{"status":"ok","version":"1.0.0","uptime":...}
```

### Option B: Render

1. Go to https://render.com → **New Web Service**
2. Connect GitHub repo
3. Runtime: Node, Build command: `npm install`, Start command: `node server.js`
4. Add environment variables (same as Railway)
5. Add a disk: Mount path `/app/data`, size 1GB

### Option C: VPS (DigitalOcean / Hetzner)

```bash
# SSH into your server
ssh root@YOUR_SERVER_IP

# Install Docker
curl -fsSL https://get.docker.com | sh

# Clone and deploy
git clone https://github.com/YOUR_USER/wardkey-server.git
cd wardkey-server
cp .env.example .env
nano .env  # Fill in your secrets

docker compose up -d

# Set up reverse proxy (Caddy — auto SSL)
apt install caddy
echo 'api.wardkey.io {
  reverse_proxy localhost:3000
}' > /etc/caddy/Caddyfile
systemctl restart caddy
```

---

## PHASE 4: Connect Frontend to Backend (15 min)

### Step 4.1 — Add API configuration to the app

Open `app.html` (your wardkey.html). Find the `<script>` tag and add near the top, after the constants:

```javascript
const API_BASE = 'https://api.wardkey.io'; // Your Railway/Render URL
```

### Step 4.2 — Add sync functions

Add these functions to your app's JavaScript (before the closing `</script>`):

```javascript
// ═══════ CLOUD SYNC ═══════
async function apiCall(endpoint, options = {}) {
  const token = localStorage.getItem('wardkey_token');
  const res = await fetch(API_BASE + endpoint, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      ...(token ? { 'Authorization': 'Bearer ' + token } : {}),
      ...options.headers
    }
  });
  if (res.status === 401) { localStorage.removeItem('wardkey_token'); }
  return res.json();
}

async function cloudSync() {
  const token = localStorage.getItem('wardkey_token');
  if (!token || !mk) return;
  try {
    const encrypted = await encrypt(V, mk);
    await apiCall('/api/vault', {
      method: 'PUT',
      body: JSON.stringify({
        data: encrypted.ct,
        iv: JSON.stringify(encrypted.iv),
        salt: JSON.stringify(Array.from(window._salt || [])),
        version: parseInt(localStorage.getItem('wardkey_version') || '0') + 1
      })
    });
    localStorage.setItem('wardkey_version',
      (parseInt(localStorage.getItem('wardkey_version') || '0') + 1).toString());
    toast('☁️ Synced', 'ok');
  } catch (e) { console.error('Sync failed:', e); }
}
```

### Step 4.3 — Update CORS on the server

Make sure your Railway environment variable `ALLOWED_ORIGINS` includes your exact domain:
```
ALLOWED_ORIGINS=https://wardkey.io,https://www.wardkey.io
```

---

## PHASE 5: Chrome Extension (20 min)

### Step 5.1 — Test locally

1. Unzip `wardkey-extension.zip`
2. Open Chrome → go to `chrome://extensions`
3. Enable **"Developer mode"** (top right toggle)
4. Click **"Load unpacked"**
5. Select the `wardkey-extension` folder
6. The 🔐 icon appears in your toolbar
7. Click it → enter a master password → test autofill on a login page

### Step 5.2 — Prepare for Chrome Web Store

1. Update `manifest.json` if needed (change name, description)
2. Take screenshots of the extension (you'll need these for the listing):
   - 1280×800 screenshot of the popup
   - 440×280 small promo tile
   - 1400×560 marquee promo tile (optional)
3. Write a short description (max 132 chars for the store)

### Step 5.3 — Create a Chrome Web Store developer account

1. Go to https://chrome.google.com/webstore/devconsole
2. Pay the one-time **$5 registration fee**
3. Verify your email

### Step 5.4 — Package the extension

```bash
cd wardkey-extension
zip -r ../wardkey-extension-store.zip . -x ".*" -x "__MACOSX/*"
```

### Step 5.5 — Submit to Chrome Web Store

1. In the Developer Dashboard → **New Item**
2. Upload `wardkey-extension-store.zip`
3. Fill in:
   - **Name:** WARDKEY Password Manager
   - **Description:** AI-enhanced password manager with autofill, password generator, and breach detection. Local-first, zero-knowledge vault encryption.
   - **Category:** Productivity
   - **Language:** English
4. Upload screenshots
5. Set **Privacy Practices:**
   - Single purpose: "Password management and autofill"
   - Permissions justification: activeTab (autofill), storage (vault), clipboardWrite (copy passwords)
6. Click **Submit for Review**
7. Review takes 1-3 business days

> 💡 While waiting for review, you can share the extension directly using Developer mode + "Load unpacked" for beta testers.

---

## PHASE 6: PWA Configuration (10 min)

### Step 6.1 — Update the manifest

Open `wardkey-manifest.json` and update:

```json
{
  "start_url": "https://wardkey.io/app",
  "scope": "https://wardkey.io/"
}
```

### Step 6.2 — Update the service worker scope

Open `wardkey-sw.js` and update the ASSETS array to match your URL structure:

```javascript
const ASSETS = [
  '/',
  '/app.html',
  '/wardkey-manifest.json'
];
```

### Step 6.3 — Test the PWA

1. Open your site in Chrome
2. Look for the install icon in the address bar (➕ icon)
3. Or check: Chrome DevTools → **Application** tab → **Manifest** (should show your app info)
4. Check **Service Workers** tab — should show "activated and running"
5. On mobile: Open in Chrome/Safari → "Add to Home Screen"
6. The app should launch fullscreen without browser chrome

### Step 6.4 — Test offline

1. Install the PWA
2. Turn off WiFi
3. Open the app — it should load from cache
4. All vault operations work offline (they're local)

---

## PHASE 7: Final Checklist

### Technical Verification

- [ ] Landing page loads at `https://wardkey.io`
- [ ] App loads at `https://wardkey.io/app`
- [ ] PWA install prompt appears in Chrome
- [ ] App works offline after first visit
- [ ] API health check returns OK: `curl https://api.wardkey.io/api/health`
- [ ] User registration works: test via app or curl
- [ ] Chrome extension loads and popup opens
- [ ] Extension autofill works on a test login page
- [ ] Dark/light mode toggle works
- [ ] All vault types are functional (passwords, cards, notes, API keys, licenses, passkeys)
- [ ] Password generator generates and copies
- [ ] TOTP authenticator shows codes
- [ ] Launch buttons open sites and copy passwords
- [ ] Share links can be created

### SEO & Analytics

- [ ] Add Google Analytics or Plausible to landing page
- [ ] Add Open Graph meta tags for social sharing
- [ ] Submit sitemap to Google Search Console
- [ ] Add favicon (already done via inline SVG)

### Legal

- [ ] Add a Privacy Policy page (required for Chrome Web Store)
- [ ] Add Terms of Service page
- [ ] Add Cookie notice (if using analytics)

---

## PHASE 8: Marketing Launch

### Day 1 — Soft Launch

1. **Product Hunt** — https://producthunt.com
   - Prepare: tagline, description, screenshots, maker profile
   - Schedule launch for Tuesday/Wednesday (best traffic days)
   - Tagline: "AI-enhanced password manager — local-first, free during launch"

2. **Hacker News** — https://news.ycombinator.com
   - Post as "Show HN: WARDKEY — Local-first password manager with AI security analysis"
   - Best times: 8-10 AM EST weekdays

3. **Reddit**
   - r/privacy — emphasize local-first, zero-knowledge vault encryption
   - r/PasswordManagers — share unique features (Credential Map, Decay Timeline)
   - r/privacy — zero-knowledge vault encryption
   - r/cybersecurity — AI security analysis features
   - r/webdev — tech stack discussion

### Day 2-7 — Content Marketing

4. **Twitter/X thread**
   - "I built a local-first password manager with zero-knowledge encryption. Here's how:"
   - Show screenshots of unique features (Credential Map, Decay Timeline)

5. **Blog post / Dev.to article**
   - "Why I Built WARDKEY: The Password Manager I Wanted But Didn't Exist"
   - Cover: local-first architecture, AI integration, zero-knowledge vault encryption

6. **YouTube demo video**
   - 2-3 minute walkthrough of key features
   - Show the Credential Map and Decay Timeline (these are your differentiators)

### Ongoing

7. **Chrome Web Store optimization**
   - Good screenshots
   - Detailed description with keywords
   - Respond to all reviews

8. **GitHub**
   - Create a polished README with screenshots for GitHub
   - Add to Awesome lists (awesome-security)

---

## Quick Reference — All Your URLs

| Service | URL |
|---------|-----|
| **App** | https://wardkey.io/app |
| **Landing** | https://wardkey.io |
| **API** | https://api.wardkey.io |
| **API Health** | https://api.wardkey.io/api/health |
| **Share Links** | https://wardkey.io/s/{id} |
| **Chrome Extension** | chrome.google.com/webstore/detail/wardkey/... |
| **GitHub (frontend)** | github.com/YOU/wardkey |
| **GitHub (backend)** | github.com/YOU/wardkey-server |
| **Vercel Dashboard** | vercel.com/YOUR_USER/wardkey |
| **Railway Dashboard** | railway.app/project/... |
| **Cloudflare DNS** | dash.cloudflare.com |

---

## Troubleshooting

**PWA won't install?**
→ manifest.json must be served from the same origin. Check DevTools → Application → Manifest for errors.

**Service worker not registering?**
→ Must be served over HTTPS. Check DevTools → Application → Service Workers.

**CORS errors on API calls?**
→ Check `ALLOWED_ORIGINS` in your Railway/Render environment variables. Must include exact origin with protocol (https://wardkey.io).

**Extension autofill not working?**
→ Content script may not be injected on the current page. Try refreshing. Some sites block content scripts (banking sites).

**Railway deployment failing?**
→ Check logs in Railway dashboard. Common issue: missing `package.json` dependencies.

---

*You're ready to launch. Ship it.* 🚀
