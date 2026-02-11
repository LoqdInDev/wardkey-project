// WARDKEY Extension — Popup Controller v2.0
const $ = id => document.getElementById(id);
const API = 'https://api.wardkey.io';
const CRYPTO_VERSION = 4;

// ═══════ STATE ═══════
let vault = {};
let unlocked = false;
let currentDomain = '';
let activeTab = 'matches';
let activePanel = 'vault'; // vault | gen | alerts | account
let genPw = '';
let authToken = null;
let authUser = null;
let syncEnabled = false;
let syncInProgress = false;
let failedAttempts = 0;
let lockoutUntil = 0;
let mfaTempToken = null;
let lockTimeout = 0; // 0=every time, ms value, or -1=browser session

// ═══════ CRYPTO (v4 — compatible with web app) ═══════
async function deriveKey(pw, salt) {
  const enc = new TextEncoder();
  const base = await crypto.subtle.importKey('raw', enc.encode(pw), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: 600000, hash: 'SHA-256' },
    base,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

async function deriveVerifyHash(pw, salt) {
  const enc = new TextEncoder();
  const base = await crypto.subtle.importKey('raw', enc.encode(pw), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt, iterations: 310000, hash: 'SHA-512' },
    base,
    256
  );
  return btoa(String.fromCharCode(...new Uint8Array(bits)));
}

async function encrypt(data, key) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const enc = new TextEncoder().encode(JSON.stringify(data));
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, enc);
  return { iv: Array.from(iv), ct: Array.from(new Uint8Array(ct)) };
}

async function decrypt(data, key) {
  const ct = new Uint8Array(data.ct);
  const iv = new Uint8Array(data.iv);
  const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ct);
  return JSON.parse(new TextDecoder().decode(pt));
}

// ═══════ STORAGE (v4 format) ═══════
async function loadVault(pw) {
  const stored = await chrome.storage.local.get('wardkey_v4');
  if (!stored.wardkey_v4) return false;
  try {
    const blob = stored.wardkey_v4;
    const salt = new Uint8Array(blob.salt);
    // Verify hash first
    const verify = await deriveVerifyHash(pw, salt);
    if (verify !== blob.verify) return false;
    const key = await deriveKey(pw, salt);
    const decrypted = await decrypt(blob.data, key);
    vault = decrypted;
    // Ensure all arrays exist
    ['passwords','cards','notes','totp','apikeys','licenses','passkeys','aliases','breaches','trash','activity'].forEach(k => {
      if (!vault[k]) vault[k] = [];
    });
    window._mk = key;
    window._salt = salt;
    window._verify = verify;
    return true;
  } catch {
    return false;
  }
}

async function saveVault() {
  if (!window._mk) return;
  const e = await encrypt(vault, window._mk);
  const blob = { v: CRYPTO_VERSION, salt: Array.from(window._salt), verify: window._verify, data: e };
  await chrome.storage.local.set({ wardkey_v4: blob });
  if (syncEnabled && authToken) syncUp(blob);
}

async function initVault(pw) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const key = await deriveKey(pw, salt);
  const verify = await deriveVerifyHash(pw, salt);
  window._mk = key;
  window._salt = salt;
  window._verify = verify;
  vault = { passwords: [], cards: [], notes: [], totp: [], apikeys: [], licenses: [], passkeys: [], aliases: [], breaches: [], trash: [], activity: [] };
  await saveVault();
}

// ═══════ AUTH PERSISTENCE ═══════
async function loadAuth() {
  const data = await chrome.storage.local.get('wardkey_auth');
  if (data.wardkey_auth) {
    authToken = data.wardkey_auth.token;
    authUser = data.wardkey_auth.user;
    syncEnabled = !!authToken;
  }
}

async function saveAuth() {
  if (authToken && authUser) {
    await chrome.storage.local.set({ wardkey_auth: { token: authToken, user: authUser } });
  } else {
    await chrome.storage.local.remove('wardkey_auth');
  }
  syncEnabled = !!authToken;
  updateSyncDot();
}

// ═══════ CLOUD SYNC ═══════
async function syncUp(blob) {
  if (syncInProgress || !authToken) return;
  syncInProgress = true;
  updateSyncDot('active');
  try {
    const res = await fetch(API + '/api/vault', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + authToken },
      body: JSON.stringify(blob)
    });
    if (res.status === 401) { authToken = null; authUser = null; saveAuth(); toast('Session expired'); return; }
    if (!res.ok) throw new Error('Sync failed');
    updateSyncDot('ok');
  } catch {
    updateSyncDot('off');
  } finally {
    syncInProgress = false;
  }
}

async function syncDown() {
  if (!authToken || !window._mk) return;
  syncInProgress = true;
  updateSyncDot('active');
  try {
    const res = await fetch(API + '/api/vault', { headers: { 'Authorization': 'Bearer ' + authToken } });
    if (res.status === 401) { authToken = null; authUser = null; saveAuth(); toast('Session expired'); return; }
    if (!res.ok) throw new Error('Download failed');
    const data = await res.json();
    if (data.vault && data.vault.data) {
      await chrome.storage.local.set({ wardkey_v4: data.vault });
      const salt = new Uint8Array(data.vault.salt);
      vault = await decrypt(data.vault.data, window._mk);
      ['passwords','cards','notes','totp','apikeys','licenses','passkeys','aliases','breaches','trash','activity'].forEach(k => {
        if (!vault[k]) vault[k] = [];
      });
      window._salt = salt;
      window._verify = data.vault.verify;
      updateSyncDot('ok');
      renderList();
      toast('Vault synced');
    } else {
      updateSyncDot('ok');
    }
  } catch {
    updateSyncDot('off');
    toast('Sync failed');
  } finally {
    syncInProgress = false;
  }
}

function updateSyncDot(state) {
  const dot = $('syncDot');
  if (!dot) return;
  dot.className = 'hdr-sync ' + (state || (syncEnabled ? 'ok' : 'off'));
}

// ═══════ UNLOCK ═══════
$('unlockBtn').onclick = async () => {
  const pw = $('masterPw').value;
  if (!pw || pw.length < 4) { shake($('masterPw')); $('lockErr').textContent = 'Min 4 characters'; return; }

  // Brute force protection
  if (Date.now() < lockoutUntil) {
    const secs = Math.ceil((lockoutUntil - Date.now()) / 1000);
    $('lockErr').textContent = `Locked out. Try again in ${secs}s`;
    shake($('masterPw'));
    return;
  }

  $('lockErr').textContent = '';
  $('unlockBtn').textContent = 'Unlocking...';
  $('unlockBtn').disabled = true;

  // Small delay to let UI update before heavy crypto
  await new Promise(r => setTimeout(r, 50));

  const hasVault = (await chrome.storage.local.get('wardkey_v4')).wardkey_v4;
  if (hasVault) {
    const ok = await loadVault(pw);
    if (!ok) {
      failedAttempts++;
      if (failedAttempts >= 5) {
        lockoutUntil = Date.now() + 60000;
        $('lockErr').textContent = 'Too many attempts. Locked for 60s';
        $('lockAttempts').textContent = '';
      } else {
        $('lockErr').textContent = 'Wrong password';
        $('lockAttempts').textContent = `${5 - failedAttempts} attempts remaining`;
      }
      shake($('masterPw'));
      $('unlockBtn').textContent = 'Unlock Vault';
      $('unlockBtn').disabled = false;
      return;
    }
  } else {
    await initVault(pw);
    toast('Vault created!');
  }

  failedAttempts = 0;
  $('lockAttempts').textContent = '';
  unlocked = true;
  window._masterPw = pw;
  $('lockScreen').style.display = 'none';
  $('appView').classList.add('on');
  $('unlockBtn').textContent = 'Unlock Vault';
  $('unlockBtn').disabled = false;

  // Store session for auto-unlock (pw in session storage — extension-only, cleared on browser close)
  chrome.storage.session?.set({ wardkey_session: { ts: Date.now(), pw } });
  chrome.runtime.sendMessage({ type: 'WARDKEY_ACTIVITY' });

  getCurrentSite();
  renderList();
  updateSyncDot();
  checkPendingSave();

  // Auto sync on unlock
  if (syncEnabled && authToken) syncDown();
};

$('masterPw').onkeydown = e => { if (e.key === 'Enter') $('unlockBtn').click(); };

$('lockBtn').onclick = () => {
  unlocked = false;
  vault = {};
  window._mk = null;
  window._salt = null;
  window._verify = null;
  window._masterPw = null;
  chrome.storage.session?.remove('wardkey_session'); // clear auto-unlock session
  $('appView').classList.remove('on');
  $('lockScreen').style.display = '';
  $('masterPw').value = '';
  $('lockErr').textContent = '';
  $('masterPw').focus();
  showPanel('vault');
};

// ═══════ CURRENT SITE ═══════
async function getCurrentSite() {
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (tab?.url) {
      const url = new URL(tab.url);
      currentDomain = url.hostname.replace('www.', '');
      $('curSite').textContent = currentDomain;
    }
  } catch { currentDomain = ''; }
}

function getMatches() {
  if (!currentDomain || !vault.passwords) return [];
  return vault.passwords.filter(p => {
    const url = (p.url || '').toLowerCase().replace('https://', '').replace('http://', '').replace('www.', '');
    const domain = currentDomain.toLowerCase();
    return url.includes(domain) || domain.includes(url.split('/')[0]);
  });
}

// ═══════ RENDER ═══════
function renderList() {
  const list = $('itemList');
  const gen = $('genPanel');
  const alerts = $('alertsPanel');
  const acct = $('acctPanel');
  const query = $('searchInput').value.toLowerCase();

  // Hide all panels first
  list.style.display = '';
  gen.classList.remove('on');
  alerts.classList.remove('on');
  acct.classList.remove('on');
  $('addForm').classList.remove('on');
  hideAuth();
  $('searchBar').style.display = '';
  $('tabBar').style.display = '';
  $('matchBanner').style.display = 'none';

  if (activePanel === 'gen') {
    list.style.display = 'none';
    gen.classList.add('on');
    $('searchBar').style.display = 'none';
    $('tabBar').style.display = 'none';
    return;
  }

  if (activePanel === 'alerts') {
    list.style.display = 'none';
    $('searchBar').style.display = 'none';
    $('tabBar').style.display = 'none';
    renderAlerts();
    return;
  }

  if (activePanel === 'account') {
    list.style.display = 'none';
    $('searchBar').style.display = 'none';
    $('tabBar').style.display = 'none';
    renderAccount();
    return;
  }

  // Vault panel
  let items;
  if (activeTab === 'matches') {
    items = getMatches();
    if (items.length) {
      $('matchBanner').style.display = '';
      $('matchCount').textContent = `${items.length} credential${items.length > 1 ? 's' : ''} for ${currentDomain}`;
    }
  } else if (activeTab === 'all') {
    items = vault.passwords || [];
  } else if (activeTab === 'favorites') {
    items = (vault.passwords || []).filter(p => p.fav);
  } else if (activeTab === 'recents') {
    items = [...(vault.passwords || [])].sort((a, b) => (b.modified || b.created || 0) - (a.modified || a.created || 0)).slice(0, 15);
  } else {
    items = vault.passwords || [];
  }

  if (query) {
    items = items.filter(p =>
      (p.name || '').toLowerCase().includes(query) ||
      (p.username || '').toLowerCase().includes(query) ||
      (p.url || '').toLowerCase().includes(query)
    );
  }

  if (!items.length) {
    list.innerHTML = `<div class="empty">
      <div class="empty-ic">${activeTab === 'matches' ? '🔍' : activeTab === 'favorites' ? '⭐' : activeTab === 'recents' ? '🕐' : '📭'}</div>
      <div class="empty-t">${activeTab === 'matches' ? 'No matches for this site' : activeTab === 'favorites' ? 'No favorites yet' : activeTab === 'recents' ? 'No recent items' : 'Vault is empty'}</div>
      <div class="empty-d">${activeTab === 'matches' ? 'Add credentials or check all items' : 'Items will appear here as you use WARDKEY'}</div>
    </div>`;
    return;
  }

  list.innerHTML = items.map(p => {
    const s = pwStr(p.password);
    return `<div class="item" data-id="${p.id}">
      <div class="item-ic">${p.icon || '🔑'}</div>
      <div class="item-info">
        <div class="item-name">${esc(p.name)}</div>
        <div class="item-user">${esc(p.username || '')}</div>
      </div>
      <div style="display:flex;align-items:center;gap:4px;margin-right:2px">
        <div class="sb"><div class="sb-f" style="width:${s.pct}%;background:${s.color}"></div></div>
      </div>
      <div class="item-acts">
        <button class="act act-fill" title="Autofill" data-action="fill" data-id="${p.id}">
          <svg viewBox="0 0 24 24"><path d="M11 4H4a2 2 0 00-2 2v14a2 2 0 002 2h14a2 2 0 002-2v-7"/><path d="M18.5 2.5a2.12 2.12 0 013 3L12 15l-4 1 1-4 9.5-9.5z"/></svg>
        </button>
        <button class="act" title="Copy password" data-action="copy" data-id="${p.id}">
          <svg viewBox="0 0 24 24"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 01-2-2V4a2 2 0 012-2h9a2 2 0 012 2v1"/></svg>
        </button>
        <button class="act" title="Launch site" data-action="launch" data-id="${p.id}">
          <svg viewBox="0 0 24 24"><path d="M18 13v6a2 2 0 01-2 2H5a2 2 0 01-2-2V8a2 2 0 012-2h6"/><polyline points="15 3 21 3 21 9"/><line x1="10" y1="14" x2="21" y2="3"/></svg>
        </button>
      </div>
    </div>`;
  }).join('');

  bindItemActions();

  // Update badge
  chrome.runtime.sendMessage({ type: 'WARDKEY_BADGE', count: getMatches().length });
}

function bindItemActions() {
  const list = $('itemList');
  list.querySelectorAll('.act').forEach(btn => {
    btn.onclick = e => {
      e.stopPropagation();
      const action = btn.dataset.action;
      const id = btn.dataset.id;
      const item = (vault.passwords || []).find(p => p.id === id);
      if (!item) return;
      if (action === 'fill') autofill(item);
      if (action === 'copy') copyPw(item.password);
      if (action === 'launch') launchSite(item);
    };
  });
  list.querySelectorAll('.item').forEach(el => {
    el.onclick = () => {
      const item = (vault.passwords || []).find(p => p.id === el.dataset.id);
      if (item) autofill(item);
    };
  });
}

// ═══════ ALERTS ═══════
function getAlerts() {
  const alerts = { weak: [], reused: [], old: [] };
  const pws = vault.passwords || [];
  const pwMap = {};

  pws.forEach(p => {
    if (!p.password) return;
    // Weak check
    const s = pwStr(p.password);
    if (s.pct < 40) alerts.weak.push(p);
    // Reused check
    if (!pwMap[p.password]) pwMap[p.password] = [];
    pwMap[p.password].push(p);
  });

  Object.values(pwMap).forEach(group => {
    if (group.length > 1) alerts.reused.push(...group);
  });

  // Old passwords (90+ days)
  const now = Date.now();
  pws.forEach(p => {
    const lastMod = p.modified || p.created;
    if (lastMod && (now - lastMod) > 90 * 24 * 60 * 60 * 1000) alerts.old.push(p);
  });

  return alerts;
}

function renderAlerts() {
  const panel = $('alertsPanel');
  panel.classList.add('on');
  const a = getAlerts();
  const total = a.weak.length + new Set(a.reused.map(p => p.id)).size + a.old.length;

  // Update badge
  const badge = document.querySelector('.ftr-btn[data-nav="alerts"] .ftr-badge');
  if (badge) badge.textContent = total || '';
  if (badge) badge.style.display = total ? 'flex' : 'none';

  if (!total) {
    panel.innerHTML = `<div class="alerts-ok"><div class="alerts-ok-ic">🛡️</div><div class="alerts-ok-t">All clear!</div><div style="font-size:11px;margin-top:4px">No security issues found</div></div>`;
    return;
  }

  let html = '';
  if (a.weak.length) {
    html += `<div class="alert-card"><div class="alert-card-h"><div class="alert-card-ic">⚠️</div><div class="alert-card-t">Weak Passwords</div><div class="alert-card-n">${a.weak.length}</div></div><div class="alert-card-d">${a.weak.map(p => esc(p.name)).join(', ')}</div></div>`;
  }
  const reusedUnique = [...new Set(a.reused.map(p => p.password))];
  if (reusedUnique.length) {
    const count = new Set(a.reused.map(p => p.id)).size;
    html += `<div class="alert-card"><div class="alert-card-h"><div class="alert-card-ic">🔄</div><div class="alert-card-t">Reused Passwords</div><div class="alert-card-n">${count}</div></div><div class="alert-card-d">${count} items share passwords with other entries</div></div>`;
  }
  if (a.old.length) {
    html += `<div class="alert-card"><div class="alert-card-h"><div class="alert-card-ic">🕐</div><div class="alert-card-t">Old Passwords</div><div class="alert-card-n">${a.old.length}</div></div><div class="alert-card-d">Not changed in 90+ days</div></div>`;
  }
  panel.innerHTML = html;
}

// ═══════ ACCOUNT ═══════
function renderAccount() {
  const panel = $('acctPanel');
  panel.classList.add('on');

  // Lock timeout setting (shown for all users)
  const lockOptHtml = LOCK_OPTIONS.map(o =>
    `<option value="${o.value}"${o.value === lockTimeout ? ' selected' : ''}>${o.label}</option>`
  ).join('');
  const lockSettingHtml = `
    <div class="acct-title" style="margin-top:14px">Settings</div>
    <div class="acct-card">
      <div class="acct-row">
        <div class="acct-row-l">Auto-lock</div>
        <select id="lockTimeoutSel" style="background:var(--bg3);color:var(--tx1);border:1px solid var(--bd);border-radius:4px;padding:4px 6px;font-size:12px;font-family:var(--font);outline:none;cursor:pointer">
          ${lockOptHtml}
        </select>
      </div>
    </div>`;

  if (syncEnabled && authUser) {
    panel.innerHTML = `
      <div class="acct-title">Account</div>
      <div class="acct-card">
        <div class="acct-row"><div class="acct-row-l">Email</div><div class="acct-row-v">${esc(authUser.email)}</div></div>
        <div class="acct-row"><div class="acct-row-l">Plan</div><div class="acct-row-v" style="color:var(--ac)">${esc(authUser.plan || 'free')}</div></div>
        <div class="acct-row"><div class="acct-row-l">2FA</div><div class="acct-row-v" style="color:${authUser.mfa_enabled ? 'var(--gn)' : 'var(--tx3)'}">${authUser.mfa_enabled ? 'Enabled' : 'Disabled'}</div></div>
        <div class="acct-row"><div class="acct-row-l">Cloud Sync</div><div class="acct-row-v" style="color:var(--gn)">Connected</div></div>
      </div>
      <div style="display:flex;gap:6px">
        <button class="btn btn-s" style="flex:1" id="acctSyncBtn">🔄 Sync Now</button>
        <button class="btn btn-d" style="flex:1" id="acctLogoutBtn">Log Out</button>
      </div>
      ${lockSettingHtml}`;

    $('acctSyncBtn').onclick = () => { syncDown(); toast('Syncing...'); };
    $('acctLogoutBtn').onclick = () => {
      authToken = null;
      authUser = null;
      syncEnabled = false;
      saveAuth();
      renderAccount();
      toast('Logged out');
    };
  } else {
    panel.innerHTML = `
      <div style="text-align:center;padding:20px 0">
        <div style="font-size:32px;margin-bottom:8px">☁️</div>
        <div class="acct-title" style="margin-bottom:4px">Cloud Sync</div>
        <div style="font-size:11px;color:var(--tx3);margin-bottom:16px;line-height:1.5">Sign in to sync your encrypted vault across all your devices. Your master password never leaves your device.</div>
        <button class="btn btn-p" id="acctLoginBtn" style="margin-bottom:8px">Sign In</button>
        <button class="btn btn-s" id="acctRegBtn">Create Account</button>
      </div>
      ${lockSettingHtml}`;

    $('acctLoginBtn').onclick = () => showAuth('login');
    $('acctRegBtn').onclick = () => showAuth('register');
  }

  // Bind lock timeout change
  $('lockTimeoutSel').onchange = (e) => {
    const val = parseInt(e.target.value);
    saveLockTimeout(val);
    if (val === 0) {
      chrome.storage.session?.remove('wardkey_session');
      toast('Will ask every time');
    } else {
      toast('Auto-lock updated');
    }
  };
}

// ═══════ AUTH UI ═══════
function showAuth(mode) {
  hideAuth();
  $('acctPanel').classList.remove('on');
  $('searchBar').style.display = 'none';
  $('tabBar').style.display = 'none';
  $('itemList').style.display = 'none';

  if (mode === 'login') {
    $('authLogin').classList.add('on');
    $('authEmail').focus();
  } else if (mode === 'register') {
    $('authRegister').classList.add('on');
    $('regName').focus();
  } else if (mode === '2fa') {
    $('auth2fa').classList.add('on');
    $('auth2faCode').value = '';
    $('auth2faCode').focus();
  }
}

function hideAuth() {
  $('authLogin').classList.remove('on');
  $('authRegister').classList.remove('on');
  $('auth2fa').classList.remove('on');
  $('authErr').textContent = '';
  $('regErr').textContent = '';
  $('auth2faErr').textContent = '';
}

$('showRegister').onclick = () => showAuth('register');
$('showLogin').onclick = () => showAuth('login');

// Login
$('authLoginBtn').onclick = async () => {
  const email = $('authEmail').value.trim();
  const pw = $('authPw').value;
  if (!email || !pw) { $('authErr').textContent = 'Email and password required'; return; }

  $('authLoginBtn').textContent = 'Signing in...';
  $('authLoginBtn').disabled = true;

  try {
    const res = await fetch(API + '/api/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password: pw })
    });
    const data = await res.json();
    if (!res.ok) { $('authErr').textContent = data.error || 'Login failed'; return; }

    if (data.requires2fa) {
      mfaTempToken = data.tempToken;
      showAuth('2fa');
      return;
    }

    authToken = data.token;
    authUser = data.user;
    syncEnabled = true;
    await saveAuth();
    hideAuth();

    // Download vault from cloud
    await syncDown();
    showPanel('vault');
    toast('Signed in!');
  } catch (e) {
    $('authErr').textContent = 'Connection error';
  } finally {
    $('authLoginBtn').textContent = 'Sign In';
    $('authLoginBtn').disabled = false;
  }
};

// Register
$('authRegBtn').onclick = async () => {
  const name = $('regName').value.trim();
  const email = $('regEmail').value.trim();
  const pw = $('regPw').value;
  const conf = $('regPwConf').value;

  if (!email || !pw) { $('regErr').textContent = 'Email and password required'; return; }
  if (pw.length < 8) { $('regErr').textContent = 'Password must be 8+ characters'; return; }
  if (pw !== conf) { $('regErr').textContent = 'Passwords do not match'; return; }

  $('authRegBtn').textContent = 'Creating...';
  $('authRegBtn').disabled = true;

  try {
    const res = await fetch(API + '/api/auth/register', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password: pw, name: name || undefined })
    });
    const data = await res.json();
    if (!res.ok) { $('regErr').textContent = data.error || 'Registration failed'; return; }

    authToken = data.token;
    authUser = data.user;
    syncEnabled = true;
    await saveAuth();
    hideAuth();

    // Upload current vault to cloud
    if (window._mk) {
      const e = await encrypt(vault, window._mk);
      const blob = { v: CRYPTO_VERSION, salt: Array.from(window._salt), verify: window._verify, data: e };
      await syncUp(blob);
    }
    showPanel('vault');
    toast('Account created!');
  } catch (e) {
    $('regErr').textContent = 'Connection error';
  } finally {
    $('authRegBtn').textContent = 'Create Account';
    $('authRegBtn').disabled = false;
  }
};

// 2FA Verify
$('auth2faBtn').onclick = async () => {
  const code = $('auth2faCode').value.trim();
  if (!code || code.length !== 6) { $('auth2faErr').textContent = 'Enter 6-digit code'; return; }

  $('auth2faBtn').textContent = 'Verifying...';
  $('auth2faBtn').disabled = true;

  try {
    const res = await fetch(API + '/api/auth/2fa/verify-login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ tempToken: mfaTempToken, totpCode: code })
    });
    const data = await res.json();
    if (!res.ok) { $('auth2faErr').textContent = data.error || 'Invalid code'; return; }

    authToken = data.token;
    authUser = data.user;
    syncEnabled = true;
    mfaTempToken = null;
    await saveAuth();
    hideAuth();
    await syncDown();
    showPanel('vault');
    toast('Signed in!');
  } catch (e) {
    $('auth2faErr').textContent = 'Connection error';
  } finally {
    $('auth2faBtn').textContent = 'Verify';
    $('auth2faBtn').disabled = false;
  }
};

$('auth2faCancel').onclick = () => { mfaTempToken = null; showAuth('login'); };
$('auth2faCode').onkeydown = e => { if (e.key === 'Enter') $('auth2faBtn').click(); };
$('authPw').onkeydown = e => { if (e.key === 'Enter') $('authLoginBtn').click(); };
$('regPwConf').onkeydown = e => { if (e.key === 'Enter') $('authRegBtn').click(); };

// ═══════ SAVE PASSWORD PROMPT ═══════
async function checkPendingSave() {
  const data = await chrome.storage.session?.get('wardkey_pendingSave');
  if (!data?.wardkey_pendingSave) { $('saveBanner').classList.remove('on'); return; }

  const pending = data.wardkey_pendingSave;
  $('saveBannerTitle').textContent = `Save password for ${pending.domain}?`;
  $('saveBannerDesc').textContent = pending.username ? `${pending.username}` : 'New credentials detected';
  $('saveBanner').classList.add('on');
}

$('saveBannerYes').onclick = async () => {
  const data = await chrome.storage.session?.get('wardkey_pendingSave');
  if (!data?.wardkey_pendingSave) return;

  const pending = data.wardkey_pendingSave;

  // Check if credential exists for this domain+username
  const existing = (vault.passwords || []).find(p =>
    (p.url || '').toLowerCase().includes(pending.domain) &&
    (p.username || '').toLowerCase() === (pending.username || '').toLowerCase()
  );

  if (existing) {
    // Update existing
    if (existing.password !== pending.password) {
      if (!existing.history) existing.history = [];
      existing.history.push({ pw: existing.password, changed: Date.now() });
      existing.password = pending.password;
      existing.modified = Date.now();
    }
  } else {
    // Create new
    vault.passwords.push({
      id: crypto.randomUUID(),
      name: pending.domain,
      username: pending.username || '',
      password: pending.password,
      url: 'https://' + pending.domain,
      cat: '',
      tags: [],
      notes: '',
      created: Date.now(),
      modified: Date.now(),
      history: [],
      icon: '🔑',
      fav: false,
      sens: false,
      fields: []
    });
  }

  await saveVault();
  await chrome.storage.session?.remove('wardkey_pendingSave');
  $('saveBanner').classList.remove('on');
  renderList();
  toast(existing ? 'Password updated' : 'Password saved');
};

$('saveBannerNo').onclick = async () => {
  await chrome.storage.session?.remove('wardkey_pendingSave');
  $('saveBanner').classList.remove('on');
};

// ═══════ ACTIONS ═══════
async function autofill(item) {
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    await chrome.tabs.sendMessage(tab.id, {
      type: 'WARDKEY_FILL',
      username: item.username || '',
      password: item.password || ''
    });
    toast('Filled');
    setTimeout(() => window.close(), 600);
  } catch {
    copyPw(item.password);
    toast('Copied (autofill unavailable)');
  }
}

function copyPw(pw) {
  navigator.clipboard.writeText(pw);
  toast('Copied');
  setTimeout(() => { navigator.clipboard.writeText('').catch(() => {}); }, 30000);
}

function launchSite(item) {
  let url = item.url;
  if (!url) return;
  if (!url.startsWith('http')) url = 'https://' + url;
  copyPw(item.password);
  chrome.tabs.create({ url });
  toast('Launched');
}

// ═══════ PASSWORD GENERATOR ═══════
const genOpts = { upper: true, lower: true, nums: true, syms: true };

function generatePw() {
  const len = parseInt($('genLen').value);
  let chars = '';
  if (genOpts.lower) chars += 'abcdefghijklmnopqrstuvwxyz';
  if (genOpts.upper) chars += 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
  if (genOpts.nums) chars += '0123456789';
  if (genOpts.syms) chars += '!@#$%^&*()_+-=[]{}|;:,.<>?';
  if (!chars) chars = 'abcdefghijklmnopqrstuvwxyz';

  const arr = crypto.getRandomValues(new Uint8Array(len));
  genPw = Array.from(arr, b => chars[b % chars.length]).join('');
  $('genOut').textContent = genPw;

  const s = pwStr(genPw);
  $('genStr').style.width = s.pct + '%';
  $('genStr').style.background = s.color;
  $('genStrL').textContent = s.label;
}

$('genLen').oninput = () => { $('genLenV').textContent = $('genLen').value; };
$('genBtn').onclick = generatePw;
$('genCopy').onclick = () => { if (genPw) copyPw(genPw); };
$('genFill').onclick = async () => {
  if (!genPw) return;
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    await chrome.tabs.sendMessage(tab.id, { type: 'WARDKEY_FILL_PW', password: genPw });
    toast('Filled');
  } catch { copyPw(genPw); }
};

document.querySelectorAll('.gen-opt').forEach(el => {
  el.onclick = () => {
    const opt = el.dataset.opt;
    genOpts[opt] = !genOpts[opt];
    el.classList.toggle('on', genOpts[opt]);
  };
});

// ═══════ PANEL NAVIGATION ═══════
function showPanel(panel) {
  activePanel = panel;
  document.querySelectorAll('.ftr-btn').forEach(b => b.classList.toggle('on', b.dataset.nav === panel));
  if (panel === 'vault') {
    activeTab = 'matches';
    document.querySelectorAll('.tab').forEach(t => t.classList.toggle('on', t.dataset.tab === 'matches'));
  }
  renderList();
}

// Tabs
document.querySelectorAll('.tab').forEach(tab => {
  tab.onclick = () => {
    activeTab = tab.dataset.tab;
    document.querySelectorAll('.tab').forEach(t => t.classList.toggle('on', t === tab));
    renderList();
  };
});

// Footer
document.querySelectorAll('.ftr-btn').forEach(btn => {
  btn.onclick = () => {
    showPanel(btn.dataset.nav);
  };
});

$('searchInput').oninput = () => renderList();

// ═══════ ADD ITEM (+) BUTTON ═══════
let addItemType = null;

$('addBtn').onclick = (e) => {
  e.stopPropagation();
  $('addDrop').classList.toggle('on');
};

// Close dropdown on outside click
document.addEventListener('click', () => { $('addDrop').classList.remove('on'); });

document.querySelectorAll('.add-drop-item').forEach(item => {
  item.onclick = (e) => {
    e.stopPropagation();
    $('addDrop').classList.remove('on');
    openAddForm(item.dataset.type);
  };
});

const ADD_FORMS = {
  password: {
    icon: '🔑', title: 'Add Password',
    fields: [
      { id: 'addName', placeholder: 'Name (e.g. Google)', type: 'text' },
      { id: 'addUrl', placeholder: 'Website URL', type: 'url' },
      { id: 'addUsername', placeholder: 'Username / Email', type: 'text' },
      { id: 'addPassword', placeholder: 'Password', type: 'password' }
    ]
  },
  card: {
    icon: '💳', title: 'Add Payment Card',
    fields: [
      { id: 'addName', placeholder: 'Card name (e.g. Visa ending 4242)', type: 'text' },
      { id: 'addHolder', placeholder: 'Cardholder name', type: 'text' },
      { id: 'addNumber', placeholder: 'Card number', type: 'text' },
      { id: 'addExp', placeholder: 'Expiry (MM/YY)', type: 'text' },
      { id: 'addCvv', placeholder: 'CVV', type: 'password' }
    ]
  },
  note: {
    icon: '📝', title: 'Add Secure Note',
    fields: [
      { id: 'addName', placeholder: 'Note title', type: 'text' },
      { id: 'addContent', placeholder: 'Note content', type: 'textarea' }
    ]
  },
  totp: {
    icon: '🔢', title: 'Add TOTP Key',
    fields: [
      { id: 'addName', placeholder: 'Name (e.g. GitHub)', type: 'text' },
      { id: 'addIssuer', placeholder: 'Issuer', type: 'text' },
      { id: 'addSecret', placeholder: 'Secret key (base32)', type: 'text' }
    ]
  }
};

function openAddForm(type) {
  addItemType = type;
  const config = ADD_FORMS[type];
  $('addFormIcon').textContent = config.icon;
  $('addFormTitle').textContent = config.title;

  // Auto-fill URL with current site for passwords
  let html = '';
  config.fields.forEach(f => {
    if (f.type === 'textarea') {
      html += `<textarea class="inp" id="${f.id}" placeholder="${f.placeholder}" style="min-height:80px;resize:vertical"></textarea>`;
    } else {
      html += `<input class="inp" id="${f.id}" placeholder="${f.placeholder}" type="${f.type}">`;
    }
  });
  $('addFormFields').innerHTML = html;

  // Pre-fill URL for password type
  if (type === 'password' && currentDomain) {
    const urlField = $('addUrl');
    if (urlField) urlField.value = 'https://' + currentDomain;
  }

  // Show form panel
  activePanel = 'addform';
  $('addForm').classList.add('on');
  $('itemList').style.display = 'none';
  $('genPanel').classList.remove('on');
  $('alertsPanel').classList.remove('on');
  $('acctPanel').classList.remove('on');
  hideAuth();
  $('searchBar').style.display = 'none';
  $('tabBar').style.display = 'none';
  $('matchBanner').style.display = 'none';

  // Focus first field
  const firstField = $('addFormFields').querySelector('.inp');
  if (firstField) firstField.focus();
}

$('addFormCancel').onclick = () => {
  $('addForm').classList.remove('on');
  addItemType = null;
  showPanel('vault');
};

$('addFormSave').onclick = async () => {
  if (!addItemType) return;

  if (addItemType === 'password') {
    const name = $('addName')?.value.trim();
    const url = $('addUrl')?.value.trim();
    const username = $('addUsername')?.value.trim();
    const password = $('addPassword')?.value;
    if (!name) { shake($('addName')); return; }
    if (!password) { shake($('addPassword')); return; }
    vault.passwords.push({
      id: crypto.randomUUID(), name, url: url || '', username: username || '', password,
      cat: '', tags: [], notes: '', created: Date.now(), modified: Date.now(),
      history: [], icon: '🔑', fav: false, sens: false, fields: []
    });
  } else if (addItemType === 'card') {
    const name = $('addName')?.value.trim();
    const holder = $('addHolder')?.value.trim();
    const number = $('addNumber')?.value.trim();
    const exp = $('addExp')?.value.trim();
    const cvv = $('addCvv')?.value;
    if (!name) { shake($('addName')); return; }
    if (!vault.cards) vault.cards = [];
    vault.cards.push({
      id: crypto.randomUUID(), name, number: number || '', holder: holder || '',
      exp: exp || '', cvv: cvv || '', pin: '', type: '', billing: '', icon: '💳'
    });
  } else if (addItemType === 'note') {
    const name = $('addName')?.value.trim();
    const content = $('addContent')?.value;
    if (!name) { shake($('addName')); return; }
    if (!vault.notes) vault.notes = [];
    vault.notes.push({
      id: crypto.randomUUID(), name, content: content || '',
      created: Date.now(), modified: Date.now(), icon: '📝'
    });
  } else if (addItemType === 'totp') {
    const name = $('addName')?.value.trim();
    const issuer = $('addIssuer')?.value.trim();
    const secret = $('addSecret')?.value.trim();
    if (!name) { shake($('addName')); return; }
    if (!secret) { shake($('addSecret')); return; }
    if (!vault.totp) vault.totp = [];
    vault.totp.push({
      id: crypto.randomUUID(), name, secret, issuer: issuer || '', icon: '🔢'
    });
  }

  await saveVault();
  $('addForm').classList.remove('on');
  addItemType = null;
  showPanel('vault');
  toast('Item saved');
};

// ═══════ IMPORT FROM WEB APP ═══════
chrome.runtime.onMessage.addListener((msg) => {
  if (msg.type === 'WARDKEY_IMPORT') {
    if (msg.passwords) vault.passwords = msg.passwords;
    saveVault();
    renderList();
    toast(`Imported ${(msg.passwords || []).length} items`);
  }
  if (msg.type === 'WARDKEY_PENDING_SAVE' && unlocked) {
    checkPendingSave();
  }
});

// ═══════ HELPERS ═══════
function pwStr(pw) {
  if (!pw) return { pct: 0, color: 'var(--rd)', label: 'None' };
  let pool = 0;
  if (/[a-z]/.test(pw)) pool += 26;
  if (/[A-Z]/.test(pw)) pool += 26;
  if (/\d/.test(pw)) pool += 10;
  if (/[^a-zA-Z0-9]/.test(pw)) pool += 32;
  const bits = Math.log2(Math.pow(pool || 26, pw.length));
  const pct = Math.min(100, (bits / 128) * 100);
  let color, label;
  if (bits < 28) { color = 'var(--rd)'; label = 'Weak'; }
  else if (bits < 50) { color = 'var(--og)'; label = 'Fair'; }
  else if (bits < 70) { color = 'var(--yl)'; label = 'Good'; }
  else { color = 'var(--gn)'; label = 'Strong'; }
  return { pct, color, label };
}

function esc(s) {
  const d = document.createElement('div');
  d.textContent = s;
  return d.innerHTML;
}

function shake(el) {
  el.style.animation = 'none';
  el.offsetHeight;
  el.style.animation = 'shake .4s';
}

let toastTimer;
function toast(msg) {
  const existing = document.querySelector('.toast');
  if (existing) existing.remove();
  const t = document.createElement('div');
  t.className = 'toast';
  t.textContent = msg;
  document.body.appendChild(t);
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => t.remove(), 2000);
}

// ═══════ THEME TOGGLE ═══════
let currentTheme = 'dark';

async function loadTheme() {
  const data = await chrome.storage.local.get('wardkey_theme');
  currentTheme = data.wardkey_theme || 'dark';
  applyTheme();
}

function applyTheme() {
  if (currentTheme === 'light') {
    document.documentElement.setAttribute('data-theme', 'light');
    $('themeBtn').textContent = '☀️';
  } else {
    document.documentElement.removeAttribute('data-theme');
    $('themeBtn').textContent = '🌙';
  }
}

$('themeBtn').onclick = async () => {
  currentTheme = currentTheme === 'dark' ? 'light' : 'dark';
  applyTheme();
  await chrome.storage.local.set({ wardkey_theme: currentTheme });
};

// ═══════ LOCK TIMEOUT SETTING ═══════
const LOCK_OPTIONS = [
  { value: 0, label: 'Every time' },
  { value: 900000, label: '15 minutes' },
  { value: 3600000, label: '1 hour' },
  { value: 86400000, label: '1 day' },
  { value: 604800000, label: '1 week' },
  { value: -1, label: 'Browser session (until closed)' }
];

async function loadLockTimeout() {
  const data = await chrome.storage.local.get('wardkey_lockTimeout');
  lockTimeout = data.wardkey_lockTimeout ?? 0;
}

async function saveLockTimeout(val) {
  lockTimeout = val;
  await chrome.storage.local.set({ wardkey_lockTimeout: val });
}

// ═══════ AUTO-UNLOCK ═══════
async function tryAutoUnlock() {
  if (lockTimeout === 0) return; // every time = always ask

  const data = await chrome.storage.session?.get('wardkey_session');
  if (!data?.wardkey_session?.pw) return;

  const session = data.wardkey_session;
  const elapsed = Date.now() - session.ts;

  // Check if session is still valid
  if (lockTimeout === -1 || elapsed < lockTimeout) {
    // Try to unlock with stored password
    $('lockErr').textContent = '';
    const hasVault = (await chrome.storage.local.get('wardkey_v4')).wardkey_v4;
    if (!hasVault) return;

    const ok = await loadVault(session.pw);
    if (!ok) {
      // Stored pw no longer valid (vault changed?) — clear session
      chrome.storage.session?.remove('wardkey_session');
      return;
    }

    unlocked = true;
    window._masterPw = session.pw;
    $('lockScreen').style.display = 'none';
    $('appView').classList.add('on');

    // Refresh session timestamp
    chrome.storage.session?.set({ wardkey_session: { ts: Date.now(), pw: session.pw } });

    getCurrentSite();
    renderList();
    updateSyncDot();
    checkPendingSave();
    if (syncEnabled && authToken) syncDown();
  }
}

// ═══════ INIT ═══════
loadTheme();
loadAuth();
loadLockTimeout().then(() => tryAutoUnlock()).finally(() => {
  document.body.classList.add('ready');
});

// Keyboard shortcuts
document.addEventListener('keydown', e => {
  if (e.key === 'Escape') {
    if ($('authLogin').classList.contains('on') || $('authRegister').classList.contains('on') || $('auth2fa').classList.contains('on')) {
      hideAuth();
      showPanel('account');
      return;
    }
    if (unlocked) $('lockBtn').click();
    else window.close();
  }
});

// Create alerts badge on load
const alertsBadge = document.createElement('div');
alertsBadge.className = 'ftr-badge';
alertsBadge.style.display = 'none';
const alertsFtrBtn = document.querySelector('.ftr-btn[data-nav="alerts"]');
if (alertsFtrBtn) alertsFtrBtn.appendChild(alertsBadge);
