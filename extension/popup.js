// WARDKEY Extension — Popup Controller
const $ = id => document.getElementById(id);

// ═══════ STATE ═══════
let vault = [];
let unlocked = false;
let currentDomain = '';
let activeTab = 'matches';
let genPw = '';

// ═══════ CRYPTO ═══════
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

async function decrypt(data, key) {
  const ct = Uint8Array.from(atob(data.ct), c => c.charCodeAt(0));
  const iv = new Uint8Array(data.iv);
  const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ct);
  return JSON.parse(new TextDecoder().decode(pt));
}

async function encrypt(data, key) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const enc = new TextEncoder().encode(JSON.stringify(data));
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, enc);
  return { ct: btoa(String.fromCharCode(...new Uint8Array(ct))), iv: Array.from(iv) };
}

// ═══════ STORAGE ═══════
async function loadVault(pw) {
  const data = await chrome.storage.local.get(['wardkey_vault', 'wardkey_salt']);
  if (!data.wardkey_vault) return false;
  try {
    const salt = new Uint8Array(data.wardkey_salt);
    const key = await deriveKey(pw, salt);
    const decrypted = await decrypt(data.wardkey_vault, key);
    vault = decrypted.passwords || [];
    window._mk = key;
    window._salt = salt;
    return true;
  } catch {
    return false;
  }
}

async function saveVault() {
  if (!window._mk) return;
  const encrypted = await encrypt({ passwords: vault }, window._mk);
  await chrome.storage.local.set({ wardkey_vault: encrypted, wardkey_salt: Array.from(window._salt) });
}

async function initVault(pw) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const key = await deriveKey(pw, salt);
  window._mk = key;
  window._salt = salt;
  vault = [];
  await saveVault();
}

// ═══════ UNLOCK ═══════
$('unlockBtn').onclick = async () => {
  const pw = $('masterPw').value;
  if (pw.length < 4) { shake($('masterPw')); return; }

  const hasVault = (await chrome.storage.local.get('wardkey_vault')).wardkey_vault;
  if (hasVault) {
    const ok = await loadVault(pw);
    if (!ok) { shake($('masterPw')); toast('Wrong password'); return; }
  } else {
    await initVault(pw);
    toast('Vault created!');
  }
  unlocked = true;
  $('lockScreen').style.display = 'none';
  $('appView').classList.add('on');
  getCurrentSite();
  renderList();
};

$('masterPw').onkeydown = e => { if (e.key === 'Enter') $('unlockBtn').click(); };

$('lockBtn').onclick = () => {
  unlocked = false;
  vault = [];
  window._mk = null;
  $('appView').classList.remove('on');
  $('lockScreen').style.display = '';
  $('masterPw').value = '';
  $('masterPw').focus();
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
  if (!currentDomain) return [];
  return vault.filter(p => {
    const url = (p.url || '').toLowerCase().replace('https://', '').replace('http://', '').replace('www.', '');
    const domain = currentDomain.toLowerCase();
    return url.includes(domain) || domain.includes(url.split('/')[0]);
  });
}

// ═══════ RENDER ═══════
function renderList() {
  const list = $('itemList');
  const gen = $('genPanel');
  const query = $('searchInput').value.toLowerCase();

  if (activeTab === 'gen') {
    list.style.display = 'none';
    gen.classList.add('on');
    $('matchBanner').style.display = 'none';
    return;
  }

  list.style.display = '';
  gen.classList.remove('on');

  let items;
  if (activeTab === 'matches') {
    items = getMatches();
    if (items.length) {
      $('matchBanner').style.display = '';
      $('matchCount').textContent = `${items.length} credential${items.length > 1 ? 's' : ''} for ${currentDomain}`;
    } else {
      $('matchBanner').style.display = 'none';
    }
  } else {
    items = vault;
    $('matchBanner').style.display = 'none';
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
      <div class="empty-ic">${activeTab === 'matches' ? '🔍' : '📭'}</div>
      <div class="empty-t">${activeTab === 'matches' ? 'No matches for this site' : 'Vault is empty'}</div>
      <div class="empty-d">${activeTab === 'matches' ? 'Add credentials or check all items' : 'Import from WARDKEY web app or add items'}</div>
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

  // Bind actions
  list.querySelectorAll('.act').forEach(btn => {
    btn.onclick = e => {
      e.stopPropagation();
      const action = btn.dataset.action;
      const id = btn.dataset.id;
      const item = vault.find(p => p.id === id);
      if (!item) return;
      if (action === 'fill') autofill(item);
      if (action === 'copy') copyPw(item.password);
      if (action === 'launch') launchSite(item);
    };
  });

  list.querySelectorAll('.item').forEach(el => {
    el.onclick = () => {
      const item = vault.find(p => p.id === el.dataset.id);
      if (item) autofill(item);
    };
  });
}

// ═══════ ACTIONS ═══════
async function autofill(item) {
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    await chrome.tabs.sendMessage(tab.id, {
      type: 'WARDKEY_FILL',
      username: item.username || '',
      password: item.password || ''
    });
    toast('✓ Filled');
    setTimeout(() => window.close(), 600);
  } catch {
    // Fallback: copy password
    copyPw(item.password);
    toast('Copied (autofill unavailable)');
  }
}

function copyPw(pw) {
  navigator.clipboard.writeText(pw);
  toast('✓ Copied');
  // Auto-clear after 30s
  setTimeout(() => {
    navigator.clipboard.writeText('').catch(() => {});
  }, 30000);
}

function launchSite(item) {
  let url = item.url;
  if (!url) return;
  if (!url.startsWith('http')) url = 'https://' + url;
  copyPw(item.password);
  chrome.tabs.create({ url });
  toast('🚀 Launched');
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
$('genCopy').onclick = () => { if (genPw) { copyPw(genPw); } };
$('genFill').onclick = async () => {
  if (!genPw) return;
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    await chrome.tabs.sendMessage(tab.id, { type: 'WARDKEY_FILL_PW', password: genPw });
    toast('✓ Filled');
  } catch { copyPw(genPw); }
};

document.querySelectorAll('.gen-opt').forEach(el => {
  el.onclick = () => {
    const opt = el.dataset.opt;
    genOpts[opt] = !genOpts[opt];
    el.classList.toggle('on', genOpts[opt]);
  };
});

// ═══════ TABS ═══════
document.querySelectorAll('.tab').forEach(tab => {
  tab.onclick = () => {
    activeTab = tab.dataset.tab;
    document.querySelectorAll('.tab').forEach(t => t.classList.toggle('on', t === tab));
    document.querySelectorAll('.ftr-btn').forEach(b => b.classList.toggle('on', b.dataset.nav === activeTab || (b.dataset.nav === 'matches' && (activeTab === 'matches' || activeTab === 'all'))));
    renderList();
  };
});

document.querySelectorAll('.ftr-btn').forEach(btn => {
  btn.onclick = () => {
    const nav = btn.dataset.nav;
    if (nav === 'settings') {
      chrome.runtime.openOptionsPage?.() || chrome.tabs.create({ url: 'options.html' });
      return;
    }
    activeTab = nav === 'matches' ? 'matches' : nav;
    document.querySelectorAll('.tab').forEach(t => t.classList.toggle('on', t.dataset.tab === activeTab));
    document.querySelectorAll('.ftr-btn').forEach(b => b.classList.remove('on'));
    btn.classList.add('on');
    renderList();
  };
});

$('searchInput').oninput = () => renderList();

// ═══════ IMPORT FROM WEB APP ═══════
chrome.runtime.onMessage.addListener((msg) => {
  if (msg.type === 'WARDKEY_IMPORT') {
    vault = msg.passwords || [];
    saveVault();
    renderList();
    toast(`Imported ${vault.length} items`);
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

// Auto-unlock if session is still active
chrome.storage.session?.get('wardkey_session', data => {
  if (data?.wardkey_session) {
    // Session key exists — user was recently active
  }
});

// Keyboard shortcut
document.addEventListener('keydown', e => {
  if (e.key === 'Escape') {
    if (unlocked) $('lockBtn').click();
    else window.close();
  }
});
