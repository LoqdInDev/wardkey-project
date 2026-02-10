// WARDKEY Background Service Worker

// ═══════ CONTEXT MENU ═══════
chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.create({
    id: 'wardkey-generate',
    title: '🔐 WARDKEY — Generate Password',
    contexts: ['editable']
  });
  chrome.contextMenus.create({
    id: 'wardkey-open',
    title: '🔐 WARDKEY — Open Vault',
    contexts: ['page', 'frame']
  });
});

chrome.contextMenus.onClicked.addListener((info, tab) => {
  if (info.menuItemId === 'wardkey-generate') {
    // Generate and fill password
    const chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=';
    const arr = new Uint8Array(20);
    crypto.getRandomValues(arr);
    const pw = Array.from(arr, b => chars[b % chars.length]).join('');
    chrome.tabs.sendMessage(tab.id, { type: 'WARDKEY_FILL_PW', password: pw }).catch(() => {});
  }
  if (info.menuItemId === 'wardkey-open') {
    chrome.action.openPopup();
  }
});

// ═══════ KEYBOARD SHORTCUTS ═══════
chrome.commands.onCommand.addListener((command) => {
  if (command === 'generate_password') {
    chrome.tabs.query({ active: true, currentWindow: true }, ([tab]) => {
      if (!tab) return;
      const chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=';
      const arr = new Uint8Array(20);
      crypto.getRandomValues(arr);
      const pw = Array.from(arr, b => chars[b % chars.length]).join('');
      chrome.tabs.sendMessage(tab.id, { type: 'WARDKEY_FILL_PW', password: pw }).catch(() => {});
    });
  }
});

// ═══════ BADGE ═══════
// Show credential count for current site
chrome.tabs.onActivated.addListener(async ({ tabId }) => {
  try {
    const tab = await chrome.tabs.get(tabId);
    if (!tab?.url) return;
    updateBadge(tab);
  } catch {}
});

chrome.tabs.onUpdated.addListener((tabId, info, tab) => {
  if (info.status === 'complete' && tab?.url) {
    updateBadge(tab);
  }
});

async function updateBadge(tab) {
  try {
    const url = new URL(tab.url);
    const domain = url.hostname.replace('www.', '');

    const data = await chrome.storage.local.get('wardkey_vault');
    if (!data.wardkey_vault) {
      chrome.action.setBadgeText({ text: '', tabId: tab.id });
      return;
    }

    // We can't decrypt here without the key, so just show a subtle indicator
    chrome.action.setBadgeText({ text: '', tabId: tab.id });
    chrome.action.setBadgeBackgroundColor({ color: '#3d7cf5' });
  } catch {
    chrome.action.setBadgeText({ text: '', tabId: tab.id });
  }
}

// ═══════ AUTO-LOCK TIMER ═══════
let lockTimeout;
const LOCK_AFTER_MS = 5 * 60 * 1000; // 5 minutes

chrome.alarms.create('wardkey-autolock', { periodInMinutes: 1 });
chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === 'wardkey-autolock') {
    chrome.storage.session?.get('wardkey_lastActive', (data) => {
      if (data?.wardkey_lastActive) {
        const elapsed = Date.now() - data.wardkey_lastActive;
        if (elapsed > LOCK_AFTER_MS) {
          // Clear session
          chrome.storage.session?.remove('wardkey_session');
        }
      }
    });
  }
});

// ═══════ MESSAGE HANDLER ═══════
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.type === 'WARDKEY_OPEN_POPUP') {
    chrome.action.openPopup();
  }
  if (msg.type === 'WARDKEY_ACTIVITY') {
    chrome.storage.session?.set({ wardkey_lastActive: Date.now() });
  }
});

// ═══════ INSTALL ═══════
chrome.runtime.onInstalled.addListener((details) => {
  if (details.reason === 'install') {
    chrome.tabs.create({
      url: 'http://localhost:5173/wardkey.html?source=extension'
    });
  }
});
