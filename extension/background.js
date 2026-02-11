// WARDKEY Background Service Worker v2.0

// ═══════ INSTALL & CONTEXT MENU ═══════
chrome.runtime.onInstalled.addListener((details) => {
  // Context menus
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

  // Open welcome page on first install
  if (details.reason === 'install') {
    chrome.tabs.create({ url: 'https://wardkey.io?source=extension' });
  }
});

chrome.contextMenus.onClicked.addListener((info, tab) => {
  if (info.menuItemId === 'wardkey-generate') {
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
chrome.tabs.onActivated.addListener(async ({ tabId }) => {
  try {
    const tab = await chrome.tabs.get(tabId);
    if (tab?.url) updateBadge(tab);
  } catch {}
});

chrome.tabs.onUpdated.addListener((tabId, info, tab) => {
  if (info.status === 'complete' && tab?.url) updateBadge(tab);
});

async function updateBadge(tab) {
  try {
    const url = new URL(tab.url);
    if (url.protocol !== 'http:' && url.protocol !== 'https:') {
      chrome.action.setBadgeText({ text: '', tabId: tab.id });
      return;
    }
    // Badge count is set by popup when unlocked
    chrome.action.setBadgeBackgroundColor({ color: '#3d7cf5' });
  } catch {
    chrome.action.setBadgeText({ text: '', tabId: tab.id });
  }
}

// ═══════ AUTO-LOCK TIMER ═══════
chrome.alarms.create('wardkey-autolock', { periodInMinutes: 1 });
chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === 'wardkey-autolock') {
    chrome.storage.session?.get('wardkey_session', (data) => {
      if (data?.wardkey_session) {
        const elapsed = Date.now() - data.wardkey_session;
        if (elapsed > 5 * 60 * 1000) {
          chrome.storage.session?.remove('wardkey_session');
        }
      }
    });
  }
});

// ═══════ NEVER-SAVE LIST ═══════
async function isNeverSave(domain) {
  const data = await chrome.storage.local.get('wardkey_neverSave');
  const list = data.wardkey_neverSave || [];
  return list.includes(domain);
}

// ═══════ MESSAGE HANDLER ═══════
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.type === 'WARDKEY_OPEN_POPUP') {
    chrome.action.openPopup();
  }

  if (msg.type === 'WARDKEY_ACTIVITY') {
    chrome.storage.session?.set({ wardkey_lastActive: Date.now() });
  }

  if (msg.type === 'WARDKEY_BADGE') {
    chrome.tabs.query({ active: true, currentWindow: true }, ([tab]) => {
      if (tab) {
        const text = msg.count > 0 ? String(msg.count) : '';
        chrome.action.setBadgeText({ text, tabId: tab.id });
      }
    });
  }

  // Save password flow: content script detected form submit
  if (msg.type === 'WARDKEY_SAVE_PROMPT') {
    (async () => {
      // Check never-save list
      if (await isNeverSave(msg.domain)) return;

      // Store pending save in session
      await chrome.storage.session?.set({
        wardkey_pendingSave: {
          domain: msg.domain,
          username: msg.username,
          password: msg.password,
          url: msg.url,
          timestamp: msg.timestamp
        }
      });

      // Show save bar in the content script
      if (sender.tab?.id) {
        chrome.tabs.sendMessage(sender.tab.id, {
          type: 'WARDKEY_SHOW_SAVE',
          domain: msg.domain,
          username: msg.username
        }).catch(() => {});
      }

      // Notify popup if open
      chrome.runtime.sendMessage({ type: 'WARDKEY_PENDING_SAVE' }).catch(() => {});
    })();
  }

  // User clicked "Save" in content script bar
  if (msg.type === 'WARDKEY_SAVE_CONFIRM') {
    chrome.storage.session?.set({
      wardkey_pendingSave: {
        domain: msg.domain,
        username: msg.username,
        password: msg.password,
        url: msg.url,
        timestamp: Date.now()
      }
    });
    // Notify popup to process the save
    chrome.runtime.sendMessage({ type: 'WARDKEY_PENDING_SAVE' }).catch(() => {});
  }

  // User clicked "Never" for a domain
  if (msg.type === 'WARDKEY_SAVE_NEVER') {
    (async () => {
      const data = await chrome.storage.local.get('wardkey_neverSave');
      const list = data.wardkey_neverSave || [];
      if (!list.includes(msg.domain)) {
        list.push(msg.domain);
        await chrome.storage.local.set({ wardkey_neverSave: list });
      }
      await chrome.storage.session?.remove('wardkey_pendingSave');
    })();
  }

  return true;
});
