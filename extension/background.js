// WARDKEY Background Service Worker v2.0

// Restrict session storage to trusted contexts only (extension pages, NOT content scripts)
chrome.storage.session.setAccessLevel({ accessLevel: 'TRUSTED_CONTEXTS' });

// ═══════ INSTALL & CONTEXT MENU ═══════
chrome.runtime.onInstalled.addListener((details) => {
  // Session storage already restricted to trusted contexts at top of file

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

async function updateBadge(tab) {
  try {
    const url = new URL(tab.url);
    if (url.protocol !== 'http:' && url.protocol !== 'https:') {
      chrome.action.setBadgeText({ text: '', tabId: tab.id });
      return;
    }
    chrome.action.setBadgeBackgroundColor({ color: '#3d7cf5' });
  } catch {
    chrome.action.setBadgeText({ text: '', tabId: tab.id });
  }
}

// ═══════ TAB NAVIGATION — PROMOTE CAPTURES TO PENDING SAVES ═══════
// When a tab navigates, check if the content script had captured credentials.
// If so, promote them from wardkey_capture to wardkey_pendingSave so the
// dialog shows on the new page.
chrome.tabs.onUpdated.addListener((tabId, info, tab) => {
  if (info.status === 'loading' && tab?.url) {
    // Tab is navigating — check for captured credentials
    chrome.storage.session?.get('wardkey_capture', async (data) => {
      if (data?.wardkey_capture?.password) {
        const capture = data.wardkey_capture;
        // Only promote if recent (within 30 seconds)
        if (Date.now() - capture.timestamp < 30000) {
          // Check never-save list
          if (await isNeverSave(capture.domain)) {
            chrome.storage.session?.remove('wardkey_capture');
            return;
          }
          // Promote to pending save
          await chrome.storage.session?.set({ wardkey_pendingSave: capture });
          // Notify popup if open
          chrome.runtime.sendMessage({ type: 'WARDKEY_PENDING_SAVE' }).catch(() => {});
        }
        // Clear the capture
        chrome.storage.session?.remove('wardkey_capture');
      }
    });

    // Also update badge
    updateBadge(tab);
  }
  if (info.status === 'complete' && tab?.url) updateBadge(tab);
});

// ═══════ AUTO-LOCK TIMER ═══════
chrome.alarms.create('wardkey-autolock', { periodInMinutes: 1 });
chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === 'wardkey-autolock') {
    chrome.storage.local.get('wardkey_lockTimeout', (settings) => {
      const timeout = settings.wardkey_lockTimeout ?? 0;
      if (timeout === 0 || timeout === -1) return;
      chrome.storage.session?.get('wardkey_session', (data) => {
        if (data?.wardkey_session?.ts) {
          const elapsed = Date.now() - data.wardkey_session.ts;
          if (elapsed > timeout) {
            chrome.storage.session?.remove('wardkey_session');
          }
        }
      });
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

  // Content script credential capture (via message passing, not direct session storage)
  if (msg.type === 'WARDKEY_STORE_CAPTURE') {
    chrome.storage.session?.set({
      wardkey_capture: {
        domain: msg.domain,
        username: msg.username,
        password: msg.password,
        url: msg.url,
        timestamp: msg.timestamp
      }
    });
  }

  // Content script checks for pending save dialog
  if (msg.type === 'WARDKEY_CHECK_PENDING') {
    chrome.storage.session?.get('wardkey_pendingSave', (data) => {
      sendResponse({ pending: data?.wardkey_pendingSave || null });
    });
    return true; // async sendResponse
  }

  // Content script dismisses pending save
  if (msg.type === 'WARDKEY_DISMISS_PENDING') {
    chrome.storage.session?.remove('wardkey_pendingSave');
  }

  // Legacy: content script form submit detection (backup path)
  if (msg.type === 'WARDKEY_SAVE_PROMPT') {
    (async () => {
      if (await isNeverSave(msg.domain)) return;
      await chrome.storage.session?.set({
        wardkey_pendingSave: {
          domain: msg.domain,
          username: msg.username,
          password: msg.password,
          url: msg.url,
          timestamp: msg.timestamp
        }
      });
      chrome.runtime.sendMessage({ type: 'WARDKEY_PENDING_SAVE' }).catch(() => {});
    })();
  }

  // User clicked "Save" in content script dialog
  if (msg.type === 'WARDKEY_SAVE_CONFIRM') {
    (async () => {
      await chrome.storage.session.set({
        wardkey_pendingSave: {
          domain: msg.domain,
          username: msg.username,
          password: msg.password,
          url: msg.url,
          timestamp: Date.now(),
          confirmed: true
        }
      });
      chrome.runtime.sendMessage({ type: 'WARDKEY_PENDING_SAVE' }).catch(() => {});
    })();
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
