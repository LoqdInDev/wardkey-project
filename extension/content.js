// WARDKEY Content Script — Form Detection, Autofill & Save Prompt
(() => {
  'use strict';

  // ═══════ FORM DETECTION ═══════
  const SELECTORS = {
    username: [
      'input[autocomplete="username"]',
      'input[autocomplete="email"]',
      'input[type="email"]',
      'input[type="text"][name*="user"]',
      'input[type="text"][name*="email"]',
      'input[type="text"][name*="login"]',
      'input[type="text"][name*="mail"]',
      'input[type="text"][name*="acct"]',
      'input[type="text"][name*="handle"]',
      'input[type="text"][id*="user"]',
      'input[type="text"][id*="email"]',
      'input[type="text"][id*="login"]',
      'input[type="text"][id*="mail"]',
      'input[type="text"][placeholder*="mail" i]',
      'input[type="text"][placeholder*="user" i]',
      'input[type="text"][placeholder*="login" i]',
      'input[type="text"][placeholder*="phone" i]',
      'input[type="text"][aria-label*="mail" i]',
      'input[type="text"][aria-label*="user" i]',
      'input[type="tel"]',
      'input[name="identifier"]',
      'input[name="account"]',
      'input[name="login"]',
      'input[name="email"]',
      'input[name="login_field"]',
      'input[name="session[username_or_email]"]'
    ],
    password: [
      'input[type="password"]',
      'input[autocomplete="current-password"]',
      'input[autocomplete="new-password"]'
    ]
  };

  function findFields(root) {
    const scope = root || document;
    const fields = { username: null, password: null, newPassword: null };

    const pwFields = scope.querySelectorAll(SELECTORS.password.join(','));
    if (pwFields.length >= 2) {
      fields.password = pwFields[0];
      fields.newPassword = pwFields[1];
    } else if (pwFields.length === 1) {
      fields.password = pwFields[0];
    }

    for (const sel of SELECTORS.username) {
      const el = scope.querySelector(sel);
      if (el && isVisible(el)) {
        fields.username = el;
        break;
      }
    }

    // Fallback: if no username found, look for any visible text/email input
    // that appears before the password field in the DOM
    if (!fields.username && fields.password) {
      const form = fields.password.closest('form') || scope;
      const allInputs = form.querySelectorAll('input[type="text"], input[type="email"], input[type="tel"], input:not([type])');
      for (const inp of allInputs) {
        if (inp === fields.password || inp === fields.newPassword) continue;
        if (inp.type === 'hidden' || inp.type === 'submit') continue;
        if (!isVisible(inp)) continue;
        // Must appear before the password field in DOM order
        if (fields.password.compareDocumentPosition(inp) & Node.DOCUMENT_POSITION_PRECEDING) {
          fields.username = inp;
          break;
        }
      }
    }

    return fields;
  }

  function isVisible(el) {
    const rect = el.getBoundingClientRect();
    const style = getComputedStyle(el);
    return rect.width > 0 && rect.height > 0 &&
           style.display !== 'none' &&
           style.visibility !== 'hidden' &&
           style.opacity !== '0';
  }

  // ═══════ WARDKEY ICON INJECTION ═══════
  function injectIcons() {
    const fields = findFields();
    const targets = [fields.username, fields.password, fields.newPassword].filter(Boolean);

    targets.forEach(field => {
      if (field.dataset.wardkeyIcon) return;
      field.dataset.wardkeyIcon = 'true';

      const wrapper = field.parentElement;
      if (!wrapper) return;

      const pos = getComputedStyle(wrapper).position;
      if (pos === 'static') wrapper.style.position = 'relative';

      const btn = document.createElement('div');
      btn.className = 'wardkey-field-icon';
      btn.innerHTML = '🔐';
      btn.title = 'Fill with WARDKEY';

      const rect = field.getBoundingClientRect();
      const wrapRect = wrapper.getBoundingClientRect();
      btn.style.cssText = `
        position:absolute;
        right:${Math.max(4, wrapRect.right - rect.right + 6)}px;
        top:50%;
        transform:translateY(-50%);
        width:22px;height:22px;
        display:flex;align-items:center;justify-content:center;
        font-size:13px;
        cursor:pointer;
        z-index:2147483646;
        border-radius:4px;
        transition:background .15s;
        background:transparent;
      `;

      btn.onmouseenter = () => btn.style.background = 'rgba(61,124,245,.1)';
      btn.onmouseleave = () => btn.style.background = 'transparent';
      btn.onclick = (e) => {
        e.preventDefault();
        e.stopPropagation();
        chrome.runtime.sendMessage({ type: 'WARDKEY_OPEN_POPUP' });
      };

      wrapper.appendChild(btn);
    });
  }

  // ═══════ AUTOFILL HANDLER ═══════
  function fillField(el, value) {
    if (!el || !value) return;
    const nativeSetter = Object.getOwnPropertyDescriptor(
      Object.getPrototypeOf(el), 'value'
    )?.set || Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')?.set;

    if (nativeSetter) {
      nativeSetter.call(el, value);
    } else {
      el.value = value;
    }

    el.dispatchEvent(new Event('input', { bubbles: true }));
    el.dispatchEvent(new Event('change', { bubbles: true }));
    el.dispatchEvent(new KeyboardEvent('keydown', { bubbles: true }));
    el.dispatchEvent(new KeyboardEvent('keyup', { bubbles: true }));
  }

  // ═══════ LIVE CREDENTIAL TRACKING ═══════
  // Track credentials AS THE USER TYPES — stored in session storage
  // so they survive page navigation. Background detects navigation
  // and promotes the capture to a "pending save".
  let trackedFields = new Set();

  function trackCredentialFields() {
    const fields = findFields();
    const pwField = fields.password || fields.newPassword;
    if (!pwField) return;

    const allFields = [fields.username, fields.password, fields.newPassword].filter(Boolean);

    allFields.forEach(field => {
      if (trackedFields.has(field)) return;
      trackedFields.add(field);

      const storeCapture = () => {
        const pw = (fields.password?.value || fields.newPassword?.value || '').trim();
        if (!pw) return;
        const username = (fields.username?.value || '').trim();

        chrome.runtime.sendMessage({
          type: 'WARDKEY_STORE_CAPTURE',
          domain: location.hostname.replace('www.', ''),
          username,
          password: pw,
          url: location.href,
          timestamp: Date.now()
        }).catch(() => {});
      };

      field.addEventListener('input', storeCapture);
      field.addEventListener('change', storeCapture);
      field.addEventListener('blur', storeCapture);
    });
  }

  // ═══════ SAVE PASSWORD DIALOG (LastPass-style) ═══════
  function showSaveBar(data) {
    const existing = document.getElementById('wardkey-save-dialog');
    if (existing) existing.remove();

    const overlay = document.createElement('div');
    overlay.id = 'wardkey-save-dialog';
    overlay.setAttribute('role', 'dialog');
    overlay.setAttribute('aria-labelledby', 'wardkey-dialog-title');
    overlay.innerHTML = `
      <div class="wardkey-dialog-card">
        <div class="wardkey-dialog-header">
          <span class="wardkey-dialog-title" id="wardkey-dialog-title">Add to WARDKEY?</span>
          <button class="wardkey-dialog-close" aria-label="Close dialog">✕</button>
        </div>
        <div class="wardkey-dialog-body">
          <div class="wardkey-dialog-site">
            <div class="wardkey-dialog-favicon">🔐</div>
            <div class="wardkey-dialog-info">
              <div class="wardkey-dialog-domain">${escapeHtml(data.domain)}</div>
              <div class="wardkey-dialog-user">${escapeHtml(data.username || 'New credentials')}</div>
            </div>
          </div>
        </div>
        <div class="wardkey-dialog-footer">
          <span class="wardkey-dialog-brand">🔐 WARDKEY</span>
          <div class="wardkey-dialog-actions">
            <button class="wardkey-dialog-btn wardkey-dialog-skip" aria-label="Dismiss">Not now</button>
            <button class="wardkey-dialog-btn wardkey-dialog-save" aria-label="Save password">Add password</button>
          </div>
        </div>
      </div>
    `;
    document.body.appendChild(overlay);

    // Focus trap: remember what was focused, focus first button
    const prevFocus = document.activeElement;
    const saveBtn = overlay.querySelector('.wardkey-dialog-save');
    const skipBtn = overlay.querySelector('.wardkey-dialog-skip');
    const closeBtn = overlay.querySelector('.wardkey-dialog-close');
    const focusable = [closeBtn, skipBtn, saveBtn];
    saveBtn.focus();

    const trapFocus = (e) => {
      if (e.key === 'Tab') {
        const idx = focusable.indexOf(document.activeElement);
        if (e.shiftKey) {
          e.preventDefault();
          focusable[(idx - 1 + focusable.length) % focusable.length].focus();
        } else {
          e.preventDefault();
          focusable[(idx + 1) % focusable.length].focus();
        }
      }
    };
    overlay.addEventListener('keydown', trapFocus);

    const closeDialog = () => {
      overlay.removeEventListener('keydown', trapFocus);
      const card = overlay.querySelector('.wardkey-dialog-card');
      if (card) { card.style.opacity = '0'; card.style.transform = 'translateY(-10px) scale(.98)'; }
      setTimeout(() => overlay.remove(), 200);
      if (prevFocus && prevFocus.focus) prevFocus.focus();
    };

    // Escape key to close
    overlay.addEventListener('keydown', (e) => {
      if (e.key === 'Escape') {
        chrome.runtime.sendMessage({ type: 'WARDKEY_DISMISS_PENDING' }).catch(() => {});
        closeDialog();
      }
    });

    saveBtn.onclick = () => {
      chrome.runtime.sendMessage({ type: 'WARDKEY_SAVE_CONFIRM', ...data }).catch(() => {});
      closeDialog();
    };

    skipBtn.onclick = () => {
      chrome.runtime.sendMessage({ type: 'WARDKEY_DISMISS_PENDING' }).catch(() => {});
      closeDialog();
    };
    closeBtn.onclick = () => {
      chrome.runtime.sendMessage({ type: 'WARDKEY_DISMISS_PENDING' }).catch(() => {});
      closeDialog();
    };

    // Click outside card to dismiss
    overlay.onclick = (e) => {
      if (e.target === overlay) {
        chrome.runtime.sendMessage({ type: 'WARDKEY_DISMISS_PENDING' }).catch(() => {});
        closeDialog();
      }
    };
  }

  function escapeHtml(s) {
    const d = document.createElement('div');
    d.textContent = s;
    return d.innerHTML;
  }

  // ═══════ FILL SUCCESS BANNER ═══════
  function showFillBanner() {
    const existing = document.getElementById('wardkey-fill-banner');
    if (existing) existing.remove();

    const banner = document.createElement('div');
    banner.id = 'wardkey-fill-banner';
    banner.innerHTML = '🔐 <strong>WARDKEY</strong> — Credentials filled';
    banner.style.cssText = `
      position:fixed;top:12px;right:12px;z-index:2147483647;
      padding:10px 18px;
      background:linear-gradient(135deg,#0c0c14,#1a1a28);
      color:#e8e8f0;font-family:-apple-system,sans-serif;font-size:13px;
      border-radius:8px;border:1px solid rgba(61,124,245,.3);
      box-shadow:0 8px 32px rgba(0,0,0,.4);
      display:flex;align-items:center;gap:8px;
      animation:wardkey-slide .3s ease-out;
    `;
    document.body.appendChild(banner);

    setTimeout(() => {
      banner.style.transition = 'opacity .3s';
      banner.style.opacity = '0';
      setTimeout(() => banner.remove(), 300);
    }, 2500);
  }

  // ═══════ MESSAGE HANDLER ═══════
  chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
    if (msg.type === 'WARDKEY_FILL') {
      const fields = findFields();
      if (fields.username && msg.username) fillField(fields.username, msg.username);
      if (fields.password && msg.password) fillField(fields.password, msg.password);
      showFillBanner();
      sendResponse({ success: true });
    }

    if (msg.type === 'WARDKEY_FILL_PW') {
      const fields = findFields();
      const target = fields.newPassword || fields.password;
      if (target && msg.password) {
        fillField(target, msg.password);
        showFillBanner();
      }
      sendResponse({ success: true });
    }

    if (msg.type === 'WARDKEY_DETECT') {
      const fields = findFields();
      sendResponse({
        hasLogin: !!(fields.username || fields.password),
        hasUsername: !!fields.username,
        hasPassword: !!fields.password,
        domain: location.hostname.replace('www.', '')
      });
    }

    if (msg.type === 'WARDKEY_SHOW_SAVE') {
      if (!saveDialogShown) {
        saveDialogShown = true;
        showSaveBar(msg);
      }
    }

    return true;
  });

  // ═══════ CHECK PENDING SAVE ON PAGE LOAD ═══════
  let saveDialogShown = false;

  async function checkPendingSaveOnLoad() {
    if (saveDialogShown) return;
    try {
      const response = await chrome.runtime.sendMessage({ type: 'WARDKEY_CHECK_PENDING' });
      if (response?.pending) {
        const pending = response.pending;
        // Don't re-show if user already confirmed — popup will handle it
        if (pending.confirmed) return;
        // Only show if it's recent (within 5 minutes)
        if (Date.now() - pending.timestamp < 300000) {
          saveDialogShown = true;
          showSaveBar(pending);
        }
      }
    } catch {}
  }

  // ═══════ INIT ═══════
  setTimeout(injectIcons, 800);
  setTimeout(trackCredentialFields, 1000);

  // Poll for pending saves — handles redirect chains (check every 2s for 60s)
  let saveCheckCount = 0;
  const saveChecker = setInterval(() => {
    saveCheckCount++;
    if (saveDialogShown || saveCheckCount > 30) { clearInterval(saveChecker); return; }
    checkPendingSaveOnLoad();
  }, 2000);

  // Also check right after page fully loads
  if (document.readyState === 'complete') {
    checkPendingSaveOnLoad();
  } else {
    window.addEventListener('load', () => setTimeout(checkPendingSaveOnLoad, 500));
  }

  const observer = new MutationObserver(() => {
    setTimeout(injectIcons, 300);
    // Re-check for new password fields to track
    setTimeout(trackCredentialFields, 500);
  });
  observer.observe(document.body, { childList: true, subtree: true });
})();
