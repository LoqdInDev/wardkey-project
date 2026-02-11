// WARDKEY Content Script — Form Detection, Autofill & Save Prompt
(() => {
  'use strict';

  // ═══════ FORM DETECTION ═══════
  const SELECTORS = {
    username: [
      'input[type="email"]',
      'input[type="text"][name*="user"]',
      'input[type="text"][name*="email"]',
      'input[type="text"][name*="login"]',
      'input[type="text"][id*="user"]',
      'input[type="text"][id*="email"]',
      'input[type="text"][id*="login"]',
      'input[autocomplete="username"]',
      'input[autocomplete="email"]',
      'input[name="identifier"]',
      'input[name="account"]'
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

  // ═══════ FORM SUBMIT DETECTION (Save Password Prompt) ═══════
  let lastCaptured = null;

  function captureCredentials(form) {
    const fields = findFields(form || document);
    const pw = fields.password || fields.newPassword;
    if (!pw || !pw.value) return null;

    let username = '';
    if (fields.username && fields.username.value) {
      username = fields.username.value;
    }

    return {
      domain: location.hostname.replace('www.', ''),
      username,
      password: pw.value,
      url: location.href,
      timestamp: Date.now()
    };
  }

  // Listen for form submissions
  document.addEventListener('submit', (e) => {
    const creds = captureCredentials(e.target);
    if (creds && creds.password) {
      lastCaptured = creds;
      // Small delay to let form submit complete, then send to background
      setTimeout(() => {
        if (lastCaptured) {
          chrome.runtime.sendMessage({
            type: 'WARDKEY_SAVE_PROMPT',
            ...lastCaptured
          }).catch(() => {});
        }
      }, 500);
    }
  }, true);

  // Also detect clicks on submit buttons (for forms without submit events)
  document.addEventListener('click', (e) => {
    const btn = e.target.closest('button[type="submit"], input[type="submit"], button:not([type])');
    if (!btn) return;

    const form = btn.closest('form');
    if (!form) return;

    const creds = captureCredentials(form);
    if (creds && creds.password) {
      lastCaptured = creds;
      setTimeout(() => {
        if (lastCaptured) {
          chrome.runtime.sendMessage({
            type: 'WARDKEY_SAVE_PROMPT',
            ...lastCaptured
          }).catch(() => {});
        }
      }, 500);
    }
  }, true);

  // ═══════ SAVE PASSWORD DIALOG (LastPass-style) ═══════
  function showSaveBar(data) {
    const existing = document.getElementById('wardkey-save-dialog');
    if (existing) existing.remove();

    const overlay = document.createElement('div');
    overlay.id = 'wardkey-save-dialog';
    overlay.innerHTML = `
      <div class="wardkey-dialog-card">
        <div class="wardkey-dialog-header">
          <span class="wardkey-dialog-title">Add to WARDKEY?</span>
          <button class="wardkey-dialog-close">✕</button>
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
            <button class="wardkey-dialog-btn wardkey-dialog-skip">Not now</button>
            <button class="wardkey-dialog-btn wardkey-dialog-save">Add password</button>
          </div>
        </div>
      </div>
    `;
    document.body.appendChild(overlay);

    const dismiss = () => {
      const card = overlay.querySelector('.wardkey-dialog-card');
      if (card) { card.style.opacity = '0'; card.style.transform = 'translateY(-10px) scale(.98)'; }
      setTimeout(() => overlay.remove(), 200);
    };

    overlay.querySelector('.wardkey-dialog-save').onclick = () => {
      chrome.runtime.sendMessage({ type: 'WARDKEY_SAVE_CONFIRM', ...data }).catch(() => {});
      dismiss();
    };

    overlay.querySelector('.wardkey-dialog-skip').onclick = dismiss;
    overlay.querySelector('.wardkey-dialog-close').onclick = dismiss;

    // Click outside card to dismiss
    overlay.onclick = (e) => { if (e.target === overlay) dismiss(); };

    // Auto-dismiss after 20 seconds
    setTimeout(() => { if (document.getElementById('wardkey-save-dialog')) dismiss(); }, 20000);
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
      showSaveBar(msg);
    }

    return true;
  });

  // ═══════ INIT ═══════
  setTimeout(injectIcons, 800);

  const observer = new MutationObserver(() => {
    setTimeout(injectIcons, 300);
  });
  observer.observe(document.body, { childList: true, subtree: true });

  window.addEventListener('unload', () => observer.disconnect());
})();
