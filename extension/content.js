// WARDKEY Content Script — Form Detection & Autofill
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

  function findFields() {
    const fields = { username: null, password: null, newPassword: null };

    // Find password fields
    const pwFields = document.querySelectorAll(SELECTORS.password.join(','));
    if (pwFields.length >= 2) {
      fields.password = pwFields[0];
      fields.newPassword = pwFields[1];
    } else if (pwFields.length === 1) {
      fields.password = pwFields[0];
    }

    // Find username field
    for (const sel of SELECTORS.username) {
      const el = document.querySelector(sel);
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

      // Set position relative on parent if needed
      const pos = getComputedStyle(wrapper).position;
      if (pos === 'static') wrapper.style.position = 'relative';

      // Create icon button
      const btn = document.createElement('div');
      btn.className = 'wardkey-field-icon';
      btn.innerHTML = '🔐';
      btn.title = 'Fill with WARDKEY';

      // Position inside the field
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
        // Open extension popup
        chrome.runtime.sendMessage({ type: 'WARDKEY_OPEN_POPUP' });
      };

      wrapper.appendChild(btn);
    });
  }

  // ═══════ AUTOFILL HANDLER ═══════
  function fillField(el, value) {
    if (!el || !value) return;
    // Set native value
    const nativeSetter = Object.getOwnPropertyDescriptor(
      Object.getPrototypeOf(el), 'value'
    )?.set || Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')?.set;

    if (nativeSetter) {
      nativeSetter.call(el, value);
    } else {
      el.value = value;
    }

    // Dispatch events that React/Angular/Vue listen to
    el.dispatchEvent(new Event('input', { bubbles: true }));
    el.dispatchEvent(new Event('change', { bubbles: true }));
    el.dispatchEvent(new KeyboardEvent('keydown', { bubbles: true }));
    el.dispatchEvent(new KeyboardEvent('keyup', { bubbles: true }));
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

    return true;
  });

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

    // Add animation
    const style = document.createElement('style');
    style.textContent = '@keyframes wardkey-slide{from{opacity:0;transform:translateY(-12px)}to{opacity:1;transform:translateY(0)}}';
    document.head.appendChild(style);

    setTimeout(() => {
      banner.style.transition = 'opacity .3s';
      banner.style.opacity = '0';
      setTimeout(() => { banner.remove(); style.remove(); }, 300);
    }, 2500);
  }

  // ═══════ INIT ═══════
  // Inject icons after a short delay to let page render
  setTimeout(injectIcons, 800);

  // Re-inject on dynamic page changes (SPAs)
  const observer = new MutationObserver(() => {
    setTimeout(injectIcons, 300);
  });
  observer.observe(document.body, { childList: true, subtree: true });

  // Clean up on page unload
  window.addEventListener('unload', () => observer.disconnect());
})();
