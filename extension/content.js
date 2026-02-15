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

  // Find username/email from hidden inputs or page text when no visible username field exists
  // Handles multi-step logins (Google, Microsoft, Facebook) where email is shown as text on password page
  function findUsernameHint() {
    // 1. Hidden inputs with email/username-like names
    const hiddenSelectors = [
      'input[type="hidden"][name="identifier"]',
      'input[type="hidden"][name="email"]',
      'input[type="hidden"][name="username"]',
      'input[type="hidden"][name="login"]',
      'input[type="hidden"][name*="user"]',
      'input[type="hidden"][name*="email"]',
      'input[type="hidden"][name*="login_hint"]'
    ];
    for (const sel of hiddenSelectors) {
      const el = document.querySelector(sel);
      if (el?.value?.trim()) return el.value.trim();
    }

    // 2. Google-specific: data-identifier attribute
    const gIdent = document.querySelector('[data-identifier]');
    if (gIdent?.dataset?.identifier) return gIdent.dataset.identifier;

    // 3. Google profile identifier displayed as text
    const profileEmail = document.querySelector('#profileIdentifier');
    if (profileEmail?.textContent?.includes('@')) return profileEmail.textContent.trim();

    // 4. Look for email displayed as text near password field (common pattern)
    // Check small text elements that contain an email address pattern
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    const candidates = document.querySelectorAll(
      '.identifier, .email-display, [data-email], #identifierLink, #hiddenEmail, .sign-in-card .email'
    );
    for (const el of candidates) {
      const text = (el.textContent || el.dataset?.email || '').trim();
      if (emailRegex.test(text)) return text;
    }

    return '';
  }

  // ═══════ WARDKEY ICON INJECTION ═══════
  let activeDropdown = null;

  function closeDropdown() {
    if (activeDropdown) {
      activeDropdown.remove();
      activeDropdown = null;
    }
  }

  // Close dropdown when clicking elsewhere
  document.addEventListener('click', (e) => {
    if (activeDropdown && !activeDropdown.contains(e.target) && !e.target.closest('.wardkey-field-icon')) {
      closeDropdown();
    }
  }, true);
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') closeDropdown();
  });

  function showCredentialDropdown(anchorField) {
    closeDropdown();
    const domain = location.hostname.replace(/^www\./, '');

    chrome.runtime.sendMessage({ type: 'WARDKEY_GET_SITE_CREDENTIALS', domain }, (response) => {
      if (chrome.runtime.lastError || !response) {
        // Extension not available or vault locked — fall back to opening popup
        chrome.runtime.sendMessage({ type: 'WARDKEY_OPEN_POPUP' });
        return;
      }

      const creds = response.credentials || [];
      const dropdown = document.createElement('div');
      dropdown.className = 'wardkey-dropdown';

      // Header
      const header = document.createElement('div');
      header.className = 'wardkey-dropdown-header';
      header.innerHTML = '<span class="wardkey-dropdown-brand">🔐 WARDKEY</span>';
      const closeBtn = document.createElement('button');
      closeBtn.className = 'wardkey-dropdown-close';
      closeBtn.textContent = '✕';
      closeBtn.onclick = (e) => { e.stopPropagation(); closeDropdown(); };
      header.appendChild(closeBtn);
      dropdown.appendChild(header);

      if (creds.length === 0) {
        const empty = document.createElement('div');
        empty.className = 'wardkey-dropdown-empty';
        empty.innerHTML = 'No saved passwords for this site<br><a class="wardkey-dropdown-open">Open WARDKEY</a>';
        const openLink = empty.querySelector('.wardkey-dropdown-open');
        if (openLink) openLink.onclick = () => { closeDropdown(); chrome.runtime.sendMessage({ type: 'WARDKEY_OPEN_POPUP' }); };
        dropdown.appendChild(empty);
      } else {
        creds.forEach(cred => {
          const item = document.createElement('button');
          item.className = 'wardkey-dropdown-item';
          item.innerHTML = `
            <div class="wardkey-dropdown-icon">🔑</div>
            <div class="wardkey-dropdown-info">
              <div class="wardkey-dropdown-name">${escapeHtml(cred.name || cred.url || domain)}</div>
              <div class="wardkey-dropdown-user">${escapeHtml(cred.username || 'No username')}</div>
            </div>
          `;
          item.onclick = (e) => {
            e.stopPropagation();
            const fields = findFields();
            if (fields.username && cred.username) fillField(fields.username, cred.username);
            if (fields.password && cred.password) fillField(fields.password, cred.password);
            if (fields.newPassword && cred.password) fillField(fields.newPassword, cred.password);
            closeDropdown();
          };
          dropdown.appendChild(item);
        });
      }

      document.body.appendChild(dropdown);
      activeDropdown = dropdown;

      // Position below the anchor field
      const rect = anchorField.getBoundingClientRect();
      const dropRect = dropdown.getBoundingClientRect();
      let top = rect.bottom + 4;
      let left = rect.left;

      // Keep within viewport
      if (top + dropRect.height > window.innerHeight) top = rect.top - dropRect.height - 4;
      if (left + dropRect.width > window.innerWidth) left = window.innerWidth - dropRect.width - 8;
      if (left < 4) left = 4;

      dropdown.style.top = top + 'px';
      dropdown.style.left = left + 'px';
    });
  }

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
        showCredentialDropdown(field);
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

    // Track username-only pages (multi-step login: email on page 1, password on page 2)
    if (!pwField && fields.username) {
      if (!trackedFields.has(fields.username)) {
        trackedFields.add(fields.username);
        const storeUsername = () => {
          const username = (fields.username?.value || '').trim();
          if (!username) return;
          chrome.runtime.sendMessage({
            type: 'WARDKEY_STORE_USERNAME',
            domain: location.hostname.replace(/^www\./, ''),
            username,
            url: location.href,
            timestamp: Date.now()
          }).catch(() => {});
        };
        fields.username.addEventListener('change', storeUsername);
        fields.username.addEventListener('blur', storeUsername);
        // Also capture on form submit for the username step
        const form = fields.username.closest('form');
        if (form && !form.dataset.wardkeySubmit) {
          form.dataset.wardkeySubmit = 'true';
          form.addEventListener('submit', storeUsername, { capture: true });
        }
      }
      return;
    }

    if (!pwField) return;

    const allFields = [fields.username, fields.password, fields.newPassword].filter(Boolean);

    allFields.forEach(field => {
      if (trackedFields.has(field)) return;
      trackedFields.add(field);

      const storeCapture = (includePassword) => {
        const pw = (fields.password?.value || fields.newPassword?.value || '').trim();
        if (!pw) return;
        // Try visible username field first, then hidden inputs/page text for multi-step logins
        const username = (fields.username?.value || '').trim() || findUsernameHint();
        const msg = {
          type: 'WARDKEY_STORE_CAPTURE',
          domain: location.hostname.replace(/^www\./, ''),
          username,
          hasPassword: true,
          url: location.href,
          timestamp: Date.now()
        };
        // Include password on blur of password fields (captures right before submit click)
        if (includePassword) msg.password = pw;
        chrome.runtime.sendMessage(msg).catch(() => {});
      };

      const isPwField = (field === fields.password || field === fields.newPassword);
      field.addEventListener('input', () => storeCapture(false));
      field.addEventListener('change', () => storeCapture(false));
      field.addEventListener('blur', () => storeCapture(isPwField));
    });

    // Detect form submission to capture password before page navigates away
    const form = pwField.closest('form');
    if (form && !form.dataset.wardkeySubmit) {
      form.dataset.wardkeySubmit = 'true';
      form.addEventListener('submit', () => {
        const pw = (fields.password?.value || fields.newPassword?.value || '').trim();
        if (!pw) return;
        const username = (fields.username?.value || '').trim() || findUsernameHint();
        chrome.runtime.sendMessage({
          type: 'WARDKEY_STORE_CAPTURE',
          domain: location.hostname.replace(/^www\./, ''),
          username,
          hasPassword: true,
          password: pw,
          url: location.href,
          timestamp: Date.now()
        }).catch(() => {});
      }, { capture: true });
    }
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
      // Capture password NOW before page navigates away
      const fields = findFields();
      const pw = fields.password?.value || fields.newPassword?.value || '';
      // Use data.username if available, otherwise try to find it from hidden inputs/page text
      const username = data.username || (fields.username?.value || '').trim() || findUsernameHint();
      chrome.runtime.sendMessage({ type: 'WARDKEY_SAVE_CONFIRM', domain: data.domain, username, url: data.url, password: pw }).catch(() => {});
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

  // Security-reviewed: This escapeHtml implementation is safe against XSS.
  // It uses the browser's built-in textContent/innerHTML encoding which correctly
  // escapes all HTML special characters (<, >, &, ", ') in user-supplied strings.
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
    if (sender.id !== chrome.runtime.id) return;
    // Return current password field value to popup for save flow
    if (msg.type === 'WARDKEY_GET_PASSWORD') {
      const fields = findFields();
      const pw = fields.password?.value || '';
      sendResponse({ password: pw });
      return;
    }

    if (msg.type === 'WARDKEY_FILL') {
      // Require domain verification for vault credential fills
      if (!msg.targetDomain) {
        sendResponse({ success: false, error: 'No target domain specified' });
        return;
      }
      try {
        const currentHost = location.hostname.replace(/^www\./, '');
        const targetHost = msg.targetDomain.replace(/^www\./, '');
        if (currentHost !== targetHost && !currentHost.endsWith('.' + targetHost)) {
          sendResponse({ success: false, error: 'Domain mismatch' });
          return;
        }
      } catch (e) { sendResponse({ success: false, error: 'Invalid domain' }); return; }
      const fields = findFields();
      if (fields.username && msg.username) fillField(fields.username, msg.username);
      if (fields.password && msg.password) fillField(fields.password, msg.password);
      showFillBanner();
      sendResponse({ success: true });
    }

    if (msg.type === 'WARDKEY_FILL_PW') {
      if (location.protocol !== 'http:' && location.protocol !== 'https:') {
        sendResponse({ success: false, error: 'Invalid protocol' });
        return;
      }
      // Domain verification — prevent filling generated password on wrong site
      if (!msg.targetDomain) {
        sendResponse({ success: false, error: 'No target domain specified' });
        return;
      }
      if (msg.targetDomain) {
        const currentHost = location.hostname.replace(/^www\./, '').toLowerCase();
        const expectedHost = msg.targetDomain.replace(/^www\./, '').toLowerCase();
        if (currentHost !== expectedHost && !currentHost.endsWith('.' + expectedHost)) {
          sendResponse({ success: false, error: 'Domain mismatch' });
          return;
        }
      }
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
        domain: location.hostname.replace(/^www\./, '')
      });
    }

    if (msg.type === 'WARDKEY_SHOW_SAVE') {
      if (typeof msg.domain !== 'string' || typeof msg.username !== 'string') return;
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

  let _iconDebounce, _trackDebounce;
  const observer = new MutationObserver(() => {
    clearTimeout(_iconDebounce);
    clearTimeout(_trackDebounce);
    _iconDebounce = setTimeout(injectIcons, 300);
    _trackDebounce = setTimeout(trackCredentialFields, 500);
  });
  observer.observe(document.body, { childList: true, subtree: true });
})();
