// WARDKEY Service Worker v5
const CACHE_NAME = 'wardkey-v6';
const ASSETS = [
  '/',
  '/index.html',
  '/app.html',
  '/wardkey-manifest.json',
  '/assets/logo-icon.png',
  '/assets/logo-icon-512.png',
  '/assets/logo-icon-192.png',
  '/assets/logo-icon-180.png',
  '/assets/logo-icon-128.png',
  '/assets/logo-icon-32.png',
  '/assets/logo-text.png',
  '/assets/logo-text-nav.png',
  '/assets/logo-text-lock.png',
  'https://fonts.googleapis.com/css2?family=DM+Sans:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600;700&display=swap',
  'https://fonts.googleapis.com/css2?family=Instrument+Serif:ital@0;1&family=Outfit:wght@300;400;500;600;700;800;900&family=JetBrains+Mono:wght@400;500;600&display=swap'
];

// Install — cache core assets
self.addEventListener('install', e => {
  e.waitUntil(
    caches.open(CACHE_NAME)
      .then(cache => cache.addAll(ASSETS))
      .then(() => self.skipWaiting())
  );
});

// Activate — clean old caches
self.addEventListener('activate', e => {
  e.waitUntil(
    caches.keys().then(keys =>
      Promise.all(keys.filter(k => k !== CACHE_NAME).map(k => caches.delete(k)))
    ).then(() => self.clients.claim())
  );
});

// Fetch — only handle same-origin GET requests + font CDN
self.addEventListener('fetch', e => {
  const url = new URL(e.request.url);
  const isFont = url.hostname.includes('googleapis') || url.hostname.includes('gstatic');
  const isSameOrigin = url.origin === self.location.origin;

  // ONLY intercept same-origin GETs and font requests — let everything else pass through untouched
  if (e.request.method !== 'GET') return;
  if (!isSameOrigin && !isFont) return;

  // Cache-first for app shell and fonts
  e.respondWith(
    caches.match(e.request).then(cached => {
      if (cached) return cached;
      return fetch(e.request).then(res => {
        if (res.ok) {
          const clone = res.clone();
          caches.open(CACHE_NAME).then(c => c.put(e.request, clone)).catch(()=>{});
        }
        return res;
      });
    }).catch(() => {
      if (e.request.mode === 'navigate') {
        return caches.match('/app.html');
      }
    })
  );
});

// Handle messages from the app
self.addEventListener('message', e => {
  if (e.data === 'skipWaiting') self.skipWaiting();
  if (e.data === 'clearCache') {
    caches.delete(CACHE_NAME).then(() => {
      self.clients.matchAll().then(clients => {
        clients.forEach(c => c.postMessage('cacheCleared'));
      });
    });
  }
});
