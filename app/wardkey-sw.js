// WARDKEY Service Worker v1.0
const CACHE_NAME = 'wardkey-v2';
const ASSETS = [
  './',
  './wardkey.html',
  './wardkey-manifest.json',
  'https://fonts.googleapis.com/css2?family=DM+Sans:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600;700&display=swap'
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

// Fetch — cache-first for app shell, network-first for API/fonts
self.addEventListener('fetch', e => {
  const url = new URL(e.request.url);

  // Skip non-GET, cross-origin API, and chrome-extension requests
  if (e.request.method !== 'GET') return;
  if (url.origin !== self.location.origin && !url.hostname.includes('googleapis') && !url.hostname.includes('gstatic')) return;
  if (url.protocol === 'chrome-extension:') return;

  // Network-first for API calls
  if (url.pathname.startsWith('/api/')) {
    e.respondWith(
      fetch(e.request)
        .then(res => {
          const clone = res.clone();
          caches.open(CACHE_NAME).then(c => c.put(e.request, clone));
          return res;
        })
        .catch(() => caches.match(e.request))
    );
    return;
  }

  // Cache-first for everything else (app shell, fonts, etc.)
  e.respondWith(
    caches.match(e.request).then(cached => {
      if (cached) return cached;
      return fetch(e.request).then(res => {
        // Only cache same-origin and font requests
        if (res.ok && (url.origin === self.location.origin || url.hostname.includes('googleapis') || url.hostname.includes('gstatic'))) {
          const clone = res.clone();
          caches.open(CACHE_NAME).then(c => c.put(e.request, clone));
        }
        return res;
      });
    }).catch(() => {
      // Offline fallback
      if (e.request.mode === 'navigate') {
        return caches.match('./wardkey.html');
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
