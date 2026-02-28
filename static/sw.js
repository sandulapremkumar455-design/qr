/* ═══════════════════════════════════════════════
   Smart Attendance System Service Worker — Offline PWA Support
   ═══════════════════════════════════════════════ */

const CACHE_NAME = 'smartatt-v1';
const OFFLINE_QUEUE_KEY = 'attendr-offline-scans';

// Pages/assets to cache for offline use
const CACHE_URLS = [
  '/student/scan',
  '/student/dashboard',
  '/login',
  '/static/icon-192.png',
  'https://unpkg.com/html5-qrcode@2.3.8/html5-qrcode.min.js',
  'https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css'
];

// ── INSTALL: cache all essential files ──
self.addEventListener('install', function(event) {
  event.waitUntil(
    caches.open(CACHE_NAME).then(function(cache) {
      return cache.addAll(CACHE_URLS).catch(function(e) {
        console.log('[SW] Cache install partial:', e);
      });
    })
  );
  self.skipWaiting();
});

// ── ACTIVATE: clean old caches ──
self.addEventListener('activate', function(event) {
  event.waitUntil(
    caches.keys().then(function(keys) {
      return Promise.all(
        keys.filter(function(k) { return k !== CACHE_NAME; })
            .map(function(k) { return caches.delete(k); })
      );
    })
  );
  self.clients.claim();
});

// ── FETCH: serve from cache when offline ──
self.addEventListener('fetch', function(event) {
  var url = new URL(event.request.url);

  // Never intercept API calls — let them fail naturally so client can queue them
  if (url.pathname.startsWith('/api/')) return;

  // For navigation requests (page loads) — cache-first with network fallback
  if (event.request.mode === 'navigate') {
    event.respondWith(
      fetch(event.request).catch(function() {
        return caches.match(event.request).then(function(cached) {
          return cached || caches.match('/student/scan');
        });
      })
    );
    return;
  }

  // For static assets — cache first
  event.respondWith(
    caches.match(event.request).then(function(cached) {
      return cached || fetch(event.request).then(function(response) {
        // Cache new successful responses
        if (response && response.status === 200) {
          var clone = response.clone();
          caches.open(CACHE_NAME).then(function(cache) {
            cache.put(event.request, clone);
          });
        }
        return response;
      });
    }).catch(function() {
      // Completely offline and not cached
      return new Response('Offline', { status: 503 });
    })
  );
});

// ── BACKGROUND SYNC: retry queued offline scans ──
self.addEventListener('sync', function(event) {
  if (event.tag === 'sync-attendance') {
    event.waitUntil(syncOfflineScans());
  }
});

async function syncOfflineScans() {
  // Get all clients and ask them to sync
  const clients = await self.clients.matchAll();
  clients.forEach(function(client) {
    client.postMessage({ type: 'SYNC_NOW' });
  });
}

// ── MESSAGE from page: trigger sync ──
self.addEventListener('message', function(event) {
  if (event.data && event.data.type === 'SKIP_WAITING') {
    self.skipWaiting();
  }
});
