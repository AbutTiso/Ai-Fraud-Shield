// Service Worker for AI Fraud Shield PWA
// Version 2.0 - With Push Notification Support

const CACHE_NAME = 'fraudshield-v2';
const VERSION = '2.0.0';

// Assets to cache
const urlsToCache = [
  '/',
  '/static/detector/css/style.css',
  '/static/detector/css/home.css',
  '/static/detector/js/main.js',
  '/manifest.json',
  '/offline/'
];

// Install event - cache assets
self.addEventListener('install', event => {
  console.log('Service Worker installing...');
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then(cache => {
        console.log('Opened cache');
        return cache.addAll(urlsToCache);
      })
      .then(() => self.skipWaiting())
  );
});

// Fetch event - serve from cache if offline
self.addEventListener('fetch', event => {
  event.respondWith(
    caches.match(event.request)
      .then(response => {
        // Cache hit - return response
        if (response) {
          return response;
        }
        
        // Clone the request
        const fetchRequest = event.request.clone();
        
        return fetch(fetchRequest).then(response => {
          // Check if valid response
          if (!response || response.status !== 200 || response.type !== 'basic') {
            return response;
          }
          
          // Clone the response
          const responseToCache = response.clone();
          
          caches.open(CACHE_NAME)
            .then(cache => {
              cache.put(event.request, responseToCache);
            });
          
          return response;
        }).catch(() => {
          // Return offline page if fetch fails
          return caches.match('/offline/');
        });
      })
  );
});

// Activate event - clean up old caches
self.addEventListener('activate', event => {
  console.log('Service Worker activating...');
  const cacheWhitelist = [CACHE_NAME];
  event.waitUntil(
    caches.keys().then(cacheNames => {
      return Promise.all(
        cacheNames.map(cacheName => {
          if (cacheWhitelist.indexOf(cacheName) === -1) {
            console.log('Deleting old cache:', cacheName);
            return caches.delete(cacheName);
          }
        })
      );
    }).then(() => self.clients.claim())
  );
});

// ============================================================
// PUSH NOTIFICATION HANDLERS
// ============================================================

// Handle push notifications
self.addEventListener('push', function(event) {
  console.log('Push notification received');
  
  let data = {};
  
  try {
    data = event.data.json();
  } catch (e) {
    data = {
      title: '🚨 Scam Alert',
      body: event.data ? event.data.text() : 'New scam detected!',
      icon: '/static/detector/icons/icon-192.png',
      badge: '/static/detector/icons/icon-72.png',
      vibrate: [200, 100, 200],
      requireInteraction: true
    };
  }
  
  const options = {
    body: data.body || 'Be aware of new scam activity in your area.',
    icon: data.icon || '/static/detector/icons/icon-192.png',
    badge: data.badge || '/static/detector/icons/icon-72.png',
    vibrate: data.vibrate || [200, 100, 200, 100, 200],
    data: data.data || { url: '/' },
    requireInteraction: data.requireInteraction || true,
    actions: data.actions || [
      { action: 'view', title: 'View Details' },
      { action: 'dismiss', title: 'Dismiss' }
    ],
    tag: data.tag || 'scam-alert',
    renotify: true
  };
  
  event.waitUntil(
    self.registration.showNotification(data.title || '🛡️ AI Fraud Shield Alert', options)
  );
});

// Handle notification clicks
self.addEventListener('notificationclick', function(event) {
  console.log('Notification clicked:', event.action);
  
  event.notification.close();
  
  const notificationData = event.notification.data || {};
  const urlToOpen = notificationData.url || '/';
  
  if (event.action === 'view') {
    // User clicked "View Details"
    event.waitUntil(
      clients.openWindow(urlToOpen)
    );
  } else if (event.action === 'dismiss') {
    // User clicked "Dismiss" - just close
    return;
  } else {
    // User clicked the notification body
    event.waitUntil(
      clients.matchAll({ type: 'window', includeUncontrolled: true })
        .then(windowClients => {
          // Check if there is already a window/tab open with the target URL
          for (let i = 0; i < windowClients.length; i++) {
            const client = windowClients[i];
            if (client.url === urlToOpen && 'focus' in client) {
              return client.focus();
            }
          }
          // If no window/tab is open, open a new one
          if (clients.openWindow) {
            return clients.openWindow(urlToOpen);
          }
        })
    );
  }
});

// ============================================================
// BACKGROUND SYNC (for offline reports)
// ============================================================

self.addEventListener('sync', function(event) {
  console.log('Background sync event:', event.tag);
  
  if (event.tag === 'sync-reports') {
    event.waitUntil(syncReports());
  }
});

async function syncReports() {
  console.log('Syncing pending reports...');
  
  // Get pending reports from IndexedDB or localStorage
  // This would be implemented with your existing report system
  try {
    const cache = await caches.open('pending-reports');
    const pendingReports = await cache.keys();
    
    for (const request of pendingReports) {
      const response = await fetch(request);
      if (response.ok) {
        await cache.delete(request);
        console.log('Synced report:', request.url);
      }
    }
  } catch (error) {
    console.error('Sync error:', error);
  }
}

// ============================================================
// PERIODIC BACKGROUND UPDATES (optional)
// ============================================================

self.addEventListener('periodicsync', function(event) {
  console.log('Periodic sync event:', event.tag);
  
  if (event.tag === 'update-scam-alerts') {
    event.waitUntil(updateScamAlerts());
  }
});

async function updateScamAlerts() {
  console.log('Updating scam alerts in background...');
  
  try {
    const response = await fetch('/api/scam-alerts/');
    const alerts = await response.json();
    
    if (alerts.count > 0) {
      const cache = await caches.open('scam-alerts');
      await cache.put('/api/scam-alerts/', new Response(JSON.stringify(alerts)));
      console.log('Scam alerts updated:', alerts.count);
    }
  } catch (error) {
    console.error('Update error:', error);
  }
}

// ============================================================
// MESSAGE HANDLING (from main thread)
// ============================================================

self.addEventListener('message', function(event) {
  console.log('Message received in SW:', event.data);
  
  if (event.data.type === 'SKIP_WAITING') {
    self.skipWaiting();
  }
  
  if (event.data.type === 'GET_VERSION') {
    event.ports[0].postMessage({ version: VERSION });
  }
});

// ============================================================
// LOGGING
// ============================================================

console.log(`✅ AI Fraud Shield Service Worker v${VERSION} loaded`);