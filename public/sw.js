// betachat service worker.
//
// Today it does one thing: when the app is opened with no connection, show a small
// "you're offline" page instead of the browser's error page. Chat itself needs the
// network (accounts and messages live on the server), so nothing else is cached.
// In particular index.html is never cached, so a new deploy is always picked up on the
// next launch and there is no stale copy of the app to get stuck on.
//
// Web Push will hook in here later: add `push` and `notificationclick` listeners below.

const CACHE = "betachat-offline-v1";
// Cloudflare serves offline.html at /offline and redirects /offline.html to it. Use the final URL:
// a service worker can't answer a page load with a redirected response.
const OFFLINE_URL = "/offline";

self.addEventListener("install", (event) => {
  event.waitUntil(
    caches
      .open(CACHE)
      .then((cache) => cache.add(OFFLINE_URL))
      .then(() => self.skipWaiting())
  );
});

self.addEventListener("activate", (event) => {
  event.waitUntil(
    caches
      .keys()
      .then((keys) => Promise.all(keys.filter((key) => key !== CACHE).map((key) => caches.delete(key))))
      .then(() => self.clients.claim())
  );
});

self.addEventListener("fetch", (event) => {
  const { request } = event;
  // Only page loads. API calls, the chat WebSocket, avatars, fonts and everything else go
  // straight to the network exactly as they did before the service worker existed.
  if (request.mode !== "navigate") return;

  event.respondWith(
    fetch(request).catch(async () => (await caches.match(OFFLINE_URL)) || Response.error())
  );
});
