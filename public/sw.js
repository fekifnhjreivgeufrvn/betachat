// betachat service worker.
//
// Today it does one thing: when the app is opened with no connection, show a small
// "you're offline" page instead of the browser's error page. Chat itself needs the
// network (accounts and messages live on the server), so nothing else is cached.
// In particular index.html is never cached, so a new deploy is always picked up on the
// next launch and there is no stale copy of the app to get stuck on.
//
// It also receives Web Push messages (see src/push.js on the server) and shows them as system
// notifications, and reopens the right room when one is tapped.

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

// ---- Web Push ---------------------------------------------------------------
// The server (pushToAway in src/index.js) sends { title, body, room, tag } as the encrypted
// payload. The browser decrypts it for us; event.data.json() just parses what's left.
self.addEventListener("push", (event) => {
  let payload = {};
  try {
    payload = event.data ? event.data.json() : {};
  } catch {
    // Not JSON (or no body). Show something rather than nothing, so a malformed push is never silent.
  }
  const title = typeof payload.title === "string" && payload.title ? payload.title : "betachat";
  const body = typeof payload.body === "string" ? payload.body : "";
  const room = typeof payload.room === "string" ? payload.room : "";
  const tag = typeof payload.tag === "string" && payload.tag ? payload.tag : room ? `betachat:${room}` : "betachat";

  event.waitUntil(
    self.registration.showNotification(title, {
      body,
      tag, // a newer message for the same room replaces the old notification instead of stacking
      renotify: true,
      icon: "/icons/icon-192.png",
      badge: "/icons/icon-192.png",
      data: { room },
    })
  );
});

// Tapping the notification brings an already-open betachat tab to the front and switches it to
// that room, or opens a new tab there if none is open. Same behaviour a notification shown by the
// page itself already has (see showNotification's `data: { room }` in index.html).
self.addEventListener("notificationclick", (event) => {
  event.notification.close();
  const room = (event.notification.data && event.notification.data.room) || "";
  const target = room ? `${self.registration.scope}?room=${encodeURIComponent(room)}` : self.registration.scope;

  event.waitUntil(
    (async () => {
      const openClients = await self.clients.matchAll({ type: "window", includeUncontrolled: true });
      const ours = openClients.find((client) => client.url.startsWith(self.registration.scope));
      if (ours) {
        if ("navigate" in ours) {
          try {
            await ours.navigate(target);
          } catch {
            // Some browsers refuse to navigate a background tab; it still gets focused below,
            // and the page's own applyRoom() picks up ?room= from a fresh load regardless.
          }
        }
        return ours.focus();
      }
      return self.clients.openWindow(target);
    })()
  );
});
