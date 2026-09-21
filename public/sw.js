// betachat's service worker. It has two jobs and does nothing else (it caches nothing, so the page
// is always the current one):
//   1. When the server pushes a message to this device, show it as a notification.
//   2. When that notification is tapped, bring betachat forward on the right room.
//
// Every push must end in a visible notification. Safari on iPhone and iPad cancels a subscription
// that receives pushes without showing anything, so this always calls showNotification.

self.addEventListener("install", () => self.skipWaiting());
self.addEventListener("activate", (event) => event.waitUntil(self.clients.claim()));

self.addEventListener("push", (event) => {
  let data = {};
  try {
    data = event.data ? event.data.json() : {};
  } catch {}
  const text = (value, fallback) => (typeof value === "string" && value ? value : fallback);
  const room = text(data.room, "");

  event.waitUntil(
    self.registration.showNotification(text(data.title, "betachat"), {
      body: text(data.body, "New message"),
      tag: text(data.tag, "betachat"), // a newer message for the same room replaces the older notification
      renotify: true,
      icon: "/icons/icon-192.png",
      data: { room },
    })
  );
});

self.addEventListener("notificationclick", (event) => {
  event.notification.close();
  const room = (event.notification.data && event.notification.data.room) || "";
  const target = room ? `/?room=${encodeURIComponent(room)}` : "/";

  event.waitUntil(
    (async () => {
      const windows = await self.clients.matchAll({ type: "window", includeUncontrolled: true });
      for (const client of windows) {
        await client.focus();
        // Already on that room? Nothing more to do. Otherwise go there.
        if (room && new URL(client.url).searchParams.get("room") !== room && "navigate" in client) {
          try {
            await client.navigate(target);
          } catch {}
        }
        return;
      }
      await self.clients.openWindow(target);
    })()
  );
});
