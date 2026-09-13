const CACHE = "ft-chat-v17";
const PRECACHE = [
  "/",
  "/index.html",
  "/styles.css",
  "/app.js",
  "/manifest.json",
  "/icons/icon-192.png",
  "/icons/icon-512.png",
];

self.addEventListener("install", (event) => {
  event.waitUntil(
    caches.open(CACHE).then((cache) => cache.addAll(PRECACHE)).then(() => self.skipWaiting())
  );
});

self.addEventListener("activate", (event) => {
  event.waitUntil(
    caches.keys().then((keys) =>
      Promise.all(keys.filter((k) => k !== CACHE).map((k) => caches.delete(k)))
    ).then(() => self.clients.claim())
  );
});

self.addEventListener("sync", (event) => {
  if (event.tag === "chat-flush") {
    event.waitUntil(
      self.clients.matchAll({ type: "window" }).then((clients) => {
        clients.forEach((c) => c.postMessage({ op: "flush" }));
      })
    );
  }
});

self.addEventListener("message", (event) => {
  if (event.data && event.data.op === "flush") {
    self.clients.matchAll({ type: "window" }).then((clients) => {
      clients.forEach((c) => c.postMessage({ op: "flush" }));
    });
  }
});

self.addEventListener("push", (event) => {
  event.waitUntil((async () => {
    let data = { title: "Chat Aberto", body: "Nova mensagem" };
    try {
      if (event.data) data = { ...data, ...event.data.json() };
    } catch {
      try {
        data.body = event.data.text();
      } catch {
        /* ignore */
      }
    }
    const windows = await self.clients.matchAll({ type: "window", includeUncontrolled: true });
    const focused = windows.some((c) => c.focused);
    if (data.kind === "message" && focused) return;
    await self.registration.showNotification(data.title || "Chat Aberto", {
      body: data.body || "",
      icon: "/icons/icon-192.png",
      badge: "/icons/icon-192.png",
      tag: data.kind === "message" ? "chat-message" : "moderation",
      renotify: true,
      data,
    });
  })());
});

self.addEventListener("notificationclick", (event) => {
  event.notification.close();
  event.waitUntil(
    self.clients.matchAll({ type: "window", includeUncontrolled: true }).then((clients) => {
      for (const client of clients) {
        if ("focus" in client) return client.focus();
      }
      if (self.clients.openWindow) return self.clients.openWindow("/");
    })
  );
});

self.addEventListener("fetch", (event) => {
  const req = event.request;
  if (req.method !== "GET") return;

  const url = new URL(req.url);
  if (url.pathname.startsWith("/socket.io") || url.pathname.startsWith("/api/")) return;

  if (url.pathname.startsWith("/uploads/")) {
    event.respondWith(
      caches.open(CACHE).then(async (cache) => {
        const cached = await cache.match(req);
        if (cached) return cached;
        const res = await fetch(req);
        if (res.ok) cache.put(req, res.clone());
        return res;
      })
    );
    return;
  }

  event.respondWith(
    caches.match(req).then((cached) => {
      const fetched = fetch(req)
        .then((res) => {
          if (res && res.ok) {
            const copy = res.clone();
            caches.open(CACHE).then((cache) => cache.put(req, copy));
          }
          return res;
        })
        .catch(() => cached || caches.match("/"));
      return cached || fetched;
    })
  );
});
