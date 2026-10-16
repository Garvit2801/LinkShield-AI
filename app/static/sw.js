// LinkShield service worker. Its one job is the Android share target: when another app shares
// text or a file to LinkShield, keep it in this browser and open the app, which then runs the check.
// Nothing else is intercepted or cached, so the app never serves a stale page.
const SHARED = 'linkshield-shared';

self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', event => event.waitUntil(self.clients.claim()));

self.addEventListener('fetch', event => {
  const url = new URL(event.request.url);
  if (event.request.method !== 'POST' || url.origin !== self.location.origin || url.pathname !== '/share') return;
  event.respondWith((async () => {
    try {
      const form = await event.request.formData();
      const text = ['title', 'text', 'url'].map(k => form.get(k)).filter(v => typeof v === 'string' && v.trim()).join(' ').slice(0, 6000);
      const file = form.getAll('file').find(f => f instanceof File && f.size);
      const cache = await caches.open(SHARED);
      await cache.delete('/shared/file');
      await cache.put('/shared/text', new Response(text));
      if (file) {
        await cache.put('/shared/file', new Response(file, {
          headers: { 'Content-Type': file.type || 'application/octet-stream', 'X-File-Name': encodeURIComponent(file.name || 'shared-file') },
        }));
      }
      return Response.redirect('/app?shared=1#scan', 303);
    } catch {
      return Response.redirect('/app#scan', 303);
    }
  })());
});
