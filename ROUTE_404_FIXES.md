# Route / 404 and Service Worker Fixes

Applied fixes:

1. Added explicit routes for `/`, `/dashboard`, `/login`, and `/app` so direct navigation and `/?action=login` return the SPA shell instead of Flask 404.
2. Added HEAD support for `/` so platform probes no longer receive 404.
3. Updated `/sw.js` to remove the no-op `fetch` event handler that Chrome warns about.
4. Kept `/favicon.ico` as 204 and `/manifest.json` as JSON to avoid noisy browser errors.

After deploy, hard refresh once or unregister the old service worker if Chrome still shows the old warning from cache.
