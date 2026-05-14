# Patch Notes — DM delay/blink, immediate notifications, avatar persistence

Applied fixes:

1. DM message blink after send
   - Updated `frontend.js`, `main.js`, and production `template.html`.
   - The DM SSE merge now skips a second state update when the API-confirmed optimistic message already exists.

2. Receiver delay / fallback polling
   - Updated DM thread fallback polling from 8000ms to 3000ms in `frontend.js`, `main.js`, and `template.html`.
   - SSE is still the primary real-time path; the faster poll is only a fallback for missed/buffered SSE events.

3. Web notifications not immediate
   - Added direct browser notification + toast handling inside the root SSE `dm_created` path in `frontend.js`, `main.js`, and `template.html`.
   - Added dedupe through `notifiedDmIdsRef` so the later poll will not trigger the same notification again.

4. Profile photo vanishing after restart
   - Added `_evict_me_cache(uid)` in `app.py` to clear Redis + in-process `/api/auth/me` cache.
   - Added cache eviction after user updates.
   - Added `/api/profile` so any logged-in user can update their own avatar/name without requiring Admin/Manager permissions.
   - Updated avatar upload calls to use `/api/profile` in `frontend.js`, `main.js`, and production `template.html`.

Important production note:
- `template.html` is patched because this app appears to serve the inline SPA from Flask. Patching only `main.js` or `frontend.js` may not affect production.
