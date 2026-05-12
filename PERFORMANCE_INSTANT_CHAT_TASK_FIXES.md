# Performance fixes: instant tasks, channel cache, DM cache

## Fixed

1. **Create Task delay**
   - `ProjectDetail.saveTask` is now fully optimistic and fire-and-forget.
   - The modal closes immediately and a temporary task appears instantly.
   - Server confirmation replaces the temporary task in the background.
   - Failed saves are marked locally instead of blocking the UI.

2. **Channel switching delay**
   - Added `msgCacheRef` per project/channel.
   - Previously opened channels render from cache instantly.
   - Background fetch silently refreshes the cache.
   - Polling updates the same cache so switching back stays instant.
   - Channel send now appends an optimistic message immediately.

3. **DM “Loading conversation…” delay**
   - DM threads are pre-warmed aggressively for all visible contacts.
   - Removed the blocking spinner path for first click.
   - When cached data exists, the conversation renders immediately.
   - Backend incremental DM support is already used through `?since=`.

## Files changed

- `main.js`
- `frontend.js`
- `template.html`

## Validation

- `node --check main.js` passed.
- `node --check frontend.js` passed.
- `python3 -m py_compile app.py blueprints/projects_tasks_files.py` passed.
