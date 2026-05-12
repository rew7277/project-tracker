# Persisting task/DM/channel issues fixed

## 1) Task create still returned 500
Two backend problems were found:

- `_cache_inject_item(...)` was called by `create_task`, but the previous patch accidentally left that code body indented under `_bust_dm_thread` instead of defining a real top-level function. That caused `NameError: _cache_inject_item is not defined` after the task insert, so the API returned 500.
- `next_task_id()` used only the last 6 digits of the millisecond timestamp. That repeats roughly every 16.6 minutes and can intermittently hit duplicate primary-key errors. It now uses full millisecond timestamp + random suffix.

Files changed:
- `app.py`
- `blueprints/projects_tasks_files.py`

## 2) DM briefly showed “Start a conversation…” before messages
The cache could contain an empty prefetched thread, so the UI treated the thread as loaded and showed the empty-state before the real API response arrived.

Fixes:
- Added persistent localStorage DM cache so messages can render immediately after refresh once seen.
- Added `refreshingThread` state so empty-state is not shown while a selected thread is still refreshing.
- Real API responses update both memory cache and localStorage.
- Removed an accidental channel-prefetch block inside the DM component.

File changed:
- `frontend.js`

## 3) Channel briefly showed “Opening channel…” before messages
Channel messages were memory-only cached, so refresh wiped the cache. Also an empty prefetch could flash the wrong state.

Fixes:
- Added persistent localStorage channel cache.
- Added `refreshingChannel` state so the UI does not show the empty-state during a selected-channel refresh.
- Channel fetches update memory cache + localStorage.

File changed:
- `frontend.js`
