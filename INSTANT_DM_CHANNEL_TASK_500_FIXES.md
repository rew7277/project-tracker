# Instant DM / Channel / Task 500 fixes

## What was broken

1. **Create Task 500 error**
   - The `tasks` table now has extra columns like `team_id`, `parent_id`, `story_points`, `sprint`, `task_type`, and `labels`.
   - Some create flows still used `INSERT INTO tasks VALUES (...)` with only 12/13 values.
   - SQLite/Postgres rejects that with a 500 because the table has more columns than supplied values.
   - Notification inserts also used raw `INSERT INTO notifications VALUES (...)`, which breaks when older/newer DB schemas have extra columns.

2. **DM delay / false empty screen**
   - On first click, the UI had no cached thread yet.
   - `loadMsgs()` accidentally cleared `loadingThread`, so the render showed `👋 Start a conversation...` while the API request was still running.
   - `switchToUser()` also showed loading even when cached data already existed.

3. **Channel delay / Opening channel screen**
   - Channel messages were only fetched after selecting a project.
   - First selection had no cache, so it had to wait for `/api/messages?project=...`.

## What changed

### Backend
- Replaced unsafe raw inserts with explicit column lists:
  - `INSERT INTO tasks(id, workspace_id, title, ... team_id) VALUES (...)`
  - `INSERT INTO notifications(id, workspace_id, type, content, user_id, read, ts, ...) VALUES (...)`
  - `INSERT INTO messages(id, workspace_id, sender, project, content, ts, is_system) VALUES (...)`
- Patched both:
  - `app.py`
  - `blueprints/projects_tasks_files.py`

### Frontend
- DM now prefetches all visible member conversations in background with limited concurrency.
- DM no longer shows the empty “Start a conversation” state while data is still loading.
- DM cached thread clicks render immediately.
- Channel messages now prefetch for all projects in background.
- Channel clicks use in-memory cache immediately, then silently reconcile with the server.

## Note
First page load can still depend on `/api/auth/me` and `/api/app-data`, but after the DM/channel screen is mounted, switching tabs should feel instant because data is warmed in memory.
