# Checked fixes applied

## Frontend API errors
- Replaced silent API handling with `_apiRequest()`.
- All `get/post/put/del/upload` calls now check `response.ok`.
- Failed requests dispatch `pt:api-error` and show a toast via the existing toast system.
- Added 15-second de-duplication to avoid polling-error toast spam.

## SSE vs polling
- Existing `/api/stream` is now used for project/task/ticket/message/DM/notification/reminder refresh events.
- Added backend publishes for project channel messages, DMs, notifications, and reminders.
- Reduced fallback polling:
  - Channel message timestamp fallback: 60s
  - Open DM fallback: 60s
  - DM unread fallback: 120s
  - Notification fallback: 120s
  - Reminder due fallback: 60s

## DB indexes
Added indexes for file/task/project/ticket/time-log access patterns:
- `idx_files_ws_task_ts`
- `idx_files_ws_project_ts`
- `idx_subtasks_ws_task`
- `idx_task_comments_ws_task_ts`
- `idx_tickets_ws_project_created`
- `idx_time_logs_ws_project_task_date`

## Server-side permissions
- Added `require_role()` decorator.
- Added/strengthened RBAC on user, project, team, and file delete mutation routes.
- Note: `pf_perms` can still be used only for UI display; backend permission checks are now the source of truth for these key routes.

## File upload validation
- Added extension allowlist and blocked active/executable types.
- Added lightweight MIME/signature sniffing.
- Added per-file size limit and per-workspace quota.
- Added `VIRUS_SCAN_CMD` hook for ClamAV or another scanner.
- Sanitized original filenames with `os.path.basename()`.

## Static serving
- `/static/<path>` no longer serves arbitrary files from `BASE_DIR`.
- Only approved static asset extensions are served from `static/` or `pf_static/`.

## Dark theme centralization
- Added theme utility classes/tokens in `template.html`.
- Existing CSS variables are preserved; new UI should use `theme-surface`, `theme-input`, `theme-glass`, etc.

## Monolith splitting
- Full blueprint/component splitting was not done in this patch because it is a high-risk structural refactor across an ~8k-line backend and ~9k-line frontend.
- The safer path is to split route groups one by one with tests after this stability/security patch.

## Validation run
- `python -m py_compile app.py` passed.
- `node --check frontend.js` passed.
