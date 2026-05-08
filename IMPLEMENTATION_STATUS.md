# Implementation status after latest patch

## Fixed in this package
- `/` now serves `landing.html` so the public domain opens the landing page.
- `/login`, `/dashboard`, `/app`, and `/?action=login` still serve the app/login shell.
- Email task assignment template contrast fixed: no more white text on pale background.
- Added `EMAIL_TEMPLATE_SAMPLE.html` so the email design can be previewed before sending.
- Existing API error handling, fallback polling reductions, DB indexes, upload validation, and key RBAC decorators remain included.

## Already implemented from previous requests
- Frontend `api.get/post/put/delete/upload` uses response checks and toast errors.
- SSE `/api/stream` is used for task/project/ticket/message/DM/notification/reminder refresh events, with polling retained as fallback.
- Added dashboard-focused DB indexes for files, subtasks, task comments, tickets, and time logs.
- Added backend role decorators on key mutation/delete routes. `pf_perms` is now only UI-side display state, not a security source.
- File upload validation includes extension allowlist, MIME/signature sniffing, per-file limit, workspace quota, and optional `VIRUS_SCAN_CMD` hook.
- Static serving is restricted.
- Dark-theme utility tokens/classes were added.

## Partial / not fully implemented yet
- Full monolith split into Flask blueprints and separate frontend component files is not included. That is a larger refactor and should be done route-by-route with regression testing.
- Dark theme centralization is started, but old inline styles still exist and need phased replacement.
- RBAC is strengthened on key routes, but a full route-by-route permission audit is still recommended before production hardening.
