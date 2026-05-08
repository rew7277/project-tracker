# Deep Link, Task Save, and Lightweight System Fixes

## Fixed

### 1. Email task/ticket links opened the landing page
Root cause: `/` only routed app-shell actions for login/signup. Links like `/?action=task&id=T-616363` were treated as public landing requests.

Change:
- Added `task`, `ticket`, `project`, `dashboard`, `tasks`, `tickets`, etc. to the app-shell action list.
- React now reads `?action=task&id=...` and opens the Tasks page.
- If the task exists in loaded data, the task modal opens automatically.
- Ticket deep links now open the Tickets page and attempt to open the matching ticket.

### 2. Task creation felt slow
Root cause: the task modal waited until the API request finished before closing, even though the parent view already supports optimistic task insertion.

Change:
- New task creation without reminder now closes instantly.
- The task is inserted optimistically in the UI while the API finishes in the background.
- Reminder-enabled task creation still waits for the real task id so the reminder attaches correctly.

### 3. Lighter system recommendations added
Suggested next optimizations:
- Move email/push sending to a durable background queue instead of request threads.
- Keep SSE as primary for notifications/reminders/unread counts and reduce polling intervals.
- Paginate tasks/projects/tickets instead of loading everything on every app-data refresh.
- Add route-level timing logs to find slow DB queries.
- Split large React views into lazy-loaded modules.
- Avoid full `load()` after every mutation; patch local state and refresh only the affected resource.
- Add DB indexes for every `workspace_id + created/status/user_id/project_id` query pattern.
