# Email + Notification fixes

## Toast spam fixed
The repeated `HTTP 500 request failed` cards were caused by background API calls (app-data refresh, notifications, reminders, presence, DM unread, timelogs) dispatching toast errors every time polling/SSE fallback retried.

Changed in `frontend.js`:
- Background polling endpoints are now console-only for API failures.
- Visible API error toasts are deduped for 2 minutes per unique error.
- `401/403` and `/api/auth/me` no longer create error toasts during normal logged-out/expired-session checks.
- `/api/app-data` failure no longer clears the dashboard unless it is an auth failure.

Important: this stops the endless user-facing notifications. If a real 500 still exists, it will remain visible in browser console/server logs so it can be debugged without spamming users.

## Email template changed
Replaced the previous preview-heavy/glass style with a cleaner corporate email template designed for actual inbox rendering:
- Table-first layout.
- Inline-safe styles.
- Dark professional header.
- Clear task/ticket card.
- Cleaner CTA button.
- Completion/resolution banner for completed tasks/tickets.
- Less dependency on gradients, external fonts, hover, or unsupported email CSS.

