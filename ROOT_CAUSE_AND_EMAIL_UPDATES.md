# Runtime 500 + Email Template Fixes

## Root cause of repeated refresh errors

The refresh-time failures were caused by `_appdata_cache_get(...)` being called by these endpoints but not defined in `app.py`:

- `GET /api/reminders/due`
- `GET /api/notifications`
- `GET /api/dm/unread`
- also used by `GET /api/tickets`

That produced a Python `NameError`, which became HTTP 500 responses on every refresh and every polling interval.

## Backend fixes added

- Added `_appdata_cache_get(...)` and `_appdata_cache_set(...)` compatibility helpers.
- Added safe fallbacks for `/api/reminders/due`, `/api/notifications`, and `/api/dm/unread`.
- These endpoints now return `[]` instead of breaking the whole UI if a background poll fails.
- DB fallback responses are cached so the next polling cycle is faster.

## Frontend fixes added

- Background polling endpoints are console-only for errors:
  - `/api/auth/me`
  - `/api/presence`
  - `/api/notifications`
  - `/api/reminders/due`
  - `/api/dm/unread`
  - `/api/timelogs`
- User-facing toast spam is deduped for 2 minutes.
- Important user-triggered API failures still show a visible toast.

## Email template updates

- Reworked the inbox-safe email shell.
- Improved professional task/ticket notification cards.
- Added stronger completion/resolution celebration block.
- Added `EMAIL_TEMPLATE_SAMPLE.html` showing supported scenarios.

## Note about animations in email

Real inboxes like Gmail and Outlook strip many CSS animations. The template now uses graceful fallbacks: it looks professional without animation, and clients that support CSS animation get subtle celebration motion.
