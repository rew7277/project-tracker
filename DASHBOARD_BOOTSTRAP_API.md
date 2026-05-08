# Dashboard Bootstrap API

Implemented `GET /api/dashboard/bootstrap` as the single startup payload for the dashboard.

## What it replaces

The frontend dashboard load now uses one endpoint instead of separate startup requests for projects, tasks, tickets, notifications, DM unread, reminders, teams, users, and workspace data.

## Endpoint

```
GET /api/dashboard/bootstrap
GET /api/dashboard/bootstrap?team_id=<id>
GET /api/dashboard/bootstrap?bust=1
```

It reuses the existing stale-while-revalidate cache layer and includes a `summary` object for dashboard cards/badges.

## Returned sections

- `users`
- `projects`
- `tasks`
- `tickets`
- `teams`
- `workspace`
- `notifications`
- `dm_unread`
- `reminders`
- `summary`

## Why this helps

- Fewer startup HTTP calls
- Fewer repeated auth/session checks
- Lower DB connection pressure
- Cleaner frontend hydration
- Easier SSE delta updates later

`/api/app-data` remains as a compatibility alias, so older code or cached clients will not break.
