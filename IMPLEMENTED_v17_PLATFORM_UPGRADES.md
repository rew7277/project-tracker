# v17 Platform Upgrade Notes

Implemented on top of v16:

## Realtime + performance
- Added a dedicated Ops Center route for realtime, delivery risk, workload, and SLA health.
- Reduced DM unread fallback polling from 3 seconds to 15 seconds because `/api/stream` is now the primary realtime path.
- Reduced notification fallback polling from 8 seconds to 20 seconds.
- Stopped global dashboard bootstrap reloads for DM/channel message events; those are handled by DM/channel-specific refresh events to avoid vanish/reappear UI loops.
- Kept ticket/task/project events on the bootstrap reload path because those screens depend on aggregate counts and filters.

## Operations Command Center
- Portfolio health score.
- Delayed project heatmap.
- Team workload matrix.
- SLA/critical ticket metrics.
- Unread signal metrics.
- AI-style next-action cards.
- Realtime health and performance cards.

## Command palette / search
- Existing Ctrl/Cmd+K command palette is now surfaced from Ops Center.
- Ops Center provides quick navigation to Dashboard, Timeline, Tickets, Team, Notifications, and filtered task views.

## Notification center / deep links
- Existing notification deep links preserved for DM, tickets, tasks, projects, reminders, and channels.
- Realtime notification events trigger lightweight notification refresh instead of always forcing full app reload.

## PWA polish
- Added `/icon-192.png` route to stop production 404 spam from manifest/icon requests.

## Validation
- `node --check main.js`
- `node --check frontend.js`
- `python -m py_compile app.py`
