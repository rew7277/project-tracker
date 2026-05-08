# Phase 2 Blueprint Split

Implemented in this ZIP:

- Added `blueprints/` package.
- Extracted Projects, Tasks, Subtasks, and Files API routes from `app.py` into `blueprints/projects_tasks_files.py`.
- Registered the extracted blueprint from `app.py`.
- Kept compatibility with existing DB helpers, auth decorators, event publishers, caches, and upload validation through a safe legacy-global bridge.

Why the bridge exists:

The original application is a large monolith with shared globals. A hard cut into fully independent modules would require changing hundreds of internal references at once. This implementation moves the heaviest API surface out of `app.py` while keeping runtime behavior stable.

Next safe split targets:

1. `blueprints/auth.py`
2. `blueprints/realtime.py` for SSE/presence/messages
3. `services/db.py` to remove the compatibility bridge
4. `services/rbac.py` for route-by-route permissions
5. Frontend component split under `frontend/`
