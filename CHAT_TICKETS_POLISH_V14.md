# Chat + Tickets Polish V14

## DM menu fix
- Converted message action menu to a fixed, viewport-clamped popover.
- Menu now opens above or below the message depending on available space.
- Prevents Reply/Edit/Pin/Delete from going off-screen for small/edge messages.
- Improved menu styling with modern glass panel, rounded controls, and smoother pop animation.

## Ticketing improvements
- Added ticket KPI cards: Open workload, Critical, Unassigned, My queue.
- Added ticket search by ID, title, description, type, priority, and status.
- Improved empty state with context-aware messaging and create-ticket CTA.
- Kept existing ticket filters and deep-link behavior intact.

## Validation
- node --check main.js
- node --check frontend.js
- python3 -m py_compile app.py
