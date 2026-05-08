# Login Blank Page Fix

## Root cause
`/?action=login` was returning the SPA HTML, but the HTML was missing the external runtime scripts for React, ReactDOM, PropTypes, Recharts, and HTM.

Because of that, `waitForLibs()` kept waiting forever and React never rendered the AuthScreen, so the browser showed a blank white page.

## Fix
- Restored required runtime CDN scripts in `template.html`.
- Added an 8-second startup fallback message if runtime libraries fail to load.
- Kept workspace routing intact.

## Expected behavior
- `https://projecttracker.in/?action=login` shows the login screen.
- `https://projecttracker.in/fsbl/?action=login` shows the login screen.
- Workspace-scoped links still work for tasks/tickets/projects.
