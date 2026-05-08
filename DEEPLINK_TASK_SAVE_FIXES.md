# Deep-link + task save fixes

## Issues found

1. Email task links used `/?action=task&id=T-xxxxxx`, but the deployed page was still using the older inline JavaScript inside `template.html`. That copy did not read `action=task`, so the app opened Dashboard even though the URL was correct.

2. The frontend only tried to open a task if it was already present in the initial `/api/app-data` task list. Since task lists are capped/cached for performance, a valid email-linked task might not be in the first payload, so no modal opened.

3. There was no `GET /api/tasks/<id>` endpoint to fetch exactly one task for a deep link.

4. The visible create-task UI was using the older inline template code, so Save could still wait for the `/api/tasks` request. The standalone `frontend.js` had improvements, but `template.html` needed to be synced.

## Fixes added

- Synced the latest frontend logic into `template.html` so production serves the same fixed code.
- Added `GET /api/tasks/<tid>` for direct email/deep-link task lookup.
- Updated task deep-link handling to:
  - switch to the Kanban/tasks view,
  - find the task in current data if available,
  - otherwise fetch `/api/tasks/<id>`, inject it into local state, and open the task modal.
- Updated new task creation to be fully optimistic from the UI side:
  - card appears immediately,
  - modal closes immediately,
  - server save runs in background,
  - temp task is replaced by the real server task when the API returns.
- Added quiet API options so background deep-link/task-save calls do not create noisy error toasts.

## Expected result

- Clicking `Open Task` from email should open the logged-in app and automatically show that exact task modal.
- Creating a task should no longer feel blocked by email/push notification side effects.
- You may still see the POST `/api/tasks` timing in the browser network tab, but the UI should not wait on it.
