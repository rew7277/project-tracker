# Workspace-scoped routing update

## Why this change was needed
Links like:

```text
https://projecttracker.in/?action=task&id=T-966576
```

are not safe enough for a multi-company/multi-workspace system because the same display task id can exist in more than one workspace.

## New link format
Email/deep links now use the workspace slug first:

```text
https://projecttracker.in/<workspace-slug>/?action=task&id=T-966576
```

Example:

```text
https://projecttracker.in/fsbl/?action=task&id=T-966576
```

## What was implemented

- Added workspace-scoped slug-only app routes:
  - `/<workspace>/`
  - `/<workspace>/dashboard`
  - `/<workspace>/projects`
  - `/<workspace>/tasks`
  - `/<workspace>/kanban`
  - `/<workspace>/channels`
  - `/<workspace>/dm`
  - `/<workspace>/tickets`
  - `/<workspace>/timeline`
  - `/<workspace>/reminders`
  - `/<workspace>/team`
  - `/<workspace>/productivity`
  - `/<workspace>/ai-docs`
  - `/<workspace>/timesheet`
  - `/<workspace>/vault`
  - `/<workspace>/settings`

- Updated email links for:
  - task assignment
  - task reassignment
  - due soon
  - overdue
  - ticket assignment
  - ticket status
  - dashboard/status/comment links

- Root legacy links such as `/?action=task&id=...` now redirect logged-in users to their workspace URL automatically.

- Frontend browser routing now keeps workspace slug in the URL when changing sidebar pages.

## Important note
This uses the workspace slug, not the workspace id, in visible URLs. The backend session still validates that the logged-in user belongs to the workspace before serving workspace-scoped pages.
