# V20 fixes

## Ops Center blank screen
- Added `ops` to the valid frontend route list.
- Fixed `/ops` route sync so selecting Ops Center keeps the correct route.
- Expanded Ops access guard to support Admin, Owner, Workspace Owner, Manager, Project Manager, Team Lead, and Super Admin role naming variants.
- Hardened Ops Center container styling so cards render against the dark background.

## Channels JSON crash
- Fixed channel member parsing when `project.members` is stored as a plain user id or comma-separated string instead of JSON.
- Replaced unsafe `JSON.parse(sp.members)` in Channels with a tolerant `parseIdList()` helper.
- Hardened active team member parsing similarly.

## Validation
- `node --check main.js`
- `node --check frontend.js`
- `python3 -m py_compile app.py`
