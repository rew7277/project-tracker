# DM Reactions Fix

Added message reactions to Direct Messages.

## Reactions supported
👍 ❤️ 😂 😮 😢 🔥 👏 👀 🚀

## Backend
- Added `dm_reactions` table and index.
- Added reactions to `/api/dm/<other_id>` response.
- Added `POST /api/dm/react` to toggle the current user's reaction.
- Added `dm_reaction` SSE event so other open clients refresh the current thread.

## Frontend
- Added reaction picker under each saved DM message.
- Added grouped reaction badges with counts.
- Clicking an existing badge toggles the current user's reaction.
- Reaction changes update the local thread immediately and refresh via SSE for other users/tabs.

## Validation
- `node --check main.js` passed.
- `node --check frontend.js` passed.
- `python3 -m py_compile app.py` passed.
