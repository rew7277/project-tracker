# DM Reactions UI + Speed Fix v9

## Fixed
- Reaction picker no longer renders permanently beside every DM message.
- Emoji picker now appears only when hovering a message row.
- Existing reaction badges remain compact under the message bubble.
- Reaction clicks now update the UI optimistically before the API finishes.
- Failed reaction requests rollback by reloading the active thread.
- SSE `dm_reaction` events now carry the updated message reaction payload.
- Removed full app-data reload for `dm_reaction` events to reduce lag and unnecessary network calls.

## Files changed
- `main.js`
- `frontend.js`
- `template.html`
- `app.py`

## Validated
- `node --check main.js`
- `node --check frontend.js`
- `python3 -m py_compile app.py`
