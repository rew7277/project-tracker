# DM Reactions Click + Stability Fix V10

Changes:
- Reaction picker opens on message click instead of hover.
- Picker stays open long enough to move the cursor and choose an emoji.
- Clicking outside the message area closes the picker.
- Reaction clicks update immediately on the frontend.
- In-flight reaction state is protected for 10 seconds so polling/cache responses cannot overwrite the optimistic reaction and make it vanish/reappear.
- SSE reaction payloads update only the changed message reactions instead of forcing a full thread reload.
- Removed appdata cache bust from `/api/dm/react` to avoid slow reaction round-trips and stale UI refresh races.

Validated:
- `node --check main.js`
- `node --check frontend.js`
- `python3 -m py_compile app.py`
