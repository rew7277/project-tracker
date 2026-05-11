# Realtime DM + Notification Fixes

## Fixed issues

1. **Wrong DM conversation visible for ~2 seconds**
   - Added a hard DOM clear on user switch before React/Preact commits state.
   - Added `msgThreadId` isolation so message bubbles only render when they belong to the currently selected DM user.
   - Added sender/recipient filtering before rendering DM bubbles.
   - Kept stale async response protection with request sequencing.

2. **Messages taking too long to appear for sender/recipient**
   - Added optimistic DM sending: sender sees their message immediately while `/api/dm` is still saving.
   - Added pending/failed send states.
   - Reduced DM unread fallback polling from 120s to 3s for environments where SSE is delayed/disconnected.

3. **DM notifications not appearing immediately**
   - Server now busts `dm_unread`, `notifications`, `notifs`, and `appdata` caches immediately after sending a DM and before publishing SSE.
   - Client now refreshes unread counts and the active DM thread as soon as `dm_created` SSE arrives.
   - Notification fallback polling reduced from 120s to 5s.

4. **Clicking DM notification should open exact user tab**
   - Notification click now detects `sender_id` / sender fields and sets the DM target user.
   - It routes directly to Direct Messages and refreshes the matching conversation.

## Files changed
- `main.js`
- `app.py`
