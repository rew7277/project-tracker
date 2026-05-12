# Call + Instant Message Fixes V34

## Fixed call UX
- Incoming DM calls now render a true full-screen Teams-style overlay.
- Receiver sees large green connect and red disconnect circular call buttons.
- Ringtone starts while the full-screen incoming call overlay is visible.
- Ringtone stops on accept, reject, call status updates, and 45-second missed timeout.
- Accept opens the shared Google Meet invite URL.
- Reject/missed/end status is synced to both users through SSE `call_status`.
- Caller and receiver are marked `In a call` with red presence while active.

## Fixed Google Meet routing
- Replaced separate `https://meet.google.com/new` usage with a deterministic shared Meet lookup URL per call.
- Caller opens the Meet waiting room immediately after starting the call.
- Receiver opens the same call URL after pressing the green connect button.

## Fixed message loading delay
- DM threads render instantly from local cache when available.
- DM refreshes now use incremental `?since=` fetching instead of repeatedly loading the full thread.
- Background prefetch still warms DM threads after the Direct Messages view opens.
- Optimistic send still shows messages immediately before the server confirms.

## Important files updated
- `template.html`
- `frontend.js`
- `main.js`
- `app.py`
