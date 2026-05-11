# Google Meet Calls V26

Implemented DM Google Meet call flow.

## Frontend
- Added a video-call button in the Direct Messages composer.
- Clicking it calls `POST /api/calls/google-meet` with the selected DM user.
- On success, the app:
  - posts the Google Meet invite card into the DM thread,
  - opens the Google Meet URL in a new browser tab,
  - shows the invite code inside the chat bubble.
- If Google Calendar permission is missing, the user is prompted to connect Google.

## Backend
- Added `POST /api/calls/google-meet`.
- Uses Google Calendar API conference creation to generate a real Google Meet link.
- Creates a DM message with the Meet URL and invite code.
- Sends a `call` notification to the recipient.
- Publishes realtime SSE updates for DM and notification refresh.

## Google requirement
Automatic Meet creation requires Google OAuth with:

```txt
https://www.googleapis.com/auth/calendar.events
```

The Google OAuth login scope has been updated to include Calendar Events.
Users should reconnect Google once after this update so the session receives the new permission.
