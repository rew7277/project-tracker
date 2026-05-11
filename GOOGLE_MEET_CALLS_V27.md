# Google Meet Calls V27

## Why the icon was not visible
The Google Meet button was added only in `frontend.js`, while the running UI can be served from `main.js` / `template.html`. This version patches all three UI sources so the camera button appears beside the voice-note button in Direct Messages.

## Updated files
- `app.py`
- `frontend.js`
- `main.js`
- `template.html`
- `GOOGLE_MEET_CALLS_V26.md`
- `GOOGLE_MEET_CALLS_V27.md`

## UI placement
Direct Messages composer:
Attach file → Emoji → Google Meet camera → Voice note → Message box → Send

## Backend endpoint
`POST /api/calls/google-meet`

Payload:
```json
{
  "type": "dm",
  "targetId": "USER_ID",
  "title": "Call with teammate"
}
```

## Behavior
- Creates a Google Calendar event with Meet conference data when OAuth Calendar permission exists.
- Posts the Meet invite into the DM thread.
- Opens the Meet URL in a new browser tab.
- Sends a notification to the recipient.
- Shows an auth prompt if Google Calendar permission is missing.
