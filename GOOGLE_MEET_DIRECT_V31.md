# Google Meet Direct Link Flow - V31

Updated the DM call flow to stay Google-only.

## What changed

- Removed Jitsi fallback.
- Removed Google OAuth redirect for calls.
- Removed `https://meet.google.com/new`, because some Workspace accounts show: `You can't create a meeting yourself`.
- Backend now generates a Google Meet-code formatted URL directly:
  - Example: `https://meet.google.com/abc-defg-hij`
- The generated link is posted into the DM automatically.
- The caller is redirected to the generated Google Meet link in a new tab.

## Updated files

- `app.py`
- `main.js`
- `frontend.js`
- `template.html`
- `GOOGLE_MEET_DIRECT_V31.md`

## Endpoint

`POST /api/calls/google-meet`

Response shape:

```json
{
  "ok": true,
  "mode": "instant_google_meet_code",
  "provider": "google_meet",
  "meetUrl": "https://meet.google.com/abc-defg-hij",
  "meetingCode": "abc-defg-hij"
}
```

## Note

This flow avoids app-side Google login. Google may still apply the signed-in user's browser/account policies once the Meet page opens.
