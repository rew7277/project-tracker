# Google Meet Calls V28

Fixes the `/api/calls/google-meet` 409 issue.

## What changed

- `/api/calls/google-meet` no longer returns HTTP 409 when Google OAuth is not connected.
- It now returns a normal JSON response with `needsGoogleAuth: true`.
- DM frontend opens the Google connection flow cleanly instead of showing a failed request error.
- The Meet request is now sent with `{ quiet: true }` so the global API error toast does not show for expected auth setup.

## Required for real Google Meet auto code

Set these environment variables:

```bash
GOOGLE_CLIENT_ID=your-google-client-id
GOOGLE_CLIENT_SECRET=your-google-client-secret
APP_BASE_URL=https://your-app-domain.com
```

Google Cloud Console redirect URI:

```txt
https://your-app-domain.com/api/auth/google/callback
```

Scope used:

```txt
https://www.googleapis.com/auth/calendar.events
```

After connecting Google once, click the Meet button again. The backend will create the Calendar event, generate the Google Meet URL/code, post the invite into DM, and open the Meet in a new tab.
