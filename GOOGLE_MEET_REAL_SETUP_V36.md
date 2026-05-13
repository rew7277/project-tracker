# Google Meet real call setup - v36

This version removes the fake `https://meet.google.com/lookup/<callId>` fallback because Google rejects random meeting codes with **Check your meeting code**.

The call flow now creates the Meet room first on the backend by calling:

`POST https://meet.googleapis.com/v2/spaces`

Required server env vars, recommended:

```bash
GOOGLE_CLIENT_ID=...
GOOGLE_CLIENT_SECRET=...
GOOGLE_REFRESH_TOKEN=...
```

The refresh token must include this OAuth scope:

```text
https://www.googleapis.com/auth/meetings.space.created
```

Quick testing is also supported with an access token, but it expires:

```bash
GOOGLE_MEET_ACCESS_TOKEN=...
```

Behavior now:

- If Meet API succeeds, caller opens the valid Google Meet URL and waits.
- Receiver gets the global full-screen popup only from a fresh live `call_status:ringing` SSE event.
- Receiver joins the same valid Meet URL after pressing the green connect button.
- If Google OAuth is missing or invalid, no receiver popup is shown and no broken Meet URL is sent.
