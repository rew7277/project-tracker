# Google Meet Instant Mode — v29

## What changed

The Direct Message Google Meet button now opens an instant Google Meet room without forcing Google OAuth / Gmail login through the app.

## Updated flow

1. User clicks the Google Meet button in DM.
2. Frontend calls `POST /api/calls/google-meet`.
3. Backend returns instant mode with `https://meet.google.com/new`.
4. Frontend opens Google Meet in a new browser tab.
5. User copies the generated Meet URL from Google Meet and pastes it into the DM.

## Important limitation

Without Google Calendar OAuth, Google does not return the final meeting code/link to the app automatically. The only no-OAuth option is to open `https://meet.google.com/new` and let the user paste the generated link.

## Files updated

- `app.py`
- `main.js`
- `frontend.js`
- `template.html`
- `GOOGLE_MEET_INSTANT_V29.md`
