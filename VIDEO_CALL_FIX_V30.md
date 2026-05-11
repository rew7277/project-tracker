# Video Call Fix V30

## Problem fixed
Google Meet instant creation (`https://meet.google.com/new`) can show:

> You can't create a meeting yourself. Contact your system administrator.

That is controlled by the signed-in Google Workspace admin policy, so the app cannot bypass it without Google Calendar OAuth/admin permission.

## What changed
- Removed direct `https://meet.google.com/new` opening from the DM call button.
- `POST /api/calls/google-meet` now creates an instant browser video room link that works without Google OAuth/admin permission.
- The call invite is automatically posted into the selected DM.
- The caller is redirected to the video room in a new tab.
- The recipient gets a DM notification and can click **Join video call**.
- DM messages now render video-call invites as a proper card.

## Files updated
- `app.py`
- `main.js`
- `frontend.js`
- `template.html`
- `VIDEO_CALL_FIX_V30.md`

## Notes
This keeps the same backend route name for compatibility, but the returned provider is now `jitsi` because Google Meet blocks meeting creation for accounts whose Workspace admin disabled meeting creation.
