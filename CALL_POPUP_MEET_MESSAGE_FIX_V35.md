# V35 Call Popup + Google Meet + DM speed fix

## Fixed
- Removed the bug where opening a DM thread with an old `CALL_INVITE` message immediately showed the incoming-call screen.
- Incoming call overlay now opens only from the live SSE `call_status: ringing` event.
- Added a global Teams-style incoming call popup at the app root, so it appears in the middle of the screen from any page, not only inside Direct Messages.
- Green Connect and red Disconnect buttons are shown clearly.
- Accept routes the receiver to the caller's DM and opens the same Meet URL.
- Reject/missed/end status is synced to both users.
- Caller and receiver call event now carries sender/recipient names in SSE payload.

## Google Meet generation note
The backend now first tries to create a real Google Meet room through the Google Meet REST API using `GOOGLE_MEET_ACCESS_TOKEN` or `GOOGLE_ACCESS_TOKEN` from environment variables. If that token is not configured, it falls back to a nickname Meet URL.

Google does not allow a production app to create real Google Meet rooms anonymously from browser-only code. Configure a valid server-side OAuth token for production.
