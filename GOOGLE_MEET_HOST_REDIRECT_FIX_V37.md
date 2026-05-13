# Google Meet Host / Redirect Fix v37

Fixed two issues from production testing:

1. **Both caller and receiver stuck in Meet lobby**
   - Real Meet spaces are now created with `config.accessType = OPEN` and `entryPointAccess = ALL`.
   - This prevents the instant-call flow from depending on a separate manual host-admit step.
   - If a Workspace admin policy forces restricted meetings, Google can still override this; otherwise invitees can join directly.

2. **ProjectTracker tab being replaced by Google Meet**
   - Removed `window.location.href = meetUrl` fallback.
   - ProjectTracker remains open.
   - Caller sees a ProjectTracker modal with **Join as host**.
   - Receiver opens Meet only after clicking the green **Connect** button.
   - If browser blocks popups, the app shows a toast instead of replacing the current app tab.

Also kept the existing behavior:
- Incoming call popup appears only from live `call_status:ringing` SSE events.
- Old DM call messages do not reopen popups.
- Real Google Meet URL is still created server-side through the Meet REST API.
