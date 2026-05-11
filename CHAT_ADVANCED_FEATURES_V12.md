# Chat Advanced Features V12

Implemented on top of V11:

- DM reply-to-message with quoted preview.
- DM edit message.
- DM delete message with soft-delete placeholder.
- DM pin/unpin message with pinned banner.
- DM typing indicator via SSE.
- DM read receipt text: Sent / Seen.
- DM conversation search.
- DM unread divider for newly opened unread messages.
- DM voice-note recording and upload.
- DM drag-and-drop attachments.
- DM image preview modal by double-clicking image/file message.
- Expanded WhatsApp-style emoji/reaction set.
- Smoother cursor-following reaction/emoji hover animation.
- Channel drag-and-drop attachments.
- Backend endpoints for edit/delete/pin/typing.
- Backend schema columns for reply/edit/delete/pin/delivered/seen state.
- Audio upload extensions enabled for voice notes.

Validation:

- node --check main.js
- node --check frontend.js
- python -m py_compile app.py
