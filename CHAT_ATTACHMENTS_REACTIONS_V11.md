# Chat Attachments + Reaction Animation V11

## Added
- DM message bar attachment button.
- Channel message bar attachment button.
- DM message bar emoji picker.
- Channel message bar emoji picker.
- Attachment messages are sent as downloadable `/api/files/<id>` links.
- Message text now renders safe clickable attachment/download links.

## Improved
- DM reaction picker now has more WhatsApp-style reactions.
- Reaction icons animate on cursor hover with lift, scale, and shadow.
- Backend `/api/dm/react` now accepts the expanded reaction set.

## Validation
- `node --check main.js` passed.
- `node --check frontend.js` passed.
- `python -m py_compile app.py` passed.
