# Chat Polish & Sync Fix V13

## Fixed
- Message reaction picker now uses only key reactions: 👍 ❤️ 😂 😮 😢 🔥 👏 🙏.
- Full emoji set remains available only from the message composer emoji button.
- Reaction picker opens only when clicking a message and closes after selection/outside click.
- Reaction picker/menu received glassmorphism styling, pop animation, and smoother emoji hover movement.
- Reply/Edit/Pin/Delete menu redesigned from plain browser-like buttons to a modern floating action panel.
- Voice notes now render as inline audio playback controls instead of plain local download-style attachment links.
- Browser recording uses Opus WebM where available for better quality.
- Background DM polling reduced and merge logic now preserves optimistic local messages/reactions so items do not vanish/reappear during sync.
- Stale background refreshes no longer erase pending sends or reaction states.

## Validated
- node --check main.js
- node --check frontend.js
- python3 -m py_compile app.py
