# Changes in v6

## 🐛 Logout Bug Fix (CRITICAL)
- **Root cause**: `logout()` was fire-and-forget — the redirect fired before the server's `Set-Cookie: expires=past` header arrived, leaving the session cookie active.
- **Fix**: `await` the `/api/auth/logout` POST *before* calling `window.location.replace('/')`. This ensures the browser processes the cookie-clear header before navigating.

---

## Phase 1 — Auth Hardening

### ✅ Login Rate Limit — 15-minute window
- Changed from 60s to **900s (15 min)** window.
- Max 5 failed attempts per email/IP per 15 minutes.
- Already Redis-backed when `REDIS_URL` is set; in-process fallback otherwise.

### ✅ Email Verification
- New users receive a **24-hour verification link** on registration.
- `users.email_verified` column tracks status.
- `GET /api/auth/verify-email?token=...` activates the account.
- `POST /api/auth/resend-verification` resends the link.
- Login page shows a ✓ success banner when `?verified=1` is in the URL.

### ✅ Forgot Password / Reset Token (12-minute expiry)
- `POST /api/auth/forgot-password` — sends a secure reset link (12-min expiry, within the 10–15 min requirement).
- `POST /api/auth/reset-password` — validates token, sets new password, invalidates ALL existing sessions.
- Full UI: "Forgot password?" link on login form → dedicated reset screen.

### ✅ Session Security
- Flask sessions already use **HTTP-only secure cookies** (not localStorage).
- Sessions now include a `session_id` token for per-device tracking.

### ✅ Device/Session Management
- `user_sessions` table tracks every login: device name, IP, user agent, timestamps.
- `GET /api/auth/sessions` — lists all active sessions.
- `DELETE /api/auth/sessions/<id>` — revoke a specific device.
- `POST /api/auth/sessions/logout-all` — invalidates all sessions immediately.
- **UI**: "Active Sessions" panel in the profile dropdown shows all devices with revoke buttons and a "Logout from All Devices" option.

### ✅ Google Account Linking
- Existing: if a user registered with email/password and signs in with Google using the same email, accounts are safely linked (auth_provider updated, no duplicate user created).

---

## Phase 2 — Organization / Workspace Model

### ✅ Workspace ID-based URLs
- Already implemented: `/{workspace_slug}/{workspace_id}/dashboard`
- All login/register/Google OAuth responses return `workspace_dashboard_url`.

### ✅ Invite Users by Email
- `POST /api/workspace/invite` — admin/owner sends an email invite with role assignment.
- `POST /api/auth/accept-invite` — accepts the invite; creates account if new user, links if existing.
- `GET /api/workspace/invites` — list pending invites.
- `DELETE /api/workspace/invites/<id>` — revoke an invite.
- **UI**: "✉️ Invite by Email" card in Workspace Settings with role picker and pending invite list.

### ✅ Role-Based Access
- Roles: **Owner, Admin, Developer, Tester, Viewer** (existing) plus **Admin** now enforced on invite endpoint.
- Invite role selector: Viewer / Tester / Developer / Admin.

### ✅ Domain Auto-Join
- `GET/POST /api/workspace/domain-settings` — manage allowed email domains.
- `POST /api/auth/domain-join-check` — frontend can check if a user's email domain matches any workspace.
- `POST /api/auth/domain-join-request` — user requests to join; auto-joins if approval not required, or creates pending account.
- **UI**: "🌐 Domain Auto-Join" card in Workspace Settings with domain tag management and approval toggle.

---

## New DB Columns / Tables
```sql
-- Phase 1
ALTER TABLE users ADD COLUMN email_verified INTEGER DEFAULT 0;
ALTER TABLE users ADD COLUMN email_verify_token TEXT DEFAULT '';
ALTER TABLE users ADD COLUMN email_verify_expires TEXT DEFAULT '';
ALTER TABLE users ADD COLUMN pw_reset_token TEXT DEFAULT '';
ALTER TABLE users ADD COLUMN pw_reset_expires TEXT DEFAULT '';

CREATE TABLE user_sessions (
  id TEXT PRIMARY KEY, user_id TEXT, workspace_id TEXT,
  device_name TEXT, ip TEXT, user_agent TEXT,
  login_at TEXT, last_seen TEXT, is_current INTEGER DEFAULT 0
);

-- Phase 2
CREATE TABLE workspace_invites (
  id TEXT PRIMARY KEY, workspace_id TEXT, email TEXT,
  role TEXT, invited_by TEXT, token TEXT UNIQUE,
  expires TEXT, accepted INTEGER DEFAULT 0, created TEXT
);

ALTER TABLE workspaces ADD COLUMN allowed_domains TEXT DEFAULT '[]';
ALTER TABLE workspaces ADD COLUMN domain_join_requires_approval INTEGER DEFAULT 1;
```

## Deployment Notes
- Set `APP_BASE_URL=https://your-domain.com` for correct email verification/reset links.
- Existing `SMTP_*` / `RESEND_API_KEY` env vars power all new emails.
- No breaking changes — all migrations are wrapped in try/except.
