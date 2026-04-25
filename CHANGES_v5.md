# Project Tracker v5.0 — Enterprise Edition Changes

## Critical Security Fixes

### 🔴 AI API Key No Longer Exposed to Browser
**Before:** `frontend.js` called `https://api.anthropic.com/v1/messages` directly with `ws.ai_api_key` in the request header — visible in DevTools / network tab.  
**After:** All AI calls route through `/api/ai/chat` on the backend. The API key never leaves the server.

### 🔴 CORS Restricted
**Before:** `CORS(app, supports_credentials=True)` — open to all origins.  
**After:** Reads `ALLOWED_ORIGINS` env var (comma-separated). Warns if not set in production.  
**Action needed:** Set `ALLOWED_ORIGINS=https://yourapp.railway.app` in Railway.

### 🔴 CSP: Removed `unsafe-eval`
**Before:** CSP allowed `unsafe-eval` in script-src.  
**After:** Removed. Only `unsafe-inline` remains (needed for legacy inline scripts).

## New Features Added

### Incident Management (`/api/incidents`)
- Create, update, resolve incidents with severity levels (critical/high/medium/low)
- Auto Slack notification for critical/high incidents
- Timeline tracking with status changes
- RCA and postmortem fields
- `GET /api/incidents/stats` — summary counts

### Approval Workflows (`/api/approvals`)
- Create approval requests linked to tasks/tickets/deployments
- Multiple approvers with partial approval tracking
- Auto-notification to approvers
- Approve/reject with reason
- `POST /api/approvals/<id>/approve` and `/reject`

### Recurring Tasks (`/api/recurring-tasks`)
- Daily, weekly, monthly recurring task templates
- Background thread auto-creates tasks when due
- `PUT /api/recurring-tasks/<id>` to enable/disable

### GitHub Integration (`/api/github/*`)
- Link repositories to workspace
- Webhook endpoint for push, PR, issues, workflow_run events
- Auto-links commits/PRs to tasks via `T-XXX` references in commit messages
- `GET /api/github/events?task_id=T-001` — see GitHub activity per task

### Smart Search (`/api/search`)
- Full-text search across tasks, projects, tickets, users in one query
- Filter by `?type=tasks|projects|tickets|users`

### Release Calendar (`/api/releases`)
- Plan releases with dates, environment, status
- Public roadmap: `GET /api/roadmap/public/<ws_id>` (no auth)

### On-Call Schedule (`/api/oncall`)
- Create rotation schedules with team members
- `POST /api/oncall/<id>/rotate` — rotate to next member

### GDPR Compliance
- `GET /api/gdpr/export` — ZIP of all personal data
- `POST /api/gdpr/delete` — anonymise and delete personal data

### Project Health Score (`/api/projects/<id>/health`)
- Score 0–100 based on completion rate, blockers, overdue tasks
- Status: healthy / at_risk / warning / critical

### Risk Dashboard (`/api/risk-dashboard`)
- Lists overdue, blocked, critical-priority tasks workspace-wide
- Breakdown by project

### Feature Flags (`/api/feature-flags`)
- Toggle per-workspace features: incidents, approvals, recurring tasks, GitHub, etc.
- Admin only

### CSV Import/Export
- `POST /api/import/csv` — import tasks from Jira/Linear/Trello CSV exports
- `GET /api/export/csv` — export all tasks

### Email-to-Task (`POST /api/email-to-task`)
- Forward emails to create tasks automatically
- Secured by workspace invite code as token

### Slack Integration
- Set `slack_webhook_url` in workspace settings
- Auto-notified on: incident creation (critical/high), task assignment

### OpenAPI Docs (`GET /api/docs`)
- Machine-readable API spec at `/api/docs`
- Documents all v1 public API endpoints

## Environment Variables (New in v5)

| Variable | Purpose |
|---|---|
| `ALLOWED_ORIGINS` | Comma-separated CORS origins (e.g. `https://app.railway.app`) |
| `SENTRY_DSN` | Sentry error tracking DSN |
| `GITHUB_CLIENT_ID` | GitHub OAuth app client ID |
| `GITHUB_CLIENT_SECRET` | GitHub OAuth app client secret |
| `APP_URL` | Full base URL (e.g. `https://yourapp.railway.app`) |

## Deployment Checklist (Updated)

- [ ] Set `ALLOWED_ORIGINS` to your Railway/custom domain
- [ ] Set `DATABASE_URL` (PostgreSQL connection string)
- [ ] Set `SECRET_KEY` (64+ char random string)
- [ ] Set `VAULT_ENCRYPTION_KEY` (Fernet key, generate with `python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"`)
- [ ] Set `APP_URL` to full HTTPS URL
- [ ] Configure `SMTP_*` or `RESEND_API_KEY` for email
- [ ] Optionally set `SENTRY_DSN` for error tracking
- [ ] Optionally set `STRIPE_SECRET_KEY` for billing
