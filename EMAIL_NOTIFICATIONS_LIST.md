# Project Tracker email notifications

Current outgoing email types in this codebase:

1. OTP login code — `send_otp_email`
2. Email verification — `_send_verification_email`
3. Password reset — `_send_password_reset_email`
4. Workspace invitation — `_send_workspace_invite_email`
5. Task assigned — `send_task_assigned_email`
6. Task reassigned — `send_task_reassigned_email`
7. Task status/stage changed — `send_status_change_email`
8. Task completed celebration — `send_task_completed_email`
9. Task due soon reminder — `send_task_due_soon_email`
10. Task overdue alert — `send_task_overdue_email`
11. New task comment — `send_comment_email`
12. @mention in task/comment thread — `send_mention_email`
13. Ticket assigned — `send_ticket_assigned_email`
14. Ticket status updated/resolved/closed — `send_ticket_status_email`
15. Weekly / bi-weekly project status digest — `send_status_summary_digest` via `/api/email/status-summary`
16. Workspace SMTP test email — `/api/workspace/email-test`

Notes:
- Browser preview and real inbox will never match 100% because Gmail/Outlook strip some CSS.
- The updated production templates are table-first and inline-style heavy to reduce the difference.
- Completion and resolved-ticket emails include static celebration fallback plus optional CSS animation for clients that support it.
