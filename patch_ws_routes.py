from pathlib import Path
p=Path('/mnt/data/wsroute/app.py')
s=p.read_text()
# Insert helpers after _email_abs_url
needle='''def _email_abs_url(path_or_url=""):\n    # Return an absolute HTTPS URL for email links.\n    base = (os.environ.get("APP_BASE_URL") or APP_URL or "https://projecttracker.in").rstrip("/")\n    target = str(path_or_url or "")\n    if target.startswith("http://") or target.startswith("https://"):\n        return target\n    if not target.startswith("/"):\n        target = "/" + target\n    return base + target\n'''
insert=needle+'''

_RESERVED_WORKSPACE_SLUGS = {
    "api", "static", "favicon.ico", "manifest.json", "sw.js",
    "dashboard", "login", "app", "admin", "about", "privacy", "terms",
    "security", "password-generator", "onboarding", "projects", "tasks",
    "tickets", "messages", "dm", "channels", "settings", "assets"
}


def _workspace_slug_for_id(workspace_id):
    """Resolve a stable workspace slug for workspace-scoped links."""
    try:
        with get_db() as db:
            ws = db.execute(
                "SELECT name, workspace_slug FROM workspaces WHERE id=?",
                (workspace_id,)
            ).fetchone()
        if not ws:
            return "workspace"
        slug = (ws["workspace_slug"] or "").strip()
        return slug or _slugify(ws["name"] or "workspace")
    except Exception:
        return "workspace"


def _workspace_link(workspace_id, target=""):
    """Build a workspace-scoped app URL, e.g. /fsbl/?action=task&id=T-1."""
    slug = _workspace_slug_for_id(workspace_id)
    target = str(target or "")
    if target.startswith("http://") or target.startswith("https://"):
        return target
    if target.startswith("?"):
        return f"/{slug}/{target}"
    if not target.startswith("/"):
        target = "/" + target
    return f"/{slug}{target}"
'''
if needle in s and '_workspace_link' not in s:
    s=s.replace(needle,insert)
# Update auth/me dashboard URL slug only
s=s.replace('result["workspace_dashboard_url"] = f"/{slug}/{u[\'workspace_id\']}/dashboard"','result["workspace_dashboard_url"] = f"/{slug}/dashboard"')
s=s.replace('"dashboard_url":  f"{base}/{slug}/{ws[\'id\']}/dashboard",','"dashboard_url":  f"{base}/{slug}/dashboard",')
s=s.replace('"sso_login_url":  f"{base}/{slug}/{ws[\'id\']}/sso/login",','"sso_login_url":  f"{base}/{slug}/{ws[\'id\']}/sso/login",')
# Email link replacements specific
repls={
'f"/?action=task&id={_email_escape(task_id)}"':'_workspace_link(workspace_id, f"?action=task&id={_email_escape(task_id)}")',
'"/?action=dashboard"':'_workspace_link(workspace_id, "?action=dashboard")',
'f"/?action=ticket&id={_email_escape(ticket_id)}"':'_workspace_link(workspace_id, f"?action=ticket&id={_email_escape(ticket_id)}")',
}
for a,b in repls.items():
    s=s.replace(a,b)
# Add slug-only routes before ws_id routes
needle2='''# ── Workspace-scoped app pages  /<ws_name>/<ws_id>/<page>  ──────────────────\n\n'''
block='''# ── Workspace-scoped app pages  /<workspace_slug>/<page>  ──────────────────

@app.route("/<ws_name>/", methods=["GET", "HEAD"])
@app.route("/<ws_name>/dashboard", methods=["GET", "HEAD"])
@app.route("/<ws_name>/projects", methods=["GET", "HEAD"])
@app.route("/<ws_name>/projects/<proj_id>", methods=["GET", "HEAD"])
@app.route("/<ws_name>/tasks", methods=["GET", "HEAD"])
@app.route("/<ws_name>/kanban", methods=["GET", "HEAD"])
@app.route("/<ws_name>/messages", methods=["GET", "HEAD"])
@app.route("/<ws_name>/channels", methods=["GET", "HEAD"])
@app.route("/<ws_name>/dm", methods=["GET", "HEAD"])
@app.route("/<ws_name>/tickets", methods=["GET", "HEAD"])
@app.route("/<ws_name>/timeline", methods=["GET", "HEAD"])
@app.route("/<ws_name>/reminders", methods=["GET", "HEAD"])
@app.route("/<ws_name>/team", methods=["GET", "HEAD"])
@app.route("/<ws_name>/productivity", methods=["GET", "HEAD"])
@app.route("/<ws_name>/ai-docs", methods=["GET", "HEAD"])
@app.route("/<ws_name>/timesheet", methods=["GET", "HEAD"])
@app.route("/<ws_name>/vault", methods=["GET", "HEAD"])
@app.route("/<ws_name>/password-generator", methods=["GET", "HEAD"])
@app.route("/<ws_name>/settings", methods=["GET", "HEAD"])
@app.route("/<ws_name>/app", methods=["GET", "HEAD"])
def ws_slug_app_page(ws_name, **kwargs):
    """Serve the SPA under a workspace slug, without exposing workspace id in URLs."""
    if request.method == "HEAD":
        return Response(status=200, headers={"Cache-Control": "no-store"})
    slug = (ws_name or "").strip().lower()
    if not slug or slug in _RESERVED_WORKSPACE_SLUGS or "." in slug:
        return _serve_html() if request.args.get("action") else ("", 404)
    # If logged in, ensure the URL slug belongs to the logged-in workspace.
    if "user_id" in session and session.get("workspace_id"):
        expected = _workspace_slug_for_id(session.get("workspace_id"))
        if expected and slug != expected:
            # Preserve deep-link query while correcting the workspace path.
            qs = ("?" + request.query_string.decode("utf-8")) if request.query_string else ""
            tail = request.path.split("/", 2)[2] if request.path.count("/") >= 2 else "dashboard"
            if not tail:
                tail = "dashboard"
            return redirect(f"/{expected}/{tail}{qs}")
    return _serve_html()

'''
if needle2 in s and 'def ws_slug_app_page' not in s:
    s=s.replace(needle2,block+needle2)
# Root legacy: for action and logged in redirect to workspace slug
old='''    if action in app_actions:\n        return _serve_html()\n    return _serve_landing()\n'''
new='''    if action in app_actions:\n        if "user_id" in session and session.get("workspace_id"):\n            qs = ("?" + request.query_string.decode("utf-8")) if request.query_string else ""\n            return redirect(f"/{_workspace_slug_for_id(session.get('workspace_id'))}/{qs}")\n        return _serve_html()\n    return _serve_landing()\n'''
if old in s:
    s=s.replace(old,new)
p.write_text(s)
