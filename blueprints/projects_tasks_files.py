"""
blueprints/projects_tasks_files.py
Projects, Tasks, Subtasks, Files, and related API routes.
These were extracted from the monolithic app.py (Phase 2 modularisation).
All helpers (get_db, wid, login_required, ts, _audit, _sse_publish, etc.)
are imported from the parent app module at registration time.
"""

from flask import Blueprint, request, jsonify, session
import os, json, secrets, mimetypes

bp = Blueprint("projects_tasks_files", __name__)

# ── lazy imports of app-level helpers ────────────────────────────────────────
# We import lazily (inside each function) to avoid circular-import issues at
# module load time.  The parent app registers this blueprint AFTER all helpers
# are defined, so by the time any route is called everything is available.

def _app():
    import app as _a
    return _a


def _get_db():
    return _app().get_db()


def _wid():
    return session.get("workspace_id", "")


def _ts():
    return _app().ts()


def _audit(action, target="", detail=""):
    try:
        _app()._audit(action, target, detail)
    except Exception:
        pass


def _sse(workspace_id, event_type, data):
    try:
        _app()._sse_publish(workspace_id, event_type, data)
    except Exception:
        pass


def _cache_bust(workspace_id, *tables):
    try:
        _app()._cache_bust(workspace_id, *tables)
    except Exception:
        pass


def _login_required(f):
    from functools import wraps
    @wraps(f)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            return jsonify({"error": "Unauthorized"}), 401
        return f(*args, **kwargs)
    return wrapper


# ═══════════════════════════════════════════════════════════════
# PROJECTS
# ═══════════════════════════════════════════════════════════════

@bp.route("/api/projects", methods=["GET"])
@_login_required
def get_projects():
    ws = _wid()
    team_id = request.args.get("team_id", "").strip()
    bust    = request.args.get("bust", "")
    with _get_db() as db:
        if team_id:
            rows = db.execute(
                "SELECT * FROM projects WHERE workspace_id=? AND team_id=? "
                "AND deleted_at='' ORDER BY created DESC",
                (ws, team_id)
            ).fetchall()
        else:
            rows = db.execute(
                "SELECT * FROM projects WHERE workspace_id=? AND deleted_at='' "
                "ORDER BY created DESC",
                (ws,)
            ).fetchall()
        projects = []
        for r in rows:
            p = dict(r)
            try:
                p["members"] = json.loads(p.get("members") or "[]")
            except Exception:
                p["members"] = []
            projects.append(p)
        return jsonify(projects)


@bp.route("/api/projects/all", methods=["GET"])
@_login_required
def get_projects_all():
    """Return ALL projects for this workspace (no team filter) — used by search/select dropdowns."""
    ws = _wid()
    with _get_db() as db:
        rows = db.execute(
            "SELECT id, name, color, team_id FROM projects "
            "WHERE workspace_id=? AND deleted_at='' ORDER BY name",
            (ws,)
        ).fetchall()
        return jsonify([dict(r) for r in rows])


@bp.route("/api/projects/last-messages", methods=["GET"])
@_login_required
def get_projects_last_messages():
    """Return the most-recent message timestamp per project — used by the channels sidebar."""
    ws = _wid()
    with _get_db() as db:
        rows = db.execute(
            "SELECT project, MAX(ts) as last_ts, COUNT(*) as count "
            "FROM messages WHERE workspace_id=? GROUP BY project",
            (ws,)
        ).fetchall()
        return jsonify([dict(r) for r in rows])


@bp.route("/api/projects", methods=["POST"])
@_login_required
def create_project():
    ws  = _wid()
    uid = session.get("user_id", "")
    d   = request.get_json(force=True) or {}
    name = (d.get("name") or "").strip()
    if not name:
        return jsonify({"error": "Project name is required"}), 400
    pid = "p" + secrets.token_hex(8)
    members = json.dumps(d.get("members") or [uid])
    with _get_db() as db:
        db.execute(
            "INSERT INTO projects (id,workspace_id,name,description,owner,members,"
            "start_date,target_date,progress,color,created,team_id,deleted_at) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,'')",
            (pid, ws, name,
             d.get("description", ""),
             uid, members,
             d.get("start_date", ""),
             d.get("target_date", ""),
             0,
             d.get("color", "#2563eb"),
             _ts(),
             d.get("team_id", ""))
        )
        db.commit()
    _cache_bust(ws, "projects")
    _sse(ws, "project_updated", {"id": pid})
    _audit("project_created", uid, f"Created project '{name}'")
    return jsonify({"id": pid, "name": name}), 201


@bp.route("/api/projects/<pid>", methods=["GET"])
@_login_required
def get_project(pid):
    ws = _wid()
    with _get_db() as db:
        row = db.execute(
            "SELECT * FROM projects WHERE id=? AND workspace_id=? AND deleted_at=''",
            (pid, ws)
        ).fetchone()
    if not row:
        return jsonify({"error": "Not found"}), 404
    p = dict(row)
    try:
        p["members"] = json.loads(p.get("members") or "[]")
    except Exception:
        p["members"] = []
    return jsonify(p)


@bp.route("/api/projects/<pid>", methods=["PUT"])
@_login_required
def update_project(pid):
    ws  = _wid()
    uid = session.get("user_id", "")
    d   = request.get_json(force=True) or {}
    with _get_db() as db:
        row = db.execute(
            "SELECT * FROM projects WHERE id=? AND workspace_id=? AND deleted_at=''",
            (pid, ws)
        ).fetchone()
        if not row:
            return jsonify({"error": "Not found"}), 404
        fields = []
        params = []
        for col in ("name", "description", "start_date", "target_date",
                    "color", "team_id", "progress"):
            if col in d:
                fields.append(f"{col}=?")
                params.append(d[col])
        if "members" in d:
            fields.append("members=?")
            params.append(json.dumps(d["members"]))
        if not fields:
            return jsonify({"error": "Nothing to update"}), 400
        params += [pid, ws]
        db.execute(
            f"UPDATE projects SET {','.join(fields)} WHERE id=? AND workspace_id=?",
            params
        )
        db.commit()
    _cache_bust(ws, "projects")
    _sse(ws, "project_updated", {"id": pid})
    _audit("project_updated", uid, f"Updated project {pid}")
    return jsonify({"ok": True})


@bp.route("/api/projects/<pid>", methods=["DELETE"])
@_login_required
def delete_project(pid):
    ws  = _wid()
    uid = session.get("user_id", "")
    with _get_db() as db:
        db.execute(
            "UPDATE projects SET deleted_at=? WHERE id=? AND workspace_id=?",
            (_ts(), pid, ws)
        )
        db.commit()
    _cache_bust(ws, "projects")
    _sse(ws, "project_updated", {"id": pid, "deleted": True})
    _audit("project_deleted", uid, f"Deleted project {pid}")
    return jsonify({"ok": True})


@bp.route("/api/projects/<pid>/members", methods=["POST"])
@_login_required
def update_project_members(pid):
    ws  = _wid()
    d   = request.get_json(force=True) or {}
    members = d.get("members", [])
    with _get_db() as db:
        db.execute(
            "UPDATE projects SET members=? WHERE id=? AND workspace_id=?",
            (json.dumps(members), pid, ws)
        )
        db.commit()
    _cache_bust(ws, "projects")
    _sse(ws, "project_updated", {"id": pid})
    return jsonify({"ok": True})


# ═══════════════════════════════════════════════════════════════
# TASKS
# ═══════════════════════════════════════════════════════════════

@bp.route("/api/tasks", methods=["GET"])
@_login_required
def get_tasks():
    ws      = _wid()
    project = request.args.get("project", "")
    team_id = request.args.get("team_id", "")
    stage   = request.args.get("stage", "")
    with _get_db() as db:
        base = ("SELECT * FROM tasks WHERE workspace_id=? AND deleted_at='' "
                "AND parent_id=''")
        params = [ws]
        if project:
            base += " AND project=?"
            params.append(project)
        if team_id:
            base += " AND team_id=?"
            params.append(team_id)
        if stage:
            base += " AND stage=?"
            params.append(stage)
        base += " ORDER BY created DESC LIMIT 2000"
        rows = db.execute(base, params).fetchall()
        tasks = []
        for r in rows:
            t = dict(r)
            try:
                t["comments"] = json.loads(t.get("comments") or "[]")
            except Exception:
                t["comments"] = []
            try:
                t["labels"] = json.loads(t.get("labels") or "[]")
            except Exception:
                t["labels"] = []
            tasks.append(t)
        return jsonify(tasks)


@bp.route("/api/tasks/<tid>", methods=["GET"])
@_login_required
def get_task(tid):
    ws = _wid()
    with _get_db() as db:
        row = db.execute(
            "SELECT * FROM tasks WHERE id=? AND workspace_id=? AND deleted_at=''",
            (tid, ws)
        ).fetchone()
        if not row:
            return jsonify({"error": "Not found"}), 404
        t = dict(row)
        # Attach subtasks
        subs = db.execute(
            "SELECT * FROM subtasks WHERE task_id=? AND workspace_id=? ORDER BY created",
            (tid, ws)
        ).fetchall()
        t["subtasks"] = [dict(s) for s in subs]
        # Attach files
        files = db.execute(
            "SELECT id,name,size,mime,uploaded_by,ts FROM files "
            "WHERE task_id=? AND workspace_id=? ORDER BY ts DESC",
            (tid, ws)
        ).fetchall()
        t["files"] = [dict(f) for f in files]
        try:
            t["comments"] = json.loads(t.get("comments") or "[]")
        except Exception:
            t["comments"] = []
        try:
            t["labels"] = json.loads(t.get("labels") or "[]")
        except Exception:
            t["labels"] = []
    return jsonify(t)


@bp.route("/api/tasks", methods=["POST"])
@_login_required
def create_task():
    ws  = _wid()
    uid = session.get("user_id", "")
    d   = request.get_json(force=True) or {}
    title = (d.get("title") or "").strip()
    if not title:
        return jsonify({"error": "Task title is required"}), 400
    tid = "t" + secrets.token_hex(8)
    with _get_db() as db:
        db.execute(
            "INSERT INTO tasks (id,workspace_id,title,description,project,assignee,"
            "priority,stage,created,due,pct,comments,team_id,parent_id,"
            "story_points,sprint,task_type,labels,deleted_at) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,'')",
            (tid, ws, title,
             d.get("description", ""),
             d.get("project", ""),
             d.get("assignee", ""),
             d.get("priority", "medium"),
             d.get("stage", "backlog"),
             _ts(),
             d.get("due", ""),
             0,
             json.dumps([]),
             d.get("team_id", ""),
             d.get("parent_id", ""),
             int(d.get("story_points", 0)),
             d.get("sprint", ""),
             d.get("task_type", "task"),
             json.dumps(d.get("labels", [])))
        )
        db.commit()
    _cache_bust(ws, "tasks")
    _sse(ws, "task_updated", {"id": tid})
    _audit("task_created", uid, f"Created task '{title}'")
    return jsonify({"id": tid, "title": title}), 201


@bp.route("/api/tasks/<tid>", methods=["PUT"])
@_login_required
def update_task(tid):
    ws  = _wid()
    uid = session.get("user_id", "")
    d   = request.get_json(force=True) or {}
    with _get_db() as db:
        row = db.execute(
            "SELECT * FROM tasks WHERE id=? AND workspace_id=? AND deleted_at=''",
            (tid, ws)
        ).fetchone()
        if not row:
            return jsonify({"error": "Not found"}), 404
        fields, params = [], []
        scalar_cols = ("title","description","project","assignee","priority",
                       "stage","due","pct","team_id","parent_id",
                       "story_points","sprint","task_type")
        for col in scalar_cols:
            if col in d:
                fields.append(f"{col}=?")
                params.append(d[col])
        if "labels" in d:
            fields.append("labels=?")
            params.append(json.dumps(d["labels"]))
        if "comments" in d:
            fields.append("comments=?")
            params.append(json.dumps(d["comments"]))
        if not fields:
            return jsonify({"error": "Nothing to update"}), 400
        params += [tid, ws]
        db.execute(
            f"UPDATE tasks SET {','.join(fields)} WHERE id=? AND workspace_id=?",
            params
        )
        db.commit()
    _cache_bust(ws, "tasks")
    _sse(ws, "task_updated", {"id": tid})
    _audit("task_updated", uid, f"Updated task {tid}")
    return jsonify({"ok": True})


@bp.route("/api/tasks/<tid>", methods=["DELETE"])
@_login_required
def delete_task(tid):
    ws  = _wid()
    uid = session.get("user_id", "")
    with _get_db() as db:
        db.execute(
            "UPDATE tasks SET deleted_at=? WHERE id=? AND workspace_id=?",
            (_ts(), tid, ws)
        )
        db.commit()
    _cache_bust(ws, "tasks")
    _sse(ws, "task_updated", {"id": tid, "deleted": True})
    _audit("task_deleted", uid, f"Deleted task {tid}")
    return jsonify({"ok": True})


@bp.route("/api/tasks/<tid>/comment", methods=["POST"])
@_login_required
def add_task_comment(tid):
    ws  = _wid()
    uid = session.get("user_id", "")
    d   = request.get_json(force=True) or {}
    text = (d.get("text") or d.get("content") or "").strip()
    if not text:
        return jsonify({"error": "Comment text required"}), 400
    with _get_db() as db:
        row = db.execute(
            "SELECT comments FROM tasks WHERE id=? AND workspace_id=? AND deleted_at=''",
            (tid, ws)
        ).fetchone()
        if not row:
            return jsonify({"error": "Task not found"}), 404
        try:
            comments = json.loads(row["comments"] or "[]")
        except Exception:
            comments = []
        u_row = db.execute("SELECT name, avatar, color FROM users WHERE id=?", (uid,)).fetchone()
        new_comment = {
            "id": secrets.token_hex(6),
            "user": uid,
            "userName": u_row["name"] if u_row else "Unknown",
            "avatar":   u_row["avatar"] if u_row else "",
            "color":    u_row["color"]  if u_row else "#2563eb",
            "text": text,
            "ts":   _ts(),
        }
        comments.append(new_comment)
        db.execute(
            "UPDATE tasks SET comments=? WHERE id=? AND workspace_id=?",
            (json.dumps(comments), tid, ws)
        )
        db.commit()
    _cache_bust(ws, "tasks")
    _sse(ws, "task_updated", {"id": tid})
    return jsonify({"ok": True, "comment": new_comment}), 201


# ═══════════════════════════════════════════════════════════════
# SUBTASKS
# ═══════════════════════════════════════════════════════════════

@bp.route("/api/subtasks/<tid>", methods=["GET"])
@_login_required
def get_subtasks(tid):
    ws = _wid()
    with _get_db() as db:
        rows = db.execute(
            "SELECT * FROM subtasks WHERE task_id=? AND workspace_id=? ORDER BY created",
            (tid, ws)
        ).fetchall()
    return jsonify([dict(r) for r in rows])


@bp.route("/api/subtasks/<tid>", methods=["POST"])
@_login_required
def create_subtask(tid):
    ws  = _wid()
    uid = session.get("user_id", "")
    d   = request.get_json(force=True) or {}
    title = (d.get("title") or "").strip()
    if not title:
        return jsonify({"error": "Title required"}), 400
    sid = "s" + secrets.token_hex(8)
    with _get_db() as db:
        db.execute(
            "INSERT INTO subtasks (id,workspace_id,task_id,title,done,assignee,created) "
            "VALUES (?,?,?,?,?,?,?)",
            (sid, ws, tid, title, 0, d.get("assignee", ""), _ts())
        )
        db.commit()
    _cache_bust(ws, "tasks")
    _sse(ws, "task_updated", {"id": tid})
    return jsonify({"id": sid, "title": title}), 201


@bp.route("/api/subtasks/<tid>/<sid>", methods=["PUT"])
@_login_required
def update_subtask(tid, sid):
    ws = _wid()
    d  = request.get_json(force=True) or {}
    with _get_db() as db:
        fields, params = [], []
        for col in ("title", "done", "assignee"):
            if col in d:
                fields.append(f"{col}=?")
                params.append(int(d[col]) if col == "done" else d[col])
        if not fields:
            return jsonify({"error": "Nothing to update"}), 400
        params += [sid, tid, ws]
        db.execute(
            f"UPDATE subtasks SET {','.join(fields)} "
            "WHERE id=? AND task_id=? AND workspace_id=?",
            params
        )
        db.commit()
    _cache_bust(ws, "tasks")
    _sse(ws, "task_updated", {"id": tid})
    return jsonify({"ok": True})


@bp.route("/api/subtasks/<tid>/<sid>", methods=["DELETE"])
@_login_required
def delete_subtask(tid, sid):
    ws = _wid()
    with _get_db() as db:
        db.execute(
            "DELETE FROM subtasks WHERE id=? AND task_id=? AND workspace_id=?",
            (sid, tid, ws)
        )
        db.commit()
    _cache_bust(ws, "tasks")
    _sse(ws, "task_updated", {"id": tid})
    return jsonify({"ok": True})


@bp.route("/api/subtasks/search", methods=["GET"])
@_login_required
def search_subtasks():
    """Full-text search across subtasks — used by the global Ctrl+K search."""
    ws = _wid()
    q  = (request.args.get("q") or "").strip()
    if len(q) < 2:
        return jsonify([])
    like = f"%{q.lower()}%"
    with _get_db() as db:
        rows = db.execute(
            "SELECT s.id, s.title, s.task_id, s.done, t.title as task_title "
            "FROM subtasks s LEFT JOIN tasks t ON t.id=s.task_id "
            "WHERE s.workspace_id=? AND LOWER(s.title) LIKE ? LIMIT 20",
            (ws, like)
        ).fetchall()
    return jsonify([dict(r) for r in rows])


# ═══════════════════════════════════════════════════════════════
# FILES (task & project attachments)
# ═══════════════════════════════════════════════════════════════

@bp.route("/api/files/<task_id>", methods=["GET"])
@_login_required
def get_files(task_id):
    ws = _wid()
    with _get_db() as db:
        rows = db.execute(
            "SELECT id,name,size,mime,uploaded_by,ts FROM files "
            "WHERE task_id=? AND workspace_id=? ORDER BY ts DESC",
            (task_id, ws)
        ).fetchall()
    return jsonify([dict(r) for r in rows])


@bp.route("/api/files/<task_id>", methods=["POST"])
@_login_required
def upload_file(task_id):
    ws  = _wid()
    uid = session.get("user_id", "")
    try:
        a = _app()
        MAX_BYTES = a.MAX_UPLOAD_BYTES
        QUOTA     = a.WORKSPACE_UPLOAD_QUOTA_BYTES
        UPLOAD_DIR = a.UPLOAD_DIR
        _looks_like = a._looks_like_upload_mime
        _ws_bytes   = a._workspace_upload_bytes
    except Exception as e:
        return jsonify({"error": f"Upload config error: {e}"}), 500

    f = request.files.get("file")
    if not f:
        return jsonify({"error": "No file provided"}), 400

    data = f.read()
    if len(data) > MAX_BYTES:
        return jsonify({"error": "File too large"}), 413

    ok, mime = _looks_like(f.filename, data, f.content_type or "")
    if not ok:
        return jsonify({"error": mime}), 415

    with _get_db() as db:
        used = _ws_bytes(db, ws)
        if used + len(data) > QUOTA:
            return jsonify({"error": "Workspace storage quota exceeded"}), 413

    fid  = "f" + secrets.token_hex(8)
    dest = os.path.join(UPLOAD_DIR, fid)
    os.makedirs(UPLOAD_DIR, exist_ok=True)
    with open(dest, "wb") as out:
        out.write(data)

    with _get_db() as db:
        db.execute(
            "INSERT INTO files (id,workspace_id,name,size,mime,task_id,project_id,uploaded_by,ts) "
            "VALUES (?,?,?,?,?,?,?,?,?)",
            (fid, ws, f.filename, len(data), mime, task_id, "", uid, _ts())
        )
        db.commit()

    _sse(ws, "task_updated", {"id": task_id})
    return jsonify({"id": fid, "name": f.filename, "size": len(data), "mime": mime}), 201


@bp.route("/api/files/<task_id>/<fid>", methods=["DELETE"])
@_login_required
def delete_file(task_id, fid):
    ws = _wid()
    uid = session.get("user_id", "")
    try:
        UPLOAD_DIR = _app().UPLOAD_DIR
    except Exception:
        UPLOAD_DIR = ""
    with _get_db() as db:
        row = db.execute(
            "SELECT * FROM files WHERE id=? AND task_id=? AND workspace_id=?",
            (fid, task_id, ws)
        ).fetchone()
        if not row:
            return jsonify({"error": "Not found"}), 404
        db.execute("DELETE FROM files WHERE id=?", (fid,))
        db.commit()
    # Remove file from disk (best-effort)
    try:
        dest = os.path.join(UPLOAD_DIR, fid)
        if os.path.isfile(dest):
            os.remove(dest)
    except Exception:
        pass
    _sse(ws, "task_updated", {"id": task_id})
    _audit("file_deleted", uid, f"Deleted file {fid} from task {task_id}")
    return jsonify({"ok": True})


@bp.route("/api/files/download/<fid>", methods=["GET"])
@_login_required
def download_file(fid):
    from flask import send_file as _send_file, abort
    ws = _wid()
    try:
        UPLOAD_DIR = _app().UPLOAD_DIR
    except Exception:
        abort(500)
    with _get_db() as db:
        row = db.execute(
            "SELECT * FROM files WHERE id=? AND workspace_id=?",
            (fid, ws)
        ).fetchone()
    if not row:
        abort(404)
    path = os.path.join(UPLOAD_DIR, fid)
    if not os.path.isfile(path):
        abort(404)
    return _send_file(
        path,
        mimetype=row["mime"] or "application/octet-stream",
        as_attachment=True,
        download_name=row["name"]
    )


# ═══════════════════════════════════════════════════════════════
# PROJECT HEALTH / RISK
# ═══════════════════════════════════════════════════════════════

@bp.route("/api/projects/<pid>/health", methods=["GET"])
@_login_required
def project_health(pid):
    ws = _wid()
    with _get_db() as db:
        proj = db.execute(
            "SELECT * FROM projects WHERE id=? AND workspace_id=? AND deleted_at=''",
            (pid, ws)
        ).fetchone()
        if not proj:
            return jsonify({"error": "Not found"}), 404
        tasks = db.execute(
            "SELECT stage, priority, due FROM tasks "
            "WHERE project=? AND workspace_id=? AND deleted_at=''",
            (pid, ws)
        ).fetchall()

    total    = len(tasks)
    done     = sum(1 for t in tasks if t["stage"] == "completed")
    blocked  = sum(1 for t in tasks if t["stage"] == "blocked")
    overdue  = 0
    from datetime import datetime
    now = datetime.utcnow().isoformat()
    for t in tasks:
        if t["due"] and t["due"] < now and t["stage"] not in ("completed", "blocked"):
            overdue += 1

    pct = int(done / total * 100) if total else 0
    if blocked > 2 or overdue > 3:
        health = "at_risk"
    elif pct >= 80:
        health = "on_track"
    else:
        health = "needs_attention"

    return jsonify({
        "health":  health,
        "total":   total,
        "done":    done,
        "blocked": blocked,
        "overdue": overdue,
        "pct":     pct,
    })
