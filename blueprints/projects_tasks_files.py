"""Projects, tasks, subtasks, and files API blueprint.

This module is intentionally compatible with the legacy monolith during the
Phase 2 split. It syncs runtime globals from the loaded app module so existing
DB helpers, auth/session helpers, event publishers, and utility functions keep
working while these routes live outside app.py.
"""
from __future__ import annotations

import sys
from functools import wraps

from flask import Blueprint, request, jsonify, session, send_file

bp = Blueprint("projects_tasks_files", __name__)


def _core_module():
    """Return the running app module whether launched as gunicorn app:app or python app.py."""
    mod = sys.modules.get("app") or sys.modules.get("__main__")
    if mod is None:
        raise RuntimeError("Project Tracker core app module is not loaded")
    return mod


def _sync_core_globals():
    """Expose legacy helpers to extracted route functions without circular imports."""
    core = _core_module()
    globals().update({k: v for k, v in core.__dict__.items() if not k.startswith("__")})
    globals()["bp"] = bp


@bp.before_request
def _before_projects_tasks_files_request():
    _sync_core_globals()


def _deferred_decorator(name, *dargs, **dkwargs):
    def decorate(fn):
        @wraps(fn)
        def wrapped(*args, **kwargs):
            _sync_core_globals()
            real = getattr(_core_module(), name)
            if dargs or dkwargs:
                return real(*dargs, **dkwargs)(fn)(*args, **kwargs)
            return real(fn)(*args, **kwargs)
        return wrapped
    return decorate


login_required = _deferred_decorator("login_required")


def require_role(*roles):
    return _deferred_decorator("require_role", *roles)


# ── Projects ──────────────────────────────────────────────────────────────────
@bp.route("/api/projects/all")
@login_required
def get_all_projects():
    """Return ALL workspace projects — used by Channels so everyone can see all project status."""
    with get_db() as db:
        rows=db.execute("SELECT * FROM projects WHERE workspace_id=? ORDER BY created DESC",(wid(),)).fetchall()
        return jsonify([dict(r) for r in rows])

@bp.route("/api/projects/last-messages")
@login_required
def get_projects_last_messages():
    """Return the latest message timestamp per project — used to sort channels by activity."""
    with get_db() as db:
        rows=db.execute(
            "SELECT project, MAX(ts) as last_ts FROM messages WHERE workspace_id=? GROUP BY project",
            (wid(),)).fetchall()
        return jsonify({r["project"]: r["last_ts"] for r in rows})

def _fetch_app_data_from_db(ws, team_id, uid):
    """Execute all app-data queries in ONE round-trip using a single connection.
    pg8000 is synchronous so we batch all SELECTs through the same connection
    object — each .run() call reuses the same TCP socket, costing only the
    server-side execution time instead of a full network round-trip per query.
    With Postgres on Railway US-West and users in India (~180ms RTT),
    going from 9 separate queries to 9 queries on ONE connection saves
    ~8 × 180ms = ~1.44s per request."""
    now_str = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S")

    # Get a single pooled connection and run ALL queries on it
    conn = _get_pool_conn()
    try:
        def _q(sql, params=()):
            pg_sql, pdict = _sql_compat(sql, params)
            rows = conn.run(pg_sql, **pdict) if pdict else conn.run(pg_sql)
            cols = [c["name"] for c in (conn.columns or [])]
            return [dict(zip(cols, r)) for r in (rows or [])]

        # Exclude avatar_data from bulk fetch — it's 20-100KB per user as base64.
        # Avatars are served separately via /api/users/<uid>/avatar with 24h browser cache.
        users    = _q("SELECT id,name,email,role,avatar,color,workspace_id,last_active,two_fa_enabled,totp_verified FROM users WHERE workspace_id=? ORDER BY name", (ws,))

        if team_id:
            projects = _q("SELECT * FROM projects WHERE workspace_id=? AND team_id=? ORDER BY created DESC LIMIT 300", (ws, team_id))
            # Exclude comments from bulk fetch — comments are a JSON blob stored inline
            # and can be large. They are fetched on-demand when a task is opened.
            tasks    = _q("""SELECT id,workspace_id,title,description,project,assignee,priority,stage,
                                    created,due,pct,team_id,story_points,task_type,labels,sprint,deleted_at
                             FROM tasks WHERE workspace_id=? AND team_id=? AND deleted_at=''
                             ORDER BY created DESC LIMIT 500""", (ws, team_id))
        else:
            projects = _q("SELECT * FROM projects WHERE workspace_id=? ORDER BY created DESC LIMIT 300", (ws,))
            tasks    = _q("""SELECT id,workspace_id,title,description,project,assignee,priority,stage,
                                    created,due,pct,team_id,story_points,task_type,labels,sprint,deleted_at
                             FROM tasks WHERE workspace_id=? AND deleted_at=''
                             ORDER BY created DESC LIMIT 500""", (ws,))

        notifs   = _q("SELECT * FROM notifications WHERE workspace_id=? AND user_id=? ORDER BY ts DESC LIMIT 50", (ws, uid))
        dm_unread= _q("SELECT sender,COUNT(*) as cnt FROM direct_messages WHERE workspace_id=? AND recipient=? AND read=0 GROUP BY sender", (ws, uid))
        ws_rows  = _q("SELECT * FROM workspaces WHERE id=?", (ws,))
        teams    = _q("SELECT * FROM teams WHERE workspace_id=?", (ws,))
        tickets  = _q("SELECT * FROM tickets WHERE workspace_id=? ORDER BY created DESC LIMIT 200", (ws,))
        reminders= _q("SELECT * FROM reminders WHERE workspace_id=? AND user_id=? AND remind_at>=? ORDER BY remind_at", (ws, uid, now_str))

        return {
            "users": users, "projects": projects, "tasks": tasks,
            "notifications": notifs, "dm_unread": dm_unread,
            "workspace": ws_rows[0] if ws_rows else {},
            "teams": teams, "tickets": tickets, "reminders": reminders,
        }
    finally:
        _return_pool_conn(conn)


def _etag_response(result):
    """Return a jsonify response with ETag header; emit 304 if client has fresh copy."""
    etag = hashlib.md5(json.dumps(result, sort_keys=True, default=str).encode()).hexdigest()
    if request.headers.get("If-None-Match") == etag:
        return "", 304
    resp = jsonify(result)
    resp.headers["ETag"] = etag
    return resp


@bp.route("/api/app-data")
@login_required
def get_app_data():
    """Single endpoint that returns all dashboard data.

    Caching strategy:
    - bust=1 query param: skip all caches, hit DB directly (used post-mutation)
    - Serve from in-memory cache instantly (0ms) when entry is fresh (<20s)
    - Serve stale data instantly AND refresh in background when 20-120s old
    - Only block on DB when cache is completely cold (first load after restart)
    This means after the first load, every subsequent poll returns in <5ms.
    Multi-worker note: bust=1 forces a fresh DB read on the receiving worker
    and re-warms that worker's cache, solving cross-worker stale data issues.
    """
    ws      = wid()
    uid     = session["user_id"]
    team_id = request.args.get("team_id", "")
    cache_key = f"appdata:{ws}:{uid}:{team_id}"
    # Force-refresh: skip all caches (used right after mutations)
    if request.args.get("bust") == "1":
        result = _fetch_app_data_from_db(ws, team_id, uid)
        _cache_set(cache_key, result)
        etag = hashlib.md5(json.dumps(result, sort_keys=True, default=str).encode()).hexdigest()
        resp = jsonify(result)
        resp.headers["ETag"] = etag
        return resp

    now = _time.time()

    # --- Redis SWR path ---
    if _redis_client is not None:
        try:
            raw = _redis_client.get(f"ptcache:{cache_key}")
            if raw:
                entry = _json.loads(raw)
                age = now - entry["ts"]
                if age < _CACHE_TTL:
                    return _etag_response(entry["val"])   # fresh
                if age < _CACHE_STALE:
                    # Try to become the one refresher using SET NX (atomic)
                    lock_key = f"ptcache:lock:{cache_key}"
                    acquired = _redis_client.set(lock_key, "1", nx=True, ex=30)
                    if acquired:
                        def _bg_refresh_redis():
                            try:
                                result = _fetch_app_data_from_db(ws, team_id, uid)
                                _cache_set(cache_key, result)
                            except Exception as _e:
                                log.warning("[app-data bg-refresh] %s", _e)
                            finally:
                                try: _redis_client.delete(lock_key)
                                except: pass
                        _cthread.Thread(target=_bg_refresh_redis, daemon=True).start()
                    return _etag_response(entry["val"])   # stale but fast
        except Exception:
            pass  # Redis blip — fall through to dict

    # --- In-process dict SWR path ---
    entry = _CACHE.get(cache_key)

    if entry:
        age = now - entry["ts"]
        if age < _CACHE_TTL:
            return _etag_response(entry["val"])
        if age < _CACHE_STALE and not entry.get("refreshing"):
            with _CACHE_LOCK:
                if cache_key in _CACHE:
                    _CACHE[cache_key]["refreshing"] = True
            def _bg_refresh():
                try:
                    result = _fetch_app_data_from_db(ws, team_id, uid)
                    _cache_set(cache_key, result)
                except Exception as _e:
                    log.warning("[app-data bg-refresh] %s", _e)
                    with _CACHE_LOCK:
                        if cache_key in _CACHE:
                            _CACHE[cache_key]["refreshing"] = False
            _cthread.Thread(target=_bg_refresh, daemon=True).start()
            return _etag_response(entry["val"])   # stale but fast

    # Cache cold or too stale — block on DB (first load only)
    result = _fetch_app_data_from_db(ws, team_id, uid)
    _cache_set(cache_key, result)
    etag = hashlib.md5(json.dumps(result, sort_keys=True, default=str).encode()).hexdigest()
    if request.headers.get("If-None-Match") == etag:
        return "", 304
    resp = jsonify(result)
    resp.headers["ETag"] = etag
    return resp



def _appdata_cache_get(ws, uid, key):
    """Try to read a specific key from the appdata cache (any team_id variant).
    Returns (data, found). Used by lightweight polling endpoints to avoid
    duplicate DB queries — if app-data is cached, sub-endpoints are free."""
    # Try no-team variant first (most common), then any team variant
    for suffix in ["", ":"] :
        for ckey, entry in list(_CACHE.items()):
            if ckey.startswith(f"appdata:{ws}:{uid}") and not entry.get("refreshing", False):
                age = _time.time() - entry["ts"]
                if age < _CACHE_STALE:
                    val = entry["val"]
                    if key in val:
                        return val[key], True
    return None, False

@bp.route("/api/projects")
@login_required
def get_projects():
    ws, uid = wid(), session["user_id"]
    team_id = request.args.get("team_id", "")
    bust    = request.args.get("bust", "0") == "1"   # bust=1 skips ALL caches (called after delete)

    if not bust:
        data, found = _appdata_cache_get(ws, uid, "projects")
        if found:
            if team_id:
                return jsonify([p for p in data if p.get("team_id") == team_id])
            return jsonify(data)
        cache_key = f"projects:{ws}:{team_id}"
        cached = _cache_get(cache_key)
        if cached is not None:
            return jsonify(cached)

    # bust=1 OR cache cold — always hit DB
    with get_db() as db:
        if team_id:
            rows = db.execute(
                "SELECT * FROM projects WHERE workspace_id=? AND team_id=? ORDER BY created DESC",
                (ws, team_id)).fetchall()
        else:
            rows = db.execute(
                "SELECT * FROM projects WHERE workspace_id=? ORDER BY created DESC", (ws,)).fetchall()
        result = [dict(r) for r in rows]
        if not bust:
            cache_key = f"projects:{ws}:{team_id}"
            _cache_set(cache_key, result)
        return jsonify(result)

@bp.route("/api/projects",methods=["POST"])
@login_required
@require_role("Admin", "Manager", "TeamLead")
def create_project():
    d=request.json or {}
    if not d.get("name"): return jsonify({"error":"Name required"}),400
    pid=f"p{int(datetime.now().timestamp()*1000)}"
    members=d.get("members",[session["user_id"]])
    if session["user_id"] not in members: members.insert(0,session["user_id"])
    with get_db() as db:
        db.execute("INSERT INTO projects VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                   (pid,wid(),d["name"],d.get("description",""),session["user_id"],
                    json.dumps(members),d.get("startDate",""),d.get("targetDate",""),0,
                    d.get("color","#5a8cff"),ts(),d.get("team_id","")))
        p=db.execute("SELECT * FROM projects WHERE id=? AND workspace_id=?",(pid,wid())).fetchone()
        creator=db.execute("SELECT name FROM users WHERE id=?",(session["user_id"],)).fetchone()
        cname=creator["name"] if creator else "Someone"
        for uid in members:
            if uid != session["user_id"]:
                nid=f"n{int(datetime.now().timestamp()*1000)}"
                db.execute("INSERT INTO notifications VALUES (?,?,?,?,?,?,?)",
                           (nid,wid(),"project_added",f"You were added to project '{d['name']}'",uid,0,ts()))
                threading.Thread(target=push_notification_to_user,
                    args=(db,uid,f"📁 Added to project: {d['name']}",
                          f"{cname} added you to '{d['name']}'","/"),daemon=True).start()
        # Inject into appdata cache FIRST so workers with stale cache get the new project immediately.
        _cache_inject_item(wid(), "projects", dict(p))
        # Bust the FULL workspace cache — this forces the next /api/app-data background
        # refresh to re-fetch from DB with the new project included.
        # Previously only busting 'notifs' left the appdata cache stale, causing the
        # background SWR refresh to overwrite state and make the new project disappear.
        _cache_bust_ws(wid())
        # Push SSE event so connected clients update immediately without waiting for next poll
        _sse_publish(wid(), "project_updated", {"id": pid, "action": "created"})
        return jsonify(dict(p))

@bp.route("/api/projects/<pid>",methods=["PUT"])
@login_required
def update_project(pid):
    d=request.json or {}
    with get_db() as db:
        p=db.execute("SELECT * FROM projects WHERE id=? AND workspace_id=?",(pid,wid())).fetchone()
        if not p: return jsonify({"error":"Not found"}),404
        p_team = p["team_id"] if "team_id" in p.keys() else ""
        try: old_mems=set(json.loads(p["members"] or "[]"))
        except: old_mems=set()
        new_mems=d.get("members", list(old_mems))
        db.execute("""UPDATE projects SET name=?,description=?,start_date=?,target_date=?,color=?,members=?,team_id=?
                      WHERE id=? AND workspace_id=?""",
                   (d.get("name",p["name"]),d.get("description",p["description"]),
                    d.get("start_date",p["start_date"]),d.get("target_date",p["target_date"]),
                    d.get("color",p["color"]),
                    json.dumps(new_mems),
                    d.get("team_id",p_team),pid,wid()))
        updated=db.execute("SELECT * FROM projects WHERE id=? AND workspace_id=?",(pid,wid())).fetchone()
        actor=db.execute("SELECT name FROM users WHERE id=?",(session["user_id"],)).fetchone()
        aname=actor["name"] if actor else "Someone"
        # Only notify NEWLY ADDED members — not all members on every save (was slow + spammy)
        newly_added=[uid for uid in new_mems if uid not in old_mems and uid!=session["user_id"]]
        base_ts=int(datetime.now().timestamp()*1000)
        if newly_added:
            # Batch all notification inserts in ONE round-trip instead of N separate queries
            placeholders=",".join(["(?,?,?,?,?,?,?)"]*len(newly_added))
            flat=[v for i,uid in enumerate(newly_added)
                  for v in (f"n{base_ts+i}",wid(),"project_added",
                            f"{aname} added you to project '{updated['name']}'",uid,0,ts())]
            db.execute(f"INSERT INTO notifications(id,workspace_id,type,content,user_id,read,ts) VALUES {placeholders}",flat)
            for uid in newly_added:
                threading.Thread(target=push_notification_to_user,
                    args=(db,uid,f"\U0001f4c1 Added to project: {updated['name']}",
                          f"{aname} added you to '{updated['name']}'","/"),daemon=True).start()
    # Bust FULL workspace cache so app-data reflects member changes instantly on next poll.
    # Previously only busted 'projects' standalone cache, leaving app-data cache stale —
    # that's why added members weren't visible until cache expired.
    _cache_bust_ws(wid())
    # Notify connected clients via SSE so they reload without waiting 30s
    _sse_publish(wid(), "project_updated", {"id": pid, "action": "updated"})
    return jsonify(dict(updated))
@bp.route("/api/projects/<pid>",methods=["DELETE"])
@login_required
@require_role("Admin", "Manager")
def del_project(pid):
    workspace_id = wid()
    with get_db() as db:
        cu=db.execute("SELECT role FROM users WHERE id=?",(session["user_id"],)).fetchone()
        cu_role=cu["role"] if cu else "Viewer"
        if cu_role not in ("Admin","Manager"):
            return jsonify({"error":"Only Admin or Manager can delete projects."}),403
        db.execute("DELETE FROM projects WHERE id=? AND workspace_id=?",(pid,workspace_id))
        db.execute("DELETE FROM tasks WHERE project=? AND workspace_id=?",(pid,workspace_id))
        db.execute("DELETE FROM files WHERE project_id=? AND workspace_id=?",(pid,workspace_id))
    # Cache bust AFTER the with-block exits (i.e. after COMMIT).
    # Busting inside caused a race: concurrent GET /api/projects could query Postgres
    # while DELETE was still uncommitted, re-cache the stale row, making deleted
    # projects reappear on next reload().
    _cache_bust_ws(workspace_id)
    return jsonify({"ok":True})

@bp.route("/api/projects/bulk-assign-team",methods=["POST"])
@login_required
def bulk_assign_team():
    """Assign a team_id to multiple projects at once."""
    d=request.json or {}
    team_id=d.get("team_id","")
    project_ids=d.get("project_ids",[])
    if not project_ids: return jsonify({"error":"project_ids required"}),400
    with get_db() as db:
        cu=db.execute("SELECT role FROM users WHERE id=?",(session["user_id"],)).fetchone()
        if not cu or cu["role"] not in ("Admin","Manager"):
            return jsonify({"error":"Only Admin or Manager can assign teams to projects."}),403
        for pid in project_ids:
            db.execute("UPDATE projects SET team_id=? WHERE id=? AND workspace_id=?",(team_id,pid,wid()))
        return jsonify({"ok":True,"updated":len(project_ids)})

# ── Tasks ─────────────────────────────────────────────────────────────────────
@bp.route("/api/tasks")
@login_required
def get_tasks():
    team_id = request.args.get("team_id","")
    ws, uid = wid(), session["user_id"]
    bust = request.args.get("bust") == "1"
    # Check shared appdata cache first — avoids DB entirely during polling.
    # Skip cache entirely when bust=1 (called right after task creation) so the
    # newly created task is always visible and never vanishes on the next reload.
    if not bust:
        data, found = _appdata_cache_get(ws, uid, "tasks")
        if found:
            if team_id:
                return jsonify([t for t in data if t.get("team_id") == team_id])
            return jsonify(data)
        cache_key = f"tasks:{ws}:{team_id}"
        cached = _cache_get(cache_key)
        if cached is not None: return jsonify(cached)
    with get_db() as db:
        if team_id:
            team = db.execute("SELECT member_ids FROM teams WHERE id=? AND workspace_id=?",(team_id,wid())).fetchone()
            member_ids = json.loads(team["member_ids"] if team else "[]")
            team_projects = db.execute(
                "SELECT id FROM projects WHERE workspace_id=? AND team_id=?",(wid(),team_id)).fetchall()
            proj_ids = [p["id"] for p in team_projects]
            # Use SQL WHERE IN instead of Python-side filtering — much faster
            placeholders_p = ",".join("?" * len(proj_ids)) if proj_ids else "''"
            placeholders_m = ",".join("?" * len(member_ids)) if member_ids else "''"
            sql = f"""SELECT * FROM tasks WHERE workspace_id=? AND (
                team_id=? OR
                {f"project IN ({placeholders_p})" if proj_ids else "1=0"} OR
                {f"assignee IN ({placeholders_m})" if member_ids else "1=0"}
            ) ORDER BY created DESC LIMIT 500"""
            params = [wid(), team_id] + proj_ids + member_ids
            result = [dict(r) for r in db.execute(sql, params).fetchall()]
            _cache_set(f"tasks:{wid()}:{team_id}", result)
            return jsonify(result)
        # Limit to 500 most recent — prevents huge payloads on large workspaces
        result = [dict(r) for r in db.execute(
            "SELECT * FROM tasks WHERE workspace_id=? ORDER BY created DESC LIMIT 500",(wid(),)).fetchall()]
        _cache_set(f"tasks:{wid()}:", result)
        return jsonify(result)

def next_task_id(db, ws):
    import time, secrets
    # Avoid COUNT(*) and avoid the old last-6-ms collision bug.
    # Old IDs repeated every ~16.6 minutes; this caused intermittent 500s
    # from duplicate primary keys on task creation.
    return f"T-{int(time.time() * 1000)}{secrets.token_hex(2)}"

@bp.route("/api/tasks",methods=["POST"])
@login_required
def create_task():
    d=request.json or {}
    if not d.get("title"): return jsonify({"error":"Title required"}),400
    with get_db() as db:
        tid=next_task_id(db,wid())
        db.execute("INSERT INTO tasks(id,workspace_id,title,description,project,assignee,priority,stage,created,due,pct,comments,team_id) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                   (tid,wid(),d["title"],d.get("description",""),d.get("project",""),
                    d.get("assignee",""),d.get("priority","medium"),d.get("stage","backlog"),
                    ts(),d.get("due",""),d.get("pct",0),json.dumps(d.get("comments",[])),
                    d.get("team_id","")))
        # Batch: fetch creator + assignee info + project members in ONE round-trip each
        creator=db.execute("SELECT name FROM users WHERE id=?",(session["user_id"],)).fetchone()
        cname=creator["name"] if creator else "Someone"
        base_ts=int(datetime.now().timestamp()*1000)
        assignee_user=None
        if d.get("assignee"):
            assignee_user=db.execute("SELECT name,email FROM users WHERE id=?",(d["assignee"],)).fetchone()
        proj=None
        proj_members=[]
        if d.get("project"):
            proj=db.execute("SELECT name,members FROM projects WHERE id=? AND workspace_id=?",(d["project"],wid())).fetchone()
            if proj:
                try: proj_members=json.loads(proj["members"] or "[]")
                except: proj_members=[]
        # Build ALL notification rows first, then batch-insert in ONE query
        notif_rows=[]
        if assignee_user:
            notif_rows.append((f"n{base_ts}",wid(),"task_assigned",
                               f"{cname} assigned you to '{d['title']}'",d["assignee"],0,ts()))
        for i,uid in enumerate(proj_members):
            if uid==session["user_id"] or uid==d.get("assignee"): continue
            proj_name=proj["name"] if proj else ""
            notif_rows.append((f"n{base_ts+10+i}",wid(),"task_assigned",
                               f"{cname} created task '{d['title']}' in {proj_name}",uid,0,ts()))
        if notif_rows:
            placeholders=",".join(["(?,?,?,?,?,?,?)"]*len(notif_rows))
            flat=[v for row in notif_rows for v in row]
            db.execute(f"INSERT INTO notifications(id,workspace_id,type,content,user_id,read,ts) VALUES {placeholders}",flat)
        # Send emails + push notifications in background threads (non-blocking)
        if assignee_user:
            if assignee_user["email"]:
                threading.Thread(target=send_task_assigned_email,
                    args=(assignee_user["email"],assignee_user["name"],d["title"],cname,tid,wid()),
                    daemon=True).start()
            threading.Thread(target=push_notification_to_user,
                args=(db,d["assignee"],f"✅ New task assigned: {d['title']}",
                      f"{cname} assigned you this task [{d.get('priority','medium')}]","/"),
                daemon=True).start()
        for uid in proj_members:
            if uid==session["user_id"] or uid==d.get("assignee"): continue
            threading.Thread(target=push_notification_to_user,
                args=(db,uid,f"📋 New task in {proj['name'] if proj else ''}",
                      f"{cname} created '{d['title']}'","/"),daemon=True).start()
        t=db.execute("SELECT * FROM tasks WHERE id=? AND workspace_id=?",(tid,wid())).fetchone()
        if d.get("project") and proj:
            assignee_name=f" → assigned to {assignee_user['name']}" if assignee_user else ""
            sysmid=f"m{base_ts+1}"
            msg=f"📋 **{cname}** created task **{d['title']}**{assignee_name} [{d.get('priority','medium').title()}]"
            db.execute("INSERT INTO messages(id,workspace_id,sender,project,content,ts,is_system) VALUES (?,?,?,?,?,?,?)",
                       (sysmid,wid(),"system",d["project"],msg,ts(),1))
        _cache_inject_item(wid(), "tasks", dict(t))
        # Bust full workspace cache so app-data background refresh picks up the new task.
        # Previously only busting 'notifs' left app-data stale, causing new tasks to vanish.
        _cache_bust_ws(wid())
        # Push SSE event — connected clients reload immediately without polling delay
        _sse_publish(wid(), "task_updated", {"id": tid, "action": "created",
                                              "project": d.get("project", ""),
                                              "assignee": d.get("assignee", "")})
        return jsonify(dict(t))


@bp.route("/api/tasks/<tid>/events", methods=["GET"])
@login_required
def get_task_events(tid):
    """Get activity log for a task."""
    with get_db() as db:
        rows = db.execute(
            """SELECT te.*, u.name as user_name, u.avatar as user_avatar, u.color as user_color
               FROM task_events te LEFT JOIN users u ON te.user_id=u.id
               WHERE te.task_id=? AND te.workspace_id=? ORDER BY te.ts DESC LIMIT 50""",
            (tid, wid())).fetchall()
        return jsonify([dict(r) for r in rows])

def log_task_event(db, workspace_id, task_id, user_id, event_type, old_val="", new_val=""):
    """Insert a task activity event."""
    try:
        eid = f"te{int(datetime.now().timestamp()*1000)}{secrets.token_hex(2)}"
        db.execute("INSERT INTO task_events VALUES (?,?,?,?,?,?,?,?)",
                   (eid, workspace_id, task_id, user_id, event_type,
                    str(old_val), str(new_val), ts()))
    except Exception as e:
        log.warning("[task_event] %s", e)

@bp.route("/api/tasks/<tid>",methods=["PUT"])
@login_required
def update_task(tid):
    d=request.json or {}
    with get_db() as db:
        cu=db.execute("SELECT role FROM users WHERE id=?",(session["user_id"],)).fetchone()
        cu_role=cu["role"] if cu else "Viewer"
        t=db.execute("SELECT * FROM tasks WHERE id=? AND workspace_id=?",(tid,wid())).fetchone()
        if not t: return jsonify({"error":"Not found"}),404

        is_admin_manager = cu_role in ("Admin","Manager")
        is_teamlead = cu_role == "TeamLead"
        is_assignee = t["assignee"] == session["user_id"]
        proj = db.execute("SELECT owner FROM projects WHERE id=? AND workspace_id=?",(t["project"],wid())).fetchone() if t["project"] else None
        is_proj_owner = proj and proj["owner"] == session["user_id"]

        if not (is_admin_manager or is_teamlead or is_proj_owner):
            if is_assignee:
                allowed={"stage","pct","comments"}
                if any(k not in allowed for k in d.keys()):
                    return jsonify({"error":"You can only update stage, progress, and comments on tasks assigned to you."}),403
            else:
                return jsonify({"error":"You do not have permission to edit this task. Only the assignee, project owner, or managers can edit tasks."}),403

        old_stage=t["stage"]
        old_assignee=t["assignee"]
        def tf(key,default=''):
            return t[key] if key in t.keys() else default
        labels_val=d.get("labels",None)
        if labels_val is not None and isinstance(labels_val,list): labels_val=json.dumps(labels_val)
        elif labels_val is None: labels_val=tf("labels","[]")
        comments_val=d.get("comments",None)
        if comments_val is None: comments_val=json.loads(t["comments"] or "[]")
        db.execute("""UPDATE tasks SET title=?,description=?,project=?,assignee=?,
                      priority=?,stage=?,due=?,pct=?,comments=?,team_id=?,
                      story_points=?,task_type=?,labels=?,sprint=? WHERE id=? AND workspace_id=?""",
                   (d.get("title",t["title"]),d.get("description",t["description"]),
                    d.get("project",t["project"]),d.get("assignee",t["assignee"]),
                    d.get("priority",t["priority"]),d.get("stage",t["stage"]),
                    d.get("due",t["due"]),d.get("pct",t["pct"]),
                    json.dumps(comments_val),
                    d.get("team_id",tf("team_id","")),
                    d.get("story_points",tf("story_points",0)),
                    d.get("task_type",tf("task_type","task")),
                    labels_val,
                    d.get("sprint",tf("sprint","")),
                    tid,wid()))
        # Log activity events
        new_stage_val = d.get("stage", old_stage)
        new_assignee_val = d.get("assignee", old_assignee)
        if new_stage_val != old_stage:
            log_task_event(db, wid(), tid, session["user_id"], "stage_change", old_stage, new_stage_val)
        if new_assignee_val != old_assignee and new_assignee_val:
            assignee_name = (db.execute("SELECT name FROM users WHERE id=?", (new_assignee_val,)).fetchone() or {}).get("name","?")
            log_task_event(db, wid(), tid, session["user_id"], "assigned", old_assignee or "", assignee_name)
            # Email the newly assigned person (including self-assignment)
            new_assignee_row = db.execute("SELECT name,email FROM users WHERE id=?", (new_assignee_val,)).fetchone()
            reassigner_row   = db.execute("SELECT name FROM users WHERE id=?", (session["user_id"],)).fetchone()
            reassigner_name  = reassigner_row["name"] if reassigner_row else "Someone"
            if new_assignee_row and new_assignee_row["email"]:
                threading.Thread(target=send_task_reassigned_email,
                    args=(new_assignee_row["email"], new_assignee_row["name"],
                          d.get("title", t["title"]), reassigner_name, tid, wid()),
                    daemon=True).start()
        if d.get("stage") and d["stage"]!=old_stage:
            base_ts2=int(datetime.now().timestamp()*1000)
            # Notify project members when a task is marked completed
            if d["stage"] in ("completed","production") and t["project"]:
                _comp_proj = db.execute("SELECT members,owner FROM projects WHERE id=? AND workspace_id=?",
                                        (t["project"],wid())).fetchone()
                _comp_actor = db.execute("SELECT name FROM users WHERE id=?", (session["user_id"],)).fetchone()
                _comp_actor_name = _comp_actor["name"] if _comp_actor else "Someone"
                if _comp_proj:
                    try: _comp_members = json.loads(_comp_proj["members"] or "[]")
                    except: _comp_members = []
                    _notified_completed = set()
                    for _cm_uid in _comp_members:
                        if _cm_uid in _notified_completed:
                            continue
                        _cm_user = db.execute("SELECT name,email FROM users WHERE id=?", (_cm_uid,)).fetchone()
                        if _cm_user and _cm_user["email"]:
                            _notified_completed.add(_cm_uid)
                            threading.Thread(target=send_task_completed_email,
                                args=(_cm_user["email"], _cm_user["name"], t["title"], _comp_actor_name, wid()),
                                daemon=True).start()
            if t["assignee"]:
                nid=f"n{base_ts2}"
                db.execute("INSERT INTO notifications VALUES (?,?,?,?,?,?,?)",
                           (nid,wid(),"status_change",f"Task '{t['title']}' moved to {d['stage']}",
                            t["assignee"],0,ts()))
                assignee_user=db.execute("SELECT name,email FROM users WHERE id=?",(t["assignee"],)).fetchone()
                changer_user=db.execute("SELECT name FROM users WHERE id=?",(session["user_id"],)).fetchone()
                changer_name=changer_user["name"] if changer_user else "Someone"
                if assignee_user and assignee_user["email"]:
                    threading.Thread(target=send_status_change_email,
                        args=(assignee_user["email"],assignee_user["name"],t["title"],d["stage"],changer_name,wid()),
                        daemon=True).start()
                threading.Thread(target=push_notification_to_user,
                    args=(db, t["assignee"], f"🔄 Task updated: {t['title']}",
                          f"{changer_name} moved it to {d['stage']}", "/"),
                    daemon=True).start()
            if t["project"]:
                proj=db.execute("SELECT members FROM projects WHERE id=? AND workspace_id=?",(t["project"],wid())).fetchone()
                if proj:
                    try: members=json.loads(proj["members"] or "[]")
                    except: members=[]
                    actor=db.execute("SELECT name FROM users WHERE id=?",(session["user_id"],)).fetchone()
                    aname=actor["name"] if actor else "Someone"
                    for i2,uid in enumerate(members):
                        if uid==session["user_id"] or uid==t["assignee"]: continue
                        nid2=f"n{base_ts2+20+i2}"
                        db.execute("INSERT INTO notifications VALUES (?,?,?,?,?,?,?)",
                                   (nid2,wid(),"status_change",f"{aname} moved '{t['title']}' → {d['stage']}",uid,0,ts()))
                        threading.Thread(target=push_notification_to_user,
                            args=(db, uid, f"🔄 {t['title']} → {d['stage']}",
                                  f"{aname} updated the task stage", "/"),
                            daemon=True).start()
                sysmid=f"m{base_ts2+2}"
                db.execute("INSERT INTO messages(id,workspace_id,sender,project,content,ts,is_system) VALUES (?,?,?,?,?,?,?)",
                           (sysmid,wid(),"system",t["project"],
                            f"⚡ **{aname}** moved **{t['title']}** → {d['stage'].title()}",ts(),1))
        new_comments=d.get("comments",[])
        old_comments=json.loads(t["comments"] or "[]")
        if len(new_comments)>len(old_comments) and t["project"]:
            latest=new_comments[-1]
            commenter=db.execute("SELECT name FROM users WHERE id=?",(latest.get("uid",""),)).fetchone()
            cname=commenter["name"] if commenter else "Someone"
            sysmid=f"m{int(datetime.now().timestamp()*1000)+3}"
            db.execute("INSERT INTO messages(id,workspace_id,sender,project,content,ts,is_system) VALUES (?,?,?,?,?,?,?)",
                       (sysmid,wid(),"system",t["project"],
                        f"💬 **{cname}** commented on **{t['title']}**: {latest.get('text','')}",ts(),1))
            if t["assignee"] and t["assignee"]!=session["user_id"]:
                nid2=f"n{int(datetime.now().timestamp()*1000)+4}"
                db.execute("INSERT INTO notifications VALUES (?,?,?,?,?,?,?)",
                           (nid2,wid(),"comment",f"{cname} commented on '{t['title']}': {latest.get('text','')}",
                            t["assignee"],0,ts()))
                assignee_user=db.execute("SELECT name,email FROM users WHERE id=?",(t["assignee"],)).fetchone()
                if assignee_user and assignee_user["email"]:
                    threading.Thread(target=send_comment_email,
                        args=(assignee_user["email"],assignee_user["name"],t["title"],cname,latest.get('text',''),wid()),
                        daemon=True).start()
            # @mention detection: notify any @mentioned user who isn't already the assignee
            import re as _re_mention
            comment_text_raw = latest.get("text","")
            mentioned_names = _re_mention.findall(r'@([\w ]+)', comment_text_raw)
            if mentioned_names:
                all_users_ws = db.execute("SELECT id,name,email FROM users WHERE workspace_id=?", (wid(),)).fetchall()
                commenter_row = db.execute("SELECT name FROM users WHERE id=?", (session["user_id"],)).fetchone()
                commenter_name_m = commenter_row["name"] if commenter_row else "Someone"
                for mu in all_users_ws:
                    for mn in mentioned_names:
                        if mu["name"].strip().lower() == mn.strip().lower():
                            if mu["id"] != t.get("assignee","") and mu["email"]:
                                threading.Thread(target=send_mention_email,
                                    args=(mu["email"], mu["name"], commenter_name_m,
                                          t["title"], comment_text_raw, wid()),
                                    daemon=True).start()
                            break
                threading.Thread(target=push_notification_to_user,
                    args=(db, t["assignee"], f"💬 Comment on: {t['title']}",
                          f"{cname}: {latest.get('text','')[:80]}", "/"),
                    daemon=True).start()
        _cache_bust_ws(wid())
        updated_task = dict(db.execute("SELECT * FROM tasks WHERE id=? AND workspace_id=?",(tid,wid())).fetchone())
        # Push SSE — all workspace clients get the new stage/assignee immediately
        _sse_publish(wid(), "task_updated", {"id": tid, "action": "updated",
                                              "stage": updated_task.get("stage",""),
                                              "project": updated_task.get("project","")})
        return jsonify(updated_task)


@bp.route("/api/subtasks/search")
@login_required
def search_subtasks():
    q = request.args.get("q","").strip().lower()
    if not q or len(q) < 2:
        return jsonify([])
    with get_db() as db:
        rows = db.execute("""
    SELECT s.*, t.title as task_title, t.project
            FROM subtasks s
            JOIN tasks t ON s.task_id = t.id
            WHERE s.workspace_id = ?
            AND (LOWER(s.id) LIKE ? OR LOWER(s.title) LIKE ?)
            LIMIT 10
        """, (wid(), f"%{q}%", f"%{q}%")).fetchall()
        return jsonify([dict(r) for r in rows])

@bp.route("/api/tasks/<tid>/subtasks", methods=["GET"])
@login_required
def get_subtasks(tid):
    with get_db() as db:
        rows=db.execute("SELECT * FROM subtasks WHERE task_id=? AND workspace_id=? ORDER BY created",(tid,wid())).fetchall()
        return jsonify([dict(r) for r in rows])

@bp.route("/api/tasks/<tid>/subtasks", methods=["POST"])
@login_required
def create_subtask(tid):
    d=request.json or {}
    sid=f"st{int(datetime.now().timestamp()*1000)}{secrets.token_hex(3)}"
    with get_db() as db:
        db.execute("INSERT INTO subtasks VALUES (?,?,?,?,?,?,?)",
                   (sid,wid(),tid,d.get("title","Untitled"),0,d.get("assignee",""),ts()))
        return jsonify({"id":sid,"task_id":tid,"title":d.get("title",""),"done":0})

@bp.route("/api/subtasks/<sid>", methods=["PUT"])
@login_required
def update_subtask(sid):
    d=request.json or {}
    with get_db() as db:
        st=db.execute("SELECT * FROM subtasks WHERE id=? AND workspace_id=?",(sid,wid())).fetchone()
        if not st: return jsonify({"error":"Not found"}),404
        done=d.get("done",st["done"])
        title=d.get("title",st["title"])
        assignee=d.get("assignee",st["assignee"])
        db.execute("UPDATE subtasks SET done=?,title=?,assignee=? WHERE id=?",(done,title,assignee,sid))
        return jsonify({"ok":True})

@bp.route("/api/subtasks/<sid>", methods=["DELETE"])
@login_required
def delete_subtask(sid):
    with get_db() as db:
        db.execute("DELETE FROM subtasks WHERE id=? AND workspace_id=?",(sid,wid()))
        return jsonify({"ok":True})

@bp.route("/api/tasks/<tid>",methods=["DELETE"])
@login_required
def del_task(tid):
    with get_db() as db:
        cu=db.execute("SELECT role FROM users WHERE id=?",(session["user_id"],)).fetchone()
        cu_role=cu["role"] if cu else "Viewer"
        if cu_role not in ("Admin","Manager","TeamLead"):
            return jsonify({"error":"Only Admin, Manager, or TeamLead can delete tasks."}),403
        db.execute("DELETE FROM tasks WHERE id=? AND workspace_id=?",(tid,wid()))
    _cache_bust_ws(wid())
    return jsonify({"ok":True})

# ── Files ─────────────────────────────────────────────────────────────────────
@bp.route("/api/files")
@login_required
def get_files():
    task_id=request.args.get("task_id"); project_id=request.args.get("project_id")
    with get_db() as db:
        if task_id:
            rows=db.execute("SELECT * FROM files WHERE task_id=? AND workspace_id=? ORDER BY ts DESC",(task_id,wid())).fetchall()
        elif project_id:
            rows=db.execute("SELECT * FROM files WHERE project_id=? AND workspace_id=? ORDER BY ts DESC",(project_id,wid())).fetchall()
        else: rows=[]
        return jsonify([dict(r) for r in rows])

@bp.route("/api/files",methods=["POST"])
@login_required
def upload_file():
    f=request.files.get("file")
    if not f or not f.filename:
        return jsonify({"error":"No file"}),400

    original_name = os.path.basename(f.filename).strip()
    data=f.read()
    if not data:
        return jsonify({"error":"Empty file"}),400
    if len(data)>MAX_UPLOAD_BYTES:
        return jsonify({"error":f"File too large (max {MAX_UPLOAD_BYTES//1024//1024}MB)"}),400

    ok, mime_or_error = _looks_like_upload_mime(original_name, data, f.content_type)
    if not ok:
        return jsonify({"error":mime_or_error}),400

    task_id=request.form.get("task_id","")
    project_id=request.form.get("project_id","")
    ws_id=wid()
    fid=f"f{int(datetime.now().timestamp()*1000)}{secrets.token_hex(3)}"
    path=os.path.join(UPLOAD_DIR,fid)

    with get_db() as db:
        used=_workspace_upload_bytes(db, ws_id)
        if used + len(data) > WORKSPACE_UPLOAD_QUOTA_BYTES:
            return jsonify({"error":"Workspace upload quota exceeded"}),413

    with open(path,"wb") as fp:
        fp.write(data)

    clean, scan_msg = scan_upload_for_virus(path, original_name)
    if not clean:
        try: os.remove(path)
        except Exception: pass
        return jsonify({"error":"Upload rejected by virus scanner", "details": scan_msg}),400

    with get_db() as db:
        db.execute("INSERT INTO files VALUES (?,?,?,?,?,?,?,?,?)",
                   (fid,ws_id,original_name,len(data),mime_or_error,task_id,project_id,session["user_id"],ts()))
        row=db.execute("SELECT * FROM files WHERE id=? AND workspace_id=?",(fid,ws_id)).fetchone()
        return jsonify(dict(row))

@bp.route("/api/files/<fid>")
@login_required
def download_file(fid):
    with get_db() as db:
        row=db.execute("SELECT * FROM files WHERE id=? AND workspace_id=?",(fid,wid())).fetchone()
        if not row: return jsonify({"error":"Not found"}),404
    path=os.path.join(UPLOAD_DIR,fid)
    if not os.path.exists(path): return jsonify({"error":"File missing"}),404
    return send_file(path,download_name=row["name"],as_attachment=True,mimetype=row["mime"])

@bp.route("/api/files/<fid>",methods=["DELETE"])
@login_required
@require_role("Admin", "Manager", "TeamLead")
def del_file(fid):
    with get_db() as db:
        db.execute("DELETE FROM files WHERE id=? AND workspace_id=?",(fid,wid()))
    path=os.path.join(UPLOAD_DIR,fid)
    if os.path.exists(path): os.remove(path)
    return jsonify({"ok":True})

