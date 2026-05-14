"""Hybrid notification engine for Project Tracker.

Centralizes preference-aware in-app, desktop/web-push, and email notification
routing. Kept dependency-light so it can be imported by app.py without changing
Flask startup behavior.
"""
from __future__ import annotations

import json
import secrets
import threading
import time
from datetime import datetime, timedelta

PRIORITY_ORDER = {"low": 1, "medium": 2, "normal": 2, "high": 3, "critical": 4, "urgent": 4}
URGENT_PRIORITIES = {"high", "critical", "urgent"}
TERMINAL_TASK_STAGES = {"completed", "done", "closed", "cancelled"}
TERMINAL_TICKET_STATUSES = {"closed", "resolved", "done", "cancelled"}

DEFAULT_PREFS = {
    "enable_in_app": 1,
    "enable_desktop": 1,
    "enable_email": 1,
    "mute_after_hours": 0,
    "office_start": "09:00",
    "office_end": "18:00",
    "priority_only": 0,
    "digest_frequency": "daily",
    "task_assigned": 1,
    "ticket_updated": 1,
    "mention_comment": 1,
    "approval_needed": 1,
    "deadline_approaching": 1,
    "daily_summary": 1,
}

TYPE_TO_PREF = {
    "task_assigned": "task_assigned",
    "task_created": "task_assigned",
    "ticket_assigned": "ticket_updated",
    "ticket_updated": "ticket_updated",
    "ticket_sla": "ticket_updated",
    "comment": "mention_comment",
    "mention": "mention_comment",
    "approval_requested": "approval_needed",
    "deadline": "deadline_approaching",
    "daily_summary": "daily_summary",
    "team_summary": "daily_summary",
    "manager_summary": "daily_summary",
    "admin_alert": "daily_summary",
}

_started = False
_started_lock = threading.Lock()


def ensure_notification_prefs_schema(db) -> None:
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS notification_prefs (
            user_id TEXT PRIMARY KEY,
            workspace_id TEXT,
            enable_in_app INTEGER DEFAULT 1,
            enable_desktop INTEGER DEFAULT 1,
            enable_email INTEGER DEFAULT 1,
            mute_after_hours INTEGER DEFAULT 0,
            office_start TEXT DEFAULT '09:00',
            office_end TEXT DEFAULT '18:00',
            priority_only INTEGER DEFAULT 0,
            digest_frequency TEXT DEFAULT 'daily',
            task_assigned INTEGER DEFAULT 1,
            ticket_updated INTEGER DEFAULT 1,
            mention_comment INTEGER DEFAULT 1,
            approval_needed INTEGER DEFAULT 1,
            deadline_approaching INTEGER DEFAULT 1,
            daily_summary INTEGER DEFAULT 1,
            updated TEXT DEFAULT ''
        )
        """
    )
    db.execute("CREATE INDEX IF NOT EXISTS idx_notification_prefs_ws ON notification_prefs(workspace_id)")


def normalize_prefs(row) -> dict:
    prefs = dict(DEFAULT_PREFS)
    if row:
        prefs.update({k: row[k] for k in row.keys() if k in prefs or k in ("user_id", "workspace_id", "updated")})
    return prefs


def get_user_prefs(db, workspace_id: str, user_id: str) -> dict:
    ensure_notification_prefs_schema(db)
    row = db.execute(
        "SELECT * FROM notification_prefs WHERE workspace_id=? AND user_id=?",
        (workspace_id, user_id),
    ).fetchone()
    if not row:
        db.execute(
            """INSERT INTO notification_prefs(
                user_id,workspace_id,enable_in_app,enable_desktop,enable_email,mute_after_hours,
                office_start,office_end,priority_only,digest_frequency,task_assigned,ticket_updated,
                mention_comment,approval_needed,deadline_approaching,daily_summary,updated
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                user_id, workspace_id, 1, 1, 1, 0, "09:00", "18:00", 0, "daily",
                1, 1, 1, 1, 1, 1, datetime.utcnow().isoformat(),
            ),
        )
        return dict(DEFAULT_PREFS, user_id=user_id, workspace_id=workspace_id)
    return normalize_prefs(row)


def update_user_prefs(db, workspace_id: str, user_id: str, payload: dict) -> dict:
    current = get_user_prefs(db, workspace_id, user_id)
    allowed = set(DEFAULT_PREFS.keys())
    clean = {k: payload[k] for k in payload if k in allowed}
    for k in clean:
        if k not in {"office_start", "office_end", "digest_frequency"}:
            clean[k] = 1 if bool(clean[k]) else 0
    if clean:
        assignments = ",".join([f"{k}=?" for k in clean]) + ",updated=?"
        db.execute(
            f"UPDATE notification_prefs SET {assignments} WHERE workspace_id=? AND user_id=?",
            tuple(clean.values()) + (datetime.utcnow().isoformat(), workspace_id, user_id),
        )
    current.update(clean)
    return current


def _after_hours(prefs: dict) -> bool:
    if not int(prefs.get("mute_after_hours") or 0):
        return False
    now = datetime.now().strftime("%H:%M")
    start = str(prefs.get("office_start") or "09:00")[:5]
    end = str(prefs.get("office_end") or "18:00")[:5]
    if start <= end:
        return not (start <= now <= end)
    return end < now < start


def allows_notification(prefs: dict, notif_type: str, priority: str = "medium") -> bool:
    pref_key = TYPE_TO_PREF.get(notif_type)
    if pref_key and not int(prefs.get(pref_key, 1) or 0):
        return False
    if int(prefs.get("priority_only") or 0) and PRIORITY_ORDER.get((priority or "medium").lower(), 2) < 3:
        return False
    if _after_hours(prefs) and (priority or "").lower() not in URGENT_PRIORITIES:
        return False
    return True


def insert_in_app(db, workspace_id: str, user_id: str, notif_type: str, content: str, entity_id: str = "", entity_type: str = "", sender_id: str = "", now: str | None = None) -> str:
    nid = f"n{int(time.time()*1000)}{secrets.token_hex(3)}"
    db.execute(
        "INSERT INTO notifications(id,workspace_id,type,content,user_id,read,ts,sender_id,entity_id,entity_type) VALUES (?,?,?,?,?,?,?,?,?,?)",
        (nid, workspace_id, notif_type, content, user_id, 0, now or datetime.utcnow().isoformat(), sender_id or "", entity_id or "", entity_type or ""),
    )
    return nid


def dispatch_notification(*, db, workspace_id: str, user_id: str, notif_type: str, title: str, body: str = "", priority: str = "medium", entity_id: str = "", entity_type: str = "", sender_id: str = "", url: str = "/", email_fn=None, email_args: tuple = (), push_fn=None, now: str | None = None) -> dict:
    if not user_id:
        return {"in_app": False, "desktop": False, "email": False}
    prefs = get_user_prefs(db, workspace_id, user_id)
    if not allows_notification(prefs, notif_type, priority):
        return {"in_app": False, "desktop": False, "email": False, "muted": True}
    sent = {"in_app": False, "desktop": False, "email": False}
    content = body or title
    if int(prefs.get("enable_in_app", 1) or 0):
        insert_in_app(db, workspace_id, user_id, notif_type, content, entity_id, entity_type, sender_id, now)
        sent["in_app"] = True
    if push_fn and int(prefs.get("enable_desktop", 1) or 0) and (priority or "").lower() in URGENT_PRIORITIES:
        threading.Thread(target=push_fn, args=(None, user_id, title, body or title, url, f"{notif_type}-{entity_id}"), daemon=True).start()
        sent["desktop"] = True
    if email_fn and int(prefs.get("enable_email", 1) or 0):
        threading.Thread(target=email_fn, args=email_args, daemon=True).start()
        sent["email"] = True
    return sent


def role_targets(db, workspace_id: str, roles: tuple[str, ...]) -> list[str]:
    rows = db.execute(
        f"SELECT id FROM users WHERE workspace_id=? AND role IN ({','.join('?'*len(roles))})",
        (workspace_id, *roles),
    ).fetchall()
    return [r["id"] for r in rows]


def team_lead_targets(db, workspace_id: str, team_id: str = "") -> list[str]:
    ids = []
    if team_id:
        row = db.execute("SELECT lead_id FROM teams WHERE workspace_id=? AND id=?", (workspace_id, team_id)).fetchone()
        if row and row["lead_id"]:
            ids.append(row["lead_id"])
    ids += role_targets(db, workspace_id, ("TeamLead",))
    return sorted(set([x for x in ids if x]))


def notify_role_summary(*, db, workspace_id: str, roles: tuple[str, ...], notif_type: str, title: str, body: str, priority: str = "medium", entity_id: str = "", entity_type: str = "", push_fn=None):
    for uid in role_targets(db, workspace_id, roles):
        dispatch_notification(db=db, workspace_id=workspace_id, user_id=uid, notif_type=notif_type, title=title, body=body, priority=priority, entity_id=entity_id, entity_type=entity_type, push_fn=push_fn, url=f"/?view={entity_type or 'dashboard'}")


def start_background_workers(app_module):
    global _started
    with _started_lock:
        if _started:
            return
        _started = True
    threading.Thread(target=_deadline_worker, args=(app_module,), daemon=True).start()
    threading.Thread(target=_sla_worker, args=(app_module,), daemon=True).start()
    threading.Thread(target=_digest_worker, args=(app_module,), daemon=True).start()


def _deadline_worker(app):
    while True:
        try:
            now = datetime.utcnow()
            soon = now + timedelta(hours=24)
            with app.get_db() as db:
                rows = db.execute(
                    """SELECT * FROM tasks WHERE due!='' AND assignee!='' AND stage NOT IN ('completed','done','closed','cancelled')
                       AND due>=? AND due<=? LIMIT 200""",
                    (now.strftime("%Y-%m-%dT%H:%M:%S"), soon.strftime("%Y-%m-%dT%H:%M:%S")),
                ).fetchall()
                for t in rows:
                    exists = db.execute(
                        "SELECT id FROM notifications WHERE workspace_id=? AND user_id=? AND type='deadline' AND entity_id=? AND ts>=? LIMIT 1",
                        (t["workspace_id"], t["assignee"], t["id"], (now - timedelta(hours=20)).isoformat()),
                    ).fetchone()
                    if exists:
                        continue
                    dispatch_notification(db=db, workspace_id=t["workspace_id"], user_id=t["assignee"], notif_type="deadline", title=f"⏰ Deadline approaching: {t['title']}", body=f"Task due within 24 hours: {t['title']}", priority=t["priority"] or "medium", entity_id=t["id"], entity_type="task", push_fn=getattr(app, "push_notification_to_user", None), url=f"/?action=task&id={t['id']}")
        except Exception as e:
            try: app.log.warning("[notification_engine.deadline] %s", e)
            except Exception: pass
        time.sleep(1800)


def _sla_worker(app):
    while True:
        try:
            cutoff = datetime.utcnow() - timedelta(hours=24)
            with app.get_db() as db:
                rows = db.execute(
                    """SELECT * FROM tickets WHERE status NOT IN ('closed','resolved','done','cancelled')
                       AND priority IN ('high','critical','urgent') AND created<=? LIMIT 200""",
                    (cutoff.strftime("%Y-%m-%dT%H:%M:%S"),),
                ).fetchall()
                for t in rows:
                    exists = db.execute(
                        "SELECT id FROM notifications WHERE workspace_id=? AND type='ticket_sla' AND entity_id=? AND ts>=? LIMIT 1",
                        (t["workspace_id"], t["id"], (datetime.utcnow() - timedelta(hours=20)).isoformat()),
                    ).fetchone()
                    if exists:
                        continue
                    for uid in role_targets(db, t["workspace_id"], ("Manager", "Admin")):
                        u = db.execute("SELECT name,email FROM users WHERE id=?", (uid,)).fetchone()
                        email_fn = getattr(app, "send_sla_breach_email", None) if u and u["email"] else None
                        email_args = (u["email"], u["name"], t["title"], t["id"], t["priority"], t["workspace_id"]) if email_fn else ()
                        dispatch_notification(db=db, workspace_id=t["workspace_id"], user_id=uid, notif_type="ticket_sla", title=f"🚨 SLA risk: {t['title']}", body=f"High-priority ticket unresolved beyond SLA: {t['title']}", priority=t["priority"] or "high", entity_id=t["id"], entity_type="ticket", email_fn=email_fn, email_args=email_args, push_fn=getattr(app, "push_notification_to_user", None), url=f"/?view=tickets&id={t['id']}")
        except Exception as e:
            try: app.log.warning("[notification_engine.sla] %s", e)
            except Exception: pass
        time.sleep(1800)


def _digest_worker(app):
    last_key = ""
    while True:
        try:
            now = datetime.utcnow()
            key = now.strftime("%Y-%m-%d-%H")
            if now.hour == 17 and key != last_key:
                last_key = key
                with app.get_db() as db:
                    users = db.execute("SELECT id,workspace_id,role FROM users WHERE role IN ('Admin','Manager','TeamLead','Developer','Tester')").fetchall()
                    for u in users:
                        prefs = get_user_prefs(db, u["workspace_id"], u["id"])
                        if not int(prefs.get("daily_summary", 1) or 0) or not int(prefs.get("enable_in_app", 1) or 0):
                            continue
                        open_tasks = db.execute("SELECT COUNT(*) c FROM tasks WHERE workspace_id=? AND assignee=? AND stage NOT IN ('completed','done','closed')", (u["workspace_id"], u["id"])).fetchone()["c"]
                        overdue = db.execute("SELECT COUNT(*) c FROM tasks WHERE workspace_id=? AND assignee=? AND due!='' AND due<? AND stage NOT IN ('completed','done','closed')", (u["workspace_id"], u["id"], now.strftime("%Y-%m-%dT%H:%M:%S"))).fetchone()["c"]
                        dispatch_notification(db=db, workspace_id=u["workspace_id"], user_id=u["id"], notif_type="daily_summary", title="Daily summary", body=f"Daily summary: {open_tasks} open tasks, {overdue} overdue.", priority="medium", entity_type="dashboard")
        except Exception as e:
            try: app.log.warning("[notification_engine.digest] %s", e)
            except Exception: pass
        time.sleep(900)
