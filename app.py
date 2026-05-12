#!/usr/bin/env python3
"""
Project Tracker v5.0 — Enterprise Edition
Multi-tenant workspaces | AI Assistant | Stage Dropdown | Direct Messages
"""
# ── gevent monkey-patch — MUST be first import ───────────────────────────────
# Enables non-blocking I/O for SSE streams and DB connections under gevent workers.
# Safe to call even when running under gthread or development server.
try:
    from gevent import monkey as _monkey
    _monkey.patch_all()
except ImportError:
    pass  # gevent not installed — falls back to gthread workers gracefully

import os, sys, json, hashlib, secrets, random, urllib.request, urllib.error
import socket, threading, time, webbrowser, mimetypes, base64, smtplib
import re, struct, traceback, hmac, math, zlib, logging
from concurrent.futures import ThreadPoolExecutor, as_completed as _as_completed
from datetime import datetime, timedelta
from functools import wraps

# ── Structured logging ────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S',
    stream=sys.stdout
)
log = logging.getLogger("project-tracker")
try:
    import bcrypt as _bcrypt
except ImportError:
    _bcrypt = None

# ── Vault encryption (Fernet = AES-128-CBC + HMAC-SHA256) ─────────────────────
try:
    from cryptography.fernet import Fernet as _Fernet, InvalidToken as _InvalidToken
    _FERNET_OK = True
except ImportError:
    _FERNET_OK = False
    print("  ⚠ 'cryptography' package not installed — vault rows stored unencrypted.\n"
          "    Fix: pip install cryptography")

_vault_fernet_instance = None

def _get_vault_fernet():
    """Return a cached Fernet instance, creating/loading the key on first call."""
    global _vault_fernet_instance
    if not _FERNET_OK:
        return None
    if _vault_fernet_instance is not None:
        return _vault_fernet_instance
    # 1) Prefer env var (set this in Railway / Render secrets)
    env_key = os.environ.get("VAULT_ENCRYPTION_KEY", "").strip()
    if env_key:
        try:
            _vault_fernet_instance = _Fernet(env_key.encode() if isinstance(env_key, str) else env_key)
            return _vault_fernet_instance
        except Exception as e:
            print(f"  ⚠ VAULT_ENCRYPTION_KEY env var is invalid: {e} — generating a new key")
    # 2) Fall back to a persisted key file
    key_path = os.path.join(DATA_DIR, ".vault_enc_key")
    if os.path.exists(key_path):
        try:
            with open(key_path, "rb") as _kf:
                k = _kf.read().strip()
            _vault_fernet_instance = _Fernet(k)
            return _vault_fernet_instance
        except Exception:
            pass
    # 3) Generate and persist a new key
    k = _Fernet.generate_key()
    try:
        with open(key_path, "wb") as _kf:
            _kf.write(k)
        print(f"  ✓ New vault encryption key generated and saved to {key_path}")
    except Exception as e:
        print(f"  ⚠ Could not persist vault key ({e}) — key lives in memory only (restarts will lose it!)")
    _vault_fernet_instance = _Fernet(k)
    return _vault_fernet_instance

def vault_encrypt(plaintext: str) -> str:
    """Encrypt a plaintext string. Returns a Fernet token string, or the original
    if the cryptography library is unavailable (graceful degradation)."""
    f = _get_vault_fernet()
    if not f:
        return plaintext
    return f.encrypt(plaintext.encode("utf-8")).decode("utf-8")

def vault_decrypt(token: str) -> str:
    """Decrypt a Fernet token. Falls back to returning the raw value for any
    legacy unencrypted rows (so old data keeps working after upgrade)."""
    if not token:
        return token
    f = _get_vault_fernet()
    if not f:
        return token
    try:
        return f.decrypt(token.encode("utf-8")).decode("utf-8")
    except Exception:
        # Could be a pre-encryption legacy value — return as-is
        return token
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from flask import Flask, request, jsonify, session, Response, send_file, send_from_directory, redirect
from flask_cors import CORS

BASE_DIR   = os.path.dirname(os.path.abspath(__file__))
DATA_DIR   = "/data" if os.path.isdir("/data") else BASE_DIR
JS_DIR     = os.path.join(BASE_DIR, "pf_static")
UPLOAD_DIR = os.path.join(DATA_DIR, "pf_uploads")
STATIC_DIR = os.path.join(BASE_DIR, "static")
KEY_FILE   = os.path.join(DATA_DIR, ".pf_secret")

# Upload safety limits. Override in production with env vars if needed.
MAX_UPLOAD_BYTES = int(os.environ.get("MAX_UPLOAD_BYTES", str(25 * 1024 * 1024)))
WORKSPACE_UPLOAD_QUOTA_BYTES = int(os.environ.get("WORKSPACE_UPLOAD_QUOTA_BYTES", str(2 * 1024 * 1024 * 1024)))
ALLOWED_UPLOAD_EXTENSIONS = {
    ".pdf", ".png", ".jpg", ".jpeg", ".gif", ".webp", ".txt", ".md", ".csv",
    ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".zip", ".webm", ".mp3", ".wav", ".m4a", ".ogg"
}
BLOCKED_UPLOAD_EXTENSIONS = {
    ".exe", ".dll", ".bat", ".cmd", ".com", ".scr", ".ps1", ".sh", ".py", ".js",
    ".mjs", ".html", ".htm", ".svg", ".php", ".jar", ".msi", ".apk"
}
DANGEROUS_MIME_PREFIXES = ("text/html", "application/x-msdownload", "application/x-sh", "application/javascript")

# ── PostgreSQL via pg8000 (pure Python — no libpq/system deps needed) ────────
import pg8000.native
import urllib.parse, re as _re

DATABASE_URL = os.environ.get("DATABASE_URL") or os.environ.get("PGURL") or ""

def _parse_db_url(url):
    """Parse postgres://user:pass@host:port/dbname into pg8000 kwargs."""
    if not url:
        raise RuntimeError("DATABASE_URL environment variable is not set")
    url = url.replace("postgres://", "postgresql://", 1)
    p = urllib.parse.urlparse(url)
    import ssl as _ssl
    # Many managed Postgres providers expose TLS with an internal/self-signed CA.
    # That caused /api/auth/me and /api/auth/login to 500 with
    # CERTIFICATE_VERIFY_FAILED in Railway-style deployments.
    # Default to sslmode=require semantics (encrypted, no hostname/CA validation),
    # and allow strict verification by setting DB_SSL_VERIFY=true plus DB_SSL_CA_FILE
    # when your provider gives you a trusted CA bundle.
    verify = os.environ.get("DB_SSL_VERIFY", "false").lower() in ("1", "true", "yes", "verify", "verify-full")
    ca_file = os.environ.get("DB_SSL_CA_FILE", "").strip()
    if verify:
        ssl_ctx = _ssl.create_default_context(cafile=ca_file or None)
    else:
        ssl_ctx = _ssl.create_default_context()
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = _ssl.CERT_NONE
    return dict(host=p.hostname, port=p.port or 5432, user=p.username,
                password=p.password, database=p.path.lstrip("/"),
                ssl_context=ssl_ctx)

def _sql_compat(sql, params=()):
    """Convert SQLite SQL + params to PostgreSQL named-param style for pg8000.
    Returns (pg_sql, params_dict) — pg8000 run() accepts **kwargs for params.
    """
    if "INSERT OR IGNORE INTO" in sql:
        sql = sql.replace("INSERT OR IGNORE INTO", "INSERT INTO").rstrip()
        sql += " ON CONFLICT DO NOTHING"
    if "INSERT OR REPLACE INTO push_subscriptions" in sql:
        sql = sql.replace("INSERT OR REPLACE INTO push_subscriptions",
                          "INSERT INTO push_subscriptions").rstrip()
        sql += (" ON CONFLICT (endpoint) DO UPDATE SET "
                "p256dh=EXCLUDED.p256dh, auth=EXCLUDED.auth, "
                "created=EXCLUDED.created")
    params_dict = {}
    idx = [0]
    def _rep(m):
        key = f"p{idx[0]}"
        if idx[0] < len(params):
            params_dict[key] = params[idx[0]]
        idx[0] += 1
        return f":{key}"
    sql = _re.sub(r"\?", _rep, sql)
    return sql, params_dict

class _Row(dict):
    """dict subclass: supports row['col'] and row[int_index] like sqlite3.Row."""
    def __init__(self, columns, values):
        super().__init__(zip(columns, values))
        self._list = list(values)
    def __getitem__(self, key):
        if isinstance(key, int): return self._list[key]
        return super().__getitem__(key)
    def keys(self): return list(super().keys())

class _Cursor:
    """Thin wrapper so our code can call .execute()/.fetchone()/.fetchall()."""
    def __init__(self, conn):
        self._conn = conn
        self._rows = []
        self._cols = []
        self.rowcount = 0
    def execute(self, sql, params=()):
        pg_sql, params_dict = _sql_compat(sql, params)
        if params_dict:
            result = self._conn.run(pg_sql, **params_dict)
        else:
            result = self._conn.run(pg_sql)
        self._rows = result or []
        self._cols = [c["name"] for c in (self._conn.columns or [])]
        self.rowcount = self._conn.row_count or 0
        return self
    def fetchone(self):
        return _Row(self._cols, self._rows[0]) if self._rows else None
    def fetchall(self):
        return [_Row(self._cols, r) for r in self._rows]
    def __iter__(self):
        return iter(self.fetchall())

class _DB:
    """Context-manager wrapper matching 'with get_db() as db:' pattern."""
    def __init__(self, conn):
        self._conn = conn
    def execute(self, sql, params=()):
        return _Cursor(self._conn).execute(sql, params)
    def executescript(self, sql):
        """Run semicolon-separated DDL statements (used by init_db)."""
        stmts = [s.strip() for s in sql.split(";") if s.strip()]
        for stmt in stmts:
            try:
                self._conn.run(stmt)
            except Exception as e:
                msg = str(e).lower()
                safe = ["already exists", "duplicate", "column already",
                        "relation already", "index already"]
                if any(x in msg for x in safe):
                    continue
                print(f"  executescript error on: {stmt[:80]!r}: {e}")
                raise
    def commit(self):
        if not getattr(self._conn, 'autocommit', False):
            try: self._conn.run("COMMIT")
            except Exception: pass
    def close(self):
        try: self._conn.close()
        except Exception: pass
    def __enter__(self): return self
    def __exit__(self, exc_type, exc_val, exc_tb):
        if not getattr(self._conn, 'autocommit', False):
            try:
                if exc_type: self._conn.run("ROLLBACK")
                else: self._conn.run("COMMIT")
            except Exception: pass
        self.close()
        return False

class _PooledDB(_DB):
    """Like _DB but returns connection to pool on exit instead of closing it."""
    def __init__(self, conn, autocommit=False):
        super().__init__(conn)
        self._autocommit = autocommit
    def __exit__(self, exc_type, exc_val, exc_tb):
        if not self._autocommit:
            try:
                if exc_type: self._conn.run("ROLLBACK")
                else: self._conn.run("COMMIT")
            except Exception: pass
        # Return to pool instead of closing — this is the key perf improvement
        _return_pool_conn(self._conn)
        return False

def get_secret_key():
    env_key = os.environ.get("SECRET_KEY","")
    if len(env_key) >= 32: return env_key
    # On Railway: derive a STABLE key from the service/project ID so that
    # sessions survive dyno restarts (Railway filesystem is ephemeral).
    # Without this, every restart regenerates the key → all sessions become 401.
    for railway_var in ("RAILWAY_SERVICE_ID","RAILWAY_PROJECT_ID","RAILWAY_ENVIRONMENT"):
        rid = os.environ.get(railway_var,"")
        if rid:
            import hashlib as _hl
            stable = _hl.sha256(f"pt-stable-key::{rid}".encode()).hexdigest()
            log.warning("[SECRET_KEY] Using Railway-derived key from %s. Set SECRET_KEY env var for best security.", railway_var)
            return stable
    if os.path.exists(KEY_FILE):
        try:
            with open(KEY_FILE,"r") as f:
                k=f.read().strip()
                if len(k)==64: return k
        except: pass
    k=secrets.token_hex(32)
    log.warning("[SECRET_KEY] Generated ephemeral secret key — sessions will NOT survive restarts! Set SECRET_KEY env var.")
    try:
        with open(KEY_FILE,"w") as f: f.write(k)
    except: pass
    return k

app = Flask(__name__)
app.secret_key = get_secret_key()
APP_STARTED_AT = datetime.utcnow()
_is_https = os.environ.get("HTTPS","").lower() in ("1","true","on") or              os.environ.get("RAILWAY_ENVIRONMENT","") != "" or              os.environ.get("RENDER","") != ""
app.config.update(
    SESSION_COOKIE_SAMESITE="Lax",SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=_is_https,PERMANENT_SESSION_LIFETIME=86400*30,
    SESSION_COOKIE_NAME="pf_session",
    MAX_CONTENT_LENGTH=150*1024*1024)
# CORS — restrict to known origins in production
_ALLOWED_ORIGINS = [o.strip() for o in os.environ.get("ALLOWED_ORIGINS", "").split(",") if o.strip()]
if not _ALLOWED_ORIGINS:
    _ALLOWED_ORIGINS = ["*"]
    if _is_https:
        log.warning("ALLOWED_ORIGINS not set — CORS is open in production.")
CORS(app, supports_credentials=True, origins=_ALLOWED_ORIGINS if _ALLOWED_ORIGINS != ["*"] else "*")

# ── Gzip compression for all compressible responses ───────────────────────────
@app.route("/healthz")
def healthz():
    """Lightweight health check for uptime monitors (UptimeRobot etc).
    No DB query — just confirms the process is alive. Use this URL
    in UptimeRobot with a 5-minute interval to prevent Railway cold starts."""
    return jsonify({"ok": True, "uptime": str(datetime.utcnow() - APP_STARTED_AT)}), 200

# ── Bot/Scanner IP auto-ban system ──────────────────────────────────────────
# Any IP that hits 3+ scanner-pattern paths gets banned for 24h.
# Banned IPs are rejected in <0.1ms — before Flask processes anything.
import threading as _ban_thread
_BAN_LOCK   = _ban_thread.Lock()
_BAN_HITS   = {}   # ip → count of scanner hits
_BAN_LIST   = {}   # ip → ban_expiry_timestamp (epoch)
_BAN_TTL    = 86400        # 24 hours
_BAN_THRESH = 3            # hits before auto-ban

def _is_banned(ip):
    """Return True if IP is currently banned."""
    if _redis_client is not None:
        try:
            return bool(_redis_client.exists(f"ban:{ip}"))
        except Exception:
            pass
    with _BAN_LOCK:
        exp = _BAN_LIST.get(ip, 0)
        if exp and _time_mod.time() < exp:
            return True
        if exp:
            _BAN_LIST.pop(ip, None)
        return False

def _record_scanner_hit(ip):
    """Record a scanner hit; auto-ban if threshold exceeded."""
    if _redis_client is not None:
        try:
            key = f"scanhit:{ip}"
            count = _redis_client.incr(key)
            _redis_client.expire(key, 3600)    # reset hit count every hour
            if int(count) >= _BAN_THRESH:
                _redis_client.setex(f"ban:{ip}", _BAN_TTL, "1")
                log.warning("[SECURITY] Auto-banned scanner IP %s after %s hits", ip, count)
            return
        except Exception:
            pass
    with _BAN_LOCK:
        _BAN_HITS[ip] = _BAN_HITS.get(ip, 0) + 1
        if _BAN_HITS[ip] >= _BAN_THRESH:
            _BAN_LIST[ip] = _time_mod.time() + _BAN_TTL
            _BAN_HITS.pop(ip, None)
            log.warning("[SECURITY] Auto-banned scanner IP %s", ip)

def _client_ip():
    """Get real client IP, respecting Railway/proxy X-Forwarded-For."""
    xff = request.headers.get("X-Forwarded-For", "")
    if xff:
        return xff.split(",")[0].strip()
    return request.remote_addr or "unknown"

# ── Scanner path fingerprints (extended from real attack logs) ───────────────
_SCANNER_EXTS = (
    '.php', '.php5', '.php7', '.phtml', '.asp', '.aspx', '.jsp',
    '.zip', '.rar', '.tar', '.gz', '.tgz', '.bak', '.sql', '.db',
    '.env', '.git', '.svn', '.htaccess', '.htpasswd', '.DS_Store',
)
_SCANNER_PREFIXES = (
    '/wp-', '/wordpress/', '/wordpress-', '/joomla/', '/drupal/',
    '/.aws/', '/.gcp/', '/.azure/', '/.ssh/', '/.docker/', '/.kube/',
    '/phpMyAdmin', '/phpmyadmin', '/pma/', '/myadmin/', '/mysql/',
    '/admin.php', '/shell.php', '/config.php', '/setup.php',
    '/xmlrpc.php', '/install.php', '/upgrade.php', '/update.php',
    '/.env', '/.git', '/.svn', '/.htaccess', '/.well-known/',
    '/cgi-bin/', '/cgi/', '/../', '/etc/passwd', '/proc/self',
    '/vendor/', '/composer.', '/node_modules/', '/.DS_Store',
    '/backup/', '/backups/', '/db/', '/database/', '/dumps/',
    '/old/', '/test/', '/tmp/', '/temp/', '/upload/', '/uploads/',
    '/media/system/', '/wp-includes/', '/wp-content/',
    '/index/function', '/.dj/', '/adminfuns',
)
_SCANNER_EXACT = {
    '/admin', '/login.php', '/wp-login.php', '/xmlrpc.php',
    '/info.php', '/test.php', '/phpinfo.php', '/.env',
}

@app.before_request
def block_scanners():
    """
    Multi-layer bot/scanner defence:
    Layer 1 — Instant IP ban check (sub-millisecond, no logging)
    Layer 2 — Path fingerprint matching against 100+ scanner patterns
    Layer 3 — Auto-ban: IPs that hit 3+ scanner paths are banned 24h
    Layer 4 — General rate limit: 120 req/min per IP (burst protection)
    """
    ip   = _client_ip()
    path = request.path.lower()

    # ── Layer 1: Banned IP — drop immediately ────────────────────────────────
    if _is_banned(ip):
        return '', 444   # Nginx-style silent drop (no body, connection close)

    # ── Layer 2: Path fingerprint matching ───────────────────────────────────
    is_scanner = (
        any(path.endswith(ext) for ext in _SCANNER_EXTS) or
        any(path.startswith(pfx) for pfx in _SCANNER_PREFIXES) or
        path in _SCANNER_EXACT
    )

    if is_scanner:
        # ── Layer 3: Record hit + auto-ban ───────────────────────────────────
        _record_scanner_hit(ip)
        log.info("[SECURITY] Blocked scanner %s → %s", ip, request.path)
        return '', 404   # Don't reveal it's a Python/Flask app

    # ── Layer 4: General per-IP rate limit (120 req/min) ────────────────────
    # Only applies to non-API, non-static paths to avoid false positives
    # on legitimate polling (tasks, projects, presence every 30s)
    if not path.startswith('/api/') and not path.startswith('/static/'):
        rl_key = f"rl:general:{ip}"
        if _redis_client is not None:
            try:
                count = _redis_client.incr(rl_key)
                if int(count) == 1:
                    _redis_client.expire(rl_key, 60)
                if int(count) > 120:
                    log.warning("[SECURITY] Rate limited IP %s (%s req/min)", ip, count)
                    return jsonify({"error": "Too many requests"}), 429
            except Exception:
                pass

@app.after_request
def compress_response(response):
    """Gzip-compress HTML, JS, CSS and JSON responses when client supports it."""
    accept_encoding = request.headers.get("Accept-Encoding", "")
    if "gzip" not in accept_encoding:
        return response
    if response.status_code < 200 or response.status_code >= 300:
        return response
    content_type = response.content_type or ""
    compressible = any(t in content_type for t in (
        "text/html", "text/css", "application/javascript",
        "application/json", "text/javascript", "text/plain"
    ))
    if not compressible:
        return response
    data = response.get_data()
    if len(data) < 500:
        return response
    import gzip as _gzip
    compressed = _gzip.compress(data, compresslevel=6)
    if len(compressed) >= len(data):
        return response
    response.set_data(compressed)
    response.headers["Content-Encoding"] = "gzip"
    response.headers["Content-Length"] = len(compressed)
    response.headers.pop("Content-MD5", None)
    return response

@app.after_request
def bust_cache_on_write(response):
    """Auto-bust cache on writes — ONLY for endpoints that don't already call
    _cache_bust/_cache_bust_ws themselves. Uses targeted per-table bust instead
    of full workspace bust to avoid the 30-second slowness on every mutation.
    Endpoints like create_project, create_task already call _cache_bust directly,
    so we skip those paths here."""
    # NOTE: Individual endpoints call _cache_bust() with specific table names.
    # A full _cache_bust_ws here would wipe ALL cached data on every POST/PUT/DELETE,
    # forcing every subsequent API call to re-hit the DB — causing 30s perceived lag.
    # Do NOT call _cache_bust_ws here. Endpoints manage their own cache invalidation.
    return response

# ── Per-request CSP nonce (stored in Flask g) ────────────────────────────────
from flask import g as _g
import base64 as _b64

@app.before_request
def _generate_csp_nonce():
    """Generate a fresh cryptographic nonce for every request.
    Stored in Flask g so route handlers can access it via g.csp_nonce.
    The nonce is injected into the HTML template and into the CSP header
    so inline scripts are allowed ONLY when they carry this exact nonce."""
    _g.csp_nonce = _b64.b64encode(secrets.token_bytes(16)).decode()

@app.after_request
def add_security_headers(response):
    """Add security headers to every response. Uses per-request nonce for CSP."""
    nonce = getattr(_g, "csp_nonce", "")
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    # 'unsafe-inline' removed — nonce-gated inline scripts only
    nonce_src = f"'nonce-{nonce}'" if nonce else ""
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        f"script-src 'self' {nonce_src} https://unpkg.com https://cdnjs.cloudflare.com https://accounts.google.com; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "img-src 'self' data: blob: https:; "
        "connect-src 'self' wss: https://api.anthropic.com https://accounts.google.com; "
        "frame-ancestors 'self'; "
        "frame-src https://accounts.google.com;"
    )
    if request.is_secure:
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response


@app.errorhandler(404)
def _api_json_404_handler(e):
    if request.path.startswith('/api/'):
        return jsonify({"ok": False, "error": "API endpoint not found"}), 404
    return e

@app.errorhandler(500)
def _api_json_500_handler(e):
    app.logger.exception("Unhandled server error on %s", request.path)
    if request.path.startswith('/api/'):
        return jsonify({"ok": False, "error": "Server error. Check application logs for details."}), 500
    return e

CLRS=["#7c3aed","#2563eb","#059669","#d97706","#dc2626","#ec4899","#0891b2","#5a8cff"]

def get_db(autocommit=False):
    """Get a DB wrapper using the connection pool for performance.
    Falls back to a fresh connection if pool is exhausted."""
    conn = _get_pool_conn()
    conn.autocommit = autocommit
    # Wrap with a pool-returning _DB
    return _PooledDB(conn, autocommit=autocommit)

# ── pg8000 connection pool — pre-warmed, sized for gthread workers ──────────
# 2 workers × 4 threads = 8 max concurrent. Keep 12 slots, pre-warm 4.
import queue as _queue, threading as _poollock
# Pool sized for: gunicorn workers × gevent greenlets per worker.
# With POOL_SIZE env var support so Railway can tune without redeploy.
import os as _os_pool
_PG_POOL_SIZE = int(_os_pool.environ.get("PG_POOL_SIZE", "20"))
_PG_POOL      = _queue.Queue(maxsize=_PG_POOL_SIZE)
_PG_POOL_LOCK = _poollock.Lock()
_PG_KWARGS    = None   # cached once after first parse

def _pg_kwargs():
    global _PG_KWARGS
    if _PG_KWARGS is None:
        _PG_KWARGS = _parse_db_url(DATABASE_URL)
    return _PG_KWARGS

def _make_conn():
    from pg8000.native import Connection as _PGConn
    return _PGConn(**_pg_kwargs())

def _get_pool_conn():
    """Get a healthy connection from pool, or create a new one.
    We skip the SELECT 1 health-check on every borrow — that check costs
    one full India→US round-trip (180ms) per request, eliminating all the
    savings from pooling. Instead we rely on try/except around real queries
    and close broken connections there. Connections that die in the pool
    (idle TCP timeout) are caught by _return_pool_conn's ping-before-put
    for connections that have been idle a long time.
    """
    try:
        conn = _PG_POOL.get_nowait()
        return conn   # trust the connection; let the real query catch breaks
    except _queue.Empty:
        return _make_conn()

def _validate_conn(conn):
    """Light ping — called only when a query fails, not on every borrow."""
    try:
        conn.run("SELECT 1")
        return True
    except Exception:
        try: conn.close()
        except: pass
        return False

def _return_pool_conn(conn):
    """Return connection to pool, or close if pool is full."""
    try:
        _PG_POOL.put_nowait(conn)
    except _queue.Full:
        try: conn.close()
        except: pass

def _pool_conn_with_retry():
    """Get a pool connection; if the first real query fails due to a dead
    connection, discard it and open a fresh one. Called by _raw_pg and _DB."""
    conn = _get_pool_conn()
    return conn

def _prewarm_pool(n=4):
    """Open n connections at startup so first requests don't stall."""
    for _ in range(n):
        try:
            conn = _make_conn()
            _return_pool_conn(conn)
        except Exception as _e:
            log.warning("[pool prewarm] %s", _e)
            break

def _raw_pg(sql, params=(), fetch=False):
    """Execute SQL via pooled pg8000 native connection, bypassing _DB wrapper.
    Returns rows if fetch=True, else None. Raises on error.
    Retries once with a fresh connection if the pool gave a stale socket."""
    import re as _re
    pdict = {}
    idx = [0]
    def _rep(m):
        k = f"p{idx[0]}"
        pdict[k] = params[idx[0]] if idx[0] < len(params) else None
        idx[0] += 1
        return f":{k}"
    pg_sql = _re.sub(r"\?", _rep, sql)

    for attempt in range(2):
        conn = _get_pool_conn()
        try:
            rows = conn.run(pg_sql, **pdict) if pdict else conn.run(pg_sql)
            cols = [c["name"] for c in (conn.columns or [])]
            result = [dict(zip(cols, r)) for r in (rows or [])] if fetch else None
            _return_pool_conn(conn)
            return result
        except Exception as _e:
            try: conn.close()
            except: pass
            if attempt == 1:
                raise
            # first attempt failed — pool conn was stale; retry with fresh conn
            continue

# ── In-memory cache with stale-while-revalidate ─────────────────────────────
# Serves stale data instantly while refreshing in background.
# Result: 0ms for cached reads, fresh data within 1 refresh cycle.
import time as _time
import threading as _cthread

_CACHE: dict = {}        # {key: {"val": ..., "ts": float, "refreshing": bool}}
_CACHE_TTL   = 30        # 30s fresh window — SSE events notify clients on mutations, so stale UI
                         # is no longer a risk from a longer TTL. Short TTL was causing every 5s
                         # cache-cold request to block 5s on DB, saturating the connection pool.
_CACHE_STALE = 60        # serve stale data up to 60s while refreshing (was 120s)
_CACHE_LOCK  = _cthread.Lock()

# ── Redis cache layer (optional, shared across workers) ──────────────────────
# Set REDIS_URL env var (e.g. from Railway Redis service) to enable.
# Falls back to the in-process dict cache if Redis is unavailable.
import json as _json
import os as _os_redis

_redis_client = None
try:
    _REDIS_URL = _os_redis.environ.get("REDIS_URL", "")
    if _REDIS_URL:
        import redis as _redis_lib
        _redis_client = _redis_lib.from_url(
            _REDIS_URL,
            decode_responses=True,
            socket_connect_timeout=2,
            socket_timeout=2,
        )
        _redis_client.ping()   # fail fast if unreachable
        print("  [cache] Redis connected — shared cross-worker cache active")
    else:
        print("  [cache] REDIS_URL not set — using in-process dict cache")
except Exception as _re:
    print(f"  [cache] Redis unavailable ({_re}) — falling back to in-process cache")
    _redis_client = None

def _cache_get(key):
    """Return cached value if fresh/stale-usable. Checks Redis first, then dict.
    Returns None only when cache is cold or too stale."""
    # --- Redis path ---
    if _redis_client is not None:
        try:
            raw = _redis_client.get(f"ptcache:{key}")
            if raw:
                entry = _json.loads(raw)
                age = _time.time() - entry["ts"]
                if age < _CACHE_STALE:
                    return entry["val"]
            return None
        except Exception:
            pass  # Redis blip — fall through to dict cache

    # --- In-process dict path ---
    entry = _CACHE.get(key)
    if not entry:
        return None
    age = _time.time() - entry["ts"]
    if age < _CACHE_TTL:
        return entry["val"]          # fresh — serve immediately
    if age < _CACHE_STALE:
        return entry["val"]          # stale but usable — caller gets it fast
    return None                      # too old — force synchronous refresh

def _cache_set(key, val):
    # --- Redis path ---
    if _redis_client is not None:
        try:
            payload = _json.dumps({"val": val, "ts": _time.time()})
            _redis_client.setex(f"ptcache:{key}", _CACHE_STALE + 60, payload)
            return
        except Exception:
            pass  # Redis blip — fall through to dict

    # --- In-process dict path ---
    with _CACHE_LOCK:
        _CACHE[key] = {"val": val, "ts": _time.time(), "refreshing": False}

def _cache_bust(workspace_id, *tables):
    """Invalidate specific table caches for a workspace on writes."""
    if _redis_client is not None:
        try:
            keys_to_delete = []
            for t in tables:
                # Use targeted pattern per table — much faster than scanning all ws keys
                pattern = f"ptcache:{t}:{workspace_id}*"
                matched = _redis_client.keys(pattern)
                keys_to_delete.extend(matched)
                # Also bust appdata cache which embeds multiple tables
                if t != "appdata":
                    appdata_pattern = f"ptcache:appdata:{workspace_id}*"
                    keys_to_delete.extend(_redis_client.keys(appdata_pattern))
            # Deduplicate and delete in one round-trip
            unique_keys = list(set(keys_to_delete))
            if unique_keys:
                _redis_client.delete(*unique_keys)
            return
        except Exception:
            pass

    with _CACHE_LOCK:
        for key in list(_CACHE.keys()):
            if workspace_id in key:
                for t in tables:
                    if t in key:
                        _CACHE.pop(key, None)
                        break



def _cache_inject_item(workspace_id, bucket, item):
    """Best-effort cache updater used by create flows.

    Older builds referenced this helper but did not define it, which caused
    /api/tasks POST to commit the task and then crash with a 500. Keep this
    function deliberately defensive: cache failure must never fail the API.
    """
    try:
        if not workspace_id or not bucket or not isinstance(item, dict):
            return
        # Update the common list cache keys if they already exist. If not, do nothing.
        candidate_keys = [
            f"{bucket}:{workspace_id}:",
            f"appdata:{workspace_id}:tasks",
            f"appdata:{workspace_id}:projects",
        ]
        for key in candidate_keys:
            try:
                val = _cache_get(key)
                if isinstance(val, list):
                    iid = item.get('id')
                    next_val = [x for x in val if not (isinstance(x, dict) and x.get('id') == iid)]
                    next_val.insert(0, item)
                    _cache_set(key, next_val)
            except Exception:
                pass
    except Exception as e:
        try: log.warning('[cache_inject] ignored: %s', e)
        except Exception: pass

def _cache_bust_ws(workspace_id):
    """Bust ALL cache entries for a workspace."""
    if _redis_client is not None:
        try:
            pattern = f"ptcache:*{workspace_id}*"
            keys = _redis_client.keys(pattern)
            if keys:
                _redis_client.delete(*keys)
            return
        except Exception:
            pass

    with _CACHE_LOCK:
        for key in list(_CACHE.keys()):
            if workspace_id in key:
                _CACHE.pop(key, None)


def _bust_dm_thread(ws, uid1, uid2):
    """Bust the DM conversation cache for both users when a message is sent/deleted/edited."""
    keys = [f"dm_thread:{ws}:{uid1}:{uid2}", f"dm_thread:{ws}:{uid2}:{uid1}"]
    with _CACHE_LOCK:
        for k in keys:
            _CACHE.pop(k, None)
    if _redis_client is not None:
        try:
            for k in keys:
                _redis_client.delete(f"ptcache:{k}")
        except Exception:
            pass



    """After a create, inject the new item into existing cache entries
    so the next poll (background refresh) returns instantly from cache
    rather than hitting the DB cold. Non-critical — failures are silent."""
    try:
        with _CACHE_LOCK:
            for key, entry in list(_CACHE.items()):
                if workspace_id not in key:
                    continue
                val = entry.get("val", {})
                if table not in val:
                    continue
                if not isinstance(val[table], list):
                    continue
                # Only inject if not already present
                ids = {x.get("id") for x in val[table]}
                if item_dict.get("id") not in ids:
                    val[table] = [item_dict] + val[table]
    except Exception:
        pass

# Shared DDL connection — reused across all _run_ddl calls to avoid opening
# 170 separate connections on startup (which caused NO_SOCKET exhaustion).
_DDL_CONN = None
_DDL_LOCK = _poollock.Lock()

def _run_ddl(sql):
    """Run a single DDL statement, reusing a shared DDL connection. Never raises."""
    global _DDL_CONN
    with _DDL_LOCK:
        try:
            # Reuse existing connection if alive
            if _DDL_CONN is not None:
                try:
                    _DDL_CONN.run("SELECT 1")
                except Exception:
                    try: _DDL_CONN.close()
                    except: pass
                    _DDL_CONN = None
            if _DDL_CONN is None:
                _DDL_CONN = pg8000.native.Connection(**_parse_db_url(DATABASE_URL))
            _DDL_CONN.run(sql)
            print(f"  [DDL OK] {sql[:80]!r}")
        except Exception as e:
            msg = str(e).lower()
            ok_msgs = ["already exists", "duplicate", "column already",
                       "relation already", "index already"]
            if any(x in msg for x in ok_msgs):
                print(f"  [DDL skip — already exists] {sql[:60]!r}")
            else:
                print(f"  [DDL WARN] {sql[:60]!r}: {type(e).__name__}: {e}")
                # Reset connection on real errors
                try: _DDL_CONN.close()
                except: pass
                _DDL_CONN = None

def _close_ddl_conn():
    """Call after all DDL is done to release the shared connection."""
    global _DDL_CONN
    with _DDL_LOCK:
        if _DDL_CONN is not None:
            try: _DDL_CONN.close()
            except: pass
            _DDL_CONN = None

def _ensure_logout_column():
    """Add logged_out_at column to users if it doesn't exist (migration)."""
    _run_ddl("ALTER TABLE users ADD COLUMN logged_out_at TEXT DEFAULT ''")

def ensure_timelog_schema():
    """Ensure time_logs has ALL required columns. Safe to call repeatedly."""
    # Step 1: create minimal base table (id only — everything else added via ALTER)
    _run_ddl("""CREATE TABLE IF NOT EXISTS time_logs (
        id TEXT PRIMARY KEY)""")
    # Step 2: every column added individually — each gets its own fresh connection
    # This handles ANY state of the live DB regardless of when it was created
    for ddl in [
        "ALTER TABLE time_logs ADD COLUMN workspace_id TEXT DEFAULT ''",
        "ALTER TABLE time_logs ADD COLUMN user_id      TEXT DEFAULT ''",
        "ALTER TABLE time_logs ADD COLUMN team_id      TEXT DEFAULT ''",
        "ALTER TABLE time_logs ADD COLUMN date         TEXT DEFAULT ''",
        "ALTER TABLE time_logs ADD COLUMN task_name    TEXT DEFAULT ''",
        "ALTER TABLE time_logs ADD COLUMN project_id   TEXT DEFAULT ''",
        "ALTER TABLE time_logs ADD COLUMN task_id      TEXT DEFAULT ''",
        "ALTER TABLE time_logs ADD COLUMN hours        REAL DEFAULT 0",
        "ALTER TABLE time_logs ADD COLUMN minutes      INTEGER DEFAULT 0",
        "ALTER TABLE time_logs ADD COLUMN comments     TEXT DEFAULT ''",
        "ALTER TABLE time_logs ADD COLUMN created      TEXT DEFAULT ''",
        "ALTER TABLE workspaces ADD COLUMN required_hours_per_day REAL DEFAULT 8",
    ]:
        _run_ddl(ddl)


def get_user_role():
    """Fetch current user role from DB — role is not stored in session."""
    try:
        rows = _raw_pg("SELECT role FROM users WHERE id=?",
                       (session.get("user_id",""),), fetch=True)
        return rows[0]["role"] if rows else ""
    except Exception:
        return ""

def require_role(*roles):
    """Decorator for server-side RBAC. Never trust localStorage/client UI permissions."""
    def deco(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            role = get_user_role()
            if role not in roles:
                return jsonify({"error": "Forbidden", "required_roles": list(roles)}), 403
            return fn(*args, **kwargs)
        return wrapper
    return deco

def _looks_like_upload_mime(filename, data, browser_mime=""):
    """Small, dependency-free MIME sniffing. This is not a virus scanner; it rejects common active content."""
    ext = os.path.splitext((filename or "").lower())[1]
    head = (data or b"")[:512]
    if ext in BLOCKED_UPLOAD_EXTENSIONS or ext not in ALLOWED_UPLOAD_EXTENSIONS:
        return False, "File type is not allowed"
    if head.lstrip().lower().startswith((b"<html", b"<!doctype html", b"<script", b"<?php")):
        return False, "Active content is not allowed"
    guessed = mimetypes.guess_type(filename or "")[0] or "application/octet-stream"
    browser_mime = (browser_mime or "").lower()
    if browser_mime.startswith(DANGEROUS_MIME_PREFIXES):
        return False, "Unsafe MIME type"
    # Lightweight signature checks for high-risk mismatches.
    signatures = {
        ".pdf": b"%PDF", ".png": b"\x89PNG", ".jpg": b"\xff\xd8\xff", ".jpeg": b"\xff\xd8\xff",
        ".gif": (b"GIF87a", b"GIF89a"), ".zip": b"PK\x03\x04"
    }
    sig = signatures.get(ext)
    if sig:
        choices = sig if isinstance(sig, tuple) else (sig,)
        if not any(head.startswith(x) for x in choices):
            return False, f"{ext} content does not match its extension"
    return True, guessed

def _workspace_upload_bytes(db, workspace_id):
    row = db.execute("SELECT COALESCE(SUM(size),0) AS total FROM files WHERE workspace_id=?", (workspace_id,)).fetchone()
    return int((row and row["total"]) or 0)

def scan_upload_for_virus(path, original_name):
    """Virus-scan hook. Return False to block.
    Set VIRUS_SCAN_CMD, e.g. 'clamscan --no-summary', and the file path is appended.
    """
    cmd = os.environ.get("VIRUS_SCAN_CMD", "").strip()
    if not cmd:
        return True, "scan skipped"
    try:
        import subprocess, shlex
        proc = subprocess.run(shlex.split(cmd) + [path], capture_output=True, text=True, timeout=60)
        return proc.returncode == 0, (proc.stdout or proc.stderr or "scan failed")[:500]
    except Exception as e:
        log.error("Virus scan failed for %s: %s", original_name, e)
        return False, "Virus scan failed"


def hash_pw(p):
    """Hash password with bcrypt (falls back to sha256 for legacy check)."""
    try:
        import bcrypt
        return bcrypt.hashpw(p.encode(), bcrypt.gensalt(rounds=12)).decode()
    except ImportError:
        return hashlib.sha256(p.encode()).hexdigest()

def verify_pw(plain, hashed):
    """Verify password — supports both bcrypt and legacy sha256 hashes."""
    try:
        import bcrypt
        if hashed.startswith("$2b$") or hashed.startswith("$2a$"):
            return bcrypt.checkpw(plain.encode(), hashed.encode())
        return hashed == hashlib.sha256(plain.encode()).hexdigest()
    except ImportError:
        return hashed == hashlib.sha256(plain.encode()).hexdigest()

# ── OTP Store (in-memory, auto-expiring) ─────────────────────────────────────
import threading as _threading
_otp_store = {}   # {email: {"code": "123456", "expires": timestamp, "user_id": ..., "workspace_id": ...}}
_otp_lock = _threading.Lock()

def _otp_cleanup():
    """Remove expired OTPs every 2 minutes."""
    while True:
        import time as _time
        _time.sleep(120)
        now = _time.time()
        with _otp_lock:
            expired = [k for k, v in _otp_store.items() if v["expires"] < now]
            for k in expired:
                del _otp_store[k]

_threading.Thread(target=_otp_cleanup, daemon=True).start()

def generate_otp():
    """Generate a 6-digit OTP."""
    return str(secrets.randbelow(900000) + 100000)  # always 6 digits

def send_otp_email(to_email, otp_code, user_name):
    """Premium OTP email — dark theme matching all other notification emails."""
    subject = "Project Tracker \u2014 Your Login Code"
    accent  = "#6366f1"
    # Split code into individual digit spans for spacing
    digits  = "".join(
        f'<td style="padding:0 4px;"><span style="font-size:36px;font-weight:900;'
        f'color:#fff;font-family:monospace;letter-spacing:0;">{d}</span></td>'
        for d in str(otp_code)
    )
    body = f"""<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/></head>
<body style="margin:0;padding:0;background:#0f0f13;font-family:'Helvetica Neue',Helvetica,Arial,sans-serif;">
  <table width="100%" cellpadding="0" cellspacing="0" border="0" style="background:#0f0f13;min-height:100vh;">
    <tr><td align="center" style="padding:40px 16px;">
      <table width="560" cellpadding="0" cellspacing="0" border="0"
             style="max-width:560px;width:100%;background:#18181f;border-radius:20px;
                    overflow:hidden;box-shadow:0 32px 80px rgba(0,0,0,.6);">
        <!-- accent bar -->
        <tr><td style="height:4px;background:linear-gradient(90deg,{accent},transparent);font-size:0;">&nbsp;</td></tr>
        <!-- logo row -->
        <tr><td style="padding:22px 32px 16px;">
          <table width="100%" cellpadding="0" cellspacing="0" border="0">
            <tr>
              <td><span style="font-size:18px;font-weight:900;color:#fff;letter-spacing:-1px;">
                Project<span style="color:{accent};">Tracker</span></span></td>
              <td align="right"><span style="font-size:10px;color:#4a4a5a;letter-spacing:1px;text-transform:uppercase;">Login Code</span></td>
            </tr>
          </table>
        </td></tr>
        <tr><td style="height:1px;background:#2a2a35;margin:0 32px;font-size:0;">&nbsp;</td></tr>
        <!-- body -->
        <tr><td style="padding:32px 32px 24px;">
          <p style="margin:0 0 6px;font-size:26px;font-weight:800;color:#fff;line-height:1.2;">Your login code \U0001f510</p>
          <p style="margin:0 0 28px;font-size:14px;color:#8888a8;line-height:1.6;">
            Hi <strong style="color:#e0e0f0;">{user_name}</strong>,
            use the code below to complete your sign-in.
            It expires in <strong style="color:{accent};">10 minutes</strong>.
          </p>
          <!-- OTP box -->
          <table cellpadding="0" cellspacing="0" border="0" style="margin:0 auto 28px;">
            <tr>
              <td style="background:#111118;border:2px solid {accent};border-radius:16px;padding:20px 32px;text-align:center;">
                <table cellpadding="0" cellspacing="0" border="0" style="margin:0 auto;">
                  <tr>{digits}</tr>
                </table>
                <p style="margin:10px 0 0;font-size:11px;color:#5a5a7a;letter-spacing:1px;text-transform:uppercase;">One-time code</p>
              </td>
            </tr>
          </table>
          <p style="margin:0;font-size:12px;color:#4a4a5a;line-height:1.6;text-align:center;">
            If you didn't request this code, you can safely ignore this email.<br>
            Never share this code with anyone.
          </p>
        </td></tr>
        <!-- footer -->
        <tr><td style="background:#111118;padding:16px 32px;border-top:1px solid #2a2a35;text-align:center;">
          <p style="margin:0;font-size:10px;color:#4a4a5a;letter-spacing:.5px;">
            PROJECT TRACKER &nbsp;\u00b7&nbsp; Team Project Management
          </p>
        </td></tr>
      </table>
    </td></tr>
  </table>
</body>
</html>"""
    try:
        threading.Thread(target=send_email, args=(to_email, subject, body), daemon=True).start()
        return True
    except Exception as e:
        log.error("[OTP] Email send error: %s", e)
        return False
IST_OFFSET = timedelta(hours=5, minutes=30)

def now_ist():
    """Return current datetime in IST (UTC+5:30)."""
    return datetime.utcnow() + IST_OFFSET

def ts():
    """Return current IST time as ISO string with +05:30 offset."""
    return now_ist().strftime('%Y-%m-%dT%H:%M:%S') + '+05:30'


# ── Email Configuration & Function ────────────────────────────────────────────
EMAIL_ENABLED = os.environ.get('EMAIL_ENABLED', 'true').lower() == 'true'
SMTP_SERVER = os.environ.get('SMTP_SERVER', 'smtp.gmail.com')
SMTP_PORT = int(os.environ.get('SMTP_PORT', '587'))
SMTP_USERNAME = os.environ.get('SMTP_USERNAME', '')
SMTP_PASSWORD = os.environ.get('SMTP_PASSWORD', '')
FROM_EMAIL = os.environ.get('FROM_EMAIL', SMTP_USERNAME)
RESEND_API_KEY = os.environ.get('RESEND_API_KEY', '')
# RESEND_FROM_EMAIL must be a verified sender/domain in your Resend account.
# e.g. "noreply@yourdomain.com". If not set, falls back to FROM_EMAIL / SMTP_USERNAME.
# A 403 from Resend almost always means the "from" domain is not verified.
RESEND_FROM_EMAIL = os.environ.get('RESEND_FROM_EMAIL', '')
APP_URL = os.environ.get('APP_URL', 'http://localhost:5000')

def _send_via_resend(to_email, subject, body_html, from_email):
    """Send email via Resend SDK — avoids Cloudflare 1010 blocks that affect
    raw urllib calls from Railway IPs. The official SDK uses requests with
    proper headers/TLS fingerprinting that passes Cloudflare bot checks.

    Error 1010 = Cloudflare Access Denied (bot fingerprint mismatch on raw
    urllib calls). Switching to the resend SDK resolves this entirely.
    """
    if not RESEND_API_KEY:
        return False
    effective_from = RESEND_FROM_EMAIL or from_email or f"noreply@projecttracker.in"
    try:
        import resend as _resend
        _resend.api_key = RESEND_API_KEY
        params = {
            "from": f"Project Tracker <{effective_from}>",
            "to": [to_email],
            "subject": subject,
            "html": body_html,
        }
        resp = _resend.Emails.send(params)
        # SDK raises on error; if we reach here it succeeded
        log.info("[Resend] Sent to %s (id=%s)", to_email, resp.get("id", "?"))
        return True
    except Exception as e:
        log.error("[Resend] Send failed from=%s to=%s error=%s: %s",
                  effective_from, to_email, type(e).__name__, e)
        return False

def send_email(to_email, subject, body_html, workspace_id=None):
    """Send email — tries Resend API first (works on Railway), falls back to SMTP."""
    from_addr = FROM_EMAIL or SMTP_USERNAME or 'noreply@project-tracker.in'

    # ── Try Resend API first (no port restrictions) ───────────────────────
    if RESEND_API_KEY:
        log.info("[Email] Using Resend API to %s", to_email)
        return _send_via_resend(to_email, subject, body_html, from_addr)

    # ── Fall back to workspace SMTP settings ──────────────────────────────
    smtp_config = None
    if workspace_id:
        try:
            with get_db() as db:
                ws = db.execute("""SELECT smtp_server, smtp_port, smtp_username, smtp_password,
                                   from_email, email_enabled FROM workspaces WHERE id=?""",
                                (workspace_id,)).fetchone()
                if ws and ws['email_enabled']:
                    smtp_config = {
                        'server': ws['smtp_server'],
                        'port': ws['smtp_port'] or 587,
                        'username': ws['smtp_username'],
                        'password': ws['smtp_password'],
                        'from_email': ws['from_email'] or ws['smtp_username']
                    }
        except Exception as e:
            log.error("[Email] Error loading config: %s", e)

    if not smtp_config or not smtp_config.get('username') or not smtp_config.get('password'):
        if not SMTP_USERNAME or not SMTP_PASSWORD:
            log.warning("[Email] Skipped (not configured): %s -> %s", subject, to_email)
            return False
        smtp_config = {
            'server': SMTP_SERVER,
            'port': SMTP_PORT,
            'username': SMTP_USERNAME,
            'password': SMTP_PASSWORD.replace(' ', '') if SMTP_PASSWORD else '',
            'from_email': FROM_EMAIL or SMTP_USERNAME
        }

    import traceback as _tb
    try:
        msg = MIMEMultipart('alternative')
        msg['Subject'] = subject
        msg['From'] = smtp_config['from_email']
        msg['To'] = to_email
        msg.attach(MIMEText(body_html, 'html'))

        user = smtp_config['username']
        pwd  = (smtp_config['password'] or '').replace(' ', '')
        srv  = smtp_config['server']
        port = int(smtp_config['port'] or 587)
        print(f"[SMTP] >>> Connecting {srv}:{port} as {user} pwd_len={len(pwd)}")

        try:
            with smtplib.SMTP(srv, port, timeout=30) as server:
                server.ehlo()
                server.starttls()
                server.ehlo()
                print(f"[SMTP] >>> TLS OK, logging in...")
                server.login(user, pwd)
                print(f"[SMTP] >>> Login OK, sending to {to_email}...")
                server.send_message(msg)
        except Exception as inner_e:
            print(f"[SMTP] >>> STARTTLS failed ({type(inner_e).__name__}: {inner_e}), trying SSL:465...")
            import ssl as _ssl
            ctx = _ssl.create_default_context()
            with smtplib.SMTP_SSL(srv, 465, timeout=30, context=ctx) as server:
                server.login(user, pwd)
                server.send_message(msg)

        log.info("[SMTP] Sent successfully to %s", to_email)
        return True
    except Exception as e:
        log.error("[SMTP] FINAL FAILURE to %s: %s: %s", to_email, type(e).__name__, e)
        _tb.print_exc()
        return False

def _email_escape(value):
    import html as _html
    return _html.escape(str(value or ""), quote=True)


# ══════════════════════════════════════════════════════════════════════════════
# FUTURISTIC EMAIL TEMPLATE ENGINE v3.0
# Dark-glass morphism design — compatible with Gmail, Outlook, Apple Mail, iOS
# All animations use <style> keyframes (supported by Gmail via embedded CSS,
# degraded gracefully in clients that strip styles).
# ══════════════════════════════════════════════════════════════════════════════

def _email_base(
    subject_label: str,
    accent: str,
    header_icon: str,
    header_badge: str,
    inner_html: str,
    cta_url: str,
    cta_text: str,
    *,
    celebration: bool = False,
    warning: bool = False,
    urgent: bool = False,
) -> str:
    """
    Single master template — dark glassmorphism with CSS animations.
    accent       : hex color  (#10b981)
    header_icon  : emoji      (✅)
    header_badge : short text (COMPLETED · TASK)
    celebration  : adds confetti particle burst (task complete)
    warning      : adds amber pulse border (due soon)
    urgent       : adds red strobe indicator (overdue)
    """
    safe_url   = _email_escape(cta_url or APP_URL)
    safe_cta   = _email_escape(cta_text or "Open ProjectTracker →")
    safe_badge = _email_escape(header_badge or "NOTIFICATION")
    safe_icon  = header_icon or "✨"

    # Derived lighter / alpha colours (inline-safe hex expansion)
    accent_20  = accent + "33"   # 20% alpha fallback approximation
    accent_40  = accent + "66"

    # ── confetti dots (celebration only) ─────────────────────────────────────
    confetti_html = ""
    if celebration:
        palette = ["#10b981","#6366f1","#f59e0b","#ef4444","#8b5cf6",
                   "#06b6d4","#f97316","#a78bfa","#34d399","#fbbf24"]
        dots = "".join(
            f'<td style="padding:0 3px;">'
            f'<div style="width:11px;height:11px;border-radius:50%;'
            f'background:{c};display:inline-block;"></div></td>'
            for c in palette
        )
        confetti_html = f"""
        <table role="presentation" cellpadding="0" cellspacing="0" border="0"
               style="margin:0 auto 22px;">
          <tr>{dots}</tr>
        </table>"""

    # ── warning pulse bar ────────────────────────────────────────────────────
    pulse_bar = ""
    if urgent:
        pulse_bar = f"""<div style="height:3px;background:linear-gradient(90deg,#ef4444,#f97316,#ef4444);margin-bottom:0;"></div>"""
    elif warning:
        pulse_bar = f"""<div style="height:3px;background:linear-gradient(90deg,#f59e0b,#fbbf24,#f59e0b);margin-bottom:0;"></div>"""

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<meta name="color-scheme" content="dark"/>
<title>ProjectTracker</title>
<style>
/* ── Animation keyframes (Gmail supports these in <style> blocks) ── */
@keyframes pt-fade-in {{
  from {{ opacity:0; transform:translateY(18px); }}
  to   {{ opacity:1; transform:translateY(0); }}
}}
@keyframes pt-shimmer {{
  0%   {{ background-position:-200% center; }}
  100% {{ background-position: 200% center; }}
}}
@keyframes pt-bar-fill {{
  from {{ width:0%; }}
  to   {{ width:var(--bar-w,12%); }}
}}
@keyframes pt-spin {{
  from {{ transform:rotate(0deg); }}
  to   {{ transform:rotate(360deg); }}
}}
@keyframes pt-pulse {{
  0%,100% {{ opacity:1; }}
  50%     {{ opacity:.45; }}
}}
@keyframes pt-bounce-in {{
  0%   {{ transform:scale(.6); opacity:0; }}
  60%  {{ transform:scale(1.1); opacity:1; }}
  100% {{ transform:scale(1); }}
}}
@keyframes pt-confetti-1 {{ 0%{{transform:rotate(0deg) translateY(0);opacity:1;}} 100%{{transform:rotate(360deg) translateY(-30px);opacity:0;}} }}
@keyframes pt-confetti-2 {{ 0%{{transform:rotate(0deg) translateY(0);opacity:1;}} 100%{{transform:rotate(-270deg) translateY(-24px);opacity:0;}} }}
@keyframes pt-countdown {{
  from {{ stroke-dashoffset:0; }}
  to   {{ stroke-dashoffset:100; }}
}}
@keyframes pt-glow {{
  0%,100% {{ box-shadow:0 0 20px {accent}44; }}
  50%     {{ box-shadow:0 0 40px {accent}88,0 0 80px {accent}22; }}
}}

.pt-card {{ animation:pt-fade-in .55s cubic-bezier(.16,1,.3,1) both; }}
.pt-cta   {{
  display:inline-block;padding:16px 32px;
  background:linear-gradient(135deg,{accent},{accent}bb);
  color:#ffffff!important;font-size:15px;font-weight:800;text-decoration:none;
  border-radius:14px;letter-spacing:-.1px;
  box-shadow:0 12px 40px {accent}55,inset 0 1px 0 rgba(255,255,255,.25);
  transition:filter .2s;
}}
.pt-cta:hover {{ filter:brightness(1.15); }}

@media only screen and (max-width:620px){{
  .pt-outer {{ padding:16px 8px!important; }}
  .pt-card  {{ border-radius:20px!important; }}
  .pt-inner {{ padding:24px 18px!important; }}
  .pt-h1    {{ font-size:26px!important;line-height:32px!important; }}
  .pt-cols  {{ display:block!important; }}
  .pt-col   {{ width:100%!important;padding:0 0 10px!important; }}
}}
</style>
</head>
<body style="margin:0;padding:0;background:#080b14;font-family:-apple-system,BlinkMacSystemFont,'SF Pro Display','Segoe UI',Roboto,Helvetica,Arial,sans-serif;color:#e0e6f0;">

<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0"
       style="background:linear-gradient(160deg,#080b14 0%,#0d1526 40%,#080b14 100%);min-height:100vh;">
  <tr><td class="pt-outer" align="center" style="padding:40px 16px;">

    <!-- Card wrapper -->
    <table role="presentation" class="pt-card" width="600" cellpadding="0" cellspacing="0" border="0"
           style="width:600px;max-width:600px;background:linear-gradient(145deg,#111827,#0f172a);
                  border:1px solid rgba(255,255,255,.08);border-radius:28px;overflow:hidden;
                  box-shadow:0 40px 100px rgba(0,0,0,.7),0 0 0 1px rgba(255,255,255,.04),
                             inset 0 1px 0 rgba(255,255,255,.06);">

      <!-- Accent top bar -->
      {pulse_bar}
      <tr><td style="height:3px;background:linear-gradient(90deg,{accent},#818cf8,{accent});font-size:0;">&nbsp;</td></tr>

      <!-- ── HEADER ── -->
      <tr><td style="padding:28px 32px 22px;background:linear-gradient(135deg,rgba(255,255,255,.04) 0%,rgba(255,255,255,.01) 100%);">
        <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0">
          <tr>
            <!-- Logo -->
            <td style="vertical-align:middle;">
              <table role="presentation" cellpadding="0" cellspacing="0" border="0">
                <tr>
                  <td style="padding-right:10px;vertical-align:middle;">
                    <div style="width:40px;height:40px;border-radius:12px;
                                background:linear-gradient(135deg,{accent},{accent}88);
                                text-align:center;line-height:40px;font-size:20px;
                                box-shadow:0 8px 24px {accent}44;">
                      {safe_icon}
                    </div>
                  </td>
                  <td style="vertical-align:middle;">
                    <div style="font-size:19px;font-weight:900;color:#ffffff;letter-spacing:-.6px;line-height:1;">
                      Project<span style="color:{accent};">Tracker</span>
                    </div>
                    <div style="font-size:10px;font-weight:700;color:rgba(255,255,255,.45);
                                letter-spacing:1.4px;text-transform:uppercase;margin-top:2px;">
                      {safe_badge}
                    </div>
                  </td>
                </tr>
              </table>
            </td>
            <!-- Status chip -->
            <td align="right" style="vertical-align:middle;">
              <div style="display:inline-block;padding:6px 14px;border-radius:999px;
                          background:rgba(255,255,255,.07);border:1px solid rgba(255,255,255,.1);
                          font-size:10px;font-weight:800;color:rgba(255,255,255,.6);
                          letter-spacing:.8px;text-transform:uppercase;">
                Live&nbsp;·&nbsp;{subject_label}
              </div>
            </td>
          </tr>
        </table>
      </td></tr>

      <!-- Hairline separator -->
      <tr><td style="height:1px;background:linear-gradient(90deg,transparent,rgba(255,255,255,.08) 30%,rgba(255,255,255,.08) 70%,transparent);font-size:0;">&nbsp;</td></tr>

      <!-- ── BODY ── -->
      <tr><td class="pt-inner" style="padding:32px 32px 24px;">
        {confetti_html}
        {inner_html}

        <!-- CTA button -->
        <table role="presentation" cellpadding="0" cellspacing="0" border="0" style="margin-top:28px;">
          <tr>
            <td style="border-radius:14px;background:linear-gradient(135deg,{accent},{accent}cc);
                       box-shadow:0 12px 40px {accent}44,inset 0 1px 0 rgba(255,255,255,.2);">
              <a class="pt-cta" href="{safe_url}"
                 style="display:inline-block;padding:15px 30px;color:#ffffff!important;
                        font-size:14px;line-height:18px;font-weight:800;text-decoration:none;
                        border-radius:14px;letter-spacing:.1px;">
                {safe_cta}
              </a>
            </td>
          </tr>
        </table>
      </td></tr>

      <!-- ── FOOTER ── -->
      <tr><td style="padding:18px 32px 24px;
                     background:rgba(0,0,0,.25);
                     border-top:1px solid rgba(255,255,255,.05);">
        <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0">
          <tr>
            <td>
              <p style="margin:0;font-size:11px;color:rgba(255,255,255,.3);line-height:1.7;">
                ProjectTracker &nbsp;·&nbsp; Smart Project & Task Intelligence<br/>
                <a href="{safe_url}" style="color:{accent};text-decoration:none;font-weight:600;">
                  Manage notification preferences
                </a>
              </p>
            </td>
            <td align="right" style="vertical-align:top;">
              <div style="font-size:10px;color:rgba(255,255,255,.2);font-weight:600;letter-spacing:.5px;text-align:right;">
                AUTOMATED<br/>NOTIFICATION
              </div>
            </td>
          </tr>
        </table>
      </td></tr>

    </table>
    <!-- /card -->

  </td></tr>
</table>

</body>
</html>"""


def _task_card(title: str, accent: str, meta_rows: list[tuple[str, str]]) -> str:
    """Reusable dark task card with gradient left border."""
    safe_title = _email_escape(title)
    rows_html = ""
    for label, value in meta_rows:
        rows_html += f"""
        <tr>
          <td style="padding:3px 0;font-size:11px;color:rgba(255,255,255,.4);
                     font-weight:700;letter-spacing:.8px;text-transform:uppercase;
                     white-space:nowrap;padding-right:16px;">{_email_escape(label)}</td>
          <td style="padding:3px 0;font-size:12px;color:rgba(255,255,255,.75);
                     font-weight:600;">{_email_escape(value)}</td>
        </tr>"""
    return f"""
    <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0"
           style="background:linear-gradient(135deg,rgba(255,255,255,.05),rgba(255,255,255,.02));
                  border:1px solid rgba(255,255,255,.08);border-left:4px solid {accent};
                  border-radius:16px;overflow:hidden;margin:16px 0;">
      <tr><td style="padding:20px 24px;">
        <div style="font-size:11px;font-weight:800;color:rgba(255,255,255,.35);
                    letter-spacing:1.2px;text-transform:uppercase;margin-bottom:8px;">Task</div>
        <div style="font-size:20px;font-weight:900;color:#ffffff;
                    letter-spacing:-.3px;line-height:1.3;margin-bottom:14px;">{safe_title}</div>
        <table role="presentation" cellpadding="0" cellspacing="0" border="0"
               style="border-top:1px solid rgba(255,255,255,.06);padding-top:12px;width:100%;">
          {rows_html}
        </table>
      </td></tr>
    </table>"""


def _stat_pill(icon: str, label: str, value: str, color: str) -> str:
    """Small inline stat pill."""
    return f"""
    <td class="pt-col" style="width:50%;padding-right:6px;vertical-align:top;">
      <div style="background:rgba(255,255,255,.04);border:1px solid rgba(255,255,255,.07);
                  border-radius:14px;padding:14px 16px;">
        <div style="font-size:18px;margin-bottom:6px;">{icon}</div>
        <div style="font-size:10px;font-weight:800;color:rgba(255,255,255,.35);
                    letter-spacing:.9px;text-transform:uppercase;">{_email_escape(label)}</div>
        <div style="font-size:15px;font-weight:900;color:{color};margin-top:4px;">{_email_escape(value)}</div>
      </div>
    </td>"""


def _avatar_row(name: str, accent: str, sub: str = "") -> str:
    """Avatar initials circle + name/sub text."""
    initials = "".join(p[0].upper() for p in (name or "?").split()[:2])
    safe_name = _email_escape(name)
    safe_sub  = _email_escape(sub)
    return f"""
    <table role="presentation" cellpadding="0" cellspacing="0" border="0" style="margin-bottom:18px;">
      <tr>
        <td style="padding-right:14px;vertical-align:middle;">
          <div style="width:44px;height:44px;border-radius:14px;
                      background:linear-gradient(135deg,{accent},{accent}88);
                      text-align:center;line-height:44px;font-size:17px;font-weight:900;
                      color:#ffffff;box-shadow:0 8px 20px {accent}44;">{initials}</div>
        </td>
        <td style="vertical-align:middle;">
          <div style="font-size:15px;font-weight:800;color:#ffffff;">{safe_name}</div>
          {f'<div style="font-size:12px;color:rgba(255,255,255,.45);margin-top:2px;">{safe_sub}</div>' if sub else ''}
        </td>
      </tr>
    </table>"""


def _progress_bar(pct: int, accent: str) -> str:
    """Animated progress bar (CSS animation on supporting clients)."""
    w = max(3, min(100, int(pct)))
    return f"""
    <div style="height:8px;background:rgba(255,255,255,.08);border-radius:999px;
                overflow:hidden;margin-top:12px;margin-bottom:6px;">
      <div style="width:{w}%;height:8px;
                  background:linear-gradient(90deg,{accent},{accent}bb);
                  border-radius:999px;
                  animation:pt-bar-fill .9s cubic-bezier(.16,1,.3,1) both;">
      </div>
    </div>
    <div style="font-size:10px;color:rgba(255,255,255,.35);font-weight:700;">{w}% complete</div>"""


# ── Individual send functions ──────────────────────────────────────────────────

def send_task_assigned_email(user_email, user_name, task_title, assigner_name, task_id, workspace_id):
    """Futuristic task-assigned email with assignment animation indicators."""
    accent  = "#6366f1"
    subject = f"📋 New Task Assigned: {task_title}"
    safe_user     = _email_escape(user_name)
    safe_assigner = _email_escape(assigner_name)

    body = f"""
      <!-- Greeting -->
      <h1 class="pt-h1" style="margin:0 0 10px;font-size:30px;font-weight:900;
          color:#ffffff;letter-spacing:-.8px;line-height:1.2;">
        📋 You've got a new task
      </h1>
      <p style="margin:0 0 24px;font-size:15px;line-height:1.7;color:rgba(255,255,255,.55);">
        Hi <strong style="color:#ffffff;">{safe_user}</strong>,
        <strong style="color:{accent};">{safe_assigner}</strong> just assigned a task to you.
        Time to make it happen! 🚀
      </p>

      {_task_card(task_title, accent, [("Assigned by", assigner_name), ("Status", "New · Awaiting action"), ("Priority", "Normal")])}

      <!-- Stat pills -->
      <table role="presentation" class="pt-cols" width="100%"
             cellpadding="0" cellspacing="0" border="0" style="margin:8px 0 4px;">
        <tr>
          {_stat_pill("🎯", "Action required", "Start now", accent)}
          {_stat_pill("⚡", "Priority", "Normal", "#f59e0b")}
        </tr>
      </table>

      <!-- Assignment animation ticker -->
      <div style="margin-top:20px;padding:14px 18px;
                  background:rgba(99,102,241,.1);border:1px solid rgba(99,102,241,.2);
                  border-radius:12px;font-size:12px;color:rgba(255,255,255,.55);line-height:1.6;">
        <span style="color:{accent};font-weight:800;">● LIVE</span>&nbsp;
        Task has been added to your queue · Review and update progress in your dashboard
      </div>"""

    html = _email_base(
        subject_label="TASK", accent=accent, header_icon="📋",
        header_badge="TASK ASSIGNMENT", inner_html=body,
        cta_url=f"{APP_URL}/?action=task&id={task_id}", cta_text="Open Task →",
    )
    send_email(user_email, subject, html, workspace_id)


def send_status_change_email(user_email, user_name, task_title, new_stage, changer_name, workspace_id):
    """Futuristic status-change email with stage indicator."""
    stage_meta = {
        "completed":   ("#10b981", "✅", "Completed",   True,  False),
        "production":  ("#10b981", "🚀", "In Production", False, False),
        "in_progress": ("#6366f1", "⚡", "In Progress", False, False),
        "review":      ("#8b5cf6", "👀", "In Review",   False, False),
        "backlog":     ("#6b7280", "📥", "Backlog",     False, False),
        "testing":     ("#06b6d4", "🧪", "Testing",     False, False),
    }
    accent, icon, label, celeb, _ = stage_meta.get(new_stage, ("#6366f1","🔄","Updated",False,False))
    subject = f"{icon} Task → {label}: {task_title}"
    safe_user    = _email_escape(user_name)
    safe_changer = _email_escape(changer_name)

    # Stage pipeline
    stages = ["backlog","in_progress","review","testing","production","completed"]
    current_idx = stages.index(new_stage) if new_stage in stages else 0
    pipeline = ""
    for i, s in enumerate(stages):
        sm = stage_meta.get(s, ("#6b7280","·","",False,False))
        is_cur = (s == new_stage)
        is_done = (i <= current_idx)
        dot_color = sm[0] if is_done else "rgba(255,255,255,.12)"
        dot_style = f"border:2px solid {sm[0]};" if is_cur else ""
        pipeline += f"""
          <td align="center" style="width:60px;vertical-align:top;">
            <div style="width:28px;height:28px;border-radius:50%;margin:0 auto 4px;
                        background:{dot_color};{dot_style}
                        text-align:center;line-height:{'24' if is_cur else '28'}px;font-size:13px;">
              {sm[1] if is_done else ''}
            </div>
            <div style="font-size:8px;font-weight:700;color:{'#fff' if is_cur else 'rgba(255,255,255,.3)'};
                        letter-spacing:.4px;text-transform:uppercase;">{sm[2][:6]}</div>
          </td>"""

    body = f"""
      <h1 class="pt-h1" style="margin:0 0 10px;font-size:28px;font-weight:900;
          color:#ffffff;letter-spacing:-.6px;line-height:1.2;">
        {icon} Status updated
      </h1>
      <p style="margin:0 0 22px;font-size:15px;line-height:1.7;color:rgba(255,255,255,.55);">
        Hi <strong style="color:#ffffff;">{safe_user}</strong>,
        <strong style="color:{accent};">{safe_changer}</strong>
        moved your task to <strong style="color:{accent};">{label}</strong>.
      </p>

      {_task_card(task_title, accent, [("New status", f"{icon} {label}"), ("Changed by", changer_name)])}

      <!-- Stage pipeline -->
      <div style="margin-top:18px;padding:18px;
                  background:rgba(255,255,255,.03);border:1px solid rgba(255,255,255,.07);
                  border-radius:14px;">
        <div style="font-size:10px;font-weight:800;color:rgba(255,255,255,.3);
                    letter-spacing:1px;text-transform:uppercase;margin-bottom:14px;">Progress pipeline</div>
        <table role="presentation" cellpadding="0" cellspacing="0" border="0" style="width:100%;">
          <tr>{pipeline}</tr>
        </table>
      </div>"""

    html = _email_base(
        subject_label="STATUS", accent=accent, header_icon=icon,
        header_badge=f"STATUS UPDATE · {label.upper()}",
        inner_html=body, cta_url=f"{APP_URL}/?action=tasks", cta_text="View Task →",
        celebration=celeb,
    )
    send_email(user_email, subject, html, workspace_id)


def send_comment_email(user_email, user_name, task_title, commenter_name, comment_text, workspace_id):
    """Futuristic comment notification email."""
    accent  = "#f59e0b"
    subject = f"💬 {commenter_name} commented on: {task_title}"
    safe_user     = _email_escape(user_name)
    safe_comment  = _email_escape(comment_text)

    body = f"""
      <h1 class="pt-h1" style="margin:0 0 10px;font-size:28px;font-weight:900;
          color:#ffffff;letter-spacing:-.6px;line-height:1.2;">
        💬 New comment
      </h1>
      <p style="margin:0 0 22px;font-size:15px;line-height:1.7;color:rgba(255,255,255,.55);">
        Hi <strong style="color:#ffffff;">{safe_user}</strong>,
        someone left a comment on your task.
      </p>

      {_avatar_row(commenter_name, accent, "Commented just now")}

      <div style="margin-bottom:16px;font-size:11px;font-weight:800;color:rgba(255,255,255,.35);
                  letter-spacing:.9px;text-transform:uppercase;">On task</div>
      <div style="font-size:15px;font-weight:700;color:#ffffff;margin-bottom:18px;">
        {_email_escape(task_title)}
      </div>

      <!-- Comment bubble -->
      <div style="background:rgba(245,158,11,.08);border:1px solid rgba(245,158,11,.18);
                  border-left:4px solid {accent};border-radius:14px;padding:18px 20px;
                  font-size:14px;line-height:1.75;color:rgba(255,255,255,.8);">
        {safe_comment}
      </div>"""

    html = _email_base(
        subject_label="COMMENT", accent=accent, header_icon="💬",
        header_badge="NEW COMMENT", inner_html=body,
        cta_url=f"{APP_URL}/?action=tasks", cta_text="Reply to Comment →",
    )
    send_email(user_email, subject, html, workspace_id)


def send_task_reassigned_email(user_email, user_name, task_title, assigner_name, task_id, workspace_id):
    """Futuristic reassignment email."""
    accent  = "#818cf8"
    subject = f"🔄 Task reassigned to you: {task_title}"
    safe_user     = _email_escape(user_name)
    safe_assigner = _email_escape(assigner_name)

    body = f"""
      <h1 class="pt-h1" style="margin:0 0 10px;font-size:28px;font-weight:900;
          color:#ffffff;letter-spacing:-.6px;line-height:1.2;">
        🔄 Task reassigned to you
      </h1>
      <p style="margin:0 0 22px;font-size:15px;line-height:1.7;color:rgba(255,255,255,.55);">
        Hi <strong style="color:#ffffff;">{safe_user}</strong>,
        <strong style="color:{accent};">{safe_assigner}</strong>
        has transferred this task to you. You're now the owner — let's ship it!
      </p>

      {_task_card(task_title, accent, [("Reassigned by", assigner_name), ("Status", "Awaiting your action")])}

      <!-- Live indicator -->
      <div style="margin-top:16px;padding:12px 16px;
                  background:rgba(129,140,248,.1);border:1px solid rgba(129,140,248,.2);
                  border-radius:10px;font-size:12px;color:rgba(255,255,255,.5);line-height:1.6;">
        <span style="color:{accent};font-weight:800;">● REASSIGNED</span>&nbsp;
        Ownership transferred · Your queue has been updated
      </div>"""

    html = _email_base(
        subject_label="REASSIGN", accent=accent, header_icon="🔄",
        header_badge="TASK REASSIGNMENT", inner_html=body,
        cta_url=f"{APP_URL}/?action=task&id={task_id}", cta_text="Open Task →",
    )
    send_email(user_email, subject, html, workspace_id)


def send_task_due_soon_email(user_email, user_name, task_title, due_date, task_id, workspace_id):
    """Futuristic due-soon warning email with countdown indicators."""
    accent  = "#f59e0b"
    subject = f"⏰ Due Tomorrow: {task_title}"
    safe_user = _email_escape(user_name)
    safe_due  = _email_escape(str(due_date))

    body = f"""
      <h1 class="pt-h1" style="margin:0 0 10px;font-size:28px;font-weight:900;
          color:#ffffff;letter-spacing:-.6px;line-height:1.2;">
        ⏰ Due tomorrow — heads up!
      </h1>
      <p style="margin:0 0 22px;font-size:15px;line-height:1.7;color:rgba(255,255,255,.55);">
        Hi <strong style="color:#ffffff;">{safe_user}</strong>,
        this task is due <strong style="color:{accent};">tomorrow</strong>.
        You've got less than 24 hours — don't let it slip!
      </p>

      {_task_card(task_title, accent, [("Due date", due_date), ("Status", "Pending · Action needed"), ("Time left", "< 24 hours")])}

      {_progress_bar(75, accent)}

      <!-- Countdown alert -->
      <table role="presentation" class="pt-cols" width="100%"
             cellpadding="0" cellspacing="0" border="0" style="margin:16px 0 4px;">
        <tr>
          {_stat_pill("⏰", "Time remaining", "< 24 hrs", accent)}
          {_stat_pill("🚨", "Urgency", "High", "#ef4444")}
        </tr>
      </table>

      <div style="margin-top:16px;padding:14px 18px;
                  background:rgba(245,158,11,.1);border:1px solid rgba(245,158,11,.25);
                  border-radius:12px;font-size:12px;color:rgba(255,255,255,.6);line-height:1.6;">
        <span style="color:{accent};font-weight:800;">⚠ REMINDER</span>&nbsp;
        Complete or update status before midnight to avoid an overdue flag.
      </div>"""

    html = _email_base(
        subject_label="DUE SOON", accent=accent, header_icon="⏰",
        header_badge="DUE DATE REMINDER", inner_html=body,
        cta_url=f"{APP_URL}/?action=task&id={task_id}", cta_text="Complete Task →",
        warning=True,
    )
    send_email(user_email, subject, html, workspace_id)


def send_task_overdue_email(user_email, user_name, task_title, due_date, task_id, workspace_id):
    """Futuristic overdue alert email with urgent pulsing indicators."""
    accent  = "#ef4444"
    subject = f"🚨 Overdue: {task_title}"
    safe_user = _email_escape(user_name)
    safe_due  = _email_escape(str(due_date))

    body = f"""
      <h1 class="pt-h1" style="margin:0 0 10px;font-size:28px;font-weight:900;
          color:#ffffff;letter-spacing:-.6px;line-height:1.2;">
        🚨 Task overdue — immediate action needed
      </h1>
      <p style="margin:0 0 22px;font-size:15px;line-height:1.7;color:rgba(255,255,255,.55);">
        Hi <strong style="color:#ffffff;">{safe_user}</strong>,
        the deadline for this task has passed.
        Please complete it or update the due date immediately.
      </p>

      {_task_card(task_title, accent, [("Was due", due_date), ("Status", "OVERDUE · Immediate action required"), ("Days late", "Check dashboard")])}

      <table role="presentation" class="pt-cols" width="100%"
             cellpadding="0" cellspacing="0" border="0" style="margin:8px 0;">
        <tr>
          {_stat_pill("🚨", "Status", "Overdue", accent)}
          {_stat_pill("⚡", "Action", "Update now", "#f97316")}
        </tr>
      </table>

      <!-- Critical alert bar -->
      <div style="margin-top:16px;padding:14px 18px;
                  background:rgba(239,68,68,.12);border:1px solid rgba(239,68,68,.3);
                  border-radius:12px;font-size:12px;color:rgba(255,255,255,.65);line-height:1.6;">
        <span style="color:{accent};font-weight:800;">🔴 CRITICAL</span>&nbsp;
        This task is blocking your project timeline.
        Update status or mark complete immediately to clear this alert.
      </div>"""

    html = _email_base(
        subject_label="OVERDUE", accent=accent, header_icon="🚨",
        header_badge="OVERDUE ALERT", inner_html=body,
        cta_url=f"{APP_URL}/?action=task&id={task_id}", cta_text="Update Task Now →",
        urgent=True,
    )
    send_email(user_email, subject, html, workspace_id)


def send_ticket_assigned_email(user_email, user_name, ticket_title, reporter_name, ticket_id, priority, workspace_id):
    """Futuristic support ticket assignment email."""
    priority_meta = {
        "critical": ("#ef4444", "🔴", "Critical"),
        "high":     ("#f97316", "🟠", "High"),
        "medium":   ("#f59e0b", "🟡", "Medium"),
        "low":      ("#10b981", "🟢", "Low"),
    }
    accent, dot, plabel = priority_meta.get(priority, ("#6366f1", "🔵", "Normal"))
    subject = f"🎫 Ticket assigned: {ticket_title}"
    safe_user     = _email_escape(user_name)
    safe_reporter = _email_escape(reporter_name)

    body = f"""
      <h1 class="pt-h1" style="margin:0 0 10px;font-size:28px;font-weight:900;
          color:#ffffff;letter-spacing:-.6px;line-height:1.2;">
        🎫 New support ticket assigned
      </h1>
      <p style="margin:0 0 22px;font-size:15px;line-height:1.7;color:rgba(255,255,255,.55);">
        Hi <strong style="color:#ffffff;">{safe_user}</strong>,
        <strong style="color:{accent};">{safe_reporter}</strong>
        has assigned you a support ticket. Please review and respond promptly.
      </p>

      {_avatar_row(reporter_name, accent, "Reporter")}

      {_task_card(ticket_title, accent, [("Reported by", reporter_name), ("Priority", f"{dot} {plabel}"), ("Status", "Open · Assigned to you")])}

      <table role="presentation" class="pt-cols" width="100%"
             cellpadding="0" cellspacing="0" border="0" style="margin:8px 0;">
        <tr>
          {_stat_pill(dot, "Priority", plabel, accent)}
          {_stat_pill("🎫", "Type", "Support Ticket", "#818cf8")}
        </tr>
      </table>"""

    html = _email_base(
        subject_label="TICKET", accent=accent, header_icon="🎫",
        header_badge="SUPPORT TICKET", inner_html=body,
        cta_url=f"{APP_URL}/?action=ticket&id={ticket_id}", cta_text="View Ticket →",
        urgent=(priority == "critical"),
        warning=(priority == "high"),
    )
    send_email(user_email, subject, html, workspace_id)


def send_ticket_status_email(user_email, user_name, ticket_title, new_status, changer_name, ticket_id, workspace_id):
    """Futuristic ticket status update email."""
    status_meta = {
        "open":        ("#6366f1", "📂", "Opened"),
        "in_progress": ("#f59e0b", "⚡", "In Progress"),
        "resolved":    ("#10b981", "✅", "Resolved"),
        "closed":      ("#6b7280", "🔒", "Closed"),
    }
    accent, icon, label = status_meta.get(new_status, ("#6366f1", "🎫", "Updated"))
    subject = f"{icon} Ticket {label}: {ticket_title}"
    safe_user    = _email_escape(user_name)
    safe_changer = _email_escape(changer_name)
    celeb = (new_status == "resolved")

    body = f"""
      <h1 class="pt-h1" style="margin:0 0 10px;font-size:28px;font-weight:900;
          color:#ffffff;letter-spacing:-.6px;line-height:1.2;">
        {icon} Ticket {label.lower()}
      </h1>
      <p style="margin:0 0 22px;font-size:15px;line-height:1.7;color:rgba(255,255,255,.55);">
        Hi <strong style="color:#ffffff;">{safe_user}</strong>,
        <strong style="color:{accent};">{safe_changer}</strong>
        updated your ticket status to <strong style="color:{accent};">{label}</strong>.
      </p>

      {_task_card(ticket_title, accent, [("New status", f"{icon} {label}"), ("Updated by", changer_name)])}"""

    html = _email_base(
        subject_label="TICKET", accent=accent, header_icon=icon,
        header_badge=f"TICKET {label.upper()}", inner_html=body,
        cta_url=f"{APP_URL}/?action=ticket&id={ticket_id}", cta_text="View Ticket →",
        celebration=celeb,
    )
    send_email(user_email, subject, html, workspace_id)


def send_mention_email(user_email, user_name, mentioner_name, context_title, comment_text, workspace_id):
    """Futuristic @mention notification email."""
    accent   = "#a78bfa"
    subject  = f"💬 {mentioner_name} mentioned you in: {context_title}"
    safe_user    = _email_escape(user_name)
    safe_comment = _email_escape(comment_text)

    body = f"""
      <h1 class="pt-h1" style="margin:0 0 10px;font-size:28px;font-weight:900;
          color:#ffffff;letter-spacing:-.6px;line-height:1.2;">
        💬 You were mentioned
      </h1>
      <p style="margin:0 0 22px;font-size:15px;line-height:1.7;color:rgba(255,255,255,.55);">
        Hi <strong style="color:#ffffff;">{safe_user}</strong>,
        <strong style="color:{accent};">{_email_escape(mentioner_name)}</strong>
        mentioned you in <strong style="color:#ffffff;">{_email_escape(context_title)}</strong>.
      </p>

      {_avatar_row(mentioner_name, accent, "Mentioned you")}

      <!-- Mention quote block -->
      <div style="background:rgba(167,139,250,.08);border:1px solid rgba(167,139,250,.2);
                  border-left:4px solid {accent};border-radius:14px;padding:18px 20px;
                  margin-bottom:16px;">
        <div style="font-size:10px;font-weight:800;color:rgba(255,255,255,.3);
                    letter-spacing:1px;text-transform:uppercase;margin-bottom:8px;">
          Mentioned in · {_email_escape(context_title)}
        </div>
        <div style="font-size:14px;line-height:1.75;color:rgba(255,255,255,.8);">
          {safe_comment}
        </div>
      </div>"""

    html = _email_base(
        subject_label="MENTION", accent=accent, header_icon="💬",
        header_badge="@MENTION", inner_html=body,
        cta_url=f"{APP_URL}/?action=tasks", cta_text="View Thread →",
    )
    send_email(user_email, subject, html, workspace_id)


def send_task_completed_email(user_email, user_name, task_title, completer_name, workspace_id):
    """Futuristic task-completed email with full celebration animation."""
    accent  = "#10b981"
    subject = f"✅ Completed! {task_title}"
    safe_user      = _email_escape(user_name)
    safe_completer = _email_escape(completer_name)

    body = f"""
      <h1 class="pt-h1" style="margin:0 0 10px;font-size:32px;font-weight:900;
          color:#ffffff;letter-spacing:-.8px;line-height:1.2;">
        🎉 Task complete!
      </h1>
      <p style="margin:0 0 22px;font-size:15px;line-height:1.7;color:rgba(255,255,255,.55);">
        Hi <strong style="color:#ffffff;">{safe_user}</strong>,
        <strong style="color:{accent};">{safe_completer}</strong>
        just wrapped this one up. Excellent work by the team! 🤝
      </p>

      {_task_card(task_title, accent, [("Completed by", completer_name), ("Status", "✅ Done")])}

      {_progress_bar(100, accent)}

      <!-- Celebration message -->
      <div style="margin-top:20px;text-align:center;padding:20px;
                  background:linear-gradient(135deg,rgba(16,185,129,.1),rgba(16,185,129,.04));
                  border:1px solid rgba(16,185,129,.2);border-radius:16px;">
        <div style="font-size:28px;margin-bottom:8px;">🏆</div>
        <div style="font-size:14px;font-weight:800;color:{accent};margin-bottom:4px;">
          Mission Accomplished
        </div>
        <div style="font-size:12px;color:rgba(255,255,255,.45);">
          Great work! Keep the momentum going.
        </div>
      </div>"""

    html = _email_base(
        subject_label="COMPLETE", accent=accent, header_icon="✅",
        header_badge="TASK COMPLETED", inner_html=body,
        cta_url=f"{APP_URL}/?action=projects", cta_text="View Project →",
        celebration=True,
    )
    send_email(user_email, subject, html, workspace_id)




# ── Due Date Checker (runs as background thread every hour) ───────────────────

def _due_date_email_checker():
    """Background thread: checks every hour for tasks due in ~24h or overdue.
    Sends one email per task per day using a simple in-memory dedup set.
    Resets at midnight UTC so users get re-notified the next day if still open."""
    import time as _t
    _notified_due   = set()   # task IDs already sent due-soon email today
    _notified_over  = set()   # task IDs already sent overdue email today
    _last_reset_day = None

    while True:
        try:
            _t.sleep(3600)  # check every hour
            now_utc = datetime.utcnow()
            today   = now_utc.date()

            # Reset dedup sets at midnight UTC
            if _last_reset_day != today:
                _notified_due.clear()
                _notified_over.clear()
                _last_reset_day = today

            tomorrow_str = (now_utc + timedelta(hours=24)).strftime("%Y-%m-%d")
            today_str    = today.strftime("%Y-%m-%d")

            # Query all open tasks with due dates
            try:
                rows = _raw_pg(
                    """SELECT t.id, t.title, t.due, t.assignee, t.workspace_id,
                              u.name, u.email
                       FROM tasks t
                       JOIN users u ON u.id = t.assignee
                       WHERE t.deleted_at = ''
                         AND t.stage NOT IN ('completed','production')
                         AND t.assignee != ''
                         AND t.due != ''
                         AND u.email != ''""",
                    fetch=True
                )
            except Exception as e:
                log.warning("[due-checker] DB error: %s", e)
                continue

            for row in (rows or []):
                tid   = row[0] if isinstance(row, (list, tuple)) else row["id"]
                title = row[1] if isinstance(row, (list, tuple)) else row["title"]
                due   = row[2] if isinstance(row, (list, tuple)) else row["due"]
                name  = row[5] if isinstance(row, (list, tuple)) else row["name"]
                email = row[6] if isinstance(row, (list, tuple)) else row["email"]
                ws    = row[4] if isinstance(row, (list, tuple)) else row["workspace_id"]

                if not due or not email:
                    continue

                due_day = due[:10]  # "YYYY-MM-DD"

                # Overdue: due date has passed
                if due_day < today_str and tid not in _notified_over:
                    _notified_over.add(tid)
                    threading.Thread(
                        target=send_task_overdue_email,
                        args=(email, name, title, due_day, tid, ws),
                        daemon=True
                    ).start()

                # Due soon: due date is tomorrow
                elif due_day == tomorrow_str and tid not in _notified_due:
                    _notified_due.add(tid)
                    threading.Thread(
                        target=send_task_due_soon_email,
                        args=(email, name, title, due_day, tid, ws),
                        daemon=True
                    ).start()

        except Exception as e:
            log.warning("[due-checker] Unexpected error: %s", e)


# Start due-date background checker
_cthread.Thread(target=_due_date_email_checker, daemon=True).start()

# ── Push Notification Worker Pool ────────────────────────────────────────────
# A bounded pool of worker threads processes push sends sequentially.
# Replaces the old pattern of spawning one thread per recipient per event.
# Pool size is tunable via PUSH_POOL_SIZE env var (default: 5).
import queue as _push_q_mod
_PUSH_POOL_SIZE    = int(os.environ.get("PUSH_POOL_SIZE", "5"))
_push_queue        = _push_q_mod.Queue(maxsize=500)
_push_pool_started = False
_push_pool_lock    = threading.Lock()

def _push_worker():
    while True:
        try:
            fn, args, kwargs = _push_queue.get(timeout=5)
        except _push_q_mod.Empty:
            continue
        try:
            fn(*args, **kwargs)
        except Exception as _e:
            log.error("[push_worker] %s", _e)
        finally:
            _push_queue.task_done()

def _ensure_push_pool():
    global _push_pool_started
    if _push_pool_started:
        return
    with _push_pool_lock:
        if not _push_pool_started:
            for _ in range(_PUSH_POOL_SIZE):
                t = threading.Thread(target=_push_worker, daemon=True)
                t.start()
            _push_pool_started = True
            log.info("[push_pool] Started %d push worker threads", _PUSH_POOL_SIZE)

def _enqueue_push(fn, *args, **kwargs):
    """Submit a push task to the bounded worker pool.

    Replaces: threading.Thread(target=fn, args=args, daemon=True).start()
    Usage:    _enqueue_push(push_notification_to_user, db, uid, title, body, url)

    If the queue is full (>500 pending), the task is dropped with a warning
    rather than blocking the request thread or spawning an unbounded thread.
    """
    _ensure_push_pool()
    try:
        _push_queue.put_nowait((fn, args, kwargs))
    except _push_q_mod.Full:
        log.warning("[push_pool] Queue full — dropping push for %s", fn.__name__)


# ── Web Push (VAPID) ──────────────────────────────────────────────────────────
# Keys are read from environment variables VAPID_PRIVATE_KEY / VAPID_PUBLIC_KEY
# (set these as stable Railway env vars so subscriptions survive deploys).
# Falls back to the legacy file only when the env vars are absent — never
# regenerates keys on a running instance, which would invalidate all existing
# browser push subscriptions.
VAPID_KEY_FILE = os.path.join(DATA_DIR, ".pf_vapid")

def get_vapid_keys():
    """Load VAPID key pair.

    Priority order:
      1. VAPID_PRIVATE_KEY / VAPID_PUBLIC_KEY environment variables (preferred).
      2. Legacy key file on disk (migration path).
      3. Generate-and-save only when neither source exists (first-run only).

    Railway's ephemeral filesystem means a newly deployed instance may not
    have the key file; using env vars keeps keys stable across deploys.
    Set VAPID_PRIVATE_KEY and VAPID_PUBLIC_KEY in your Railway service
    variables once, and they survive every redeploy.
    """
    # 1. Prefer stable env vars — never lost across Railway redeploys
    env_priv = os.environ.get("VAPID_PRIVATE_KEY", "").strip()
    env_pub  = os.environ.get("VAPID_PUBLIC_KEY",  "").strip()
    if env_priv and env_pub:
        return {"private": env_priv, "public": env_pub}

    # 2. Fall back to legacy file (migration: first deploy after adding env vars)
    if os.path.exists(VAPID_KEY_FILE):
        try:
            with open(VAPID_KEY_FILE, "r") as f:
                d = json.load(f)
                if d.get("private") and d.get("public"):
                    log.warning(
                        "[VAPID] Using key file — set VAPID_PRIVATE_KEY and "
                        "VAPID_PUBLIC_KEY env vars on Railway to make keys "
                        "persistent across deploys. private=%s…",
                        d["private"][:12]
                    )
                    return d
        except Exception:
            pass

    # 3. First-run only: generate, save to file, and warn loudly
    try:
        keys = {"private": "", "public": "", "generated": ts()}
        try:
            from cryptography.hazmat.primitives.asymmetric.ec import (
                generate_private_key, SECP256R1)
            from cryptography.hazmat.primitives.serialization import (
                Encoding, PublicFormat, PrivateFormat, NoEncryption)
            ec_key = generate_private_key(SECP256R1())
            pub_bytes  = ec_key.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
            priv_bytes = ec_key.private_bytes(Encoding.DER, PrivateFormat.PKCS8, NoEncryption())
            keys = {
                "private":   base64.urlsafe_b64encode(priv_bytes).decode(),
                "public":    base64.urlsafe_b64encode(pub_bytes).decode().rstrip("="),
                "generated": ts(),
            }
        except ImportError:
            pass
        with open(VAPID_KEY_FILE, "w") as f:
            json.dump(keys, f)
        log.error(
            "[VAPID] Generated new key pair and saved to file. "
            "All existing push subscriptions are now INVALID. "
            "Add these to Railway env vars immediately:\n"
            "  VAPID_PRIVATE_KEY=%s\n  VAPID_PUBLIC_KEY=%s",
            keys["private"], keys["public"]
        )
        return keys
    except Exception as e:
        log.error("[VAPID] Key generation error: %s", e)
        return {"private": "", "public": ""}

def send_web_push(subscription_info, payload_dict):
    """Send a Web Push notification. Requires pywebpush."""
    try:
        from pywebpush import webpush, WebPushException
        vapid = get_vapid_keys()
        if not vapid.get("private") or not vapid.get("public"):
            return False
        webpush(
            subscription_info=subscription_info,
            data=json.dumps(payload_dict),
            vapid_private_key=vapid["private"],
            vapid_claims={"sub": "mailto:admin@projectflow.app"}
        )
        return True
    except ImportError:
        return False  # pywebpush not installed — fall back to polling
    except Exception as e:
        log.error("[WebPush] Error: %s", e)
        return False

def push_notification_to_user(db_ignored, user_id, title, body, nav_url="/", tag=None):
    """Send Web Push to all subscriptions for a given user (uses connection pool for thread safety)."""
    try:
        subs = _raw_pg(
            "SELECT * FROM push_subscriptions WHERE user_id=?", (user_id,), fetch=True
        )
    except Exception as e:
        print(f"push_notification DB error: {e}")
        return
    payload = {"title": title, "body": body, "url": nav_url, "tag": tag or title}
    dead_ids = []
    for sub in (subs or []):
        sub_info = {
            "endpoint": sub["endpoint"],
            "keys": {"p256dh": sub["p256dh"], "auth": sub["auth"]}
        }
        ok = send_web_push(sub_info, payload)
        if not ok and sub["endpoint"]:
            dead_ids.append(sub["id"])
    if dead_ids:
        placeholders = ",".join("?" * len(dead_ids))
        _raw_pg(f"DELETE FROM push_subscriptions WHERE id IN ({placeholders})", tuple(dead_ids))

# ── DB Init & Migration ───────────────────────────────────────────────────────
def init_db():
    os.makedirs(UPLOAD_DIR, exist_ok=True)
    with get_db(autocommit=True) as db:
        db.executescript("""
    CREATE TABLE IF NOT EXISTS workspaces (
                id TEXT PRIMARY KEY, name TEXT, invite_code TEXT,
                owner_id TEXT, ai_api_key TEXT, created TEXT,
                smtp_server TEXT, smtp_port INTEGER, smtp_username TEXT,
                smtp_password TEXT, from_email TEXT, email_enabled INTEGER DEFAULT 1,
                otp_enabled INTEGER DEFAULT 0);
            CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY, workspace_id TEXT, name TEXT, email TEXT,
                password TEXT, role TEXT, avatar TEXT, color TEXT, created TEXT,
                two_fa_enabled INTEGER DEFAULT 0, totp_secret TEXT DEFAULT '',
                totp_verified INTEGER DEFAULT 0,
                logged_out_at TEXT DEFAULT '',
                google_id TEXT DEFAULT '',
                google_picture TEXT DEFAULT '',
                auth_provider TEXT DEFAULT 'password');
            CREATE TABLE IF NOT EXISTS projects (
                id TEXT PRIMARY KEY, workspace_id TEXT, name TEXT, description TEXT,
                owner TEXT, members TEXT DEFAULT '[]', start_date TEXT,
                target_date TEXT, progress INTEGER DEFAULT 0, color TEXT, created TEXT,
                team_id TEXT DEFAULT '');
            CREATE TABLE IF NOT EXISTS tasks (
                id TEXT PRIMARY KEY, workspace_id TEXT, title TEXT, description TEXT,
                project TEXT, assignee TEXT, priority TEXT, stage TEXT,
                created TEXT, due TEXT, pct INTEGER DEFAULT 0, comments TEXT DEFAULT '[]',
                team_id TEXT DEFAULT '', parent_id TEXT DEFAULT '',
                story_points INTEGER DEFAULT 0, sprint TEXT DEFAULT '',
                task_type TEXT DEFAULT 'task', labels TEXT DEFAULT '[]');
            CREATE TABLE IF NOT EXISTS subtasks (
                id TEXT PRIMARY KEY, workspace_id TEXT, task_id TEXT,
                title TEXT, done INTEGER DEFAULT 0, assignee TEXT DEFAULT '',
                created TEXT);
            CREATE TABLE IF NOT EXISTS files (
                id TEXT PRIMARY KEY, workspace_id TEXT, name TEXT, size INTEGER,
                mime TEXT, task_id TEXT, project_id TEXT, uploaded_by TEXT, ts TEXT);
            CREATE TABLE IF NOT EXISTS messages (
                id TEXT PRIMARY KEY, workspace_id TEXT, sender TEXT,
                project TEXT, content TEXT, ts TEXT);
            CREATE TABLE IF NOT EXISTS direct_messages (
                id TEXT PRIMARY KEY, workspace_id TEXT, sender TEXT,
                recipient TEXT, content TEXT, read INTEGER DEFAULT 0, ts TEXT);
            CREATE TABLE IF NOT EXISTS dm_reactions (
                id TEXT PRIMARY KEY, workspace_id TEXT, message_id TEXT,
                user_id TEXT, emoji TEXT, ts TEXT,
                UNIQUE(workspace_id, message_id, user_id, emoji));
            CREATE TABLE IF NOT EXISTS notifications (
                id TEXT PRIMARY KEY, workspace_id TEXT, type TEXT, content TEXT,
                user_id TEXT, read INTEGER DEFAULT 0, ts TEXT,
                entity_id TEXT DEFAULT '', entity_type TEXT DEFAULT '',
                followup_sent INTEGER DEFAULT 0);
            CREATE TABLE IF NOT EXISTS reminders (
                id TEXT PRIMARY KEY, workspace_id TEXT, user_id TEXT,
                task_id TEXT, task_title TEXT, remind_at TEXT,
                minutes_before INTEGER DEFAULT 10, fired INTEGER DEFAULT 0,
                created TEXT);
            CREATE TABLE IF NOT EXISTS call_rooms (
                id TEXT PRIMARY KEY, workspace_id TEXT, name TEXT,
                initiator TEXT, participants TEXT DEFAULT '[]',
                status TEXT DEFAULT 'active', created TEXT);
            CREATE TABLE IF NOT EXISTS teams (
                id TEXT PRIMARY KEY, workspace_id TEXT, name TEXT,
                lead_id TEXT, member_ids TEXT DEFAULT '[]', created TEXT);
            CREATE TABLE IF NOT EXISTS tickets (
                id TEXT PRIMARY KEY, workspace_id TEXT, title TEXT, description TEXT,
                type TEXT DEFAULT 'bug', priority TEXT DEFAULT 'medium',
                status TEXT DEFAULT 'open', assignee TEXT, reporter TEXT,
                project TEXT, tags TEXT DEFAULT '[]', created TEXT, updated TEXT,
                team_id TEXT DEFAULT '');
            CREATE TABLE IF NOT EXISTS ticket_comments (
                id TEXT PRIMARY KEY, workspace_id TEXT, ticket_id TEXT,
                user_id TEXT, content TEXT, created TEXT);
            CREATE TABLE IF NOT EXISTS call_signals (
                id TEXT PRIMARY KEY, workspace_id TEXT, room_id TEXT,
                from_user TEXT, to_user TEXT, type TEXT, data TEXT,
                consumed INTEGER DEFAULT 0, created TEXT);
            CREATE TABLE IF NOT EXISTS push_subscriptions (
                id TEXT PRIMARY KEY, user_id TEXT, workspace_id TEXT,
                endpoint TEXT UNIQUE, p256dh TEXT, auth TEXT, created TEXT);
            CREATE TABLE IF NOT EXISTS time_logs (
                id TEXT PRIMARY KEY, workspace_id TEXT, user_id TEXT,
                team_id TEXT DEFAULT '', date TEXT, task_name TEXT,
                project_id TEXT DEFAULT '', task_id TEXT DEFAULT '',
                hours REAL DEFAULT 0, minutes INTEGER DEFAULT 0,
                comments TEXT DEFAULT '', created TEXT);
            CREATE INDEX IF NOT EXISTS idx_tasks_ws        ON tasks(workspace_id);
            CREATE INDEX IF NOT EXISTS idx_tasks_assignee  ON tasks(workspace_id, assignee);
            CREATE INDEX IF NOT EXISTS idx_tasks_project   ON tasks(workspace_id, project);
            CREATE INDEX IF NOT EXISTS idx_tasks_stage     ON tasks(workspace_id, stage);
            CREATE INDEX IF NOT EXISTS idx_notifs_user     ON notifications(workspace_id, user_id, read);
            CREATE INDEX IF NOT EXISTS idx_dm_recipient    ON direct_messages(workspace_id, recipient, read);
            CREATE INDEX IF NOT EXISTS idx_dm_reactions_msg ON dm_reactions(workspace_id, message_id);
            CREATE INDEX IF NOT EXISTS idx_messages_proj   ON messages(workspace_id, project);
            CREATE INDEX IF NOT EXISTS idx_timelogs_user   ON time_logs(workspace_id, user_id);
            CREATE INDEX IF NOT EXISTS idx_timelogs_date   ON time_logs(workspace_id, date);
            CREATE INDEX IF NOT EXISTS idx_reminders_user  ON reminders(workspace_id, user_id, fired);
            CREATE INDEX IF NOT EXISTS idx_tickets_ws      ON tickets(workspace_id, status);
            CREATE TABLE IF NOT EXISTS task_events (
                id TEXT PRIMARY KEY, workspace_id TEXT, task_id TEXT,
                user_id TEXT, event_type TEXT, old_val TEXT DEFAULT '',
                new_val TEXT DEFAULT '', ts TEXT);
            CREATE INDEX IF NOT EXISTS idx_task_events ON task_events(task_id, ts);
            CREATE TABLE IF NOT EXISTS audit_log (
                id TEXT PRIMARY KEY,
                admin_email TEXT DEFAULT '',
                action TEXT DEFAULT '',
                target TEXT DEFAULT '',
                detail TEXT DEFAULT '',
                created TEXT DEFAULT '');
            CREATE INDEX IF NOT EXISTS idx_audit_log_created ON audit_log(created);
        """)
        # ── Consolidated migrations (safe — each wrapped in try/except) ──────
        for stmt in [
            "ALTER TABLE projects ADD COLUMN team_id TEXT DEFAULT ''",
            "ALTER TABLE tickets ADD COLUMN team_id TEXT DEFAULT ''",
            "ALTER TABLE tasks ADD COLUMN team_id TEXT DEFAULT ''",
            "ALTER TABLE messages ADD COLUMN is_system INTEGER DEFAULT 0",
            "ALTER TABLE users ADD COLUMN avatar_data TEXT",
            "ALTER TABLE users ADD COLUMN plain_password TEXT DEFAULT ''",
            "ALTER TABLE users ADD COLUMN two_fa_enabled INTEGER DEFAULT 0",
            "ALTER TABLE users ADD COLUMN totp_secret TEXT DEFAULT ''",
            "ALTER TABLE users ADD COLUMN totp_verified INTEGER DEFAULT 0",
            "ALTER TABLE tasks ADD COLUMN parent_id TEXT DEFAULT ''",
            "ALTER TABLE tasks ADD COLUMN story_points INTEGER DEFAULT 0",
            "ALTER TABLE tasks ADD COLUMN sprint TEXT DEFAULT ''",
            "ALTER TABLE tasks ADD COLUMN task_type TEXT DEFAULT 'task'",
            "ALTER TABLE tasks ADD COLUMN labels TEXT DEFAULT '[]'",
            "ALTER TABLE workspaces ADD COLUMN otp_enabled INTEGER DEFAULT 0",
            "ALTER TABLE workspaces ADD COLUMN dm_enabled INTEGER DEFAULT 1",
            "ALTER TABLE workspaces ADD COLUMN smtp_server TEXT",
            "ALTER TABLE workspaces ADD COLUMN smtp_port INTEGER DEFAULT 587",
            "ALTER TABLE workspaces ADD COLUMN smtp_username TEXT",
            "ALTER TABLE workspaces ADD COLUMN smtp_password TEXT",
            "ALTER TABLE workspaces ADD COLUMN from_email TEXT",
            "ALTER TABLE workspaces ADD COLUMN email_enabled INTEGER DEFAULT 1",
            "ALTER TABLE call_rooms ADD COLUMN invited_users TEXT DEFAULT '[]'",
            "ALTER TABLE notifications ADD COLUMN sender_id TEXT DEFAULT ''",
            "ALTER TABLE users ADD COLUMN last_active TEXT DEFAULT ''",
            "ALTER TABLE users ADD COLUMN google_id TEXT DEFAULT ''",
            "ALTER TABLE users ADD COLUMN google_picture TEXT DEFAULT ''",
            "ALTER TABLE users ADD COLUMN auth_provider TEXT DEFAULT 'password'",
            "CREATE TABLE IF NOT EXISTS time_logs (id TEXT PRIMARY KEY, workspace_id TEXT, user_id TEXT, team_id TEXT DEFAULT '', date TEXT, task_name TEXT, project_id TEXT DEFAULT '', task_id TEXT DEFAULT '', hours REAL DEFAULT 0, minutes INTEGER DEFAULT 0, comments TEXT DEFAULT '', created TEXT)",
            "CREATE INDEX IF NOT EXISTS idx_tasks_ws ON tasks(workspace_id)",
            "CREATE INDEX IF NOT EXISTS idx_tasks_assignee ON tasks(workspace_id, assignee)",
            "CREATE INDEX IF NOT EXISTS idx_tasks_stage ON tasks(workspace_id, stage)",
            "CREATE INDEX IF NOT EXISTS idx_notifs_user ON notifications(workspace_id, user_id, read)",
            "CREATE INDEX IF NOT EXISTS idx_timelogs_user ON time_logs(workspace_id, user_id)",
            "CREATE INDEX IF NOT EXISTS idx_timelogs_date ON time_logs(workspace_id, date)",
            "CREATE TABLE IF NOT EXISTS task_events (id TEXT PRIMARY KEY, workspace_id TEXT, task_id TEXT, user_id TEXT, event_type TEXT, old_val TEXT DEFAULT \'\', new_val TEXT DEFAULT \'\', ts TEXT)",
            "CREATE INDEX IF NOT EXISTS idx_task_events ON task_events(task_id, ts)",
            "CREATE INDEX IF NOT EXISTS idx_tasks_deleted ON tasks(workspace_id, deleted_at)",
            "CREATE INDEX IF NOT EXISTS idx_tasks_proj_stage ON tasks(workspace_id, project, stage)",
            "ALTER TABLE time_logs ADD COLUMN project_id TEXT DEFAULT ''",
            "ALTER TABLE time_logs ADD COLUMN task_id TEXT DEFAULT ''",
            "ALTER TABLE workspaces ADD COLUMN required_hours_per_day REAL DEFAULT 8",
            "CREATE TABLE IF NOT EXISTS vault_cards (id TEXT PRIMARY KEY, user_id TEXT NOT NULL, title TEXT DEFAULT '', tags TEXT DEFAULT '', rows TEXT DEFAULT '[]', cols TEXT DEFAULT '[]', lock_hash TEXT DEFAULT '', created TEXT, updated TEXT)",
            "CREATE INDEX IF NOT EXISTS idx_vault_cards_user ON vault_cards(user_id)",
            "ALTER TABLE vault_cards ADD COLUMN cols TEXT DEFAULT '[]'",
            "CREATE TABLE IF NOT EXISTS vault_audit_log (id TEXT PRIMARY KEY, user_id TEXT NOT NULL, card_id TEXT NOT NULL, action TEXT NOT NULL, detail TEXT DEFAULT '', ip TEXT DEFAULT '', created TEXT)",
            "CREATE INDEX IF NOT EXISTS idx_vault_audit_user ON vault_audit_log(user_id, created)",
            "CREATE INDEX IF NOT EXISTS idx_vault_audit_card ON vault_audit_log(card_id)",
            # Performance indexes for high-frequency polling queries
            "CREATE INDEX IF NOT EXISTS idx_users_ws_active ON users(workspace_id, last_active)",
            "CREATE INDEX IF NOT EXISTS idx_users_id ON users(id)",
            "CREATE INDEX IF NOT EXISTS idx_dm_sender_ws ON direct_messages(workspace_id, sender, recipient, read)",
            "CREATE TABLE IF NOT EXISTS dm_reactions (id TEXT PRIMARY KEY, workspace_id TEXT, message_id TEXT, user_id TEXT, emoji TEXT, ts TEXT, UNIQUE(workspace_id, message_id, user_id, emoji))",
            "CREATE INDEX IF NOT EXISTS idx_dm_reactions_msg ON dm_reactions(workspace_id, message_id)",
            "ALTER TABLE direct_messages ADD COLUMN edited INTEGER DEFAULT 0",
            "ALTER TABLE direct_messages ADD COLUMN deleted INTEGER DEFAULT 0",
            "ALTER TABLE direct_messages ADD COLUMN pinned INTEGER DEFAULT 0",
            "ALTER TABLE direct_messages ADD COLUMN delivered_at TEXT DEFAULT ''",
            "ALTER TABLE direct_messages ADD COLUMN seen_at TEXT DEFAULT ''",
            "ALTER TABLE direct_messages ADD COLUMN reply_to TEXT DEFAULT ''",
            "CREATE INDEX IF NOT EXISTS idx_notifs_ts ON notifications(workspace_id, user_id, ts)",
            "CREATE INDEX IF NOT EXISTS idx_reminders_remind ON reminders(workspace_id, user_id, remind_at, fired)",
            "CREATE INDEX IF NOT EXISTS idx_tasks_deleted ON tasks(workspace_id, deleted_at, created)",
            "CREATE INDEX IF NOT EXISTS idx_tasks_ws_due ON tasks(workspace_id, due, stage)",
            "CREATE INDEX IF NOT EXISTS idx_tasks_ws_created ON tasks(workspace_id, created)",
            "CREATE INDEX IF NOT EXISTS idx_tasks_ws_assignee_due ON tasks(workspace_id, assignee, due)",
            "CREATE INDEX IF NOT EXISTS idx_projects_ws_created ON projects(workspace_id, created)",
            "CREATE INDEX IF NOT EXISTS idx_messages_ws_created ON messages(workspace_id, created)",
            "CREATE INDEX IF NOT EXISTS idx_messages_ws_task_created ON messages(workspace_id, task_id, created)",
            "CREATE INDEX IF NOT EXISTS idx_notifications_ws_user_ts ON notifications(workspace_id, user_id, ts)",
            "CREATE INDEX IF NOT EXISTS idx_direct_messages_ws_recipient_created ON direct_messages(workspace_id, recipient, created)",
            "CREATE INDEX IF NOT EXISTS idx_reminders_ws_user_due ON reminders(workspace_id, user_id, remind_at, fired)",
            "ALTER TABLE workspaces ADD COLUMN plan TEXT DEFAULT 'starter'",
            "ALTER TABLE workspaces ADD COLUMN suspended INTEGER DEFAULT 0",
            # ── Stripe billing ──
            "ALTER TABLE workspaces ADD COLUMN stripe_customer_id TEXT DEFAULT ''",
            "ALTER TABLE workspaces ADD COLUMN stripe_subscription_id TEXT DEFAULT ''",
            "ALTER TABLE workspaces ADD COLUMN plan_expires TEXT DEFAULT ''",
            "ALTER TABLE workspaces ADD COLUMN trial_ends TEXT DEFAULT ''",
            "ALTER TABLE workspaces ADD COLUMN seat_count INTEGER DEFAULT 5",
            # ── Usage metering ──
            "CREATE TABLE IF NOT EXISTS usage_events (id TEXT PRIMARY KEY, workspace_id TEXT, event_type TEXT, quantity INTEGER DEFAULT 1, meta TEXT DEFAULT '{}', created TEXT)",
            "CREATE INDEX IF NOT EXISTS idx_usage_ws ON usage_events(workspace_id, event_type, created)",
            # ── Public API keys ──
            "CREATE TABLE IF NOT EXISTS api_keys (id TEXT PRIMARY KEY, workspace_id TEXT, user_id TEXT, name TEXT, key_hash TEXT, key_prefix TEXT, scopes TEXT DEFAULT '[]', last_used TEXT DEFAULT '', created TEXT, expires TEXT DEFAULT '')",
            "CREATE INDEX IF NOT EXISTS idx_apikeys_ws ON api_keys(workspace_id)",
            "CREATE INDEX IF NOT EXISTS idx_apikeys_hash ON api_keys(key_hash)",
            # ── Webhooks ──
            "CREATE TABLE IF NOT EXISTS webhooks (id TEXT PRIMARY KEY, workspace_id TEXT, name TEXT, url TEXT, events TEXT DEFAULT '[]', secret TEXT DEFAULT '', enabled INTEGER DEFAULT 1, last_triggered TEXT DEFAULT '', fail_count INTEGER DEFAULT 0, created TEXT)",
            "CREATE TABLE IF NOT EXISTS webhook_logs (id TEXT PRIMARY KEY, webhook_id TEXT, event TEXT, status_code INTEGER DEFAULT 0, response TEXT DEFAULT '', created TEXT)",
            "CREATE INDEX IF NOT EXISTS idx_webhooks_ws ON webhooks(workspace_id)",
            "CREATE INDEX IF NOT EXISTS idx_whlogs_wh ON webhook_logs(webhook_id, created)",
            # ── Custom fields ──
            "CREATE TABLE IF NOT EXISTS custom_fields (id TEXT PRIMARY KEY, workspace_id TEXT, entity_type TEXT DEFAULT 'task', name TEXT, field_type TEXT DEFAULT 'text', options TEXT DEFAULT '[]', required INTEGER DEFAULT 0, created TEXT)",
            "CREATE TABLE IF NOT EXISTS custom_field_values (id TEXT PRIMARY KEY, workspace_id TEXT, field_id TEXT, entity_id TEXT, value TEXT DEFAULT '', created TEXT, updated TEXT)",
            "CREATE INDEX IF NOT EXISTS idx_cfv_entity ON custom_field_values(entity_id)",
            "CREATE INDEX IF NOT EXISTS idx_cf_ws ON custom_fields(workspace_id)",
            # ── SLA tracking for tickets ──
            "ALTER TABLE tickets ADD COLUMN sla_hours INTEGER DEFAULT 24",
            "ALTER TABLE tickets ADD COLUMN sla_breached INTEGER DEFAULT 0",
            "ALTER TABLE tickets ADD COLUMN first_response_at TEXT DEFAULT ''",
            "ALTER TABLE tickets ADD COLUMN resolved_at TEXT DEFAULT ''",
            "ALTER TABLE tickets ADD COLUMN sla_due_at TEXT DEFAULT ''",
            # ── Onboarding ──
            "ALTER TABLE workspaces ADD COLUMN onboarding_done INTEGER DEFAULT 0",
            "ALTER TABLE workspaces ADD COLUMN onboarding_step INTEGER DEFAULT 0",
            # ── Enhanced audit log ──
            "ALTER TABLE audit_log ADD COLUMN entity_type TEXT DEFAULT ''",
            "ALTER TABLE audit_log ADD COLUMN entity_id TEXT DEFAULT ''",
            "ALTER TABLE notifications ADD COLUMN entity_id TEXT DEFAULT ''",
            "ALTER TABLE notifications ADD COLUMN entity_type TEXT DEFAULT ''",
            "ALTER TABLE notifications ADD COLUMN followup_sent INTEGER DEFAULT 0",
            "ALTER TABLE audit_log ADD COLUMN old_value TEXT DEFAULT ''",
            "ALTER TABLE audit_log ADD COLUMN new_value TEXT DEFAULT ''",
            # ── Time tracking ──
            "CREATE TABLE IF NOT EXISTS time_entries (id TEXT PRIMARY KEY, workspace_id TEXT, task_id TEXT, user_id TEXT, description TEXT DEFAULT '', minutes INTEGER DEFAULT 0, billable INTEGER DEFAULT 1, date TEXT DEFAULT '', created TEXT, updated TEXT)",
            "CREATE INDEX IF NOT EXISTS idx_time_ws ON time_entries(workspace_id, user_id)",
            "CREATE INDEX IF NOT EXISTS idx_time_task ON time_entries(task_id)",
            "ALTER TABLE audit_log ADD COLUMN ip TEXT DEFAULT ''",
            # Performance indexes missing from original schema
            "CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)",
            "CREATE INDEX IF NOT EXISTS idx_users_workspace ON users(workspace_id)",
            "CREATE INDEX IF NOT EXISTS idx_tickets_assignee ON tickets(workspace_id, assignee)",
            "CREATE INDEX IF NOT EXISTS idx_dm_sender ON direct_messages(workspace_id, sender)",
            "CREATE INDEX IF NOT EXISTS idx_projects_workspace ON projects(workspace_id)",
            # Added: composite index for team-scoped project queries (used by _fetch_app_data_from_db)
            "CREATE INDEX IF NOT EXISTS idx_projects_team ON projects(workspace_id, team_id, created DESC)",
            # Added: composite index for tickets ordered by created (used in get_app_data LIMIT query)
            "CREATE INDEX IF NOT EXISTS idx_tickets_created ON tickets(workspace_id, created DESC)",
            "CREATE INDEX IF NOT EXISTS idx_files_ws_task_ts ON files(workspace_id, task_id, ts)",
            "CREATE INDEX IF NOT EXISTS idx_files_ws_project_ts ON files(workspace_id, project_id, ts)",
            "CREATE INDEX IF NOT EXISTS idx_subtasks_ws_task ON subtasks(workspace_id, task_id)",
            "CREATE INDEX IF NOT EXISTS idx_task_comments_ws_task_ts ON task_comments(workspace_id, task_id, ts)",
            "CREATE INDEX IF NOT EXISTS idx_tickets_ws_project_created ON tickets(workspace_id, project_id, created)",
            "CREATE INDEX IF NOT EXISTS idx_time_logs_ws_project_task_date ON time_logs(workspace_id, project_id, task_id, date)",
            "CREATE INDEX IF NOT EXISTS idx_audit_log_action ON audit_log(action)",
            "CREATE INDEX IF NOT EXISTS idx_audit_log_target ON audit_log(target)",
            # Optimized index for DM conversation fetch (UNION query: each branch hits this index)
            "CREATE INDEX IF NOT EXISTS idx_dm_conversation ON direct_messages(workspace_id, sender, recipient, ts DESC)",
            # Soft-delete support
            "ALTER TABLE users ADD COLUMN deleted_at TEXT DEFAULT ''",
            "ALTER TABLE projects ADD COLUMN deleted_at TEXT DEFAULT ''",
            "ALTER TABLE tasks ADD COLUMN deleted_at TEXT DEFAULT ''",
            # ── SSO / SAML support ──
            "ALTER TABLE workspaces ADD COLUMN sso_enabled INTEGER DEFAULT 0",
            "ALTER TABLE workspaces ADD COLUMN sso_type TEXT DEFAULT ''",
            "ALTER TABLE workspaces ADD COLUMN sso_idp_url TEXT DEFAULT ''",
            "ALTER TABLE workspaces ADD COLUMN sso_entity_id TEXT DEFAULT ''",
            "ALTER TABLE workspaces ADD COLUMN sso_x509_cert TEXT DEFAULT ''",
            "ALTER TABLE workspaces ADD COLUMN sso_attr_email TEXT DEFAULT 'email'",
            "ALTER TABLE workspaces ADD COLUMN sso_attr_name TEXT DEFAULT 'name'",
            "ALTER TABLE workspaces ADD COLUMN sso_allow_password_login INTEGER DEFAULT 1",
            "ALTER TABLE workspaces ADD COLUMN workspace_slug TEXT DEFAULT ''",
            # ── Phase 1: Email verification ──
            "ALTER TABLE users ADD COLUMN email_verified INTEGER DEFAULT 0",
            "ALTER TABLE users ADD COLUMN email_verify_token TEXT DEFAULT ''",
            "ALTER TABLE users ADD COLUMN email_verify_expires TEXT DEFAULT ''",
            # ── Phase 1: Password reset tokens (10-15 min expiry) ──
            "ALTER TABLE users ADD COLUMN pw_reset_token TEXT DEFAULT ''",
            "ALTER TABLE users ADD COLUMN pw_reset_expires TEXT DEFAULT ''",
            # ── Phase 1: Device/session management ──
            """CREATE TABLE IF NOT EXISTS user_sessions (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                workspace_id TEXT NOT NULL,
                device_name TEXT DEFAULT 'Unknown',
                ip TEXT DEFAULT '',
                user_agent TEXT DEFAULT '',
                login_at TEXT,
                last_seen TEXT,
                is_current INTEGER DEFAULT 0
            )""",
            "CREATE INDEX IF NOT EXISTS idx_sessions_user ON user_sessions(user_id)",
            # ── Phase 2: Workspace email invites ──
            """CREATE TABLE IF NOT EXISTS workspace_invites (
                id TEXT PRIMARY KEY,
                workspace_id TEXT NOT NULL,
                email TEXT NOT NULL,
                role TEXT DEFAULT 'viewer',
                invited_by TEXT,
                token TEXT UNIQUE,
                expires TEXT,
                accepted INTEGER DEFAULT 0,
                created TEXT
            )""",
            "CREATE INDEX IF NOT EXISTS idx_invites_token ON workspace_invites(token)",
            "CREATE INDEX IF NOT EXISTS idx_invites_ws ON workspace_invites(workspace_id)",
            # ── Phase 2: Domain auto-join ──
            "ALTER TABLE workspaces ADD COLUMN allowed_domains TEXT DEFAULT '[]'",
            "ALTER TABLE workspaces ADD COLUMN domain_join_requires_approval INTEGER DEFAULT 1",
            # ── Phase 2: Workspace URL slug (already exists but ensure column) ──
            "ALTER TABLE workspaces ADD COLUMN custom_url_id TEXT DEFAULT ''",
        ]:
            try: db.execute(stmt)
            except: pass
        try:
            corrupted = db.execute("SELECT id, name, avatar FROM users WHERE avatar LIKE 'data:image%%' OR (length(avatar) > 10 AND avatar !~ '^[A-Z]{1,2}$')").fetchall()
            for row in corrupted:
                uid, name, av = row['id'], row['name'] or '', row['avatar'] or ''
                initials = ''.join(w[0] for w in name.split() if w)[:2].upper() or '?'
                if av.startswith('data:image'):
                    db.execute("UPDATE users SET avatar=?, avatar_data=? WHERE id=?", (initials, av, uid))
                else:
                    db.execute("UPDATE users SET avatar=? WHERE id=?", (initials, uid))
        except Exception as e:
            print(f"Avatar cleanup migration error: {e}")
        try: db.execute("""CREATE TABLE IF NOT EXISTS subtasks (
            id TEXT PRIMARY KEY, workspace_id TEXT, task_id TEXT,
            title TEXT, done INTEGER DEFAULT 0, assignee TEXT DEFAULT '', created TEXT)""")
        except: pass
        existing_ws = db.execute("SELECT id FROM workspaces LIMIT 1").fetchone()
        if not existing_ws:
            legacy_users = db.execute("SELECT id FROM users WHERE workspace_id IS NULL LIMIT 1").fetchone()
            ws_id = f"ws{int(datetime.now().timestamp()*1000)}"
            invite = secrets.token_hex(4).upper()
            db.execute("INSERT OR IGNORE INTO workspaces VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                       (ws_id,"Demo Workspace",invite,"u1",None,ts(),None,587,None,None,None,1))
            if legacy_users:
                for tbl in ["users","projects","tasks","files","messages","direct_messages","notifications"]:
                    try: db.execute(f"UPDATE {tbl} SET workspace_id=? WHERE workspace_id IS NULL",(ws_id,))
                    except: pass
            else:
                _seed_demo(db, ws_id)

def _seed_demo(db, ws_id):
    for u in [
        ("u1","Alice Chen",  "alice@dev.io",hash_pw("pass123"),"Admin",    "AC","#7c3aed"),
        ("u2","Bob Martinez","bob@dev.io",  hash_pw("pass123"),"Developer","BM","#2563eb"),
        ("u3","Carol Smith", "carol@dev.io",hash_pw("pass123"),"Tester",   "CS","#059669"),
        ("u4","David Kim",   "david@dev.io",hash_pw("pass123"),"Developer","DK","#d97706"),
        ("u5","Eva Wilson",  "eva@dev.io",  hash_pw("pass123"),"Viewer",   "EW","#dc2626"),
    ]:
        try: db.execute("INSERT INTO users(id,workspace_id,name,email,password,role,avatar,color,created,two_fa_enabled) VALUES (?,?,?,?,?,?,?,?,?,?)",
                        (u[0],ws_id,u[1],u[2],u[3],u[4],u[5],u[6],ts(),0))
        except: pass
    for p in [
        ("p1","E-Commerce Platform",   "Modern e-commerce with payment integration & inventory.",       "u1",'["u1","u2","u3","u4"]',"2025-01-15","2025-06-30",65,"#7c3aed"),
        ("p2","Mobile Banking App",    "Secure mobile banking with biometric auth & real-time transfers.","u2",'["u1","u2","u5"]',     "2025-02-01","2025-08-15",40,"#2563eb"),
        ("p3","AI Analytics Dashboard","Real-time analytics powered by ML for business intelligence.",   "u1",'["u1","u3","u4"]',     "2025-03-01","2025-09-30",20,"#059669"),
    ]:
        try: db.execute("INSERT INTO projects VALUES (?,?,?,?,?,?,?,?,?,?,?)",(p[0],ws_id,*p[1:],ts()))
        except: pass
    for t in [
        ("T-001","Design system setup",        "Configure design tokens and component library.",       "p1","u2","high",  "completed",  "2025-02-15",100),
        ("T-002","User authentication API",    "JWT auth with refresh tokens.",                       "p1","u2","high",  "production", "2025-03-01",100),
        ("T-003","Product catalog UI",         "Product listing, filtering and search.",              "p1","u4","medium","development","2025-04-30", 60),
        ("T-004","Payment gateway integration","Stripe integration with webhooks.",                   "p1","u2","high",  "code_review","2025-05-15", 80),
        ("T-005","Cart & checkout flow",       "Shopping cart with multi-step checkout.",             "p1","u4","high",  "testing",    "2025-05-30", 70),
        ("T-006","Inventory management",       "Stock tracking and bulk import.",                     "p1","u2","medium","planning",   "2025-06-15", 10),
        ("T-007","Performance testing",        "Load testing and optimization.",                      "p1","u3","medium","backlog",    "2025-06-25",  0),
        ("T-008","Biometric auth flow",        "Face ID and fingerprint auth.",                       "p2","u2","high",  "development","2025-04-30", 55),
        ("T-009","Real-time transfers",        "WebSocket transfer notifications.",                   "p2","u2","high",  "planning",   "2025-05-30", 20),
        ("T-010","Security audit",             "Penetration testing and compliance.",                 "p2","u3","high",  "backlog",    "2025-07-15",  0),
        ("T-011","ML model integration",       "Connect ML models via REST API.",                     "p3","u4","high",  "development","2025-07-30", 25),
        ("T-012","Chart components",           "Interactive visualization components.",               "p3","u4","medium","code_review","2025-06-15", 85),
        ("T-013","Data pipeline setup",        "ETL pipeline for real-time data ingestion.",          "p3","u2","high",  "blocked",    "2025-06-01", 30),
    ]:
        try: db.execute("INSERT INTO tasks(id,workspace_id,title,description,project,assignee,priority,stage,created,due,pct,comments) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",(t[0],ws_id,t[1],t[2],t[3],t[4],t[5],t[6],ts(),t[7],t[8],"[]"))
        except: pass
    for m in [
        ("m1","u2","p1","Just pushed the auth API to staging!"),
        ("m2","u3","p1","Running test suite, will report results."),
        ("m3","u4","p1","@alice Can you review the product catalog PR?"),
        ("m4","u1","p1","Sure! Checking it after standup."),
    ]:
        try: db.execute("INSERT INTO messages(id,workspace_id,sender,project,content,ts) VALUES (?,?,?,?,?,?)",(m[0],ws_id,m[1],m[2],m[3],ts()))
        except: pass
    for n in [
        ("n1","task_assigned","You have been assigned to Cart & checkout flow","u4",0),
        ("n2","status_change","Task Payment gateway moved to Code Review","u2",0),
        ("n3","comment","Bob commented on Product catalog UI","u4",1),
    ]:
        try: db.execute("INSERT INTO notifications(id,workspace_id,type,content,user_id,read,ts) VALUES (?,?,?,?,?,?,?)",(n[0],ws_id,n[1],n[2],n[3],n[4],ts()))
        except: pass

# Server-side session invalidation cache.
# On logout: logged_out_at is written to DB and cached here.
# On login_required: any session issued before logged_out_at is rejected instantly.
# On login: cache is cleared so the new session is always accepted.
_logout_cache: dict = {}
_logout_cache_lock = _cthread.Lock()

def _get_logged_out_at(uid):
    """Return the user's logged_out_at value, or None if not cached.
    None = not in cache (caller must fetch from DB).
    ""  = cached and confirmed empty (user never logged out or just logged in).
    "ts" = cached logout timestamp (session before this ts is invalid).
    """
    cache_key = f"ptcache:logout_ts:{uid}"
    if _redis_client is not None:
        try:
            val = _redis_client.get(cache_key)
            if val is None:
                return None   # key does not exist in Redis — not cached
            return val        # "" or a timestamp string
        except Exception:
            pass
    # In-process dict
    with _logout_cache_lock:
        if uid not in _logout_cache:
            return None       # not cached yet
        return _logout_cache[uid]  # "" or timestamp

def _set_logged_out_at(uid, ts_val):
    """Store logged_out_at in cache (all workers via Redis, or local dict).
    Also evicts the per-user 'me' cache so /api/auth/me re-checks DB on next call."""
    cache_key = f"ptcache:logout_ts:{uid}"
    me_key    = f"ptcache:me:{uid}"
    if _redis_client is not None:
        try:
            _redis_client.set(cache_key, ts_val or "", ex=86400*30)
            _redis_client.delete(me_key)   # evict stale me-cache on login/logout
            return
        except Exception:
            pass
    with _logout_cache_lock:
        _logout_cache[uid] = ts_val or ""
    # Evict from in-process cache dict too
    try:
        with _CACHE_LOCK:
            _CACHE.pop(f"me:{uid}", None)
    except Exception:
        pass

def login_required(f):
    @wraps(f)
    def d(*a,**kw):
        if "user_id" not in session:
            return jsonify({"error":"Unauthorized"}),401
        uid = session["user_id"]
        login_at = session.get("login_at", "")
        if login_at:
            # Check if this session has been remotely invalidated
            cached_logout = _get_logged_out_at(uid)
            if cached_logout is None:
                # Not cached — fetch from DB once, then cache it
                try:
                    rows = _raw_pg("SELECT logged_out_at FROM users WHERE id=?", (uid,), fetch=True)
                    cached_logout = rows[0].get("logged_out_at","") if rows else ""
                    _set_logged_out_at(uid, cached_logout)
                except Exception:
                    cached_logout = ""
            # If user logged out after this session was created → reject
            if cached_logout and login_at < cached_logout:
                session.clear()
                return jsonify({"error":"Session expired. Please log in again."}),401
        return f(*a,**kw)
    return d

def wid(): return session.get("workspace_id","")

# ── Auth ──────────────────────────────────────────────────────────────────────


# ══════════════════════════════════════════════════════════════════════════════
# GOOGLE OAUTH 2.0
# Set env vars: GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, APP_BASE_URL
# Redirect URI to register in Google Cloud Console:
#   {APP_BASE_URL}/api/auth/google/callback
# ══════════════════════════════════════════════════════════════════════════════
import urllib.parse as _urlparse
import urllib.request as _urlrequest
import json as _json_mod

_GOOGLE_CLIENT_ID     = os.environ.get("GOOGLE_CLIENT_ID", "")
_GOOGLE_CLIENT_SECRET = os.environ.get("GOOGLE_CLIENT_SECRET", "")
_APP_BASE_URL         = os.environ.get("APP_BASE_URL", os.environ.get("APP_URL", "")).rstrip("/")

_GOOGLE_AUTH_URL  = "https://accounts.google.com/o/oauth2/v2/auth"
_GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"
_GOOGLE_USERINFO  = "https://www.googleapis.com/oauth2/v3/userinfo"

def _get_base_url():
    """Return base URL — prefer env var, fall back to detecting from request."""
    if _APP_BASE_URL:
        return _APP_BASE_URL
    # Auto-detect from incoming request (handles reverse proxies via X-Forwarded headers)
    host = request.headers.get("X-Forwarded-Host") or request.headers.get("Host", "")
    proto = request.headers.get("X-Forwarded-Proto", "https")
    return f"{proto}://{host}".rstrip("/")

@app.route("/api/auth/google/login")
def google_login():
    """Step 1 — redirect browser to Google's consent screen."""
    if not _GOOGLE_CLIENT_ID:
        return jsonify({"error": "Google OAuth not configured (missing GOOGLE_CLIENT_ID)"}), 503

    # CSRF protection: random state stored in session
    state = secrets.token_urlsafe(24)
    session["google_oauth_state"] = state

    base_url = _get_base_url()
    redirect_uri = f"{base_url}/api/auth/google/callback"
    log.info("[google_oauth] redirect_uri = %s", redirect_uri)  # log so you can verify it matches Google Console
    params = _urlparse.urlencode({
        "client_id":     _GOOGLE_CLIENT_ID,
        "redirect_uri":  redirect_uri,
        "response_type": "code",
        "scope":         "openid email profile https://www.googleapis.com/auth/calendar.events",
        "state":         state,
        "access_type":   "offline",
        "prompt":        "select_account",
    })
    return redirect(f"{_GOOGLE_AUTH_URL}?{params}")


@app.route("/api/auth/google/callback")
def google_callback():
    """Step 2 — Google redirects here with ?code=... Exchange code for tokens,
    fetch user-info, then create or log in the matching account."""
    error = request.args.get("error")
    if error:
        log.warning("[google_oauth] denied: %s", error)
        return redirect(f"/?action=login&error={_urlparse.quote(error)}")

    # CSRF check
    state = request.args.get("state", "")
    if state != session.pop("google_oauth_state", ""):
        log.warning("[google_oauth] state mismatch — possible CSRF")
        return redirect("/?action=login&error=state_mismatch")

    code = request.args.get("code", "")
    if not code:
        return redirect("/?action=login&error=no_code")

    redirect_uri = f"{_get_base_url()}/api/auth/google/callback"

    # ── Exchange code for tokens ──────────────────────────────────────────────
    try:
        token_data = _urlparse.urlencode({
            "code":          code,
            "client_id":     _GOOGLE_CLIENT_ID,
            "client_secret": _GOOGLE_CLIENT_SECRET,
            "redirect_uri":  redirect_uri,
            "grant_type":    "authorization_code",
        }).encode()
        req = _urlrequest.Request(_GOOGLE_TOKEN_URL, data=token_data,
                                  headers={"Content-Type": "application/x-www-form-urlencoded"})
        with _urlrequest.urlopen(req, timeout=10) as resp:
            tokens = _json_mod.loads(resp.read())
    except Exception as exc:
        log.error("[google_oauth] token exchange failed: %s", exc)
        return redirect("/?action=login&error=token_exchange_failed")

    access_token = tokens.get("access_token", "")
    if not access_token:
        return redirect("/?action=login&error=no_access_token")

    # ── Fetch Google user info ────────────────────────────────────────────────
    try:
        ui_req = _urlrequest.Request(_GOOGLE_USERINFO,
                                     headers={"Authorization": f"Bearer {access_token}"})
        with _urlrequest.urlopen(ui_req, timeout=10) as resp:
            guser = _json_mod.loads(resp.read())
    except Exception as exc:
        log.error("[google_oauth] userinfo fetch failed: %s", exc)
        return redirect("/?action=login&error=userinfo_failed")

    g_id      = guser.get("sub", "")           # stable Google user ID
    g_email   = (guser.get("email") or "").lower().strip()
    g_name    = guser.get("name") or g_email.split("@")[0]
    g_picture = guser.get("picture", "")
    g_verified = guser.get("email_verified", False)

    if not g_email or not g_verified:
        return redirect("/?action=login&error=email_not_verified")

    # ── Find or create user ───────────────────────────────────────────────────
    with get_db() as db:
        # 1. Try match by google_id (returning user who already linked)
        user = db.execute(
            "SELECT * FROM users WHERE google_id=? AND deleted_at=''",
            (g_id,)
        ).fetchone()

        # 2. Try match by email (first-time Google login for existing password user)
        if not user:
            user = db.execute(
                "SELECT * FROM users WHERE email=? AND deleted_at=''",
                (g_email,)
            ).fetchone()
            if user:
                # Link google_id to this existing account
                db.execute(
                    "UPDATE users SET google_id=?, google_picture=?, auth_provider='google' WHERE id=?",
                    (g_id, g_picture, user["id"])
                )

        # 3. No existing account — auto-create in a default workspace
        #    We create a standalone workspace named after the user's domain/name.
        if not user:
            ws_id  = f"ws{secrets.token_hex(8)}"
            ws_name = f"{g_name}'s Workspace"
            uid    = f"u{secrets.token_hex(8)}"
            color  = CLRS[hash(g_email) % len(CLRS)]
            initials = "".join(p[0].upper() for p in g_name.split()[:2]) or "?"
            created_ts = ts()

            db.execute(
                "INSERT INTO workspaces (id, name, created) VALUES (?, ?, ?)",
                (ws_id, ws_name, created_ts)
            )
            db.execute(
                """INSERT INTO users
                   (id, workspace_id, name, email, password, role, avatar, color,
                    created, google_id, google_picture, auth_provider)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
                (uid, ws_id, g_name, g_email, "", "Admin", initials, color,
                 created_ts, g_id, g_picture, "google")
            )
            user = db.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()

        if not user:
            return redirect("/?action=login&error=user_creation_failed")

        # ── Set session (same shape as password login) ────────────────────────
        login_ts = ts()
        # Clear any stale session data first (prevents 401 loop after logout→Google login)
        session.clear()
        session.permanent = True
        session["user_id"]      = user["id"]
        session["workspace_id"] = user["workspace_id"]
        session["role"]         = user.get("role", "")
        session["login_at"]     = login_ts
        session_id = secrets.token_hex(16)
        session["session_id"] = session_id
        session["google_access_token"] = access_token

        db.execute(
            "UPDATE users SET last_active=?, logged_out_at='' WHERE id=?",
            (login_ts, user["id"])
        )
        _set_logged_out_at(user["id"], "")
        _clear_attempts(f"login:{request.remote_addr}:{g_email}")
        _audit("google_login", user["id"], f"{g_name} ({g_email}) signed in via Google")
        _register_session(user["id"], user["workspace_id"], session_id)

    # Redirect to app — JS will detect the active session on next /api/auth/me
    return redirect("/?google_auth=1")


@app.route("/api/auth/google/config")
def google_auth_config():
    """Return whether Google OAuth is configured so the frontend can show/hide button."""
    return jsonify({"enabled": bool(_GOOGLE_CLIENT_ID and _GOOGLE_CLIENT_SECRET)})

# ── Login rate limiter (brute-force protection) ───────────────────────────────
import time as _time_mod
# FIX (Bug 4): Rate limiter now uses Redis atomic INCR so the 5-attempt cap
# holds across ALL gunicorn workers, not just per-process. Falls back to an
# in-process list when Redis is unavailable (local dev / no REDIS_URL).
_login_attempts = {}   # fallback only: {key: [timestamp, ...]}
_LOGIN_MAX = 5         # max attempts per window
_LOGIN_WINDOW = 900    # 15-minute window (Phase 1: max 5 attempts per 15 min)

def _check_rate_limit(key):
    """Return (allowed, seconds_until_reset). Redis-backed when available."""
    if _redis_client is not None:
        try:
            redis_key = f"rl:{key}"
            count = _redis_client.get(redis_key)
            count = int(count) if count else 0
            if count >= _LOGIN_MAX:
                ttl = _redis_client.ttl(redis_key)
                return False, max(1, int(ttl))
            return True, 0
        except Exception:
            pass  # Redis blip — fall through to in-process dict
    # In-process fallback
    now = _time_mod.time()
    attempts = [t for t in _login_attempts.get(key, []) if now - t < _LOGIN_WINDOW]
    _login_attempts[key] = attempts
    if len(attempts) >= _LOGIN_MAX:
        wait = int(_LOGIN_WINDOW - (now - attempts[0]))
        return False, max(1, wait)
    return True, 0

def _record_attempt(key):
    if _redis_client is not None:
        try:
            redis_key = f"rl:{key}"
            pipe = _redis_client.pipeline()
            pipe.incr(redis_key)
            pipe.expire(redis_key, _LOGIN_WINDOW)
            pipe.execute()
            return
        except Exception:
            pass
    _login_attempts.setdefault(key, []).append(_time_mod.time())

def _clear_attempts(key):
    if _redis_client is not None:
        try:
            _redis_client.delete(f"rl:{key}")
            return
        except Exception:
            pass
    _login_attempts.pop(key, None)

@app.route("/api/auth/login",methods=["POST"])
def login():
    d=request.json or {}
    email=d.get("email","").strip().lower()
    password=d.get("password","")
    # Rate-limit: block brute force after 5 wrong attempts per 60s
    rl_key = f"login:{request.remote_addr}:{email}"
    allowed, wait = _check_rate_limit(rl_key)
    if not allowed:
        return jsonify({"error": f"Too many attempts. Try again in {wait}s."}), 429
    with get_db() as db:
        u=db.execute("SELECT * FROM users WHERE email=?",(email,)).fetchone()
        if not u:
            _record_attempt(rl_key)
            return jsonify({"error":"Invalid email or password"}),401
        if not verify_pw(password, u["password"]):
            _record_attempt(rl_key)
            return jsonify({"error":"Invalid email or password"}),401
        # Upgrade legacy sha256 hash to bcrypt
        if not (u["password"].startswith("$2b$") or u["password"].startswith("$2a$")):
            try:
                new_hash = hash_pw(password)
                db.execute("UPDATE users SET password=? WHERE id=?",(new_hash, u["id"]))
            except Exception: pass
        # ── Google Authenticator (TOTP) — only 2FA method ────────────────────
        totp_active = u.get("totp_verified") and u.get("totp_secret")
        if totp_active:
            return jsonify({"totp_required": True, "user_id": u["id"], "name": u["name"]}), 200
        # ── No 2FA configured — direct login ─────────────────────────────────
        _clear_attempts(rl_key)  # reset limiter on success
        login_ts = ts()
        session.permanent=True
        session["user_id"]=u["id"]
        session["workspace_id"]=u["workspace_id"]
        session["role"]=u.get("role","")  # cache role in session
        session["login_at"]=login_ts       # used to detect remote logout
        session_id = secrets.token_hex(16)
        session["session_id"] = session_id
        try:
            # Clear logged_out_at so this new login is valid
            db.execute("UPDATE users SET last_active=?, logged_out_at='' WHERE id=?", (login_ts, u["id"]))
        except Exception: pass
        # CRITICAL: clear the logout cache so login_required doesn't reject
        # this new session using a stale cached logout timestamp
        _set_logged_out_at(u["id"], "")
        _register_session(u["id"], u["workspace_id"], session_id)
        _audit("user_login", u["id"], f"{u['name']} ({email}) logged in")
        result = dict(u)
        result.pop("totp_secret", None)
        result.pop("password", None)
        result.pop("avatar_data", None)
        # ── Include workspace-scoped dashboard URL in response ────────────────
        try:
            ws_row = db.execute(
                "SELECT name, workspace_slug FROM workspaces WHERE id=?",
                (u["workspace_id"],)
            ).fetchone()
            if ws_row:
                import re as _re
                slug = ws_row["workspace_slug"] or _re.sub(r"[^a-z0-9]+", "-", ws_row["name"].lower().strip()).strip("-") or "workspace"
                result["workspace_dashboard_url"] = f"/{slug}/{u['workspace_id']}/dashboard"
                result["workspace_slug"] = slug
        except Exception:
            pass
        return jsonify(result)

# ── Email OTP routes kept as stubs (for backward compat) but not used in login
@app.route("/api/auth/verify-otp",methods=["POST"])
def verify_otp():
    return jsonify({"error":"Email OTP is disabled. Use Google Authenticator."}),410

@app.route("/api/auth/resend-otp",methods=["POST"])
def resend_otp():
    return jsonify({"error":"Email OTP is disabled. Use Google Authenticator."}),410

@app.route("/api/auth/toggle-2fa",methods=["POST"])
@login_required
def toggle_user_2fa():
    """Toggle email 2FA flag (legacy — TOTP is the primary 2FA method now)."""
    d = request.json or {}
    target_id = d.get("user_id", session["user_id"])
    enabled = bool(d.get("enabled", False))
    with get_db() as db:
        caller = db.execute("SELECT role FROM users WHERE id=?", (session["user_id"],)).fetchone()
        if target_id != session["user_id"] and (not caller or caller["role"] not in ("Admin","Manager")):
            return jsonify({"error": "Only admins can change 2FA for other users"}), 403
        db.execute("UPDATE users SET two_fa_enabled=? WHERE id=? AND workspace_id=?",
                   (1 if enabled else 0, target_id, wid()))
        u = db.execute("SELECT * FROM users WHERE id=?", (target_id,)).fetchone()
        result = dict(u) if u else {}
        result.pop("password", None)
        result.pop("totp_secret", None)
        result.pop("avatar_data", None)
        return jsonify(result)

@app.route("/api/auth/2fa-status")
@login_required
def get_2fa_status():
    """Return 2FA status for all users (admin) or just current user."""
    with get_db() as db:
        caller = db.execute("SELECT role FROM users WHERE id=?", (session["user_id"],)).fetchone()
        if caller and caller["role"] == "Admin":
            rows = db.execute(
                "SELECT id, name, email, role, color, two_fa_enabled, totp_secret, totp_verified FROM users WHERE workspace_id=? ORDER BY name",
                (wid(),)).fetchall()
        else:
            rows = db.execute(
                "SELECT id, name, email, role, color, two_fa_enabled, totp_secret, totp_verified FROM users WHERE id=?",
                (session["user_id"],)).fetchall()
        result = []
        for r in rows:
            d2 = dict(r)
            d2["totp_configured"] = bool(d2.get("totp_secret") and d2.get("totp_verified"))
            d2.pop("totp_secret", None)  # never expose secret over API
            result.append(d2)
        return jsonify(result)

# ── TOTP / Google Authenticator ───────────────────────────────────────────────
def _totp_generate_secret():
    """Generate a random base32 TOTP secret."""
    import base64
    raw = secrets.token_bytes(20)
    return base64.b32encode(raw).decode().rstrip('=')

def _totp_hotp(key_b32, counter):
    """HOTP: HMAC-based OTP (RFC 4226)."""
    import hmac, hashlib, struct
    # Pad base32 to multiple of 8
    pad = (8 - len(key_b32) % 8) % 8
    key = base64.b32decode(key_b32 + '=' * pad, casefold=True)
    msg = struct.pack('>Q', counter)
    h = hmac.new(key, msg, hashlib.sha1).digest()
    offset = h[-1] & 0x0f
    code = (struct.unpack('>I', h[offset:offset+4])[0] & 0x7fffffff) % 1000000
    return f"{code:06d}"

import base64 as _b64_mod, struct as _struct_mod

def _totp_verify(secret, token, window=2):
    """Verify TOTP token with ±window steps (30s each). window=2 allows ±60s clock drift."""
    import time as _t
    counter = int(_t.time()) // 30
    for delta in range(-window, window + 1):
        expected = _totp_hotp(secret, counter + delta)
        if expected == token.strip():
            return True
    return False

def _totp_qr_url(secret, email, issuer="Project Tracker"):
    """Generate otpauth:// URL for QR code rendering."""
    import urllib.parse
    pad = (8 - len(secret) % 8) % 8
    secret_padded = secret + '=' * pad
    params = urllib.parse.urlencode({"secret": secret_padded, "issuer": issuer})
    return f"otpauth://totp/{urllib.parse.quote(issuer)}:{urllib.parse.quote(email)}?{params}"

# ── Pure-Python QR Code generator (no external deps) ─────────────────────────
def _qr_make_matrix(data: str):
    """Generate a QR code matrix for the given string using only stdlib.
    Returns a list-of-lists of booleans (True = dark module)."""
    # We use a minimal QR encoder: Version 3, Error Correction M, byte mode.
    # This handles URLs up to ~77 bytes which covers any otpauth:// URL.
    import struct, math

    # ── Reed-Solomon GF(256) over x^8+x^4+x^3+x^2+1 (QR primitive poly) ────
    GF_EXP = [0]*512; GF_LOG = [0]*256
    x = 1
    for i in range(255):
        GF_EXP[i] = x; GF_LOG[x] = i
        x = x << 1
        if x & 0x100: x ^= 0x11d
    for i in range(255,512): GF_EXP[i] = GF_EXP[i-255]

    def gf_mul(a,b):
        if a==0 or b==0: return 0
        return GF_EXP[GF_LOG[a]+GF_LOG[b]]

    def rs_poly_mul(p,q):
        r = [0]*(len(p)+len(q)-1)
        for i,a in enumerate(p):
            for j,b in enumerate(q):
                r[i+j] ^= gf_mul(a,b)
        return r

    def rs_generator(n):
        g = [1]
        for i in range(n):
            g = rs_poly_mul(g,[1, GF_EXP[i]])
        return g

    def rs_encode(msg_poly, n_ec):
        gen = rs_generator(n_ec)
        rem = list(msg_poly) + [0]*n_ec
        for i in range(len(msg_poly)):
            c = rem[i]
            if c:
                for j,b in enumerate(gen):
                    rem[i+j] ^= gf_mul(b,c)
        return rem[len(msg_poly):]

    # ── Select version (auto: try 2,3,4,5 with EC M) ─────────────────────────
    data_b = data.encode('iso-8859-1') if all(ord(c)<256 for c in data) else data.encode('utf-8')
    n = len(data_b)
    # Version capacities for EC M, byte mode (data codewords, ec codewords per block, blocks)
    VERS = [
        (1, 16, 10, 1),  (2, 28, 16, 1),  (3, 44, 26, 1),
        (4, 64, 18, 2),  (5, 86, 24, 2),  (6, 108,16, 4),
        (7, 124,18, 4),  (8, 154,22, 2),  (9, 182,22, 3),
        (10,216,26, 4),
    ]
    ver_info = None
    for v,cap,ec_per,blk in VERS:
        if n <= cap - 3:  # 2 byte mode indicator + length byte
            ver_info = (v, cap, ec_per, blk); break
    if not ver_info:
        raise ValueError(f"Data too long for QR ({n} bytes)")
    version, data_cap, ec_per_block, num_blocks = ver_info
    size = version*4 + 17

    # ── Build data bit stream ─────────────────────────────────────────────────
    bits = []
    def add_bits(val, count):
        for i in range(count-1,-1,-1): bits.append((val>>i)&1)

    add_bits(0b0100, 4)   # byte mode
    char_count_bits = 8 if version < 10 else 16
    add_bits(n, char_count_bits)
    for byte in data_b: add_bits(byte, 8)
    add_bits(0, 4)  # terminator
    while len(bits)%8: bits.append(0)

    # Convert to codewords and pad
    codewords = [int(''.join(str(b) for b in bits[i:i+8]),2) for i in range(0,len(bits),8)]
    PAD = [0xEC,0x11]
    total_data = data_cap
    while len(codewords) < total_data: codewords.append(PAD[len(codewords)%2])
    codewords = codewords[:total_data]

    # ── Reed-Solomon error correction ─────────────────────────────────────────
    block_size = total_data // num_blocks
    ec_blocks = []; data_blocks = []
    for b in range(num_blocks):
        blk = codewords[b*block_size:(b+1)*block_size]
        data_blocks.append(blk)
        ec_blocks.append(rs_encode(blk, ec_per_block))

    # Interleave
    final_cw = []
    max_d = max(len(b) for b in data_blocks)
    for i in range(max_d):
        for b in data_blocks:
            if i < len(b): final_cw.append(b[i])
    max_e = max(len(b) for b in ec_blocks)
    for i in range(max_e):
        for b in ec_blocks:
            if i < len(b): final_cw.append(b[i])

    # ── Build QR matrix ───────────────────────────────────────────────────────
    DARK=True; LIGHT=False
    mat  = [[LIGHT]*size for _ in range(size)]
    used = [[False]*size for _ in range(size)]

    def place(r,c,v):
        if 0<=r<size and 0<=c<size:
            mat[r][c]=v; used[r][c]=True

    def reserve(r,c):
        if 0<=r<size and 0<=c<size: used[r][c]=True

    def finder(tr,tc):
        for r in range(7):
            for c in range(7):
                v = (r in (0,6)) or (c in (0,6)) or (2<=r<=4 and 2<=c<=4)
                place(tr+r, tc+c, v)
        # Separator
        for i in range(8):
            place(tr+7,tc+i,LIGHT); place(tr+i,tc+7,LIGHT)
            reserve(tr+7,tc+i); reserve(tr+i,tc+7)

    finder(0,0); finder(0,size-7); finder(size-7,0)

    # Timing patterns
    for i in range(8, size-8):
        v = i%2==0
        place(6,i,v); place(i,6,v)

    # Dark module
    place(size-8,8,DARK)

    # Alignment patterns (version >= 2)
    ALIGN_POS = {2:[6,18],3:[6,22],4:[6,26],5:[6,30],6:[6,34],
                 7:[6,22,38],8:[6,24,42],9:[6,26,46],10:[6,28,50]}
    if version in ALIGN_POS:
        pos = ALIGN_POS[version]
        for r in pos:
            for c in pos:
                if used[r][c]: continue
                for dr in range(-2,3):
                    for dc in range(-2,3):
                        v = abs(dr)==2 or abs(dc)==2 or (dr==0 and dc==0)
                        place(r+dr,c+dc,v)

    # Reserve format info areas
    for i in range(9):
        reserve(8,i); reserve(i,8)
    for i in range(size-8,size):
        reserve(8,i); reserve(i,8)

    # ── Place data bits (zigzag) ──────────────────────────────────────────────
    all_bits = []
    for cw in final_cw:
        for i in range(7,-1,-1): all_bits.append((cw>>i)&1)
    # Remainder bits
    REM = [0,7,7,7,7,7,0,0,0,0,0,0,0,3,3,3,3,3,3,3,4,4,4,4,4,4,4,3,3,3,3,3,3]
    all_bits += [0]*REM[version-1]

    bi = 0
    col = size-1
    while col > 0:
        if col == 6: col -= 1
        up = True
        row_range = range(size-1,-1,-1) if up else range(size)
        rows = list(range(size-1,-1,-1))
        going_up = True
        for r in (range(size-1,-1,-1) if going_up else range(size)):
            for dc in range(2):
                c = col-dc
                if not used[r][c]:
                    if bi < len(all_bits):
                        mat[r][c] = bool(all_bits[bi]); bi+=1
        col -= 2

    # ── Apply mask 0 (checkerboard) ───────────────────────────────────────────
    for r in range(size):
        for c in range(size):
            if not used[r][c] and (r+c)%2==0:
                mat[r][c] = not mat[r][c]

    # ── Write format information (EC M, mask 0) ───────────────────────────────
    # Format = EC_M(01) + mask_0(000) = 0b01_000 = 8
    # BCH encoded: precomputed for EC=M, mask=0 → 0x7973 XOR 0x5412 = 0x2D61
    fmt = 0x2D61  # precomputed format string for EC=M, mask pattern 0
    fmt_bits = [(fmt>>i)&1 for i in range(14,-1,-1)]
    # Place format bits around finders
    pos1 = [(8,0),(8,1),(8,2),(8,3),(8,4),(8,5),(8,7),(8,8),(7,8),(5,8),(4,8),(3,8),(2,8),(1,8),(0,8)]
    pos2 = [(size-1,8),(size-2,8),(size-3,8),(size-4,8),(size-5,8),(size-6,8),(size-7,8),(size-8,8),
            (8,size-8),(8,size-7),(8,size-6),(8,size-5),(8,size-4),(8,size-3),(8,size-2),(8,size-1)]
    for i,(r,c) in enumerate(pos1[:15]):
        mat[r][c] = bool(fmt_bits[i])
    for i,(r,c) in enumerate(pos2[:15]):
        mat[r][c] = bool(fmt_bits[i])

    return mat

def _qr_to_svg(mat, cell=8, border=4):
    """Render QR matrix as SVG string."""
    n = len(mat)
    total = n*cell + 2*border
    rects = []
    for r in range(n):
        for c in range(n):
            if mat[r][c]:
                x = border + c*cell
                y = border + r*cell
                rects.append(f'<rect x="{x}" y="{y}" width="{cell}" height="{cell}"/>')
    inner = ''.join(rects)
    return (f'<svg xmlns="http://www.w3.org/2000/svg" width="{total}" height="{total}" '
            f'viewBox="0 0 {total} {total}">'
            f'<rect width="{total}" height="{total}" fill="white"/>'
            f'<g fill="black">{inner}</g>'
            f'</svg>')

def _qr_to_png_base64(mat, cell=8, border=4):
    """Render QR matrix as base64 PNG using only stdlib struct/zlib."""
    import zlib, struct as _st
    n = len(mat)
    img_w = img_h = n*cell + 2*border
    # Build raw RGBA pixels (white background, black modules)
    rows = []
    for r in range(img_h):
        row = [0]  # filter byte
        qr_r = (r - border) // cell
        for c in range(img_w):
            qr_c = (c - border) // cell
            if 0 <= qr_r < n and 0 <= qr_c < n and mat[qr_r][qr_c]:
                row += [0,0,0,255]    # black
            else:
                row += [255,255,255,255]  # white
        rows.append(bytes(row))
    raw = b''.join(rows)
    compressed = zlib.compress(raw, 9)

    def png_chunk(tag, data):
        c = _st.pack('>I', len(data)) + tag + data
        crc = zlib.crc32(tag+data) & 0xffffffff
        return c + _st.pack('>I', crc)

    png = (b'\x89PNG\r\n\x1a\n'
           + png_chunk(b'IHDR', _st.pack('>IIBBBBB', img_w, img_h, 8, 6, 0, 0, 0))
           + png_chunk(b'IDAT', compressed)
           + png_chunk(b'IEND', b''))
    return 'data:image/png;base64,' + base64.b64encode(png).decode()

def _totp_qr_base64(secret, email, issuer="Project Tracker"):
    """Generate a real scannable QR code PNG — pure Python, zero dependencies."""
    otpauth_url = _totp_qr_url(secret, email, issuer)
    try:
        mat = _qr_make_matrix(otpauth_url)
        return _qr_to_png_base64(mat, cell=8, border=4)
    except Exception as e:
        print(f"[QR] Pure-Python QR failed: {e} — trying segno")
    # Try segno if installed
    try:
        import segno, io
        qr = segno.make_qr(otpauth_url, error='M')
        buf = io.BytesIO()
        qr.save(buf, kind='png', scale=6, border=2)
        return 'data:image/png;base64,' + base64.b64encode(buf.getvalue()).decode()
    except ImportError: pass
    # Last resort: SVG (still scannable)
    try:
        mat2 = _qr_make_matrix(otpauth_url)
        svg = _qr_to_svg(mat2, cell=10, border=4)
        return 'data:image/svg+xml;base64,' + base64.b64encode(svg.encode()).decode()
    except Exception as e2:
        print(f"[QR] SVG fallback also failed: {e2}")
    return None


@app.route("/api/auth/totp/setup", methods=["POST"])
@login_required
def totp_setup():
    """Begin TOTP setup: generate a secret and return otpauth URL + optional QR."""
    with get_db() as db:
        u = db.execute("SELECT * FROM users WHERE id=?", (session["user_id"],)).fetchone()
        if not u:
            return jsonify({"error": "User not found"}), 404
        if u.get("totp_verified"):
            return jsonify({"error": "TOTP already configured. Reset it first."}), 400
        secret = _totp_generate_secret()
        db.execute("UPDATE users SET totp_secret=?, totp_verified=0 WHERE id=?", (secret, u["id"]))
        otpauth = _totp_qr_url(secret, u["email"])
        # Try to generate server-side QR (optional — client will render its own too)
        qr = None
        try:
            import qrcode as _qrc, io as _io
            _qr = _qrc.QRCode(error_correction=_qrc.constants.ERROR_CORRECT_M, box_size=8, border=4)
            _qr.add_data(otpauth); _qr.make(fit=True)
            _img = _qr.make_image(fill_color="black", back_color="white")
            _buf = _io.BytesIO(); _img.save(_buf, 'PNG')
            qr = "data:image/png;base64," + base64.b64encode(_buf.getvalue()).decode()
        except Exception:
            pass  # Client-side QRCode.js will handle it
        return jsonify({
            "secret": secret,
            "otpauth": otpauth,
            "qr_image": qr,   # None if qrcode lib not installed — client renders instead
            "email": u["email"]
        })

@app.route("/api/auth/totp/verify-setup", methods=["POST"])
@login_required
def totp_verify_setup():
    """Confirm TOTP setup by verifying the first token from the authenticator app."""
    d = request.json or {}
    token = d.get("token", "").strip().replace(" ", "")
    with get_db() as db:
        u = db.execute("SELECT * FROM users WHERE id=?", (session["user_id"],)).fetchone()
        if not u or not u.get("totp_secret"):
            return jsonify({"error": "No TOTP setup in progress. Call /setup first."}), 400
        if not _totp_verify(u["totp_secret"], token):
            return jsonify({"error": "Invalid code. Check your authenticator app and try again."}), 401
        db.execute("UPDATE users SET totp_verified=1, two_fa_enabled=1 WHERE id=?", (u["id"],))
        return jsonify({"ok": True, "message": "Google Authenticator configured successfully!"})

@app.route("/api/auth/totp/verify", methods=["POST"])
def totp_verify_login():
    """Verify TOTP token during login flow."""
    d = request.json or {}
    user_id = d.get("user_id")
    token = d.get("token", "").strip().replace(" ", "")
    if not user_id or not token:
        return jsonify({"error": "user_id and token required"}), 400
    with get_db() as db:
        u = db.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
        if not u:
            return jsonify({"error": "User not found"}), 404
        if not u.get("totp_secret") or not u.get("totp_verified"):
            return jsonify({"error": "TOTP not configured for this user"}), 400
        if not _totp_verify(u["totp_secret"], token):
            return jsonify({"error": "Invalid authenticator code. Try again."}), 401
        login_ts = ts()
        session.permanent = True
        session["user_id"] = u["id"]
        session["workspace_id"] = u["workspace_id"]
        session["login_at"] = login_ts   # needed for remote logout detection
        try:
            db.execute("UPDATE users SET last_active=?, logged_out_at='' WHERE id=?", (login_ts, u["id"]))
        except Exception: pass
        # Clear logout cache so login_required accepts this new session
        _set_logged_out_at(u["id"], "")
        _audit("user_login_totp", u["id"], f"{u['name']} logged in via Google Authenticator")
        result = dict(u)
        result.pop("password", None)
        result.pop("totp_secret", None)
        result.pop("avatar_data", None)
        # Include workspace-scoped dashboard URL (same as regular login)
        try:
            import re as _re_t
            ws_row = db.execute(
                "SELECT name, workspace_slug FROM workspaces WHERE id=?",
                (u["workspace_id"],)
            ).fetchone()
            if ws_row:
                slug = ws_row["workspace_slug"] or                        _re_t.sub(r"[^a-z0-9]+", "-", ws_row["name"].lower().strip()).strip("-") or                        "workspace"
                result["workspace_dashboard_url"] = f"/{slug}/{u['workspace_id']}/dashboard"
                result["workspace_slug"] = slug
        except Exception:
            pass
        return jsonify(result)

@app.route("/api/auth/totp/reset", methods=["POST"])
@login_required
def totp_reset():
    """Admin resets TOTP for a user (or user resets their own)."""
    d = request.json or {}
    target_id = d.get("user_id", session["user_id"])
    with get_db() as db:
        caller = db.execute("SELECT role FROM users WHERE id=?", (session["user_id"],)).fetchone()
        if target_id != session["user_id"] and (not caller or caller["role"] not in ("Admin", "Manager")):
            return jsonify({"error": "Only admins can reset TOTP for other users"}), 403
        db.execute("UPDATE users SET totp_secret='', totp_verified=0, two_fa_enabled=0 WHERE id=? AND workspace_id=?",
                   (target_id, wid()))
        return jsonify({"ok": True, "message": "TOTP reset. User can now set up a new authenticator."})

@app.route("/api/auth/logout", methods=["POST"])
def logout():
    uid = session.get("user_id", "")
    ws  = session.get("workspace_id", "")
    # Clear session cookie immediately — this device is logged out right now
    session.clear()
    if uid:
        logout_ts = ts()
        # Cache logout timestamp FIRST (instant, in-memory/Redis)
        # so all workers reject other devices immediately on next request
        _set_logged_out_at(uid, logout_ts)
        # Write to DB in background so the logout() returns instantly to client
        # (prevents 499 client-disconnect errors when DB is slow)
        def _bg_logout():
            try:
                _raw_pg("UPDATE users SET logged_out_at=? WHERE id=?", (logout_ts, uid))
            except Exception as _e:
                log.warning("[logout] DB write failed: %s", _e)
            # FIX (Bug 2): Remove push subscriptions here so the frontend
            # does not need a separate POST /api/push/unsubscribe call after
            # logout. That call was arriving after session.clear() and getting
            # a 401, leaving stale subscriptions in the DB.
            try:
                _raw_pg("DELETE FROM push_subscriptions WHERE user_id=?", (uid,))
            except Exception as _e:
                log.warning("[logout] push subscription cleanup failed: %s", _e)
            try:
                _cache_bust_ws(ws)
            except Exception:
                pass
            try:
                _audit("user_logout", uid, "User signed out — all sessions invalidated")
            except Exception:
                pass
        t = _cthread.Thread(target=_bg_logout, daemon=True)
        t.start()
        # FIX (Bug 3): _audit() calls the DB and can block long enough on a
        # slow connection for the gunicorn worker to be recycled (→ 499).
        # Moved inside the background thread so the 200 response goes out first.
    return jsonify({"ok": True})

@app.route("/signout")
@app.route("/sign-out")
def signout_redirect():
    """GET /signout — clear session and redirect to login page."""
    uid = session.get("user_id","")
    if uid:
        logout_ts = ts()
        try: _raw_pg("UPDATE users SET logged_out_at=? WHERE id=?", (logout_ts, uid))
        except Exception: pass
        _set_logged_out_at(uid, logout_ts)
    session.clear()
    return '<html><head><meta http-equiv="refresh" content="0;url=/?action=login"/></head><body>Signing out...</body></html>'


# ══════════════════════════════════════════════════════════════════════════════
# PHASE 1 — AUTH HARDENING
# ══════════════════════════════════════════════════════════════════════════════

# ── Email Verification ────────────────────────────────────────────────────────

def _send_verification_email(user_email, user_name, token, workspace_id=None):
    """Send email verification link."""
    base = os.environ.get("APP_BASE_URL", "https://your-app.railway.app")
    link = f"{base}/api/auth/verify-email?token={token}"
    subject = "Project Tracker — Verify Your Email"
    body = f"""
    <html><body style="font-family:Arial,sans-serif;background:#f4f4f4;padding:20px;">
    <div style="max-width:520px;margin:0 auto;background:#fff;border-radius:12px;overflow:hidden;box-shadow:0 2px 12px rgba(0,0,0,.08);">
      <div style="background:#0a1a00;padding:24px 32px;text-align:center;">
        <h1 style="color:#5a8cff;margin:0;font-size:22px;">Project Tracker</h1>
      </div>
      <div style="padding:32px;">
        <h2 style="color:#111;margin:0 0 8px;">Hi {user_name},</h2>
        <p style="color:#555;margin:0 0 24px;">Click the button below to verify your email address and activate your account.</p>
        <div style="text-align:center;margin:0 0 24px;">
          <a href="{link}" style="display:inline-block;background:#5a8cff;color:#fff;text-decoration:none;padding:14px 32px;border-radius:8px;font-weight:700;font-size:15px;">Verify Email</a>
        </div>
        <p style="color:#888;font-size:12px;">Link expires in 24 hours. If you didn't create an account, ignore this email.</p>
      </div>
    </div></body></html>"""
    threading.Thread(target=send_email, args=(user_email, subject, body, workspace_id), daemon=True).start()

@app.route("/api/auth/verify-email")
def verify_email():
    token = request.args.get("token", "").strip()
    if not token:
        return redirect("/?action=login&error=invalid_token")
    now_str = ts()
    with get_db() as db:
        u = db.execute("SELECT * FROM users WHERE email_verify_token=?", (token,)).fetchone()
        if not u:
            return redirect("/?action=login&error=invalid_token")
        if u["email_verify_expires"] and u["email_verify_expires"] < now_str:
            return redirect("/?action=login&error=token_expired")
        db.execute("UPDATE users SET email_verified=1, email_verify_token='', email_verify_expires='' WHERE id=?", (u["id"],))
    return redirect("/?action=login&verified=1")

@app.route("/api/auth/resend-verification", methods=["POST"])
def resend_verification():
    d = request.json or {}
    email = d.get("email", "").strip().lower()
    if not email:
        return jsonify({"error": "Email required"}), 400
    with get_db() as db:
        u = db.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
        if not u:
            return jsonify({"ok": True})  # don't reveal user existence
        if u.get("email_verified"):
            return jsonify({"ok": True, "already_verified": True})
        token = secrets.token_urlsafe(32)
        from datetime import timedelta
        expires = (now_ist() + timedelta(hours=24)).strftime('%Y-%m-%dT%H:%M:%S') + '+05:30'
        db.execute("UPDATE users SET email_verify_token=?, email_verify_expires=? WHERE id=?", (token, expires, u["id"]))
    _send_verification_email(email, u["name"], token)
    return jsonify({"ok": True})

# ── Forgot Password / Reset Token ─────────────────────────────────────────────

def _send_password_reset_email(user_email, user_name, token, workspace_id=None):
    """Send password reset email. Token expires in 12 minutes."""
    base = os.environ.get("APP_BASE_URL", "https://your-app.railway.app")
    link = f"{base}/?action=reset-password&token={token}"
    subject = "Project Tracker — Reset Your Password"
    body = f"""
    <html><body style="font-family:Arial,sans-serif;background:#f4f4f4;padding:20px;">
    <div style="max-width:520px;margin:0 auto;background:#fff;border-radius:12px;overflow:hidden;box-shadow:0 2px 12px rgba(0,0,0,.08);">
      <div style="background:#0a1a00;padding:24px 32px;text-align:center;">
        <h1 style="color:#5a8cff;margin:0;font-size:22px;">Project Tracker</h1>
      </div>
      <div style="padding:32px;">
        <h2 style="color:#111;margin:0 0 8px;">Hi {user_name},</h2>
        <p style="color:#555;margin:0 0 24px;">Click the button below to reset your password. This link expires in <b>12 minutes</b>.</p>
        <div style="text-align:center;margin:0 0 24px;">
          <a href="{link}" style="display:inline-block;background:#5a8cff;color:#fff;text-decoration:none;padding:14px 32px;border-radius:8px;font-weight:700;font-size:15px;">Reset Password</a>
        </div>
        <p style="color:#888;font-size:12px;">If you didn't request a password reset, you can safely ignore this email.</p>
      </div>
    </div></body></html>"""
    threading.Thread(target=send_email, args=(user_email, subject, body, workspace_id), daemon=True).start()

@app.route("/api/auth/forgot-password", methods=["POST"])
def forgot_password():
    d = request.json or {}
    email = d.get("email", "").strip().lower()
    if not email:
        return jsonify({"error": "Email required"}), 400
    with get_db() as db:
        u = db.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
        if not u:
            return jsonify({"ok": True})  # don't reveal user existence
        token = secrets.token_urlsafe(32)
        from datetime import timedelta
        # 12-minute expiry (within the 10-15 minute requirement)
        expires = (now_ist() + timedelta(minutes=12)).strftime('%Y-%m-%dT%H:%M:%S') + '+05:30'
        db.execute("UPDATE users SET pw_reset_token=?, pw_reset_expires=? WHERE id=?", (token, expires, u["id"]))
    _send_password_reset_email(email, u["name"], token)
    _audit("forgot_password", email, "Password reset requested")
    return jsonify({"ok": True})

@app.route("/api/auth/reset-password", methods=["POST"])
def reset_password():
    d = request.json or {}
    token = d.get("token", "").strip()
    new_pw = d.get("password", "")
    if not token or not new_pw:
        return jsonify({"error": "Token and new password required"}), 400
    if len(new_pw) < 8:
        return jsonify({"error": "Password must be at least 8 characters"}), 400
    now_str = ts()
    with get_db() as db:
        u = db.execute("SELECT * FROM users WHERE pw_reset_token=?", (token,)).fetchone()
        if not u:
            return jsonify({"error": "Invalid or expired reset link"}), 400
        if u["pw_reset_expires"] and u["pw_reset_expires"] < now_str:
            return jsonify({"error": "Reset link expired. Please request a new one."}), 400
        new_hash = hash_pw(new_pw)
        # Invalidate all sessions by updating logged_out_at
        logout_ts = ts()
        db.execute("UPDATE users SET password=?, pw_reset_token='', pw_reset_expires='', logged_out_at=? WHERE id=?",
                   (new_hash, logout_ts, u["id"]))
        _set_logged_out_at(u["id"], logout_ts)
    _audit("password_reset", u["email"], "Password reset via token")
    return jsonify({"ok": True})

# ── Device / Session Management ───────────────────────────────────────────────

def _register_session(uid, ws_id, session_id):
    """Record a new login session in user_sessions table."""
    ua = request.headers.get("User-Agent", "")[:300]
    ip = request.headers.get("X-Forwarded-For", request.remote_addr or "").split(",")[0].strip()[:64]
    # Simple device name from UA
    device_name = "Unknown"
    ua_lower = ua.lower()
    if "mobile" in ua_lower or "android" in ua_lower:
        device_name = "Mobile"
    elif "iphone" in ua_lower or "ipad" in ua_lower:
        device_name = "iPhone/iPad"
    elif "windows" in ua_lower:
        device_name = "Windows PC"
    elif "mac" in ua_lower:
        device_name = "Mac"
    elif "linux" in ua_lower:
        device_name = "Linux"
    now_str = ts()
    try:
        with get_db() as db:
            db.execute(
                "INSERT OR REPLACE INTO user_sessions(id,user_id,workspace_id,device_name,ip,user_agent,login_at,last_seen,is_current) VALUES(?,?,?,?,?,?,?,?,1)",
                (session_id, uid, ws_id, device_name, ip, ua, now_str, now_str)
            )
    except Exception as e:
        log.warning("[session_mgr] Could not register session: %s", e)

@app.route("/api/auth/sessions", methods=["GET"])
@login_required
def list_sessions():
    uid = session.get("user_id")
    sid = session.get("session_id", "")
    with get_db() as db:
        rows = db.execute(
            "SELECT id,device_name,ip,login_at,last_seen FROM user_sessions WHERE user_id=? ORDER BY last_seen DESC LIMIT 20",
            (uid,)
        ).fetchall()
    result = []
    for r in rows:
        result.append({
            "id": r["id"],
            "device_name": r["device_name"],
            "ip": r["ip"],
            "login_at": r["login_at"],
            "last_seen": r["last_seen"],
            "is_current": r["id"] == sid
        })
    return jsonify(result)

@app.route("/api/auth/sessions/<sid>", methods=["DELETE"])
@login_required
def revoke_session(sid):
    uid = session.get("user_id")
    with get_db() as db:
        db.execute("DELETE FROM user_sessions WHERE id=? AND user_id=?", (sid, uid))
    return jsonify({"ok": True})

@app.route("/api/auth/sessions/logout-all", methods=["POST"])
@login_required
def logout_all_sessions():
    uid = session.get("user_id")
    ws  = session.get("workspace_id", "")
    logout_ts = ts()
    _set_logged_out_at(uid, logout_ts)
    try:
        _raw_pg("UPDATE users SET logged_out_at=? WHERE id=?", (logout_ts, uid))
    except Exception: pass
    try:
        with get_db() as db:
            db.execute("DELETE FROM user_sessions WHERE user_id=?", (uid,))
    except Exception: pass
    session.clear()
    _audit("logout_all_sessions", uid, "User logged out from all devices")
    return jsonify({"ok": True})

# ══════════════════════════════════════════════════════════════════════════════
# PHASE 2 — ORGANIZATION / WORKSPACE MODEL
# ══════════════════════════════════════════════════════════════════════════════

# ── Email Invites ─────────────────────────────────────────────────────────────

def _send_workspace_invite_email(to_email, inviter_name, ws_name, token, role, workspace_id=None):
    base = os.environ.get("APP_BASE_URL", "https://your-app.railway.app")
    link = f"{base}/?action=accept-invite&token={token}"
    subject = f"You're invited to join {ws_name} on Project Tracker"
    body = f"""
    <html><body style="font-family:Arial,sans-serif;background:#f4f4f4;padding:20px;">
    <div style="max-width:520px;margin:0 auto;background:#fff;border-radius:12px;overflow:hidden;box-shadow:0 2px 12px rgba(0,0,0,.08);">
      <div style="background:#0a1a00;padding:24px 32px;text-align:center;">
        <h1 style="color:#5a8cff;margin:0;font-size:22px;">Project Tracker</h1>
      </div>
      <div style="padding:32px;">
        <h2 style="color:#111;margin:0 0 8px;">{inviter_name} invited you!</h2>
        <p style="color:#555;margin:0 0 8px;">You've been invited to join the <b>{ws_name}</b> workspace as <b>{role.title()}</b>.</p>
        <div style="text-align:center;margin:24px 0;">
          <a href="{link}" style="display:inline-block;background:#5a8cff;color:#fff;text-decoration:none;padding:14px 32px;border-radius:8px;font-weight:700;font-size:15px;">Accept Invitation</a>
        </div>
        <p style="color:#888;font-size:12px;">Invite link expires in 7 days. If you weren't expecting this, ignore it.</p>
      </div>
    </div></body></html>"""
    threading.Thread(target=send_email, args=(to_email, subject, body, workspace_id), daemon=True).start()

@app.route("/api/workspace/invite", methods=["POST"])
@login_required
def workspace_invite_user():
    """Admin/Owner sends an email invite to a specific address."""
    d = request.json or {}
    email = d.get("email", "").strip().lower()
    role  = d.get("role", "viewer")
    if role not in ("owner","admin","developer","tester","viewer"):
        role = "viewer"
    if not email:
        return jsonify({"error": "Email required"}), 400
    uid  = session.get("user_id")
    ws   = wid()
    with get_db() as db:
        me = db.execute("SELECT role,name FROM users WHERE id=?", (uid,)).fetchone()
        if not me or me["role"] not in ("owner","admin"):
            return jsonify({"error": "Only owners and admins can invite"}), 403
        ws_row = db.execute("SELECT name FROM workspaces WHERE id=?", (ws,)).fetchone()
        ws_name = ws_row["name"] if ws_row else "the workspace"
        # Check if already a member
        existing = db.execute("SELECT id FROM users WHERE email=? AND workspace_id=?", (email, ws)).fetchone()
        if existing:
            return jsonify({"error": "User is already a workspace member"}), 409
        # Create or update invite
        from datetime import timedelta
        token = secrets.token_urlsafe(32)
        expires = (now_ist() + timedelta(days=7)).strftime('%Y-%m-%dT%H:%M:%S') + '+05:30'
        inv_id = f"inv{secrets.token_hex(8)}"
        db.execute(
            "INSERT INTO workspace_invites(id,workspace_id,email,role,invited_by,token,expires,accepted,created) VALUES(?,?,?,?,?,?,?,0,?)",
            (inv_id, ws, email, role, uid, token, expires, ts())
        )
    _send_workspace_invite_email(email, me["name"], ws_name, token, role, ws)
    _audit("workspace_invite_sent", uid, f"Invited {email} as {role}")
    return jsonify({"ok": True, "invite_id": inv_id})

@app.route("/api/auth/accept-invite", methods=["POST"])
def accept_workspace_invite():
    """Accept a workspace email invite — creates or links user account."""
    d = request.json or {}
    token = d.get("token", "").strip()
    name  = d.get("name", "").strip()
    password = d.get("password", "")
    if not token:
        return jsonify({"error": "Invite token required"}), 400
    now_str = ts()
    with get_db() as db:
        inv = db.execute("SELECT * FROM workspace_invites WHERE token=?", (token,)).fetchone()
        if not inv:
            return jsonify({"error": "Invalid or expired invite link"}), 400
        if inv["accepted"]:
            return jsonify({"error": "Invite already used"}), 400
        if inv["expires"] and inv["expires"] < now_str:
            return jsonify({"error": "Invite link has expired"}), 400
        ws_id = inv["workspace_id"]
        email = inv["email"]
        role  = inv["role"]
        # Check if user already exists in any workspace
        existing = db.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
        if existing:
            # Link to this workspace — create a new user record for this workspace
            new_uid = f"u{secrets.token_hex(8)}"
            av = "".join(w[0] for w in (existing["name"] or name or email).split())[:2].upper()
            import random
            c = random.choice(CLRS)
            db.execute(
                "INSERT INTO users(id,workspace_id,name,email,password,role,avatar,color,created,email_verified,auth_provider) VALUES(?,?,?,?,?,?,?,?,?,1,?)",
                (new_uid, ws_id, existing["name"] or name or email.split("@")[0], email, existing["password"], role, av, c, now_str, existing.get("auth_provider","password"))
            )
            uid = new_uid
        else:
            # New user — require name + password
            if not name or not password:
                return jsonify({"error": "Name and password required to create your account"}), 400
            if len(password) < 8:
                return jsonify({"error": "Password must be at least 8 characters"}), 400
            new_uid = f"u{secrets.token_hex(8)}"
            av = "".join(w[0] for w in name.split())[:2].upper() or "?"
            import random
            c = random.choice(CLRS)
            db.execute(
                "INSERT INTO users(id,workspace_id,name,email,password,role,avatar,color,created,email_verified,auth_provider) VALUES(?,?,?,?,?,?,?,?,?,1,?)",
                (new_uid, ws_id, name, email, hash_pw(password), role, av, c, now_str, "password")
            )
            uid = new_uid
        db.execute("UPDATE workspace_invites SET accepted=1 WHERE token=?", (token,))
        # Set up session
        login_ts = ts()
        session.clear()
        session.permanent = True
        session["user_id"] = uid
        session["workspace_id"] = ws_id
        session["role"] = role
        session["login_at"] = login_ts
        session_id = secrets.token_hex(16)
        session["session_id"] = session_id
        _clear_attempts(f"login:{request.remote_addr}:{email}")
        _set_logged_out_at(uid, "")
        ws_row = db.execute("SELECT name FROM workspaces WHERE id=?", (ws_id,)).fetchone()
        ws_name = ws_row["name"] if ws_row else ""
        slug = "".join(c2 for c2 in ws_name.lower().replace(" ","-") if c2.isalnum() or c2=="-")[:30] or ws_id
    _register_session(uid, ws_id, session_id)
    _audit("invite_accepted", email, f"Joined workspace {ws_id} as {role}")
    return jsonify({"ok": True, "workspace_dashboard_url": f"/{slug}/{ws_id}/dashboard"})

@app.route("/api/workspace/invites", methods=["GET"])
@login_required
def list_workspace_invites():
    ws = wid()
    with get_db() as db:
        rows = db.execute(
            "SELECT i.*,u.name as inviter_name FROM workspace_invites i LEFT JOIN users u ON i.invited_by=u.id WHERE i.workspace_id=? ORDER BY i.created DESC LIMIT 50",
            (ws,)
        ).fetchall()
    return jsonify([dict(r) for r in rows])

@app.route("/api/workspace/invites/<inv_id>", methods=["DELETE"])
@login_required
def revoke_workspace_invite(inv_id):
    ws = wid()
    uid = session.get("user_id")
    with get_db() as db:
        me = db.execute("SELECT role FROM users WHERE id=?", (uid,)).fetchone()
        if not me or me["role"] not in ("owner","admin"):
            return jsonify({"error": "Not authorized"}), 403
        db.execute("DELETE FROM workspace_invites WHERE id=? AND workspace_id=?", (inv_id, ws))
    return jsonify({"ok": True})

# ── Domain Auto-Join ──────────────────────────────────────────────────────────

@app.route("/api/workspace/domain-settings", methods=["GET", "POST"])
@login_required
def workspace_domain_settings():
    ws = wid()
    uid = session.get("user_id")
    with get_db() as db:
        me = db.execute("SELECT role FROM users WHERE id=?", (uid,)).fetchone()
        if not me or me["role"] not in ("owner","admin"):
            return jsonify({"error": "Not authorized"}), 403
        ws_row = db.execute("SELECT allowed_domains,domain_join_requires_approval FROM workspaces WHERE id=?", (ws,)).fetchone()
        if request.method == "GET":
            import json as _json
            try:
                domains = _json.loads(ws_row["allowed_domains"] or "[]")
            except Exception:
                domains = []
            return jsonify({
                "allowed_domains": domains,
                "requires_approval": bool(ws_row["domain_join_requires_approval"])
            })
        # POST — update
        d = request.json or {}
        import json as _json
        domains = d.get("allowed_domains", [])
        # Sanitize domains
        clean_domains = []
        for dom in domains:
            dom = dom.strip().lower().lstrip("@")
            if dom and "." in dom:
                clean_domains.append(dom)
        requires_approval = d.get("requires_approval", True)
        db.execute(
            "UPDATE workspaces SET allowed_domains=?, domain_join_requires_approval=? WHERE id=?",
            (_json.dumps(clean_domains), 1 if requires_approval else 0, ws)
        )
    return jsonify({"ok": True, "allowed_domains": clean_domains})

@app.route("/api/auth/domain-join-check", methods=["POST"])
def domain_join_check():
    """Check if an email's domain allows auto-join to any workspace."""
    d = request.json or {}
    email = d.get("email","").strip().lower()
    if not email or "@" not in email:
        return jsonify({"workspaces": []})
    domain = email.split("@")[1]
    import json as _json
    with get_db() as db:
        workspaces = db.execute("SELECT id,name,allowed_domains,domain_join_requires_approval FROM workspaces WHERE suspended=0").fetchall()
    matches = []
    for ws in workspaces:
        try:
            allowed = _json.loads(ws["allowed_domains"] or "[]")
        except Exception:
            allowed = []
        if domain in allowed:
            matches.append({
                "workspace_id": ws["id"],
                "workspace_name": ws["name"],
                "requires_approval": bool(ws["domain_join_requires_approval"])
            })
    return jsonify({"workspaces": matches})

@app.route("/api/auth/domain-join-request", methods=["POST"])
def domain_join_request():
    """User requests to join a workspace via domain match."""
    d = request.json or {}
    email     = d.get("email","").strip().lower()
    ws_id_req = d.get("workspace_id","").strip()
    name      = d.get("name","").strip()
    password  = d.get("password","")
    if not email or not ws_id_req or not name or not password:
        return jsonify({"error": "All fields required"}), 400
    if len(password) < 8:
        return jsonify({"error": "Password must be at least 8 characters"}), 400
    if "@" not in email:
        return jsonify({"error": "Invalid email"}), 400
    domain = email.split("@")[1]
    import json as _json
    with get_db() as db:
        ws = db.execute("SELECT * FROM workspaces WHERE id=? AND suspended=0", (ws_id_req,)).fetchone()
        if not ws:
            return jsonify({"error": "Workspace not found"}), 404
        try:
            allowed = _json.loads(ws["allowed_domains"] or "[]")
        except Exception:
            allowed = []
        if domain not in allowed:
            return jsonify({"error": "Your email domain is not allowed for this workspace"}), 403
        existing = db.execute("SELECT id FROM users WHERE email=? AND workspace_id=?", (email, ws_id_req)).fetchone()
        if existing:
            return jsonify({"error": "You already have an account in this workspace"}), 409
        requires_approval = bool(ws["domain_join_requires_approval"])
        new_uid = f"u{secrets.token_hex(8)}"
        av = "".join(c2 for c2 in name.split())
        av = "".join(w[0] for w in name.split())[:2].upper() or "?"
        import random
        c = random.choice(CLRS)
        now_str = ts()
        # If requires approval, create as pending; otherwise create as viewer immediately
        role = "viewer"
        db.execute(
            "INSERT INTO users(id,workspace_id,name,email,password,role,avatar,color,created,email_verified) VALUES(?,?,?,?,?,?,?,?,?,1)",
            (new_uid, ws_id_req, name, email, hash_pw(password), role, av, c, now_str)
        )
        ws_name = ws["name"]
        slug = "".join(c2 for c2 in ws_name.lower().replace(" ","-") if c2.isalnum() or c2=="-")[:30] or ws_id_req
        if not requires_approval:
            login_ts = ts()
            session.clear()
            session.permanent = True
            session["user_id"] = new_uid
            session["workspace_id"] = ws_id_req
            session["role"] = role
            session["login_at"] = login_ts
            session_id = secrets.token_hex(16)
            session["session_id"] = session_id
            _set_logged_out_at(new_uid, "")
            _register_session(new_uid, ws_id_req, session_id)
            _audit("domain_join", email, f"Auto-joined {ws_id_req} via domain {domain}")
            return jsonify({"ok": True, "workspace_dashboard_url": f"/{slug}/{ws_id_req}/dashboard"})
        else:
            # Notify admins
            _audit("domain_join_request", email, f"Requested access to {ws_id_req} via domain {domain}")
            return jsonify({"ok": True, "pending_approval": True})




@app.route("/api/auth/register",methods=["POST"])
def register():
    d=request.json or {}
    mode=d.get("mode","create")  # 'create' or 'join'
    if not d.get("name") or not d.get("email") or not d.get("password"):
        return jsonify({"error":"All fields required"}),400
    uid=f"u{int(datetime.now().timestamp()*1000)}"
    av="".join(w[0] for w in d["name"].split())[:2].upper()
    c=random.choice(CLRS)
    ws_id=None
    if mode=="create":
        if not d.get("workspace_name"):
            return jsonify({"error":"Workspace name required"}),400
        ws_id=f"ws{int(datetime.now().timestamp()*1000)}"
        invite=secrets.token_hex(4).upper()
        with get_db() as db:
            db.execute("INSERT INTO workspaces VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                       (ws_id,d["workspace_name"],invite,uid,None,ts(),None,587,None,None,None,1))
    elif mode=="join":
        code=d.get("invite_code","").strip().upper()
        with get_db() as db:
            ws=db.execute("SELECT id FROM workspaces WHERE invite_code=?",(code,)).fetchone()
            if not ws: return jsonify({"error":"Invalid invite code"}),400
            ws_id=ws["id"]
    else:
        return jsonify({"error":"Invalid mode"}),400
    try:
        with get_db() as db:
            # Send email verification token
            verify_token = secrets.token_urlsafe(32)
            from datetime import timedelta
            verify_expires = (now_ist() + timedelta(hours=24)).strftime('%Y-%m-%dT%H:%M:%S') + '+05:30'
            login_ts = ts()
            db.execute(
                "INSERT INTO users(id,workspace_id,name,email,password,role,avatar,color,created,email_verified,email_verify_token,email_verify_expires) VALUES(?,?,?,?,?,?,?,?,?,0,?,?)",
                (uid, ws_id, d["name"], d["email"], hash_pw(d["password"]),
                 d.get("role","Developer"), av, c, login_ts, verify_token, verify_expires))
            session.permanent = True
            session["user_id"] = uid
            session["workspace_id"] = ws_id
            session["role"] = d.get("role","Developer")
            session["login_at"] = login_ts
            session_id = secrets.token_hex(16)
            session["session_id"] = session_id
            _set_logged_out_at(uid, "")
            # Send verification email (non-blocking)
            _send_verification_email(d["email"], d["name"], verify_token)
            _register_session(uid, ws_id, session_id)
            _audit("user_register", uid, f"{d['name']} ({d['email']}) registered via {mode}")
            # Build workspace dashboard URL
            ws_row = db.execute("SELECT name,workspace_slug FROM workspaces WHERE id=?", (ws_id,)).fetchone()
            slug = ""
            if ws_row:
                import re as _re
                slug = ws_row["workspace_slug"] or _re.sub(r"[^a-z0-9]+", "-", (ws_row["name"] or "").lower().strip()).strip("-") or "workspace"
            result = {"id":uid,"workspace_id":ws_id,"name":d["name"],"email":d["email"],
                      "role":d.get("role","Developer"),"avatar":av,"color":c}
            if slug:
                result["workspace_dashboard_url"] = f"/{slug}/{ws_id}/dashboard"
            return jsonify(result)
    except Exception as e:
        if "UNIQUE" in str(e): return jsonify({"error":"Email already registered"}),400
        return jsonify({"error":str(e)}),500

@app.route("/api/presence", methods=["POST"])
@login_required
def update_presence():
    """Update user last_active timestamp. Throttled: only writes to DB once per 60s
    per user. Uses _raw_pg (pooled, no extra SELECT 1) for the write."""
    uid = session["user_id"]
    ws  = wid()
    throttle_key = f"presence_write:{uid}"
    # Skip DB write if we wrote recently — return instantly
    if _cache_get(throttle_key):
        return jsonify({"ok": True, "throttled": True})
    try:
        _raw_pg("UPDATE users SET last_active=? WHERE id=? AND workspace_id=?",
                (ts(), uid, ws))
    except Exception as _e:
        log.warning("[presence] write failed: %s", _e)
    # Mark throttle via proper cache (Redis if available, dict otherwise)
    _cache_set(throttle_key, True)
    # Bust presence cache so next GET sees the fresh timestamp
    _cache_bust(ws, "presence")
    return jsonify({"ok": True})

@app.route("/api/presence")
@login_required
def get_presence():
    """Returns list of user IDs active in last 3 minutes. Cached 15s."""
    ws = wid()
    cache_key = f"presence:{ws}"
    cached = _cache_get(cache_key)
    if cached is not None: return jsonify(cached)
    try:
        cutoff = (now_ist() - timedelta(minutes=3)).strftime('%Y-%m-%dT%H:%M:%S')
        rows = _raw_pg(
            "SELECT id FROM users WHERE workspace_id=? AND last_active>?",
            (ws, cutoff), fetch=True)
        result = [r["id"] for r in (rows or [])]
    except Exception:
        result = []
    _cache_set(cache_key, result)
    return jsonify(result)

@app.route("/api/meet/notify", methods=["POST"])
@login_required
def meet_notify():
    """Send a Google Meet call notification to a specific user."""
    d = request.json or {}
    target_id = d.get("target_id")
    room_name = d.get("room_name", "")
    caller_name_override = d.get("caller_name", "")
    if not target_id:
        return jsonify({"error": "target_id required"}), 400
    with get_db() as db:
        caller = db.execute("SELECT name FROM users WHERE id=?", (session["user_id"],)).fetchone()
        cname = caller_name_override or (caller["name"] if caller else "Someone")
        nid = f"n{int(datetime.now().timestamp()*1000)}"
        msg = f"📹 {cname} is calling you — click to join the meeting"
        try:
            db.execute(
                "INSERT INTO notifications(id,workspace_id,type,content,user_id,read,ts,sender_id) VALUES (?,?,?,?,?,?,?,?)",
                (nid, wid(), "call", msg, target_id, 0, ts(), session["user_id"]))
        except:
            db.execute(
                "INSERT INTO notifications(id,workspace_id,type,content,user_id,read,ts) VALUES (?,?,?,?,?,?,?)",
                (nid, wid(), "call", msg, target_id, 0, ts()))
        return jsonify({"ok": True, "caller": cname, "room": room_name})

@app.route("/api/auth/me")
def me():
    if "user_id" not in session: return jsonify({"error":"Not logged in"}),401
    uid = session["user_id"]

    # Cache auth/me for 30s per user — it's polled constantly and almost
    # never changes. This saves 2 DB queries (user + workspace) × 180ms RTT
    # = ~360ms on every poll cycle.
    me_cache_key = f"me:{uid}"
    cached_me = _cache_get(me_cache_key)
    if cached_me is not None:
        return jsonify(cached_me)

    try:
        import re as _re
        rows = _raw_pg(
            "SELECT u.*, w.name as _ws_name, w.workspace_slug as _ws_slug "
            "FROM users u LEFT JOIN workspaces w ON w.id=u.workspace_id "
            "WHERE u.id=?",
            (uid,), fetch=True
        )
        if not rows:
            session.clear()
            return jsonify({"error":"Not found"}),404
        u = rows[0]
        if u.get("workspace_id"):
            session["workspace_id"] = u["workspace_id"]
        result = dict(u)
        for k in ("password","plain_password","totp_secret","_ws_name","_ws_slug"):
            result.pop(k, None)
        ws_name = u.get("_ws_name","")
        ws_slug = u.get("_ws_slug","")
        if ws_name or ws_slug:
            slug = ws_slug or _re.sub(r"[^a-z0-9]+", "-", ws_name.lower().strip()).strip("-") or "workspace"
            result["workspace_dashboard_url"] = f"/{slug}/{u['workspace_id']}/dashboard"
            result["workspace_slug"] = slug
            result["workspace_id_from_me"] = u["workspace_id"]
        _cache_set(me_cache_key, result)
        return jsonify(result)
    except Exception as _e:
        log.error("[auth/me] %s", _e)
        # Fallback: original two-query approach
        with get_db() as db:
            u=db.execute("SELECT * FROM users WHERE id=?",(uid,)).fetchone()
            if not u: session.clear(); return jsonify({"error":"Not found"}),404
            if u["workspace_id"]: session["workspace_id"]=u["workspace_id"]
            result = dict(u)
            for k in ("password","plain_password","totp_secret"):
                result.pop(k, None)
            return jsonify(result)

# ── Vault ─────────────────────────────────────────────────────────────────────
# All `rows` data is Fernet-encrypted (AES-128-CBC + HMAC-SHA256) before being
# stored in the database. vault_encrypt / vault_decrypt are defined near the top
# of this file. If the `cryptography` package is unavailable the functions are
# no-ops so the feature degrades gracefully (no silent data loss).

@app.route("/api/vault", methods=["GET"])
@login_required
def vault_list():
    with get_db() as db:
        records = db.execute(
            "SELECT * FROM vault_cards WHERE user_id=? ORDER BY created DESC",
            (session["user_id"],)
        ).fetchall()
    result = []
    for r in records:
        card = dict(r)
        # Decrypt rows — vault_decrypt falls back gracefully for legacy plain rows
        try:
            card["rows"] = vault_decrypt(card.get("rows") or "[]")
        except Exception:
            card["rows"] = "[]"
        result.append(card)
    return jsonify(result)

@app.route("/api/vault", methods=["POST"])
@login_required
def vault_create():
    d = request.json or {}
    now = ts()
    cid = "c" + str(int(time.time()*1000)) + secrets.token_hex(3)
    plain_rows = json.dumps(d.get("rows", []))
    encrypted_rows = vault_encrypt(plain_rows)
    with get_db() as db:
        db.execute(
            "INSERT INTO vault_cards (id,user_id,title,tags,rows,cols,lock_hash,created,updated) "
            "VALUES (?,?,?,?,?,?,?,?,?)",
            (cid, session["user_id"], d.get("title", ""), d.get("tags", ""),
             encrypted_rows, json.dumps(d.get("cols") or []),
             d.get("lock_hash", ""), now, now)
        )
    _vault_audit(session["user_id"], cid, "create", d.get("title", ""))
    return jsonify({"id": cid, "created": now})

@app.route("/api/vault/<cid>", methods=["PUT"])
@login_required
def vault_update(cid):
    d = request.json or {}
    now = ts()
    plain_rows = json.dumps(d.get("rows", []))
    encrypted_rows = vault_encrypt(plain_rows)
    with get_db() as db:
        db.execute(
            "UPDATE vault_cards SET title=?,tags=?,rows=?,cols=?,lock_hash=?,updated=? "
            "WHERE id=? AND user_id=?",
            (d.get("title", ""), d.get("tags", ""), encrypted_rows,
             json.dumps(d.get("cols") or []),
             d.get("lock_hash", ""), now, cid, session["user_id"])
        )
    return jsonify({"ok": True})

@app.route("/api/vault/<cid>", methods=["DELETE"])
@login_required
def vault_delete(cid):
    with get_db() as db:
        db.execute("DELETE FROM vault_cards WHERE id=? AND user_id=?", (cid, session["user_id"]))
        db.execute("DELETE FROM vault_audit_log WHERE card_id=? AND user_id=?", (cid, session["user_id"]))
    return jsonify({"ok": True})

# ── Vault Audit Log ────────────────────────────────────────────────────────────
def _vault_audit(user_id, card_id, action, detail="", ip=""):
    """Insert a vault audit log entry. Non-blocking — swallows errors."""
    try:
        aid = "va" + secrets.token_hex(6)
        now = ts()
        with get_db() as db:
            db.execute(
                "INSERT INTO vault_audit_log (id,user_id,card_id,action,detail,ip,created) "
                "VALUES (?,?,?,?,?,?,?)",
                (aid, user_id, card_id, action, detail[:200], ip[:60], now)
            )
    except Exception as e:
        log.warning("[vault_audit] non-fatal: %s", e)

@app.route("/api/vault/audit", methods=["GET"])
@login_required
def vault_audit_list():
    """Return the 50 most recent vault audit events for the current user."""
    with get_db() as db:
        rows = db.execute(
            "SELECT a.id, a.card_id, a.action, a.detail, a.ip, a.created, "
            "       v.title AS card_title "
            "FROM vault_audit_log a "
            "LEFT JOIN vault_cards v ON a.card_id = v.id "
            "WHERE a.user_id=? ORDER BY a.created DESC LIMIT 50",
            (session["user_id"],)
        ).fetchall()
    return jsonify([dict(r) for r in rows])

@app.route("/api/vault/<cid>/audit", methods=["POST"])
@login_required
def vault_audit_event(cid):
    """Log a reveal or copy event triggered by the frontend."""
    d = request.json or {}
    action = (d.get("action") or "").strip()[:50]
    detail = (d.get("detail") or "").strip()[:200]
    if action not in ("reveal", "copy", "unlock"):
        return jsonify({"error": "Invalid action"}), 400
    # Verify the card belongs to this user before logging
    with get_db() as db:
        card = db.execute(
            "SELECT id FROM vault_cards WHERE id=? AND user_id=?",
            (cid, session["user_id"])
        ).fetchone()
    if not card:
        return jsonify({"error": "Not found"}), 404
    ip = request.headers.get("X-Forwarded-For", request.remote_addr or "")[:60]
    _vault_audit(session["user_id"], cid, action, detail, ip)
    return jsonify({"ok": True})

# ── Workspace ─────────────────────────────────────────────────────────────────
@app.route("/api/workspace")
@login_required
def get_workspace():
    with get_db() as db:
        ws=db.execute("SELECT * FROM workspaces WHERE id=?",(wid(),)).fetchone()
        if not ws: return jsonify({"error":"Workspace not found"}),404
        return jsonify(dict(ws))

@app.route("/api/workspace",methods=["PUT"])
@login_required
def update_workspace():
    d=request.json or {}
    with get_db() as db:
        if "name" in d: db.execute("UPDATE workspaces SET name=? WHERE id=?",(d["name"],wid()))
        if "ai_api_key" in d: db.execute("UPDATE workspaces SET ai_api_key=? WHERE id=?",(d["ai_api_key"],wid()))
        if "smtp_server" in d: db.execute("UPDATE workspaces SET smtp_server=? WHERE id=?",(d["smtp_server"],wid()))
        if "smtp_port" in d: db.execute("UPDATE workspaces SET smtp_port=? WHERE id=?",(d["smtp_port"],wid()))
        if "smtp_username" in d: db.execute("UPDATE workspaces SET smtp_username=? WHERE id=?",(d["smtp_username"],wid()))
        if "smtp_password" in d: db.execute("UPDATE workspaces SET smtp_password=? WHERE id=?",(d["smtp_password"],wid()))
        if "from_email" in d: db.execute("UPDATE workspaces SET from_email=? WHERE id=?",(d["from_email"],wid()))
        if "email_enabled" in d: db.execute("UPDATE workspaces SET email_enabled=? WHERE id=?",(1 if d["email_enabled"] else 0,wid()))
        if "otp_enabled" in d: db.execute("UPDATE workspaces SET otp_enabled=? WHERE id=?",(1 if d["otp_enabled"] else 0,wid()))
        if "dm_enabled" in d: db.execute("UPDATE workspaces SET dm_enabled=? WHERE id=?",(1 if d["dm_enabled"] else 0,wid()))
        ws=db.execute("SELECT * FROM workspaces WHERE id=?",(wid(),)).fetchone()
        return jsonify(dict(ws))

@app.route("/api/workspace/new-invite",methods=["POST"])
@login_required
def new_invite():
    invite=secrets.token_hex(4).upper()
    with get_db() as db:
        db.execute("UPDATE workspaces SET invite_code=? WHERE id=?",(invite,wid()))
        return jsonify({"invite_code":invite})

@app.route("/api/workspace/test-email",methods=["POST"])
@login_required
def test_email():
    """Send a test email to verify SMTP configuration"""
    d=request.json or {}
    test_to=d.get("test_email")
    if not test_to:
        return jsonify({"error":"test_email required"}),400

    subject="Project Tracker Email Test"
    body="""
    <html>
    <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
        <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
            <h2 style="color: #6366f1;">Email Configuration Test</h2>
            <p>Congratulations! Your email notifications are working correctly.</p>
            <div style="background: #f3f4f6; padding: 15px; border-radius: 8px; margin: 20px 0;">
                <p style="margin: 0;">✅ SMTP connection successful</p>
                <p style="margin: 5px 0 0 0;">✅ Email delivery working</p>
            </div>
            <p>You will now receive notifications for:</p>
            <ul style="color: #4b5563;">
                <li>Task assignments</li>
                <li>Status changes</li>
                <li>New comments</li>
            </ul>
            <p style="color: #6b7280; font-size: 12px; margin-top: 30px;">Project Tracker Notification System</p>
        </div>
    </body>
    </html>
    """
    success=send_email(test_to,subject,body,wid())
    if success:
        return jsonify({"success":True,"message":"Test email sent successfully!"})
    else:
        return jsonify({"success":False,"message":"Failed to send test email. Check SMTP settings and server logs."}),500

# ── Users ─────────────────────────────────────────────────────────────────────
@app.route("/api/users")
@login_required
def get_users():
    with get_db() as db:
        rows = db.execute(
            """SELECT id,workspace_id,name,email,role,avatar,color,created,
               two_fa_enabled,totp_verified,last_active
               FROM users WHERE workspace_id=? ORDER BY name""",
            (wid(),)).fetchall()
        caller = db.execute("SELECT role FROM users WHERE id=?", (session["user_id"],)).fetchone()
        caller_role = caller["role"] if caller else "Developer"
        can_see_passwords = caller_role in ("Admin", "Manager")
        users = []
        for r in rows:
            u = dict(r)
            u.pop('avatar_data', None)
            u.pop('password', None)
            u.pop('plain_password', None)  # never expose plaintext passwords over API
            u['totp_configured'] = bool(u.get('totp_verified') and u.get('totp_secret'))
            u.pop('totp_secret', None)
            users.append(u)
        return jsonify(users)

@app.route("/api/users",methods=["POST"])
@login_required
@require_role("Admin", "Manager")
def add_user():
    d=request.json or {}
    if not d.get("name") or not d.get("email") or not d.get("password"):
        return jsonify({"error":"All fields required"}),400
    uid=f"u{int(datetime.now().timestamp()*1000)}"
    av="".join(w[0] for w in d["name"].split())[:2].upper()
    c=random.choice(CLRS)
    try:
        with get_db() as db:
            db.execute("INSERT INTO users (id,workspace_id,name,email,password,role,avatar,color,created,avatar_data) VALUES (?,?,?,?,?,?,?,?,?,?)",
                       (uid,wid(),d["name"],d["email"],hash_pw(d["password"]),
                        d.get("role","Developer"),av,c,ts(),None))
        _cache_bust_ws(wid())
        return jsonify({"id":uid,"workspace_id":wid(),"name":d["name"],
                        "email":d["email"],"role":d.get("role","Developer"),"avatar":av,"color":c})
    except Exception as e:
        if "UNIQUE" in str(e): return jsonify({"error":"Email already in use"}),400
        return jsonify({"error":str(e)}),500

@app.route("/api/users/<uid>",methods=["PUT"])
@login_required
@require_role("Admin", "Manager")
def update_user(uid):
    d=request.json or {}
    with get_db() as db:
        if "role" in d: db.execute("UPDATE users SET role=? WHERE id=? AND workspace_id=?",(d["role"],uid,wid()))
        if "name" in d:
            av="".join(w[0] for w in d["name"].split())[:2].upper()
            db.execute("UPDATE users SET name=?,avatar=? WHERE id=? AND workspace_id=?",(d["name"],av,uid,wid()))
        if "email" in d: db.execute("UPDATE users SET email=? WHERE id=? AND workspace_id=?",(d["email"],uid,wid()))
        if "password" in d: db.execute("UPDATE users SET password=? WHERE id=? AND workspace_id=?",(hash_pw(d["password"]),uid,wid()))
        if "avatar_data" in d: db.execute("UPDATE users SET avatar_data=? WHERE id=? AND workspace_id=?",(d["avatar_data"],uid,wid()))
        u=db.execute("SELECT * FROM users WHERE id=?",(uid,)).fetchone()
        if u:
            caller=db.execute("SELECT role FROM users WHERE id=?",(session["user_id"],)).fetchone()
            caller_role=caller["role"] if caller else "Developer"
            result=dict(u)
            result.pop("password",None)
            result.pop("plain_password",None)  # never expose plaintext passwords
            _cache_bust_ws(wid())
            return jsonify(result)
        return jsonify({})

@app.route("/api/users/<uid>",methods=["DELETE"])
@login_required
@require_role("Admin")
def del_user(uid):
    with get_db() as db:
        u = db.execute("SELECT name, email FROM users WHERE id=? AND workspace_id=?",(uid,wid())).fetchone()
        db.execute("DELETE FROM users WHERE id=? AND workspace_id=?",(uid,wid()))
        name_str = f"{u['name']} ({u['email']})" if u else uid
        _audit("user_deleted", uid, f"{name_str} removed from workspace {wid()}")
    _cache_bust_ws(wid())
    return jsonify({"ok":True})

@app.route("/api/users/<uid>/avatar")
@login_required
def get_user_avatar(uid):
    """Serve a user's avatar blob with a 24h browser cache.
    Keeping avatar_data out of the /api/app-data bulk payload removes
    up to 500KB–1MB per poll for a 10-person workspace.
    """
    with get_db() as db:
        row = db.execute("SELECT avatar_data FROM users WHERE id=? AND workspace_id=?",
                         (uid, wid())).fetchone()
    data = row["avatar_data"] if row and row["avatar_data"] else None
    if not data:
        return "", 404
    etag = hashlib.md5(data.encode() if isinstance(data, str) else data).hexdigest()
    if request.headers.get("If-None-Match") == etag:
        return "", 304
    # Detect mime type from base64 data-URL prefix if present
    mime = "image/png"
    if isinstance(data, str) and data.startswith("data:"):
        mime = data.split(";")[0].split(":")[1]
        data = data.split(",", 1)[1]
    try:
        raw = base64.b64decode(data)
    except Exception:
        return "", 500
    resp = make_response(raw)
    resp.headers["Content-Type"] = mime
    resp.headers["Cache-Control"] = "public, max-age=86400"  # 24h browser cache
    resp.headers["ETag"] = etag
    return resp

# ── Projects ──────────────────────────────────────────────────────────────────
@app.route("/api/projects/all")
@login_required
def get_all_projects():
    """Return ALL workspace projects — used by Channels so everyone can see all project status."""
    with get_db() as db:
        rows=db.execute("SELECT * FROM projects WHERE workspace_id=? ORDER BY created DESC",(wid(),)).fetchall()
        return jsonify([dict(r) for r in rows])

@app.route("/api/projects/last-messages")
@login_required
def get_projects_last_messages():
    """Return the latest message timestamp per project — used to sort channels by activity."""
    with get_db() as db:
        rows=db.execute(
            "SELECT project, MAX(ts) as last_ts FROM messages WHERE workspace_id=? GROUP BY project",
            (wid(),)).fetchall()
        return jsonify({r["project"]: r["last_ts"] for r in rows})

def _fetch_app_data_from_db(ws, team_id, uid):
    """Execute all app-data queries IN PARALLEL using the connection pool.

    Each query runs on its own pooled connection in a dedicated thread, so
    total wall-clock time = max(individual query times) instead of their sum.

    Previous approach: 9 sequential queries on one connection.
    India → Railway US-West RTT ≈ 180ms → 9 × 180ms = 1.6s in network alone,
    plus server-side execution time. Total observed: ~5s.

    New approach: 9 concurrent queries, each on its own pool connection.
    All fire simultaneously → total ≈ slowest single query (~400-600ms).
    Expected improvement: 5s → ~0.5-1s for the cold-cache path.

    Pool sizing note: this borrows up to 9 connections simultaneously per
    app-data call. With PG_POOL_SIZE=30 and typical concurrent user counts
    this is fine; raise PG_POOL_SIZE if you see pool exhaustion under load.
    """
    now_str = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S")

    if team_id:
        tasks_sql    = (
            "SELECT id,workspace_id,title,description,project,assignee,priority,stage,"
            "created,due,pct,team_id,story_points,task_type,labels,sprint,deleted_at "
            "FROM tasks WHERE workspace_id=? AND team_id=? AND deleted_at='' "
            "ORDER BY created DESC LIMIT 300"
        )
        tasks_params = (ws, team_id)
        proj_sql     = "SELECT * FROM projects WHERE workspace_id=? AND team_id=? ORDER BY created DESC LIMIT 200"
        proj_params  = (ws, team_id)
    else:
        tasks_sql    = (
            "SELECT id,workspace_id,title,description,project,assignee,priority,stage,"
            "created,due,pct,team_id,story_points,task_type,labels,sprint,deleted_at "
            "FROM tasks WHERE workspace_id=? AND deleted_at='' "
            "ORDER BY created DESC LIMIT 300"
        )
        tasks_params = (ws,)
        proj_sql     = "SELECT * FROM projects WHERE workspace_id=? ORDER BY created DESC LIMIT 200"
        proj_params  = (ws,)

    # Each entry: cache_result_key → (sql, params)
    # _raw_pg is thread-safe: it borrows its own connection from the pool per call.
    queries = {
        "users":     (
            "SELECT id,name,email,role,avatar,color,workspace_id,last_active,"
            "two_fa_enabled,totp_verified FROM users WHERE workspace_id=? ORDER BY name",
            (ws,)
        ),
        "projects":  (proj_sql,  proj_params),
        "tasks":     (tasks_sql, tasks_params),
        "notifs":    (
            "SELECT * FROM notifications WHERE workspace_id=? AND user_id=? "
            "ORDER BY ts DESC LIMIT 50",
            (ws, uid)
        ),
        "dm_unread": (
            "SELECT sender, COUNT(*) as cnt FROM direct_messages "
            "WHERE workspace_id=? AND recipient=? AND read=0 GROUP BY sender",
            (ws, uid)
        ),
        "workspace": ("SELECT * FROM workspaces WHERE id=?", (ws,)),
        "teams":     ("SELECT * FROM teams WHERE workspace_id=?", (ws,)),
        # Reduced from 200 → 100: 100 tickets is still plenty for any dashboard
        # view and cuts the heaviest single payload in half.
        "tickets":   (
            "SELECT * FROM tickets WHERE workspace_id=? ORDER BY created DESC LIMIT 100",
            (ws,)
        ),
        "reminders": (
            "SELECT * FROM reminders WHERE workspace_id=? AND user_id=? "
            "AND remind_at>=? ORDER BY remind_at",
            (ws, uid, now_str)
        ),
    }

    results: dict = {}
    with ThreadPoolExecutor(max_workers=len(queries)) as pool:
        future_to_key = {
            pool.submit(_raw_pg, sql, params, True): key
            for key, (sql, params) in queries.items()
        }
        for fut in _as_completed(future_to_key):
            key = future_to_key[fut]
            try:
                results[key] = fut.result() or []
            except Exception as _e:
                log.error("[app-data] parallel query '%s' failed: %s", key, _e)
                results[key] = []

    ws_rows = results.get("workspace", [])
    return {
        "users":         results.get("users",     []),
        "projects":      results.get("projects",  []),
        "tasks":         results.get("tasks",     []),
        "notifications": results.get("notifs",    []),
        "dm_unread":     results.get("dm_unread", []),
        "workspace":     ws_rows[0] if ws_rows else {},
        "teams":         results.get("teams",     []),
        "tickets":       results.get("tickets",   []),
        "reminders":     results.get("reminders", []),
    }


def _etag_response(result):
    """Return a jsonify response with ETag header; emit 304 if client has fresh copy."""
    etag = hashlib.md5(json.dumps(result, sort_keys=True, default=str).encode()).hexdigest()
    if request.headers.get("If-None-Match") == etag:
        return "", 304
    resp = jsonify(result)
    resp.headers["ETag"] = etag
    return resp


@app.route("/api/app-data")
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

@app.route("/api/projects")
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

@app.route("/api/projects",methods=["POST"])
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
                db.execute("INSERT INTO notifications(id,workspace_id,type,content,user_id,read,ts,entity_id,entity_type) VALUES (?,?,?,?,?,?,?,?,?)",
                           (nid,wid(),"project_added",f"You were added to project '{d['name']}'",uid,0,ts(),pid,'project'))
                _enqueue_push(push_notification_to_user, *(db,uid,f"📁 Added to project: {d['name']}",
                          f"{cname} added you to '{d['name']}'",f"/?action=project&id={pid}"))
        # Inject into appdata cache FIRST so workers with stale cache get the new project immediately.
        _cache_inject_item(wid(), "projects", dict(p))
        # Bust the FULL workspace cache — this forces the next /api/app-data background
        # refresh to re-fetch from DB with the new project included.
        # Previously only busting 'notifs' left the appdata cache stale, causing the
        # background SWR refresh to overwrite state and make the new project disappear.
        # Targeted bust: projects and appdata only. Tasks cache untouched (no tasks yet).
        _cache_bust(wid(), "projects", "appdata")
        # Push SSE event so connected clients update immediately without waiting for next poll
        _sse_publish(wid(), "project_updated", {"id": pid, "action": "created"})
        return jsonify(dict(p))

@app.route("/api/projects/<pid>",methods=["PUT"])
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
                            f"{aname} added you to project '{updated['name']}'",uid,0,ts(),pid,'project')]
            placeholders=",".join(["(?,?,?,?,?,?,?,?,?)"]*len(newly_added))
            db.execute(f"INSERT INTO notifications(id,workspace_id,type,content,user_id,read,ts,entity_id,entity_type) VALUES {placeholders}",flat)
            for uid in newly_added:
                _enqueue_push(push_notification_to_user, *(db,uid,f"\U0001f4c1 Added to project: {updated['name']}",
                          f"{aname} added you to '{updated['name']}'",f"/?action=project&id={pid}"))
    # Targeted bust: projects and appdata. Member/name changes don't affect
    # task, notification, or DM caches.
    _cache_bust(wid(), "projects", "appdata")
    # Notify connected clients via SSE so they reload without waiting 30s
    _sse_publish(wid(), "project_updated", {"id": pid, "action": "updated"})
    return jsonify(dict(updated))
@app.route("/api/projects/<pid>",methods=["DELETE"])
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

@app.route("/api/projects/bulk-assign-team",methods=["POST"])
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
@app.route("/api/tasks")
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
    import time
    base = int(time.time() * 1000)
    # Use timestamp-only ID — avoids a slow COUNT(*) query on every task creation.
    # Format: T-<last6digits_of_ms_timestamp> — unique within a workspace.
    return f"T-{base % 1000000:06d}"

@app.route("/api/tasks",methods=["POST"])
@login_required
def create_task():
    d=request.json or {}
    if not d.get("title"): return jsonify({"error":"Title required"}),400
    with get_db() as db:
        tid=next_task_id(db,wid())
        # Use RETURNING * to get the row back without a separate SELECT (saves 1 round-trip)
        try:
            t_rows=db.execute(
                "INSERT INTO tasks(id,workspace_id,title,description,project,assignee,priority,stage,created,due,pct,comments,team_id) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?) RETURNING *",
                (tid,wid(),d["title"],d.get("description",""),d.get("project",""),
                 d.get("assignee",""),d.get("priority","medium"),d.get("stage","backlog"),
                 ts(),d.get("due",""),d.get("pct",0),json.dumps(d.get("comments",[])),
                 d.get("team_id",""))
            ).fetchall()
            t = t_rows[0] if t_rows else None
        except Exception:
            db.execute("INSERT INTO tasks(id,workspace_id,title,description,project,assignee,priority,stage,created,due,pct,comments,team_id) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                       (tid,wid(),d["title"],d.get("description",""),d.get("project",""),
                        d.get("assignee",""),d.get("priority","medium"),d.get("stage","backlog"),
                        ts(),d.get("due",""),d.get("pct",0),json.dumps(d.get("comments",[])),
                        d.get("team_id","")))
            t=None
        # Batch: fetch creator + assignee in ONE query instead of two sequential round-trips
        lookup_ids = list(set(filter(None, [session["user_id"], d.get("assignee")])))
        user_map = {row["id"]: row for row in db.execute(
            f"SELECT id,name,email FROM users WHERE id IN ({','.join('?'*len(lookup_ids))})",
            lookup_ids
        ).fetchall()} if lookup_ids else {}
        creator_row = user_map.get(session["user_id"])
        cname = creator_row["name"] if creator_row else "Someone"
        base_ts=int(datetime.now().timestamp()*1000)
        assignee_user = user_map.get(d.get("assignee","")) if d.get("assignee") else None
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
                               f"{cname} assigned you to '{d['title']}'",d["assignee"],0,ts(),tid,'task'))
        for i,uid in enumerate(proj_members):
            if uid==session["user_id"] or uid==d.get("assignee"): continue
            proj_name=proj["name"] if proj else ""
            notif_rows.append((f"n{base_ts+10+i}",wid(),"task_assigned",
                               f"{cname} created task '{d['title']}' in {proj_name}",uid,0,ts(),tid,'task'))
        if notif_rows:
            placeholders=",".join(["(?,?,?,?,?,?,?,?,?)"]*len(notif_rows))
            flat=[v for row in notif_rows for v in row]
            db.execute(f"INSERT INTO notifications(id,workspace_id,type,content,user_id,read,ts,entity_id,entity_type) VALUES {placeholders}",flat)
        # Send emails + push notifications in background threads (non-blocking)
        _task_url=f"/?action=task&id={tid}"
        if assignee_user:
            if assignee_user["email"]:
                threading.Thread(target=send_task_assigned_email,
                    args=(assignee_user["email"],assignee_user["name"],d["title"],cname,tid,wid()),
                    daemon=True).start()
            _enqueue_push(push_notification_to_user, db, d["assignee"],
                f"✅ New task assigned: {d['title']}",
                f"{cname} assigned you this task [{d.get('priority','medium')}]", _task_url)
        for uid in proj_members:
            if uid==session["user_id"] or uid==d.get("assignee"): continue
            _enqueue_push(push_notification_to_user, *(db,uid,f"📋 New task in {proj['name'] if proj else ''}",
                      f"{cname} created '{d['title']}'",_task_url))
        # Use RETURNING * result if available; fall back to SELECT only if needed
        if t is None:
            t=db.execute("SELECT * FROM tasks WHERE id=? AND workspace_id=?",(tid,wid())).fetchone()
        if d.get("project") and proj:
            assignee_name=f" → assigned to {assignee_user['name']}" if assignee_user else ""
            sysmid=f"m{base_ts+1}"
            msg=f"📋 **{cname}** created task **{d['title']}**{assignee_name} [{d.get('priority','medium').title()}]"
            db.execute("INSERT INTO messages(id,workspace_id,sender,project,content,ts,is_system) VALUES (?,?,?,?,?,?,?)",
                       (sysmid,wid(),"system",d["project"],msg,ts(),1))
        _cache_inject_item(wid(), "tasks", dict(t))
        # Targeted bust: only invalidate tasks + appdata caches.
        # Notifications, DM, and user caches are unaffected by a new task.
        # SSE event below notifies connected clients immediately so they refetch.
        _cache_bust(wid(), "tasks", "appdata")
        # Push SSE event — connected clients reload immediately without polling delay
        _sse_publish(wid(), "task_updated", {"id": tid, "action": "created",
                                              "project": d.get("project", ""),
                                              "assignee": d.get("assignee", "")})
        return jsonify(dict(t))


@app.route("/api/tasks/<tid>/events", methods=["GET"])
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

@app.route("/api/tasks/<tid>",methods=["PUT"])
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
                db.execute("INSERT INTO notifications(id,workspace_id,type,content,user_id,read,ts,entity_id,entity_type) VALUES (?,?,?,?,?,?,?,?,?)",
                           (nid,wid(),"status_change",f"Task '{t['title']}' moved to {d['stage']}",
                            t["assignee"],0,ts(),tid,'task'))
                assignee_user=db.execute("SELECT name,email FROM users WHERE id=?",(t["assignee"],)).fetchone()
                changer_user=db.execute("SELECT name FROM users WHERE id=?",(session["user_id"],)).fetchone()
                changer_name=changer_user["name"] if changer_user else "Someone"
                if assignee_user and assignee_user["email"]:
                    threading.Thread(target=send_status_change_email,
                        args=(assignee_user["email"],assignee_user["name"],t["title"],d["stage"],changer_name,wid()),
                        daemon=True).start()
                _enqueue_push(push_notification_to_user, *(db, t["assignee"], f"🔄 Task updated: {t['title']}",
                          f"{changer_name} moved it to {d['stage']}", f"/?action=task&id={tid}"))
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
                        db.execute("INSERT INTO notifications(id,workspace_id,type,content,user_id,read,ts,entity_id,entity_type) VALUES (?,?,?,?,?,?,?,?,?)",
                                   (nid2,wid(),"status_change",f"{aname} moved '{t['title']}' → {d['stage']}",uid,0,ts(),tid,'task'))
                        _enqueue_push(push_notification_to_user, *(db, uid, f"🔄 {t['title']} → {d['stage']}",
                                  f"{aname} updated the task stage", f"/?action=task&id={tid}"))
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
                db.execute("INSERT INTO notifications(id,workspace_id,type,content,user_id,read,ts,entity_id,entity_type) VALUES (?,?,?,?,?,?,?,?,?)",
                           (nid2,wid(),"comment",f"{cname} commented on '{t['title']}': {latest.get('text','')}",
                            t["assignee"],0,ts(),tid,'task'))
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
                _enqueue_push(push_notification_to_user, db, t["assignee"],
                    f"💬 Comment on: {t['title']}",
                    f"{cname}: {latest.get('text','')[:80]}", "/")
        _cache_bust(wid(), "tasks", "appdata")
        updated_task = dict(db.execute("SELECT * FROM tasks WHERE id=? AND workspace_id=?",(tid,wid())).fetchone())
        # Push SSE — all workspace clients get the new stage/assignee immediately
        _sse_publish(wid(), "task_updated", {"id": tid, "action": "updated",
                                              "stage": updated_task.get("stage",""),
                                              "project": updated_task.get("project","")})
        return jsonify(updated_task)


@app.route("/api/subtasks/search")
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

@app.route("/api/tasks/<tid>/subtasks", methods=["GET"])
@login_required
def get_subtasks(tid):
    with get_db() as db:
        rows=db.execute("SELECT * FROM subtasks WHERE task_id=? AND workspace_id=? ORDER BY created",(tid,wid())).fetchall()
        return jsonify([dict(r) for r in rows])

@app.route("/api/tasks/<tid>/subtasks", methods=["POST"])
@login_required
def create_subtask(tid):
    d=request.json or {}
    sid=f"st{int(datetime.now().timestamp()*1000)}{secrets.token_hex(3)}"
    with get_db() as db:
        db.execute("INSERT INTO subtasks VALUES (?,?,?,?,?,?,?)",
                   (sid,wid(),tid,d.get("title","Untitled"),0,d.get("assignee",""),ts()))
        return jsonify({"id":sid,"task_id":tid,"title":d.get("title",""),"done":0})

@app.route("/api/subtasks/<sid>", methods=["PUT"])
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

@app.route("/api/subtasks/<sid>", methods=["DELETE"])
@login_required
def delete_subtask(sid):
    with get_db() as db:
        db.execute("DELETE FROM subtasks WHERE id=? AND workspace_id=?",(sid,wid()))
        return jsonify({"ok":True})

@app.route("/api/tasks/<tid>",methods=["DELETE"])
@login_required
def del_task(tid):
    """Soft-delete: sets deleted_at instead of removing the row.
    Tasks can be recovered by an Admin. A future /api/tasks/<tid>/purge
    endpoint (Admin-only) can hard-delete when needed.
    """
    with get_db() as db:
        cu=db.execute("SELECT role FROM users WHERE id=?",(session["user_id"],)).fetchone()
        cu_role=cu["role"] if cu else "Viewer"
        if cu_role not in ("Admin","Manager","TeamLead"):
            return jsonify({"error":"Only Admin, Manager, or TeamLead can delete tasks."}),403
        task=db.execute(
            "SELECT id FROM tasks WHERE id=? AND workspace_id=? AND deleted_at=''",
            (tid,wid())
        ).fetchone()
        if not task:
            return jsonify({"error":"Task not found or already deleted"}),404
        deleted_ts = ts()
        db.execute(
            "UPDATE tasks SET deleted_at=? WHERE id=? AND workspace_id=?",
            (deleted_ts, tid, wid())
        )
    _cache_bust(wid(), "tasks", "appdata")
    _sse_publish(wid(), "task_updated", {"id": tid, "action": "deleted"})
    return jsonify({"ok":True,"deleted_at":deleted_ts})

# ── Files ─────────────────────────────────────────────────────────────────────
@app.route("/api/files")
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

@app.route("/api/files",methods=["POST"])
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

@app.route("/api/files/<fid>")
@login_required
def download_file(fid):
    with get_db() as db:
        row=db.execute("SELECT * FROM files WHERE id=? AND workspace_id=?",(fid,wid())).fetchone()
        if not row: return jsonify({"error":"Not found"}),404
    path=os.path.join(UPLOAD_DIR,fid)
    if not os.path.exists(path): return jsonify({"error":"File missing"}),404
    return send_file(path,download_name=row["name"],as_attachment=True,mimetype=row["mime"])

@app.route("/api/files/<fid>",methods=["DELETE"])
@login_required
@require_role("Admin", "Manager", "TeamLead")
def del_file(fid):
    with get_db() as db:
        db.execute("DELETE FROM files WHERE id=? AND workspace_id=?",(fid,wid()))
    path=os.path.join(UPLOAD_DIR,fid)
    if os.path.exists(path): os.remove(path)
    return jsonify({"ok":True})

# ── Messages ──────────────────────────────────────────────────────────────────
@app.route("/api/messages")
@login_required
def get_messages():
    project=request.args.get("project","")
    with get_db() as db:
        rows=db.execute("SELECT * FROM messages WHERE project=? AND workspace_id=? ORDER BY ts",
                        (project,wid())).fetchall()
        return jsonify([dict(r) for r in rows])

@app.route("/api/messages",methods=["POST"])
@login_required
def send_message():
    d=request.json or {}
    mid=f"m{int(datetime.now().timestamp()*1000)}"
    with get_db() as db:
        db.execute("INSERT INTO messages(id,workspace_id,sender,project,content,ts,is_system) VALUES (?,?,?,?,?,?,?)",
                   (mid,wid(),session["user_id"],d.get("project",""),d.get("content",""),ts(),0))
        sender=db.execute("SELECT name FROM users WHERE id=?",(session["user_id"],)).fetchone()
        sender_name=sender["name"] if sender else "Someone"
        project_row=db.execute("SELECT name FROM projects WHERE id=? AND workspace_id=?",(d.get("project",""),wid())).fetchone()
        proj_name=project_row["name"] if project_row else "a project"
        preview=d.get("content","")[:60]+("..." if len(d.get("content",""))>60 else "")
        members=db.execute("SELECT id FROM users WHERE workspace_id=? AND id!=?",(wid(),session["user_id"])).fetchall()
        base_ts=int(datetime.now().timestamp()*1000)
        for i,m in enumerate(members):
            nid=f"n{base_ts+i}"
            db.execute("INSERT INTO notifications(id,workspace_id,type,content,user_id,read,ts) VALUES (?,?,?,?,?,?,?)",
                       (nid,wid(),"message",f"#{proj_name} — {sender_name}: {preview}",m["id"],0,ts()))
        row=dict(db.execute("SELECT * FROM messages WHERE id=?",(mid,)).fetchone())
    _sse_publish(wid(), "message_created", {"id": mid, "project": d.get("project","")})
    _sse_publish(wid(), "notification_updated", {"reason": "project_message"})
    return jsonify(row)

# ── Direct Messages ───────────────────────────────────────────────────────────
def _attach_dm_reactions(db, ws_id, messages):
    """Attach grouped reaction counts/users to each DM row."""
    out=[dict(r) for r in messages]
    ids=[m.get("id") for m in out if m.get("id")]
    if not ids:
        return out
    qmarks=",".join(["?"]*len(ids))
    reaction_rows=db.execute(f"""SELECT message_id, emoji, user_id FROM dm_reactions
        WHERE workspace_id=? AND message_id IN ({qmarks})
        ORDER BY ts""", [ws_id]+ids).fetchall()
    grouped={mid:{} for mid in ids}
    for r in reaction_rows:
        msg_group=grouped.setdefault(r["message_id"], {})
        emoji_group=msg_group.setdefault(r["emoji"], {"emoji":r["emoji"], "count":0, "users":[]})
        emoji_group["count"]+=1
        emoji_group["users"].append(r["user_id"])
    for m in out:
        m["reactions"]=list(grouped.get(m.get("id"), {}).values())
    return out

@app.route("/api/dm/<other_id>")
@login_required
def get_dm(other_id):
    """Return DM conversation between the current user and other_id.

    Supports incremental fetch via ?since=<timestamp_ms>.
    Clients should store the ts of the newest message they have and pass
    it on subsequent polls so only new messages are transferred.
    Example: GET /api/dm/u123?since=1715000000000

    On the first load (no since param) the last 200 messages are returned
    to cap response size on long-running conversations.
    """
    me=session["user_id"]
    ws_id=wid()
    since=request.args.get("since","").strip()

    # Short-lived cache for full conversation loads (no ?since param).
    # SSE events trigger client-side reloads which pass ?since= (incremental),
    # so the cache is only hit for initial opens and page refreshes.
    if not since:
        dm_cache_key = f"dm_thread:{ws_id}:{me}:{other_id}"
        cached_thread = _cache_get(dm_cache_key)
        if cached_thread is not None:
            return jsonify(cached_thread)
    with get_db() as db:
        if since:
            # Incremental: only messages newer than the client's last known ts.
            # ts column stores ISO-8601 strings — lexicographic comparison works
            # because they are zero-padded. Clients pass epoch-ms; convert here.
            try:
                since_ms = int(since)
                from datetime import timezone
                since_dt = datetime.fromtimestamp(since_ms / 1000, tz=timezone.utc)
                since_str = since_dt.strftime("%Y-%m-%dT%H:%M:%S.%f")
            except (ValueError, TypeError):
                since_str = since  # caller passed an ISO string directly
            # UNION instead of OR: Postgres can use the index on each branch separately
            rows=db.execute(
                """SELECT * FROM direct_messages
                   WHERE workspace_id=? AND sender=? AND recipient=? AND ts > ?
                   UNION ALL
                   SELECT * FROM direct_messages
                   WHERE workspace_id=? AND sender=? AND recipient=? AND ts > ?
                   ORDER BY ts""",
                (ws_id, me, other_id, since_str, ws_id, other_id, me, since_str)
            ).fetchall()
        else:
            # Full load — cap at 200 most recent to bound response size.
            # UNION instead of OR: each branch can use idx_dm_sender_ws independently
            rows=db.execute(
                """SELECT * FROM (
                     SELECT * FROM direct_messages
                     WHERE workspace_id=? AND sender=? AND recipient=?
                     ORDER BY ts DESC LIMIT 200
                   ) a
                   UNION ALL
                   SELECT * FROM (
                     SELECT * FROM direct_messages
                     WHERE workspace_id=? AND sender=? AND recipient=?
                     ORDER BY ts DESC LIMIT 200
                   ) b
                   ORDER BY ts DESC LIMIT 200""",
                (ws_id, me, other_id, ws_id, other_id, me)
            ).fetchall()
            rows = list(reversed(rows))  # restore chronological order
        # Mark incoming messages as read — only if there are unread ones (avoids needless cache bust)
        unread_count = db.execute(
            "SELECT COUNT(*) FROM direct_messages "
            "WHERE workspace_id=? AND sender=? AND recipient=? AND read=0",
            (ws_id, other_id, me)
        ).fetchone()[0]
        if unread_count:
            db.execute(
                "UPDATE direct_messages SET read=1, seen_at=COALESCE(NULLIF(seen_at,''), ?) "
                "WHERE workspace_id=? AND sender=? AND recipient=? AND read=0",
                (ts(), ws_id, other_id, me)
            )
        data=_attach_dm_reactions(db, ws_id, rows)
    # Only bust caches if we actually just marked messages as read
    if unread_count:
        _cache_bust(ws_id, "dm_unread", "notifications", "notifs", "appdata")
    # Cache the full conversation so page refreshes and re-opens are instant
    if not since:
        _cache_set(f"dm_thread:{ws_id}:{me}:{other_id}", data)
    return jsonify(data)



def _create_google_meet_event(access_token, title, attendee_emails=None):
    """Create a real Google Meet link using Google Calendar API.

    Requires the current session to have a Google OAuth access token with
    https://www.googleapis.com/auth/calendar.events scope.
    """
    attendee_emails = [e for e in (attendee_emails or []) if e]
    from datetime import timezone, timedelta
    start_dt = datetime.now(timezone.utc)
    end_dt = start_dt + timedelta(hours=1)
    payload = {
        "summary": title or "Workspace call",
        "description": "Started from the Project Tracker Direct Messages call button.",
        "start": {"dateTime": start_dt.isoformat()},
        "end": {"dateTime": end_dt.isoformat()},
        "attendees": [{"email": e} for e in attendee_emails],
        "conferenceData": {
            "createRequest": {
                "requestId": f"meet-{secrets.token_hex(12)}",
                "conferenceSolutionKey": {"type": "hangoutsMeet"}
            }
        }
    }
    body = _json_mod.dumps(payload).encode("utf-8")
    url = "https://www.googleapis.com/calendar/v3/calendars/primary/events?conferenceDataVersion=1&sendUpdates=all"
    req = _urlrequest.Request(url, data=body, method="POST", headers={
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
    })
    with _urlrequest.urlopen(req, timeout=15) as resp:
        event = _json_mod.loads(resp.read())
    meet_url = event.get("hangoutLink") or ""
    if not meet_url:
        for ep in event.get("conferenceData", {}).get("entryPoints", []) or []:
            if ep.get("entryPointType") == "video" and ep.get("uri"):
                meet_url = ep.get("uri")
                break
    code = ""
    if meet_url:
        code = meet_url.rstrip("/").split("/")[-1]
    return {"event": event, "meetUrl": meet_url, "meetingCode": code}


def _create_google_meet_space(access_token):
    """Create a real Google Meet space using the Google Meet REST API.

    This must run server-side with a valid OAuth access token. Browsers cannot
    create Google Meet rooms anonymously; Google requires an authorized token.
    """
    if not access_token:
        raise ValueError("Missing Google OAuth access token")
    body = _json_mod.dumps({}).encode("utf-8")
    req = _urlrequest.Request("https://meet.googleapis.com/v2/spaces", data=body, method="POST", headers={
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
    })
    with _urlrequest.urlopen(req, timeout=15) as resp:
        space = _json_mod.loads(resp.read())
    meet_url = space.get("meetingUri") or space.get("meetingUrl") or ""
    return {"space": space, "meetUrl": meet_url, "meetingCode": space.get("meetingCode") or ""}

def _server_google_token():
    # Configure this on the server/Railway. It should be a valid Google OAuth
    # access token for a Workspace/service account flow or a user OAuth flow.
    return (os.environ.get("GOOGLE_MEET_ACCESS_TOKEN") or os.environ.get("GOOGLE_ACCESS_TOKEN") or "").strip()

@app.route("/api/calls/google-meet", methods=["POST"])
@login_required
def create_google_meet_call():
    """Start an instant DM call invite without Google Calendar OAuth.

    This intentionally does NOT call Calendar or require Google sign-in inside
    this app. It sends an in-app ringing invite immediately; when the receiver
    accepts, their browser opens Google's own instant Meet launcher.
    """
    d = request.json or {}
    target_id = (d.get("targetId") or d.get("recipient") or "").strip()
    call_type = (d.get("type") or "dm").strip().lower()
    if call_type != "dm":
        return jsonify({"ok": False, "error": "Only DM video calls are supported right now"}), 400
    if not target_id:
        return jsonify({"ok": False, "error": "Missing target user"}), 400

    ws_id = wid()
    me = session["user_id"]
    now = ts()
    call_id = f"call{int(datetime.now().timestamp()*1000)}{secrets.token_hex(3)}"
    # Prefer a real server-created Google Meet room. This does not require the
    # caller/receiver to sign in to this app, but Google still requires the
    # server to use an authorized OAuth token. Without GOOGLE_MEET_ACCESS_TOKEN
    # we fall back to a same-call nickname URL; admins should configure the token
    # for production to avoid Google prompting for account/login while creating.
    meet_url = ""
    meet_provider = "google_meet_api"
    try:
        created = _create_google_meet_space(_server_google_token())
        meet_url = created.get("meetUrl") or ""
    except Exception as e:
        log.warning("[call] Google Meet API create failed; using nickname fallback: %s", e)
        meet_provider = "google_meet_nickname_fallback"
        meet_url = f"https://meet.google.com/lookup/{call_id}"

    with get_db() as db:
        target = db.execute("SELECT id,name,email FROM users WHERE id=? AND workspace_id=? AND deleted_at=''", (target_id, ws_id)).fetchone()
        if not target:
            return jsonify({"ok": False, "error": "User not found"}), 404
        sender = db.execute("SELECT id,name,email FROM users WHERE id=? AND workspace_id=?", (me, ws_id)).fetchone()
        sender_name = sender["name"] if sender and sender["name"] else "Someone"
        target_name = target["name"] if target and target["name"] else "teammate"

        content = (
            "📞 Incoming video call\n"
            f"{sender_name} is calling you.\n"
            f"CALL_INVITE:{call_id}\n"
            f"CALL_FROM:{sender_name}\n"
            f"CALL_STATUS:ringing\n"
            f"MEET_LINK:{meet_url}"
        )
        mid = f"dm{int(datetime.now().timestamp()*1000)}{secrets.token_hex(2)}"
        db.execute("""INSERT INTO direct_messages(id,workspace_id,sender,recipient,content,read,ts,reply_to,delivered_at,seen_at,edited,deleted,pinned)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                   (mid, ws_id, me, target_id, content, 0, now, "", now, "", 0, 0, 0))
        row = dict(db.execute("SELECT * FROM direct_messages WHERE id=?", (mid,)).fetchone())

    def _after_call_start():
        try:
            with get_db() as db2:
                nid = f"n{int(datetime.now().timestamp()*1000)}{secrets.token_hex(2)}"
                try:
                    db2.execute("INSERT INTO notifications(id,workspace_id,type,content,user_id,read,ts,sender_id) VALUES (?,?,?,?,?,?,?,?)",
                                (nid, ws_id, "call", f"{sender_name} is calling you", target_id, 0, now, me))
                except Exception:
                    db2.execute("INSERT INTO notifications(id,workspace_id,type,content,user_id,read,ts) VALUES (?,?,?,?,?,?,?)",
                                (nid, ws_id, "call", f"{sender_name} is calling you", target_id, 0, now))
        except Exception as e:
            log.warning("[call] notification failed: %s", e)
        _cache_bust(ws_id, "dm_unread", "notifications", "notifs", "appdata")
        _bust_dm_thread(ws_id, me, target_id)
        _sse_publish(ws_id, "dm_created", {"id": mid, "sender": me, "recipient": target_id, "message": row})
        _sse_publish(ws_id, "call_status", {"callId": call_id, "status": "ringing", "users": [me, target_id], "sender": me, "senderName": sender_name, "recipient": target_id, "recipientName": target_name, "meetUrl": meet_url})
        _sse_publish(ws_id, "notification_updated", {"reason": "call", "sender": me, "recipient": target_id})
    threading.Thread(target=_after_call_start, daemon=True).start()

    return jsonify({
        "ok": True,
        "mode": "instant_call_invite_sent",
        "provider": meet_provider,
        "callId": call_id,
        "meetUrl": meet_url,
        "launchUrl": meet_url,
        "targetId": target_id,
        "targetName": target_name,
        "message": row
    })

@app.route("/api/calls/respond", methods=["POST"])
@login_required
def respond_instant_call():
    d = request.json or {}
    call_id = (d.get("callId") or "").strip()
    action = (d.get("action") or "").strip().lower()
    peer_id = (d.get("peerId") or d.get("targetId") or "").strip()
    meet_url = (d.get("meetUrl") or "https://meet.google.com/new").strip() or "https://meet.google.com/new"
    if action not in ("accept", "reject", "end", "missed"):
        return jsonify({"ok": False, "error": "Invalid call action"}), 400
    ws_id = wid(); me = session["user_id"]; now = ts()
    with get_db() as db:
        me_row = db.execute("SELECT name FROM users WHERE id=? AND workspace_id=?", (me, ws_id)).fetchone()
        me_name = me_row["name"] if me_row and me_row["name"] else "Someone"
        if not peer_id:
            msg = db.execute("SELECT sender,recipient FROM direct_messages WHERE workspace_id=? AND content LIKE ? ORDER BY ts DESC LIMIT 1", (ws_id, f"%CALL_INVITE:{call_id}%")).fetchone()
            if msg:
                peer_id = msg["sender"] if msg["sender"] != me else msg["recipient"]
        if peer_id:
            text = f"✅ {me_name} accepted the call" if action == "accept" else (f"❌ {me_name} rejected the call" if action == "reject" else (f"📴 Missed call from {me_name}" if action == "missed" else f"📴 {me_name} ended the call"))
            mid = f"dm{int(datetime.now().timestamp()*1000)}{secrets.token_hex(2)}"
            db.execute("""INSERT INTO direct_messages(id,workspace_id,sender,recipient,content,read,ts,reply_to,delivered_at,seen_at,edited,deleted,pinned)
                       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                       (mid, ws_id, me, peer_id, text, 0, now, "", now, "", 0, 0, 0))
            row = dict(db.execute("SELECT * FROM direct_messages WHERE id=?", (mid,)).fetchone())
        else:
            row = None
    status = "in_call" if action == "accept" else ("rejected" if action == "reject" else ("missed" if action == "missed" else "ended"))
    users = [x for x in [me, peer_id] if x]
    _cache_bust(ws_id, "dm_unread", "notifications", "notifs", "appdata")
    if peer_id: _bust_dm_thread(ws_id, me, peer_id)
    if row: _sse_publish(ws_id, "dm_created", {"id": row.get("id"), "sender": me, "recipient": peer_id, "message": row})
    _sse_publish(ws_id, "call_status", {"callId": call_id, "status": status, "action": action, "users": users, "sender": me, "recipient": peer_id, "meetUrl": meet_url})
    return jsonify({"ok": True, "status": status, "meetUrl": meet_url, "message": row})

@app.route("/api/dm/react",methods=["POST"])
@login_required
def react_dm():
    d=request.json or {}
    msg_id=(d.get("message_id") or "").strip()
    emoji=(d.get("emoji") or "").strip()
    allowed={"👍","👎","❤️","😂","🤣","😮","😢","🙏","🔥","👏","👀","🚀","🎉","💯","✅","😍","🤔","🙌","💪","🤝","⭐"}
    if not msg_id or emoji not in allowed:
        return jsonify({"error":"Invalid reaction"}),400
    ws_id=wid(); me=session["user_id"]
    with get_db() as db:
        msg=db.execute("SELECT * FROM direct_messages WHERE id=? AND workspace_id=?",(msg_id,ws_id)).fetchone()
        if not msg or (msg["sender"]!=me and msg["recipient"]!=me):
            return jsonify({"error":"Message not found"}),404
        existing=db.execute("SELECT id FROM dm_reactions WHERE workspace_id=? AND message_id=? AND user_id=? AND emoji=?",
                            (ws_id,msg_id,me,emoji)).fetchone()
        action="added"
        if existing:
            db.execute("DELETE FROM dm_reactions WHERE id=?",(existing["id"],))
            action="removed"
        else:
            rid=f"rx{int(datetime.now().timestamp()*1000)}{abs(hash(me+msg_id+emoji))%10000}"
            db.execute("INSERT OR IGNORE INTO dm_reactions(id,workspace_id,message_id,user_id,emoji,ts) VALUES (?,?,?,?,?,?)",
                       (rid,ws_id,msg_id,me,emoji,ts()))
        rows=db.execute("SELECT * FROM direct_messages WHERE id=? AND workspace_id=?",(msg_id,ws_id)).fetchall()
        data=_attach_dm_reactions(db, ws_id, rows)[0] if rows else None
    # Do not bust appdata cache for reactions; it caused stale poll/refetch races and slow UI.
    _sse_publish(ws_id, "dm_reaction", {"message_id": msg_id, "sender": msg["sender"], "recipient": msg["recipient"], "emoji": emoji, "user_id": me, "action": action, "message": data})
    return jsonify({"message_id":msg_id,"action":action,"message":data})

@app.route("/api/dm",methods=["POST"])
@login_required
def send_dm():
    d=request.json or {}
    content=(d.get("content") or "").strip()
    recipient=(d.get("recipient") or "").strip()
    reply_to=(d.get("reply_to") or "").strip()
    if not content:
        return jsonify({"error":"Empty"}),400
    if not recipient:
        return jsonify({"error":"Missing recipient"}),400

    ws_id=wid()
    me=session["user_id"]
    now=ts()
    mid=f"dm{int(datetime.now().timestamp()*1000)}{secrets.token_hex(2)}"

    with get_db() as db:
        target=db.execute("SELECT id FROM users WHERE id=? AND workspace_id=? AND deleted_at=''", (recipient, ws_id)).fetchone()
        if not target:
            return jsonify({"error":"Recipient not found"}),404
        db.execute("""INSERT INTO direct_messages(
                       id,workspace_id,sender,recipient,content,read,ts,reply_to,
                       delivered_at,seen_at,edited,deleted,pinned
                   ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                   (mid,ws_id,me,recipient,content,0,now,reply_to,now,"",0,0,0))
        row=dict(db.execute("SELECT * FROM direct_messages WHERE id=? AND workspace_id=?",(mid,ws_id)).fetchone())
        sender=db.execute("SELECT name FROM users WHERE id=? AND workspace_id=?",(me,ws_id)).fetchone()
        sender_name=sender["name"] if sender and sender["name"] else "Someone"
        preview=content[:60]+("..." if len(content)>60 else "")

    # Do slow fanout after the response path. The sender already has an
    # optimistic bubble, and the receiver is notified by SSE from this thread.
    def _after_dm_send():
        try:
            with get_db() as db2:
                nid=f"n{int(datetime.now().timestamp()*1000)}{secrets.token_hex(2)}"
                try:
                    db2.execute("INSERT INTO notifications(id,workspace_id,type,content,user_id,read,ts,sender_id) VALUES (?,?,?,?,?,?,?,?)",
                                (nid,ws_id,"dm",f"{sender_name}: {preview}",recipient,0,now,me))
                except Exception:
                    db2.execute("INSERT INTO notifications(id,workspace_id,type,content,user_id,read,ts) VALUES (?,?,?,?,?,?,?)",
                                (nid,ws_id,"dm",f"{sender_name}: {preview}",recipient,0,now))
        except Exception as e:
            log.warning("[DM] notification insert failed: %s", e)
        _cache_bust(ws_id, "dm_unread", "notifications", "notifs", "appdata")
        _bust_dm_thread(ws_id, me, recipient)
        _sse_publish(ws_id, "dm_created", {"id": mid, "sender": me, "recipient": recipient, "content": preview, "message": row})
        _sse_publish(ws_id, "notification_updated", {"reason": "dm", "sender": me, "recipient": recipient})
    threading.Thread(target=_after_dm_send, daemon=True).start()
    return jsonify(row)


def _get_dm_message_with_reactions(db, ws_id, mid):
    rows=db.execute("SELECT * FROM direct_messages WHERE id=? AND workspace_id=?",(mid,ws_id)).fetchall()
    return _attach_dm_reactions(db, ws_id, rows)[0] if rows else None

@app.route("/api/dm/edit",methods=["POST"])
@login_required
def edit_dm():
    d=request.json or {}
    mid=(d.get("message_id") or "").strip(); content=(d.get("content") or "").strip()
    if not mid or not content: return jsonify({"error":"Invalid edit"}),400
    ws_id=wid(); me=session["user_id"]
    with get_db() as db:
        msg=db.execute("SELECT * FROM direct_messages WHERE id=? AND workspace_id=?",(mid,ws_id)).fetchone()
        if not msg or msg["sender"]!=me: return jsonify({"error":"Not allowed"}),403
        db.execute("UPDATE direct_messages SET content=?, edited=1 WHERE id=? AND workspace_id=?",(content,mid,ws_id))
        data=_get_dm_message_with_reactions(db,ws_id,mid)
    _sse_publish(ws_id,"dm_updated",{"message":data})
    return jsonify({"message":data})

@app.route("/api/dm/delete",methods=["POST"])
@login_required
def delete_dm_message():
    d=request.json or {}; mid=(d.get("message_id") or "").strip()
    if not mid: return jsonify({"error":"Invalid message"}),400
    ws_id=wid(); me=session["user_id"]
    with get_db() as db:
        msg=db.execute("SELECT * FROM direct_messages WHERE id=? AND workspace_id=?",(mid,ws_id)).fetchone()
        if not msg or msg["sender"]!=me: return jsonify({"error":"Not allowed"}),403
        db.execute("UPDATE direct_messages SET content=?, deleted=1 WHERE id=? AND workspace_id=?",("This message was deleted",mid,ws_id))
        db.execute("DELETE FROM dm_reactions WHERE workspace_id=? AND message_id=?",(ws_id,mid))
        data=_get_dm_message_with_reactions(db,ws_id,mid)
    _sse_publish(ws_id,"dm_deleted",{"message":data})
    return jsonify({"message":data})

@app.route("/api/dm/pin",methods=["POST"])
@login_required
def pin_dm_message():
    d=request.json or {}; mid=(d.get("message_id") or "").strip(); pinned=1 if d.get("pinned") else 0
    if not mid: return jsonify({"error":"Invalid message"}),400
    ws_id=wid(); me=session["user_id"]
    with get_db() as db:
        msg=db.execute("SELECT * FROM direct_messages WHERE id=? AND workspace_id=?",(mid,ws_id)).fetchone()
        if not msg or (msg["sender"]!=me and msg["recipient"]!=me): return jsonify({"error":"Not allowed"}),403
        db.execute("UPDATE direct_messages SET pinned=? WHERE id=? AND workspace_id=?",(pinned,mid,ws_id))
        data=_get_dm_message_with_reactions(db,ws_id,mid)
    _sse_publish(ws_id,"dm_pinned",{"message":data})
    return jsonify({"message":data})

@app.route("/api/dm/typing",methods=["POST"])
@login_required
def dm_typing():
    d=request.json or {}; recipient=(d.get("recipient") or "").strip(); typing=bool(d.get("typing"))
    if recipient:
        _sse_publish(wid(),"dm_typing",{"sender":session["user_id"],"recipient":recipient,"typing":typing})
    return jsonify({"ok":True})

@app.route("/api/dm/unread")
@login_required
def dm_unread():
    ws, uid = wid(), session["user_id"]
    data, found = _appdata_cache_get(ws, uid, "dm_unread")
    if found: return jsonify(data)
    with get_db() as db:
        rows = db.execute("""SELECT sender,COUNT(*) as cnt FROM direct_messages
            WHERE workspace_id=? AND recipient=? AND read=0 GROUP BY sender""",
            (ws, uid)).fetchall()
        return jsonify([dict(r) for r in rows])

# ── Reminders ─────────────────────────────────────────────────────────────────
@app.route("/api/reminders", methods=["GET"])
@login_required
def get_reminders():
    include_fired=request.args.get("include_fired","0")=="1"
    with get_db() as db:
        if include_fired:
            rows=db.execute("SELECT * FROM reminders WHERE workspace_id=? AND user_id=? ORDER BY remind_at DESC",
                            (wid(),session["user_id"])).fetchall()
        else:
            rows=db.execute("SELECT * FROM reminders WHERE workspace_id=? AND user_id=? AND fired=0 ORDER BY remind_at",
                            (wid(),session["user_id"])).fetchall()
        return jsonify([dict(r) for r in rows])

@app.route("/api/reminders", methods=["POST"])
@login_required
def create_reminder():
    d=request.json or {}
    if not d.get("remind_at"): return jsonify({"error":"remind_at required"}),400
    rid=f"r{int(datetime.now().timestamp()*1000)}"
    with get_db() as db:
        db.execute("INSERT INTO reminders VALUES (?,?,?,?,?,?,?,?,?)",
                   (rid,wid(),session["user_id"],d.get("task_id",""),d.get("task_title","Reminder"),
                    d["remind_at"],d.get("minutes_before",10),0,ts()))
        row=db.execute("SELECT * FROM reminders WHERE id=?",(rid,)).fetchone()
        _enqueue_push(push_notification_to_user, db, session["user_id"], "⏰ Reminder set",
            f"{d.get('task_title','Reminder')} — you'll be notified before the time.", "/")
        result=dict(row)
    _sse_publish(wid(), "reminder_updated", {"id": rid, "action": "created"})
    return jsonify(result)

@app.route("/api/reminders/<rid>", methods=["PUT"])
@login_required
def update_reminder(rid):
    d=request.json or {}
    with get_db() as db:
        existing=db.execute("SELECT * FROM reminders WHERE id=? AND user_id=?",(rid,session["user_id"])).fetchone()
        if not existing: return jsonify({"error":"Not found"}),404
        remind_at=d.get("remind_at",existing["remind_at"])
        minutes_before=d.get("minutes_before",existing["minutes_before"])
        task_title=d.get("task_title",existing["task_title"])
        db.execute("UPDATE reminders SET remind_at=?,minutes_before=?,task_title=?,fired=0 WHERE id=? AND user_id=?",
                   (remind_at,minutes_before,task_title,rid,session["user_id"]))
        row=db.execute("SELECT * FROM reminders WHERE id=?",(rid,)).fetchone()
        _enqueue_push(push_notification_to_user, *(db, session["user_id"], "⏰ Reminder updated",
                  f"'{task_title}' has been rescheduled.", "/"))
        return jsonify(dict(row))

@app.route("/api/reminders/<rid>", methods=["DELETE"])
@login_required
def delete_reminder(rid):
    with get_db() as db:
        db.execute("DELETE FROM reminders WHERE id=? AND user_id=?",(rid,session["user_id"]))
        return jsonify({"ok":True})

# ── Teams ─────────────────────────────────────────────────────────────────────
@app.route("/api/teams", methods=["GET"])
@login_required
def get_teams():
    with get_db() as db:
        rows=db.execute("SELECT * FROM teams WHERE workspace_id=? ORDER BY created DESC",(wid(),)).fetchall()
        return jsonify([dict(r) for r in rows])

@app.route("/api/teams", methods=["POST"])
@login_required
@require_role("Admin", "Manager")
def create_team():
    d=request.json or {}
    if not d.get("name"): return jsonify({"error":"name required"}),400
    tid=f"tm{int(datetime.now().timestamp()*1000)}"
    with get_db() as db:
        db.execute("INSERT INTO teams VALUES (?,?,?,?,?,?)",
                   (tid,wid(),d["name"],d.get("lead_id",""),json.dumps(d.get("member_ids",[])),ts()))
        result=dict(db.execute("SELECT * FROM teams WHERE id=? AND workspace_id=?",(tid,wid())).fetchone())
    _cache_bust_ws(wid())
    return jsonify(result)

@app.route("/api/teams/<tid>", methods=["PUT"])
@login_required
@require_role("Admin", "Manager")
def update_team(tid):
    d=request.json or {}
    with get_db() as db:
        t=db.execute("SELECT * FROM teams WHERE id=? AND workspace_id=?",(tid,wid())).fetchone()
        if not t: return jsonify({"error":"not found"}),404
        new_member_ids = d.get("member_ids", json.loads(t["member_ids"] or "[]"))
        db.execute("UPDATE teams SET name=?,lead_id=?,member_ids=? WHERE id=?",
                   (d.get("name",t["name"]),d.get("lead_id",t["lead_id"]),
                    json.dumps(new_member_ids),tid))
        # ── Auto-sync: merge team members into all projects linked to this team ──
        # This ensures the Members tab in a project always reflects team membership.
        if new_member_ids:
            linked = db.execute(
                "SELECT id, members FROM projects WHERE workspace_id=? AND team_id=?",
                (wid(), tid)).fetchall()
            for proj in linked:
                try:
                    existing = set(json.loads(proj["members"] or "[]"))
                    merged   = list(existing | set(new_member_ids))
                    db.execute("UPDATE projects SET members=? WHERE id=? AND workspace_id=?",
                               (json.dumps(merged), proj["id"], wid()))
                except Exception:
                    pass
        updated = db.execute("SELECT * FROM teams WHERE id=? AND workspace_id=?",(tid,wid())).fetchone()
    # Bust full workspace cache so project members reflect immediately on next poll
    _cache_bust_ws(wid())
    return jsonify(dict(updated))

@app.route("/api/teams/<tid>", methods=["DELETE"])
@login_required
@require_role("Admin", "Manager")
def delete_team(tid):
    with get_db() as db:
        db.execute("DELETE FROM teams WHERE id=? AND workspace_id=?",(tid,wid()))
    _cache_bust_ws(wid())
    return jsonify({"ok":True})

@app.route("/api/teams/<tid>/dashboard")
@login_required
def team_dashboard(tid):
    """Return rich stats for a single team: projects, tasks, member workloads."""
    with get_db() as db:
        team=db.execute("SELECT * FROM teams WHERE id=? AND workspace_id=?",(tid,wid())).fetchone()
        if not team: return jsonify({"error":"Not found"}),404
        member_ids=json.loads(team["member_ids"] or "[]")
        all_tasks=db.execute("SELECT * FROM tasks WHERE workspace_id=?",(wid(),)).fetchall()
        team_tasks=[t for t in all_tasks if t["assignee"] in member_ids or (t["team_id"] if "team_id" in t.keys() else "")==tid]
        proj_ids=list({t["project"] for t in team_tasks if t["project"]})
        projects=[]
        for pid in proj_ids:
            p=db.execute("SELECT * FROM projects WHERE id=? AND workspace_id=?",(pid,wid())).fetchone()
            if p: projects.append(dict(p))
        member_stats=[]
        for uid in member_ids:
            u=db.execute("SELECT id,name,email,role,avatar,color FROM users WHERE id=?",(uid,)).fetchone()
            if not u: continue
            mtasks=[t for t in team_tasks if t["assignee"]==uid]
            member_stats.append({
                "id":uid,"name":u["name"],"role":u["role"],"avatar":u["avatar"],"color":u["color"],
                "total":len(mtasks),
                "completed":len([t for t in mtasks if t["stage"]=="completed"]),
                "in_progress":len([t for t in mtasks if t["stage"] in ("development","in-progress","code_review","testing","uat")]),
                "blocked":len([t for t in mtasks if t["stage"]=="blocked"]),
                "overdue":len([t for t in mtasks if t["due"] and t["due"]<now_ist().strftime("%Y-%m-%dT%H:%M:%S") and t["stage"]!="completed"]),
            })
        total=len(team_tasks)
        return jsonify({
            "team":dict(team),
            "projects":projects,
            "tasks":[dict(t) for t in team_tasks],
            "member_stats":member_stats,
            "summary":{
                "total_projects":len(projects),
                "total_tasks":total,
                "completed":len([t for t in team_tasks if t["stage"]=="completed"]),
                "in_progress":len([t for t in team_tasks if t["stage"] in ("development","in-progress","code_review","testing","uat")]),
                "blocked":len([t for t in team_tasks if t["stage"]=="blocked"]),
                "pending":len([t for t in team_tasks if t["stage"] in ("backlog","planning")]),
            }
        })

# ── Tickets ───────────────────────────────────────────────────────────────────
@app.route("/api/tickets", methods=["GET"])
@login_required
def get_tickets():
    ws, uid = wid(), session["user_id"]
    status  = request.args.get("status", "")
    team_id = request.args.get("team_id", "")
    # Serve from shared appdata cache when no filters applied
    if not status and not team_id:
        data, found = _appdata_cache_get(ws, uid, "tickets")
        if found: return jsonify(data)
    with get_db() as db:
        if team_id:
            team=db.execute("SELECT member_ids FROM teams WHERE id=? AND workspace_id=?",(team_id,wid())).fetchone()
            member_ids=json.loads(team["member_ids"] if team else "[]")
            team_projs=db.execute("SELECT id FROM projects WHERE workspace_id=? AND team_id=?",(wid(),team_id)).fetchall()
            proj_ids=[p["id"] for p in team_projs]
            all_rows=db.execute("SELECT * FROM tickets WHERE workspace_id=? ORDER BY created DESC",(wid(),)).fetchall()
            mem_set=set(member_ids); proj_set=set(proj_ids)
            rows=[r for r in all_rows if
                (r["team_id"] if "team_id" in r.keys() else "")==team_id or
                (r["assignee"] and r["assignee"] in mem_set) or
                (r["project"] and r["project"] in proj_set)]
            if status: rows=[r for r in rows if r["status"]==status]
        elif status:
            rows=db.execute("SELECT * FROM tickets WHERE workspace_id=? AND status=? ORDER BY created DESC",(wid(),status)).fetchall()
        else:
            rows=db.execute("SELECT * FROM tickets WHERE workspace_id=? ORDER BY created DESC",(wid(),)).fetchall()
        return jsonify([dict(r) for r in rows])

@app.route("/api/tickets", methods=["POST"])
@login_required
def create_ticket():
    d=request.json or {}
    if not d.get("title"): return jsonify({"error":"title required"}),400
    tid=f"tkt{int(datetime.now().timestamp()*1000)}"
    now=ts()
    with get_db() as db:
        db.execute("INSERT INTO tickets VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                   (tid,wid(),d["title"],d.get("description",""),d.get("type","bug"),
                    d.get("priority","medium"),d.get("status","open"),d.get("assignee",""),
                    session["user_id"],d.get("project",""),json.dumps(d.get("tags",[])),now,now,
                    d.get("team_id","")))
        if d.get("assignee"):
            nid=f"n{int(datetime.now().timestamp()*1000)}"
            reporter=db.execute("SELECT name FROM users WHERE id=?",(session["user_id"],)).fetchone()
            rname=reporter["name"] if reporter else "Someone"
            db.execute("INSERT INTO notifications(id,workspace_id,type,content,user_id,read,ts,entity_id,entity_type) VALUES (?,?,?,?,?,?,?,?,?)",
                       (nid,wid(),"task_assigned",f"🎫 {rname} assigned ticket: {d['title']}",d["assignee"],0,now,tid,'ticket'))
            # Email the assigned person (including when self-assigned)
            assignee_tkt=db.execute("SELECT name,email FROM users WHERE id=?",(d["assignee"],)).fetchone()
            if assignee_tkt and assignee_tkt["email"]:
                threading.Thread(target=send_ticket_assigned_email,
                    args=(assignee_tkt["email"],assignee_tkt["name"],d["title"],
                          rname,tid,d.get("priority","medium"),wid()),
                    daemon=True).start()
        result=dict(db.execute("SELECT * FROM tickets WHERE id=? AND workspace_id=?",(tid,wid())).fetchone())
    # Targeted bust: only tickets + appdata. Avoids wiping user/project/task caches.
    _cache_bust(wid(), "tickets", "appdata")
    _sse_publish(wid(), "ticket_updated", {"id": tid, "action": "created"})
    return jsonify(result)
@login_required
def update_ticket(tid):
    d=request.json or {}
    with get_db() as db:
        cu=db.execute("SELECT role FROM users WHERE id=?",(session["user_id"],)).fetchone()
        cu_role=cu["role"] if cu else "Viewer"
        if cu_role=="Developer":
            allowed_fields = {"status"}
            if not set(d.keys()).issubset(allowed_fields):
                return jsonify({"error":"Developers can only update ticket status."}),403
        t=db.execute("SELECT * FROM tickets WHERE id=? AND workspace_id=?",(tid,wid())).fetchone()
        if not t: return jsonify({"error":"not found"}),404
        now=ts()
        cur_team_id = t["team_id"] if "team_id" in t.keys() else ""
        db.execute("UPDATE tickets SET title=?,description=?,type=?,priority=?,status=?,assignee=?,project=?,tags=?,updated=?,team_id=? WHERE id=?",
                   (d.get("title",t["title"]),d.get("description",t["description"]),
                    d.get("type",t["type"]),d.get("priority",t["priority"]),
                    d.get("status",t["status"]),d.get("assignee",t["assignee"]),
                    d.get("project",t["project"]),json.dumps(d.get("tags",json.loads(t["tags"] or "[]"))),now,
                    d.get("team_id",cur_team_id),tid))
        result=dict(db.execute("SELECT * FROM tickets WHERE id=? AND workspace_id=?",(tid,wid())).fetchone())
        # Email on ticket status change — notify assignee and reporter if different
        if d.get("status") and d["status"] != t["status"]:
            _tkt_changer = db.execute("SELECT name FROM users WHERE id=?", (session["user_id"],)).fetchone()
            _tkt_changer_name = _tkt_changer["name"] if _tkt_changer else "Someone"
            _tkt_notified = set()
            for _tkt_uid in [t["assignee"], t["reporter"]]:
                if not _tkt_uid or _tkt_uid in _tkt_notified:
                    continue
                _tkt_notified.add(_tkt_uid)
                _tkt_user = db.execute("SELECT name,email FROM users WHERE id=?", (_tkt_uid,)).fetchone()
                if _tkt_user and _tkt_user["email"]:
                    threading.Thread(target=send_ticket_status_email,
                        args=(_tkt_user["email"], _tkt_user["name"], t["title"],
                              d["status"], _tkt_changer_name, tid, wid()),
                        daemon=True).start()
    _cache_bust(wid(), "tickets", "appdata")
    _sse_publish(wid(), "ticket_updated", {"id": tid, "action": "updated",
                                            "status": result.get("status","")})
    return jsonify(result)
@login_required
def delete_ticket(tid):
    with get_db() as db:
        cu=db.execute("SELECT role FROM users WHERE id=?",(session["user_id"],)).fetchone()
        cu_role=cu["role"] if cu else "Viewer"
        if cu_role not in ("Admin","Manager","TeamLead"):
            return jsonify({"error":"Only Admin, Manager, or TeamLead can delete tickets."}),403
        db.execute("DELETE FROM tickets WHERE id=? AND workspace_id=?",(tid,wid()))
        db.execute("DELETE FROM ticket_comments WHERE ticket_id=? AND workspace_id=?",(tid,wid()))
    _cache_bust(wid(), "tickets", "appdata")
    return jsonify({"ok":True})

@app.route("/api/tickets/<tid>/comments", methods=["GET"])
@login_required
def get_ticket_comments(tid):
    with get_db() as db:
        rows=db.execute("SELECT * FROM ticket_comments WHERE ticket_id=? AND workspace_id=? ORDER BY created",(tid,wid())).fetchall()
        return jsonify([dict(r) for r in rows])

@app.route("/api/tickets/<tid>/comments", methods=["POST"])
@login_required
def add_ticket_comment(tid):
    d=request.json or {}
    if not d.get("content"): return jsonify({"error":"content required"}),400
    cid=f"tc{int(datetime.now().timestamp()*1000)}"
    with get_db() as db:
        db.execute("INSERT INTO ticket_comments VALUES (?,?,?,?,?,?)",
                   (cid,wid(),tid,session["user_id"],d["content"],ts()))
        return jsonify(dict(db.execute("SELECT * FROM ticket_comments WHERE id=?",(cid,)).fetchone()))

# ── Calls (Huddle) ────────────────────────────────────────────────────────────

@app.route("/api/migrate-timelog", methods=["GET","POST"])
@login_required
def migrate_timelog_public():
    """Schema migration helper — requires admin login.
    FIX (Bug 5): Endpoint was completely unauthenticated, allowing any
    anonymous user to trigger DDL operations on the database. Now requires
    an active admin session."""
    if get_user_role() != "admin":
        return jsonify({"error": "Admin access required"}), 403
    results = []
    steps = [
        ("CREATE time_logs base", """CREATE TABLE IF NOT EXISTS time_logs (
            id TEXT PRIMARY KEY, workspace_id TEXT, user_id TEXT,
            hours REAL DEFAULT 0, minutes INTEGER DEFAULT 0,
            comments TEXT DEFAULT '', created TEXT)"""),
        ("ADD team_id",    "ALTER TABLE time_logs ADD COLUMN team_id    TEXT DEFAULT ''"),
        ("ADD date",       "ALTER TABLE time_logs ADD COLUMN date       TEXT DEFAULT ''"),
        ("ADD task_name",  "ALTER TABLE time_logs ADD COLUMN task_name  TEXT DEFAULT ''"),
        ("ADD project_id", "ALTER TABLE time_logs ADD COLUMN project_id TEXT DEFAULT ''"),
        ("ADD task_id",    "ALTER TABLE time_logs ADD COLUMN task_id    TEXT DEFAULT ''"),
        ("ADD req_hours",  "ALTER TABLE workspaces ADD COLUMN required_hours_per_day REAL DEFAULT 8"),
    ]
    for label, sql in steps:
        try:
            from pg8000.native import Connection as _C
            c = _C(**_parse_db_url(DATABASE_URL))
            try:
                c.run(sql)
                results.append({"step": label, "status": "ok"})
            except Exception as e:
                msg = str(e).lower()
                if any(x in msg for x in ["already exists","duplicate","column already","relation already"]):
                    results.append({"step": label, "status": "already_exists"})
                else:
                    results.append({"step": label, "status": "error", "msg": str(e)})
            finally:
                try: c.close()
                except: pass
        except Exception as e:
            results.append({"step": label, "status": "connect_error", "msg": str(e)})
    log.info("[migrate-timelog] %s", results)
    return jsonify({"ok": True, "results": results})


@app.route("/api/timelogs/setup", methods=["POST"])
@login_required
def timelogs_setup():
    # FIX (Bug 1): ensure_timelog_schema() runs ~12 sequential DDL statements
    # that can take 5-6 s total. Running it on the request thread caused the
    # client to disconnect (nginx/Railway 499) before the response arrived.
    # Solution: mirror the pattern already used in logout() — return 200
    # immediately and run the slow work in a daemon background thread.
    def _bg_setup():
        try:
            ensure_timelog_schema()
        except Exception as _e:
            log.warning("[timelogs/setup] background schema migration failed: %s", _e)
    _cthread.Thread(target=_bg_setup, daemon=True).start()
    return jsonify({"ok": True, "message": "schema migration started in background"})


@app.route("/api/timelogs", methods=["GET"])
@login_required
def get_timelogs():
    """Return timelogs. Uses a single JOIN query that also fetches role,
    eliminating the separate get_user_role() DB round-trip. Cached 20s."""
    uid  = session["user_id"]
    ws   = wid()
    cache_key = f"timelogs:{ws}:{uid}"
    cached = _cache_get(cache_key)
    if cached is not None:
        return jsonify(cached)
    try:
        # Single query: get role + timelogs in one round-trip
        rows = _raw_pg(
            "SELECT tl.*, u.name as user_name, me.role as _my_role "
            "FROM time_logs tl "
            "LEFT JOIN users u ON tl.user_id=u.id "
            "JOIN users me ON me.id=? AND me.workspace_id=? "
            "WHERE tl.workspace_id=? "
            "ORDER BY tl.date DESC, tl.created DESC LIMIT 500",
            (uid, ws, ws), fetch=True
        ) or []
        # The JOIN returns rows for all timelogs — filter by role client-side
        # (role comes from the first row)
        role = rows[0].get("_my_role", "") if rows else ""
        if role not in ("Admin", "Manager"):
            rows = [r for r in rows if r.get("user_id") == uid]
        # Strip the helper column
        for r in rows:
            r.pop("_my_role", None)
        _cache_set(cache_key, rows)
        return jsonify(rows)
    except Exception as e:
        log.error("[get_timelogs] %s", e)
        # Fallback to two-query approach
        try:
            role = get_user_role()
            ws_ = ws
            if role in ("Admin", "Manager"):
                rows = _raw_pg(
                    "SELECT tl.*, u.name as user_name FROM time_logs tl "
                    "LEFT JOIN users u ON tl.user_id=u.id "
                    "WHERE tl.workspace_id=? ORDER BY tl.date DESC, tl.created DESC LIMIT 500",
                    (ws_,), fetch=True)
            else:
                rows = _raw_pg(
                    "SELECT tl.*, u.name as user_name FROM time_logs tl "
                    "LEFT JOIN users u ON tl.user_id=u.id "
                    "WHERE tl.workspace_id=? AND tl.user_id=? "
                    "ORDER BY tl.date DESC, tl.created DESC LIMIT 500",
                    (ws_, uid), fetch=True)
            return jsonify(rows or [])
        except Exception as e2:
            log.error("[get_timelogs fallback] %s", e2)
            ensure_timelog_schema()
            return jsonify([])


@app.route("/api/timelogs", methods=["POST"])
@login_required
def create_timelog():
    d   = request.json or {}
    lid = f"tl{int(datetime.now().timestamp()*1000)}"
    values = (
        lid,
        wid(),
        session["user_id"],
        d.get("team_id", "") or "",
        d.get("date", now_ist().strftime("%Y-%m-%d")),
        d.get("task_name", "") or "",
        d.get("project_id", "") or "",
        d.get("task_id", "") or "",
        float(d.get("hours") or 0),
        int(d.get("minutes") or 0),
        d.get("comments", "") or "",
        ts()
    )
    sql = """INSERT INTO time_logs
             (id, workspace_id, user_id, team_id, date, task_name,
              project_id, task_id, hours, minutes, comments, created)
             VALUES (?,?,?,?,?,?,?,?,?,?,?,?)"""
    try:
        _raw_pg(sql, values)
        return jsonify({"id": lid, "ok": True})
    except Exception as e:
        log.error("[timelog create] %s: %s", type(e).__name__, e)
        # Run schema fix then retry
        ensure_timelog_schema()
        try:
            _raw_pg(sql, values)
            log.info("[timelog] retry succeeded: %s", lid)
            return jsonify({"id": lid, "ok": True})
        except Exception as e2:
            log.error("[timelog retry failed] %s: %s", type(e2).__name__, e2)
            return jsonify({"error": str(e2)}), 500


@app.route("/api/timelogs/<log_id>", methods=["DELETE"])
@login_required
def delete_timelog(log_id):
    rows = _raw_pg("SELECT user_id FROM time_logs WHERE id=? AND workspace_id=?",
                   (log_id, wid()), fetch=True)
    if not rows:
        return jsonify({"error": "Not found"}), 404
    if rows[0]["user_id"] != session["user_id"] and get_user_role() not in ("Admin","Manager"):
        return jsonify({"error": "Forbidden"}), 403
    _raw_pg("DELETE FROM time_logs WHERE id=?", (log_id,))
    return jsonify({"ok": True})


@app.route("/api/timelogs/<log_id>", methods=["PUT"])
@login_required
def update_timelog(log_id):
    d = request.json or {}
    rows = _raw_pg("SELECT user_id FROM time_logs WHERE id=? AND workspace_id=?",
                   (log_id, wid()), fetch=True)
    if not rows:
        return jsonify({"error": "Not found"}), 404
    if rows[0]["user_id"] != session["user_id"] and get_user_role() not in ("Admin","Manager"):
        return jsonify({"error": "Forbidden"}), 403
    _raw_pg("UPDATE time_logs SET hours=?, minutes=?, comments=? WHERE id=?",
            (float(d.get("hours") or 0), int(d.get("minutes") or 0),
             d.get("comments", "") or "", log_id))
    return jsonify({"ok": True, "id": log_id})


@app.route("/api/timelogs/required-hours", methods=["GET", "POST"])
@login_required
def required_hours():
    if request.method == "GET":
        try:
            rows = _raw_pg("SELECT required_hours_per_day FROM workspaces WHERE id=?",
                           (wid(),), fetch=True)
            hrs = float(rows[0]["required_hours_per_day"]) if rows and rows[0].get("required_hours_per_day") is not None else 8.0
        except Exception:
            hrs = 8.0
        return jsonify({"hours": hrs})
    # POST — Admin or Manager only (role fetched from DB since not in session)
    if get_user_role() not in ("Admin", "Manager"):
        return jsonify({"error": "Forbidden"}), 403
    hrs = float((request.json or {}).get("hours", 8))
    _run_ddl("ALTER TABLE workspaces ADD COLUMN required_hours_per_day REAL DEFAULT 8")
    try:
        _raw_pg("UPDATE workspaces SET required_hours_per_day=? WHERE id=?", (hrs, wid()))
        return jsonify({"ok": True})
    except Exception as e:
        log.error("[required_hours] %s", e)
        return jsonify({"error": str(e)}), 500


# [Calling/WebRTC mechanism removed — use Google Meet or external tools]

@app.route("/api/reminders/due", methods=["GET"])
@login_required
def due_reminders():
    """Return reminders due now. Checks appdata cache first; only hits DB to mark fired."""
    ws, uid = wid(), session["user_id"]
    now_str = ts()
    # Get all reminders from cache
    cached_reminders, found = _appdata_cache_get(ws, uid, "reminders")
    if found:
        due = [r for r in cached_reminders
               if not r.get("fired") and r.get("remind_at","") <= now_str]
        if due:
            ids = [r["id"] for r in due]
            try:
                with get_db() as db:
                    db.execute(f"UPDATE reminders SET fired=1 WHERE id IN ({','.join('?'*len(ids))})", ids)
                # Bust reminders cache so next poll gets updated fired status
                _cache_bust(ws, "reminders")
            except Exception: pass
        return jsonify(due)
    # Fallback: hit DB directly
    with get_db() as db:
        rows = db.execute("""SELECT * FROM reminders WHERE workspace_id=? AND user_id=?
            AND fired=0 AND remind_at <= ?""", (ws, uid, now_str)).fetchall()
        ids  = [r["id"] for r in rows]
        if ids:
            db.execute(f"UPDATE reminders SET fired=1 WHERE id IN ({','.join('?'*len(ids))})", ids)
        return jsonify([dict(r) for r in rows])

# ── Unified poll endpoint ─────────────────────────────────────────────────────
@app.route("/api/poll")
@login_required
def unified_poll():
    """Single endpoint returning dm_unread + notifications in ONE request.

    Replaces two separate polling calls (dm/unread every 15s + notifications
    every 20s) with one call every 20s — halves the per-user DB connection
    usage for the most frequent polling operations.

    Cache strategy: serves from the appdata cache (populated by /api/app-data)
    when fresh. Falls back to a single DB connection for both queries when
    the cache is cold, keeping the benefit of one connection vs two.
    """
    ws, uid = wid(), session["user_id"]

    # Try appdata cache for both — zero DB connections needed when warm
    dm_unread, found_dm     = _appdata_cache_get(ws, uid, "dm_unread")
    notifs,    found_notifs = _appdata_cache_get(ws, uid, "notifications")

    if found_dm and found_notifs:
        return jsonify({"dm_unread": dm_unread, "notifications": notifs})

    # One DB connection for whichever parts are cache-cold
    with get_db() as db:
        if not found_dm:
            rows = db.execute(
                "SELECT sender, COUNT(*) AS cnt FROM direct_messages "
                "WHERE workspace_id=? AND recipient=? AND read=0 GROUP BY sender",
                (ws, uid)
            ).fetchall()
            dm_unread = [dict(r) for r in rows]
        if not found_notifs:
            rows = db.execute(
                "SELECT * FROM notifications WHERE workspace_id=? AND user_id=? "
                "ORDER BY ts DESC LIMIT 50",
                (ws, uid)
            ).fetchall()
            notifs = [dict(r) for r in rows]

    return jsonify({"dm_unread": dm_unread, "notifications": notifs})


# ── Notifications ─────────────────────────────────────────────────────────────

@app.route("/api/notifications")
@login_required
def get_notifs():
    ws, uid = wid(), session["user_id"]
    # Serve from shared appdata cache — avoids a separate DB round-trip
    data, found = _appdata_cache_get(ws, uid, "notifications")
    if found: return jsonify(data)
    cache_key = f"notifs:{ws}:{uid}"
    cached = _cache_get(cache_key)
    if cached is not None: return jsonify(cached)
    with get_db() as db:
        rows = db.execute("""SELECT * FROM notifications WHERE workspace_id=? AND user_id=?
            ORDER BY ts DESC LIMIT 50""", (ws, uid)).fetchall()
        result = [dict(r) for r in rows]
        _cache_set(cache_key, result)
        return jsonify(result)

@app.route("/api/notifications/read-all",methods=["PUT"])
@login_required
def notifs_read_all():
    ws, uid = wid(), session["user_id"]
    with get_db() as db:
        db.execute("UPDATE notifications SET read=1 WHERE workspace_id=? AND user_id=?", (ws, uid))
    _cache_bust(ws, "notifications", "notifs", "appdata")
    return jsonify({"ok": True})

@app.route("/api/notifications/all",methods=["DELETE"])
@login_required
def notifs_clear_all():
    ws, uid = wid(), session["user_id"]
    with get_db() as db:
        db.execute("DELETE FROM notifications WHERE workspace_id=? AND user_id=?", (ws, uid))
    _cache_bust(ws, "notifications", "notifs", "appdata")
    return jsonify({"ok": True})

@app.route("/api/notifications/<nid>", methods=["DELETE"])
@login_required
def delete_notif(nid):
    ws, uid = wid(), session["user_id"]
    with get_db() as db:
        db.execute("DELETE FROM notifications WHERE id=? AND workspace_id=? AND user_id=?", (nid, ws, uid))
    _cache_bust(ws, "notifications", "notifs", "appdata")
    return jsonify({"ok": True})

@app.route("/api/notifications/<nid>/read",methods=["PUT"])
@login_required
def read_notif(nid):
    ws, uid = wid(), session["user_id"]
    with get_db() as db:
        db.execute("UPDATE notifications SET read=1 WHERE id=? AND workspace_id=? AND user_id=?", (nid, ws, uid))
    _cache_bust(ws, "notifications", "notifs", "appdata")
    return jsonify({"ok": True})

# ── Web Push API ───────────────────────────────────────────────────────────────
@app.route("/api/push/vapid-key", methods=["GET"])
def get_vapid_public_key():
    """Return VAPID public key for frontend subscription."""
    vapid = get_vapid_keys()
    return jsonify({"publicKey": vapid.get("public", "")})

@app.route("/api/push/subscribe", methods=["POST"])
@login_required
def push_subscribe():
    """Save a Web Push subscription for the current user."""
    d = request.json or {}
    endpoint = d.get("endpoint")
    keys = d.get("keys", {})
    if not endpoint:
        return jsonify({"error": "endpoint required"}), 400
    sub_id = f"ps{int(datetime.now().timestamp()*1000)}"
    with get_db() as db:
        db.execute("""INSERT OR REPLACE INTO push_subscriptions
            (id, user_id, workspace_id, endpoint, p256dh, auth, created)
            VALUES (
                COALESCE((SELECT id FROM push_subscriptions WHERE endpoint=?), ?),
                ?, ?, ?, ?, ?, ?
            )""", (endpoint, sub_id, session["user_id"], wid(),
                   endpoint, keys.get("p256dh",""), keys.get("auth",""), ts()))
    return jsonify({"ok": True})

@app.route("/api/push/unsubscribe", methods=["POST"])
@login_required
def push_unsubscribe():
    """Remove a Web Push subscription."""
    d = request.json or {}
    endpoint = d.get("endpoint")
    with get_db() as db:
        if endpoint:
            db.execute("DELETE FROM push_subscriptions WHERE endpoint=? AND user_id=?",(endpoint, session["user_id"]))
        else:
            db.execute("DELETE FROM push_subscriptions WHERE user_id=?", (session["user_id"],))
    return jsonify({"ok": True})

# ── AI Assistant ──────────────────────────────────────────────────────────────
@app.route("/api/ai/chat",methods=["POST"])
@login_required
def ai_chat():
    d=request.json or {}
    user_msg=d.get("message","").strip()
    history=d.get("history",[])
    if not user_msg: return jsonify({"error":"Empty message"}),400

    with get_db() as db:
        ws=db.execute("SELECT * FROM workspaces WHERE id=?",(wid(),)).fetchone()
        api_key=(ws["ai_api_key"] if ws and ws["ai_api_key"] else "").strip()
        if not api_key:
            return jsonify({"error":"NO_KEY","message":"Please configure your Anthropic API key in Workspace Settings (⚙) to enable AI features."}),400

        projects=db.execute("SELECT id,name,description,target_date,color FROM projects WHERE workspace_id=?",(wid(),)).fetchall()
        tasks=db.execute("SELECT id,title,stage,priority,assignee,project,due,pct FROM tasks WHERE workspace_id=?",(wid(),)).fetchall()
        users=db.execute("SELECT id,name,role FROM users WHERE workspace_id=?",(wid(),)).fetchall()
        cu=db.execute("SELECT * FROM users WHERE id=?",(session["user_id"],)).fetchone()

    proj_ctx="\n".join([f"- {p['name']} (id:{p['id']}, due:{p['target_date']})" for p in projects])
    task_ctx="\n".join([f"- [{t['id']}] {t['title']} | stage:{t['stage']} | priority:{t['priority']} | pct:{t['pct']}%" for t in tasks])
    user_ctx="\n".join([f"- {u['name']} (id:{u['id']}, role:{u['role']})" for u in users])

    system=f"""You are an AI assistant for Project Tracker — a project management tool used by the workspace "{ws['name'] if ws else 'Unknown'}".
Current user: {cu['name']} (role: {cu['role']})
Today: {datetime.now().strftime('%Y-%m-%d')}

PROJECTS:
{proj_ctx or 'No projects yet.'}

TASKS:
{task_ctx or 'No tasks yet.'}

TEAM MEMBERS:
{user_ctx}

You can answer questions, analyze status, and PERFORM ACTIONS by including JSON in your reply like:
<action>{{"type":"create_task","title":"Task name","project":"project_id","priority":"high","stage":"backlog","assignee":"user_id","due":"YYYY-MM-DD","description":"details"}}</action>
<action>{{"type":"update_task","task_id":"T-001","stage":"testing","pct":75}}</action>
<action>{{"type":"create_project","name":"Project Name","description":"desc","color":"#5a8cff","members":["user_id"]}}</action>
<action>{{"type":"eod_report"}}</action>

IMPORTANT: Always be helpful and concise. When performing actions, explain what you did. For EOD reports, summarize all task statuses by project."""
    msgs=[{"role":"user" if m["role"]=="user" else "assistant","content":m["content"]} for m in history[-10:]]
    msgs.append({"role":"user","content":user_msg})

    try:
        req_data=json.dumps({"model":"claude-sonnet-4-5","max_tokens":1500,"system":system,"messages":msgs}).encode()
        req=urllib.request.Request("https://api.anthropic.com/v1/messages",
            data=req_data,method="POST",
            headers={"Content-Type":"application/json","x-api-key":api_key,"anthropic-version":"2023-06-01"})
        with urllib.request.urlopen(req,timeout=30) as resp:
            result=json.loads(resp.read().decode())
            ai_text=result["content"][0]["text"]
    except urllib.error.HTTPError as e:
        body=e.read().decode()
        if e.code==401: return jsonify({"error":"INVALID_KEY","message":"Invalid API key. Check your key in Workspace Settings."}),400
        return jsonify({"error":"API_ERROR","message":f"Anthropic API error: {body[:200]}"}),500
    except Exception as e:
        return jsonify({"error":"NETWORK_ERROR","message":f"Could not reach AI: {str(e)}"}),500

    import re
    actions_raw=re.findall(r'<action>(.*?)</action>',ai_text,re.DOTALL)
    action_results=[]
    clean_text=re.sub(r'<action>.*?</action>','',ai_text,flags=re.DOTALL).strip()

    for ar in actions_raw:
        try:
            act=json.loads(ar.strip())
            atype=act.get("type","")
            with get_db() as db:
                if atype=="create_task":
                    tid=next_task_id(db,wid())
                    db.execute("INSERT INTO tasks(id,workspace_id,title,description,project,assignee,priority,stage,created,due,pct,comments) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                               (tid,wid(),act.get("title","New Task"),act.get("description",""),
                                act.get("project",""),act.get("assignee",""),
                                act.get("priority","medium"),act.get("stage","backlog"),
                                ts(),act.get("due",""),0,"[]"))
                    action_results.append({"type":"create_task","id":tid,"title":act.get("title")})
                elif atype=="update_task":
                    tid=act.get("task_id","")
                    t=db.execute("SELECT * FROM tasks WHERE id=? AND workspace_id=?",(tid,wid())).fetchone()
                    if t:
                        db.execute("UPDATE tasks SET stage=?,pct=?,priority=?,assignee=? WHERE id=? AND workspace_id=?",
                                   (act.get("stage",t["stage"]),act.get("pct",t["pct"]),
                                    act.get("priority",t["priority"]),act.get("assignee",t["assignee"]),tid,wid()))
                        action_results.append({"type":"update_task","id":tid})
                elif atype=="create_project":
                    pid=f"p{int(datetime.now().timestamp()*1000)}"
                    mems=act.get("members",[session["user_id"]])
                    db.execute("INSERT INTO projects VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                               (pid,wid(),act.get("name","New Project"),act.get("description",""),
                                session["user_id"],json.dumps(mems),"",act.get("target_date",""),0,
                                act.get("color","#5a8cff"),ts()))
                    action_results.append({"type":"create_project","id":pid,"name":act.get("name")})
                elif atype=="eod_report":
                    rows=db.execute("SELECT t.*,p.name as pname FROM tasks t LEFT JOIN projects p ON t.project=p.id WHERE t.workspace_id=?",(wid(),)).fetchall()
                    by_stage={}
                    for r in rows:
                        s=r["stage"]
                        by_stage.setdefault(s,[]).append(r["title"])
                    report_lines=[]
                    for st,titles in by_stage.items():
                        report_lines.append(f"**{st.upper()}** ({len(titles)}): "+", ".join(titles[:3])+("..." if len(titles)>3 else ""))
                    action_results.append({"type":"eod_report","summary":"\n".join(report_lines)})
        except Exception as ex:
            action_results.append({"type":"error","message":str(ex)})

    return jsonify({"message":clean_text,"actions":action_results,"raw":ai_text})

@app.route("/api/ai/generate-docs",methods=["POST"])
@login_required
def ai_generate_docs():
    """Generate documentation from user description + workspace data."""
    d = request.json or {}
    doc_type = d.get("type", "documentation")
    project_id = d.get("project_id", "")
    user_description = d.get("context", "").strip()
    tech_stack = d.get("tech_stack", "").strip()
    audience = d.get("audience", "technical")

    with get_db() as db:
        ws = db.execute("SELECT * FROM workspaces WHERE id=?", (wid(),)).fetchone()
        api_key = (ws["ai_api_key"] if ws and ws["ai_api_key"] else "").strip()
        if not api_key:
            return jsonify({"error": "NO_KEY", "message": "Configure your Anthropic API key in Settings → AI Assistant."}), 400

        if project_id:
            projects = db.execute("SELECT * FROM projects WHERE id=? AND workspace_id=?", (project_id, wid())).fetchall()
            tasks = db.execute(
                "SELECT t.*, u.name as assignee_name FROM tasks t LEFT JOIN users u ON t.assignee=u.id "
                "WHERE t.project=? AND t.workspace_id=?", (project_id, wid())).fetchall()
        else:
            projects = db.execute("SELECT * FROM projects WHERE workspace_id=?", (wid(),)).fetchall()
            tasks = db.execute(
                "SELECT t.*, u.name as assignee_name FROM tasks t LEFT JOIN users u ON t.assignee=u.id "
                "WHERE t.workspace_id=?", (wid(),)).fetchall()

        users_db = db.execute("SELECT id,name,role,email FROM users WHERE workspace_id=?", (wid(),)).fetchall()
        teams = db.execute("SELECT * FROM teams WHERE workspace_id=?", (wid(),)).fetchall()
        tickets = db.execute("SELECT id,title,type,status,priority FROM tickets WHERE workspace_id=? LIMIT 20", (wid(),)).fetchall()

    # Build rich workspace context
    proj_ctx = "\n".join([
        f"### {p['name']}\n- ID: {p['id']}\n- Description: {p['description'] or 'N/A'}"
        f"\n- Target date: {p['target_date'] or 'N/A'}\n- Progress: {p['progress'] or 0}%"
        for p in projects]) or "No projects yet"

    by_stage = {}
    for t in tasks:
        by_stage.setdefault(t['stage'], []).append(t)
    task_ctx = "\n".join([
        f"**{stage.upper()}** ({len(ts)} tasks): " + ", ".join([f"{t['title']} [{t['priority']}]" for t in ts[:5]])
        + ("..." if len(ts)>5 else "")
        for stage, ts in by_stage.items()])[:3000] or "No tasks"

    user_ctx = "\n".join([f"- {u['name']} ({u['role']})" for u in users_db])
    team_ctx = "\n".join([f"- {t['name']}" for t in teams]) or "No sub-teams"
    ticket_ctx = "\n".join([f"- [{t['id']}] {t['title']} | {t['type']} | {t['status']} | {t['priority']}" for t in tickets]) or "No tickets"

    workspace_data = f"""
WORKSPACE NAME: {ws['name'] if ws else 'Unknown'}
TOTAL PROJECTS: {len(projects)}
TOTAL TASKS: {len(tasks)}
TEAM MEMBERS ({len(users_db)}):
{user_ctx}
SUB-TEAMS: {team_ctx}

PROJECTS:
{proj_ctx}

TASKS BY STAGE:
{task_ctx}

OPEN TICKETS (sample):
{ticket_ctx}
"""
    user_desc_block = f"""
USER DESCRIPTION:
{user_description if user_description else '(Not provided — use workspace data above)'}

TECH STACK: {tech_stack if tech_stack else 'Not specified'}
TARGET AUDIENCE: {audience}
"""
    audience_note = {
        "technical": "Write for software engineers and architects. Include technical details, code examples, data models, and API references where appropriate.",
        "business": "Write for business stakeholders. Avoid jargon. Focus on value, goals, timelines, risks, and business outcomes. Use plain language.",
        "both": "Write for both technical and business audiences. Use clear sections — business summary first, technical details later."
    }.get(audience, "")

    if doc_type == "architecture":
        prompt = f"""You are a senior software architect. Generate a comprehensive architecture documentation with Mermaid.js diagrams.
{user_desc_block}
{workspace_data}

{audience_note}

Generate the following:

## 1. System Architecture Diagram
```mermaid
flowchart TD
  (show the main system components, services, databases, and how they connect)
```

## 2. Data Flow Diagram  
```mermaid
sequenceDiagram
  (show key user interactions and data flows between components)
```

## 3. Component Overview
Describe each major component in 2-3 sentences.

## 4. Technology Stack
List all technologies with their role in the system.

## 5. Deployment Architecture
Describe how the system is deployed (cloud, containers, etc.).

Be specific based on the description provided. If tech stack is mentioned, use it in the diagrams."""
    elif doc_type == "technical":
        prompt = f"""You are a senior technical writer. Generate a detailed technical specification document.
{user_desc_block}
{workspace_data}

{audience_note}

Generate a complete Technical Specification including:

# Technical Specification

## 1. Overview & Purpose
## 2. System Architecture
## 3. Technology Stack
| Layer | Technology | Purpose |
(create a table)
## 4. Data Models
Describe key entities and their relationships with field-level details.
## 5. API Design
List key API endpoints with method, path, purpose, request/response schema.
## 6. Authentication & Security
## 7. Performance Requirements
## 8. Integration Points
## 9. Error Handling Strategy
## 10. Testing Strategy
## 11. Deployment & DevOps

Be comprehensive and specific. Use tables, code blocks, and diagrams where appropriate."""
    elif doc_type == "api":
        prompt = f"""You are an API documentation expert. Generate complete API reference documentation.
{user_desc_block}
{workspace_data}

Generate comprehensive API Documentation including:

# API Reference

## Authentication
How to authenticate — JWT, API keys, OAuth, etc.

## Base URL & Versioning

## Endpoints
For each major resource area (based on the project description), document:
### Resource Name
#### GET /resource
- **Description**: What it returns
- **Auth required**: Yes/No
- **Query params**: List with type and description
- **Response**: JSON schema with example
#### POST /resource
(repeat for all CRUD operations)

## Error Codes
| Code | Message | Description |
(table of all error codes)

## Rate Limiting
## Webhooks (if applicable)
## SDK Examples
Show code examples in Python and JavaScript.

Base the endpoints on the actual project description and workspace task data."""
    else:  # documentation
        prompt = f"""You are a professional technical writer. Generate comprehensive project documentation.
{user_desc_block}
{workspace_data}

{audience_note}

Generate a complete Project Documentation including:

# Project Documentation

## Executive Summary
2-3 paragraphs covering what the project is, its primary goals, and current status.

## Project Overview
- **Vision**: 
- **Problem Statement**:
- **Solution**:
- **Key Stakeholders**:

## Scope & Features
### In Scope
### Out of Scope
### Key Features (table with feature, status, priority)

## Team Structure
| Name | Role | Responsibilities |
(table from workspace member data)

## Current Status
Summary of progress with a status table per project.

## Task Breakdown
Organized by stage — Completed, In Progress, In Review, Blocked, Backlog.

## Timeline & Milestones
| Milestone | Target Date | Status |

## Risks & Blockers
| Risk | Impact | Mitigation |

## Technical Architecture
Brief description of the tech stack and architecture.

## Next Steps & Recommendations
Prioritized list of immediate actions.

---
*Generated by Project Tracker AI · {datetime.now().strftime('%B %d, %Y')}*"""
    try:
        req_data = json.dumps({
            "model": "claude-sonnet-4-5",
            "max_tokens": 4000,
            "messages": [{"role": "user", "content": prompt}]
        }).encode()
        req = urllib.request.Request(
            "https://api.anthropic.com/v1/messages",
            data=req_data, method="POST",
            headers={"Content-Type": "application/json", "x-api-key": api_key, "anthropic-version": "2023-06-01"})
        with urllib.request.urlopen(req, timeout=90) as resp:
            result_json = json.loads(resp.read().decode())
            content = result_json["content"][0]["text"]
    except urllib.error.HTTPError as e:
        body = e.read().decode()
        if e.code == 401:
            return jsonify({"error": "INVALID_KEY", "message": "Invalid API key. Check your key in Settings."}), 400
        return jsonify({"error": "API_ERROR", "message": f"API error {e.code}: {body[:300]}"}), 500
    except Exception as e:
        return jsonify({"error": "NETWORK_ERROR", "message": str(e)}), 500

    return jsonify({
        "content": content,
        "type": doc_type,
        "projects": [p["name"] for p in projects],
        "task_count": len(tasks)
    })




@app.route("/api/export/csv")
@login_required
def export_csv():
    with get_db() as db:
        tasks = db.execute("SELECT * FROM tasks WHERE workspace_id=? AND deleted_at=''", (wid(),)).fetchall()
    lines = ["id,title,project,assignee,priority,stage,due,pct"]
    for t in tasks:
        lines.append(f'"{t["id"]}","{t["title"]}","{t["project"]}","{t["assignee"]}",'
                     f'"{t["priority"]}","{t["stage"]}","{t["due"]}","{t["pct"]}"')
    return Response("\n".join(lines), mimetype="text/csv",
                    headers={"Content-Disposition": "attachment;filename=tasks.csv"})

@app.route("/api/import/csv", methods=["POST"])
@login_required
def import_csv():
    """Import tasks (and optionally projects) from CSV upload."""
    import csv, io
    f = request.files.get("file")
    if not f: return jsonify({"error":"No file uploaded"}), 400
    try:
        content = f.read().decode("utf-8-sig")
        reader = csv.DictReader(io.StringIO(content))
    except Exception as e:
        return jsonify({"error": f"Could not parse CSV: {e}"}), 400

    created_projects = 0
    created_tasks = 0
    errors = []
    with get_db() as db:
        for i, row in enumerate(reader):
            try:
                row = {k.strip().lower(): (v or "").strip() for k, v in row.items()}
                proj_id = row.get("project_id", "").strip()
                proj_name = row.get("project", row.get("project_name", "")).strip()
                if proj_name and not proj_id:
                    existing = db.execute(
                        "SELECT id FROM projects WHERE workspace_id=? AND name=?", (wid(), proj_name)
                    ).fetchone()
                    if existing:
                        proj_id = existing["id"]
                    else:
                        proj_id = f"p{int(datetime.now().timestamp()*1000)+i}"
                        db.execute(
                            "INSERT INTO projects VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                            (proj_id, wid(), proj_name, "", session["user_id"],
                             json.dumps([session["user_id"]]), "", "", 0, "#5a8cff", ts())
                        )
                        created_projects += 1
                title = row.get("title", row.get("task", row.get("task_title", ""))).strip()
                if not title:
                    errors.append(f"Row {i+2}: missing title, skipped")
                    continue
                valid_stages = set(["backlog","planning","development","code_review","testing","uat","release","production","completed","blocked"])
                stage = row.get("stage", "backlog").strip()
                if stage not in valid_stages: stage = "backlog"
                valid_pris = {"critical","high","medium","low"}
                pri = row.get("priority", "medium").strip().lower()
                if pri not in valid_pris: pri = "medium"
                due = row.get("due", row.get("due_date", "")).strip()
                pct_raw = row.get("pct", row.get("progress", row.get("completion", "0"))).strip().replace("%","")
                try: pct = int(float(pct_raw))
                except: pct = 0
                assignee_id = row.get("assignee_id", row.get("assignee", "")).strip()
                if assignee_id and not assignee_id.startswith("u"):
                    u = db.execute("SELECT id FROM users WHERE workspace_id=? AND name=?", (wid(), assignee_id)).fetchone()
                    if u: assignee_id = u["id"]
                    else: assignee_id = ""
                tid = next_task_id(db, wid())
                db.execute("INSERT INTO tasks(id,workspace_id,title,description,project,assignee,priority,stage,created,due,pct,comments) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                           (tid, wid(), title, row.get("description",""), proj_id,
                            assignee_id, pri, stage, ts(), due, pct, "[]"))
                created_tasks += 1
            except Exception as e:
                errors.append(f"Row {i+2}: {e}")

    return jsonify({
        "ok": True,
        "created_tasks": created_tasks,
        "created_projects": created_projects,
        "errors": errors
    })

# ── Serve ─────────────────────────────────────────────────────────────────────
@app.route("/health")
def health():
    now = datetime.utcnow()
    uptime_seconds = int((now - APP_STARTED_AT).total_seconds())
    try:
        db_check_started = time.perf_counter()
        with get_db() as db:
            db.execute("SELECT 1")
        db_latency_ms = round((time.perf_counter() - db_check_started) * 1000, 2)
        return jsonify({
            "status":"ok",
            "service":"ProjectFlow",
            "version":"4.0",
            "timestamp":now.isoformat(timespec="seconds") + "Z",
            "uptime_seconds":uptime_seconds,
            "database":{"status":"ok","latency_ms":db_latency_ms}
        }), 200
    except Exception as e:
        return jsonify({
            "status":"error",
            "service":"ProjectFlow",
            "version":"4.0",
            "timestamp":now.isoformat(timespec="seconds") + "Z",
            "uptime_seconds":uptime_seconds,
            "database":{"status":"error","detail":str(e)}
        }), 500

@app.route("/api/auth/emergency-reset-2fa", methods=["POST"])
def emergency_reset_2fa():
    """Emergency endpoint to disable ALL 2FA workspace-wide.
    Requires the workspace invite code as proof of ownership.
    Use this if you're locked out."""
    d = request.json or {}
    invite_code = d.get("invite_code","").strip().upper()
    email = d.get("email","").strip().lower()
    if not invite_code or not email:
        return jsonify({"error":"invite_code and email required"}),400
    with get_db() as db:
        ws = db.execute("SELECT * FROM workspaces WHERE invite_code=?", (invite_code,)).fetchone()
        if not ws:
            return jsonify({"error":"Invalid invite code"}),403
        u = db.execute("SELECT id FROM users WHERE email=? AND workspace_id=?", (email, ws["id"])).fetchone()
        if not u:
            return jsonify({"error":"Email not found in this workspace"}),404
        # Reset all 2FA for the workspace
        db.execute("UPDATE workspaces SET otp_enabled=0 WHERE id=?", (ws["id"],))
        db.execute("UPDATE users SET two_fa_enabled=0, totp_secret='', totp_verified=0 WHERE workspace_id=?", (ws["id"],))
        return jsonify({"ok":True,"message":"All 2FA reset. You can now log in with email + password."})



@app.route("/manifest.json")
def web_manifest():
    """Small PWA manifest so browsers stop 404-spamming /manifest.json."""
    return jsonify({
        "name": "Project Tracker",
        "short_name": "Project Tracker",
        "start_url": "/dashboard",
        "scope": "/",
        "display": "standalone",
        "background_color": "#070313",
        "theme_color": "#7c3aed",
        "icons": []
    })

@app.route("/sw.js")
def service_worker():
    """Minimal service worker without a fetch handler.

    Chrome warns when a service worker registers an empty/no-op fetch handler because it
    slows navigations without adding offline behavior. This script activates immediately
    and intentionally avoids intercepting network requests.
    """
    js = """/* Project Tracker service worker v2: no request interception */
self.addEventListener('install', event => self.skipWaiting());
self.addEventListener('activate', event => event.waitUntil(self.clients.claim()));
"""
    return Response(js, mimetype="application/javascript", headers={"Cache-Control":"no-cache, no-store, must-revalidate"})


@app.route("/icon-192.png")
def pwa_icon_192():
    """Inline PWA icon so production stops logging /icon-192.png 404s."""
    svg = '''<svg xmlns="http://www.w3.org/2000/svg" width="192" height="192" viewBox="0 0 192 192">
  <defs><linearGradient id="g" x1="0" x2="1" y1="0" y2="1"><stop stop-color="#2563eb"/><stop offset="1" stop-color="#7c3aed"/></linearGradient></defs>
  <rect width="192" height="192" rx="44" fill="url(#g)"/>
  <path d="M52 98h88M96 54v88" stroke="white" stroke-width="16" stroke-linecap="round" opacity=".96"/>
  <circle cx="96" cy="96" r="54" fill="none" stroke="white" stroke-width="8" opacity=".26"/>
</svg>'''
    return Response(svg, mimetype="image/svg+xml", headers={"Cache-Control":"public, max-age=86400"})

@app.route("/favicon.ico")
def favicon():
    """Return 204 instead of noisy 404 when no favicon asset is deployed."""
    return Response(status=204, headers={"Cache-Control":"public, max-age=86400"})


@app.route("/static/<path:fn>")
def serve_static(fn):
    """Serve only approved static assets from static/pf_static. Never expose BASE_DIR."""
    from werkzeug.utils import safe_join
    if not fn or fn.startswith(("/", "\\")) or ".." in fn.split("/"):
        return jsonify({"error": "Invalid static path"}), 400
    allowed_ext = {".js", ".css", ".woff", ".woff2", ".png", ".jpg", ".jpeg", ".svg", ".webp", ".ico", ".map"}
    _, ext = os.path.splitext(fn.lower())
    if ext not in allowed_ext:
        return jsonify({"error": "Static file type not allowed"}), 403
    for root in [STATIC_DIR, JS_DIR, os.path.join(BASE_DIR, "pf_static")]:
        path = safe_join(root, fn)
        if path and os.path.isfile(path):
            
            # Always revalidate JS/CSS in production so UI fixes are not hidden by browser/CDN cache.
            if fn.lower().endswith((".js", ".css")):
                resp = send_from_directory(root, fn, max_age=0)
                resp.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
                resp.headers["Pragma"] = "no-cache"
                resp.headers["Expires"] = "0"
                return resp
            return send_from_directory(root, fn, max_age=604800)
    if fn == "frontend.js":
        err_js = """console.error('[Project Tracker] frontend.js not found on server.');
document.body.innerHTML='<div style=\"color:#f87171;font-family:monospace;padding:40px;background:#0a0618;min-height:100vh\"><h2>⚠ frontend.js missing</h2><p>Deploy frontend.js to /static/frontend.js or /pf_static/frontend.js.</p></div>';"""
        return Response(err_js, mimetype="application/javascript", headers={"Cache-Control": "no-cache"})
    return "", 404


@app.route("/password-generator")
def password_generator_page():
    """Serve the standalone password generator tool."""
    return PASSWORD_GENERATOR_HTML

@app.route("/privacy")
def privacy_page():
    """Serve the Privacy Policy page."""
    return _inject_nonce(_load_template('privacy.html'))

@app.route("/terms")
def terms_page():
    """Serve the Terms of Service page."""
    return _inject_nonce(_load_template('terms.html'))

@app.route("/api/admin/security-stats")
@login_required
def admin_security_stats():
    """Return live scanner/ban stats for admin dashboard."""
    uid = session.get("user_id", "")
    with get_db() as db:
        u = db.execute("SELECT role FROM users WHERE id=?", (uid,)).fetchone()
        if not u or u["role"] not in ("Admin",):
            return jsonify({"error": "Admin only"}), 403
    now = _time_mod.time()
    if _redis_client is not None:
        try:
            ban_keys = _redis_client.keys("ban:*")
            banned_ips = [k.replace("ban:", "") for k in ban_keys]
            hit_keys = _redis_client.keys("scanhit:*")
            hits = {k.replace("scanhit:", ""): int(_redis_client.get(k) or 0) for k in hit_keys}
        except Exception:
            banned_ips, hits = [], {}
    else:
        with _BAN_LOCK:
            banned_ips = [ip for ip, exp in _BAN_LIST.items() if now < exp]
            hits = dict(_BAN_HITS)
    totp_enabled = totp_disabled = 0
    no_totp = []
    try:
        with get_db() as db:
            totp_enabled = db.execute("SELECT COUNT(*) FROM users WHERE totp_verified = 1").fetchone()[0]
            totp_disabled = db.execute("SELECT COUNT(*) FROM users WHERE totp_verified IS NULL OR totp_verified = 0").fetchone()[0]
            no_totp = db.execute("""
                SELECT u.id, u.name, u.email, u.role, w.name AS workspace_name
                FROM users u
                LEFT JOIN workspaces w ON w.id = u.workspace_id
                WHERE u.totp_verified IS NULL OR u.totp_verified = 0
                ORDER BY u.created DESC LIMIT 100
            """).fetchall()
    except Exception as e:
        log.warning("[security-stats] TOTP stats unavailable: %s", e)

    return jsonify({
        "banned_ips": banned_ips,
        "banned_count": len(banned_ips),
        "pending_bans": hits,
        "ban_threshold": _BAN_THRESH,
        "ban_ttl_hours": _BAN_TTL // 3600,
        "totp_enabled": totp_enabled,
        "totp_disabled": totp_disabled,
        "no_totp": [dict(r) for r in no_totp],
    })

@app.route("/api/admin/unban-ip", methods=["POST"])
@login_required
def admin_unban_ip():
    """Manually unban an IP address."""
    uid = session.get("user_id", "")
    with get_db() as db:
        u = db.execute("SELECT role FROM users WHERE id=?", (uid,)).fetchone()
        if not u or u["role"] not in ("Admin",):
            return jsonify({"error": "Admin only"}), 403
    ip = (request.json or {}).get("ip", "").strip()
    if not ip:
        return jsonify({"error": "ip required"}), 400
    if _redis_client is not None:
        try:
            _redis_client.delete(f"ban:{ip}", f"scanhit:{ip}")
        except Exception: pass
    with _BAN_LOCK:
        _BAN_LIST.pop(ip, None)
        _BAN_HITS.pop(ip, None)
    log.info("[SECURITY] Admin manually unbanned IP %s", ip)
    return jsonify({"ok": True, "unbanned": ip})

@app.route("/security")
def security_info_page():
    """Serve the Security page."""
    return _inject_nonce(_load_template('security.html'))

@app.route("/about")
def about_page():
    """Serve the About page — always public, no login required."""
    return _inject_nonce(_load_template('about.html'))


# ══════════════════════════════════════════════════════════════════════════════
# ── Workspace-scoped URL routing  /<ws_name>/<ws_id>/dashboard  ──────────────
# ══════════════════════════════════════════════════════════════════════════════

_WS_APP_PATHS = {
    "dashboard", "projects", "tasks", "messages", "settings",
    "profile", "analytics", "tickets", "timeline", "app",
}

def _slugify(name):
    """Turn a workspace name into a URL-safe slug."""
    import re
    s = name.lower().strip()
    s = re.sub(r"[^a-z0-9]+", "-", s)
    s = s.strip("-")
    return s or "workspace"

@app.route("/<ws_name>/<ws_id>/sso/login")
def ws_sso_login(ws_name, ws_id):
    """SSO entry-point for a specific workspace.  Redirects to IdP if SAML is
    configured, otherwise falls through to the normal login page with the
    workspace pre-selected."""
    with get_db() as db:
        ws = db.execute(
            "SELECT id, name, sso_enabled, sso_type, sso_idp_url, sso_entity_id "
            "FROM workspaces WHERE id=?", (ws_id,)
        ).fetchone()

    if not ws:
        return redirect("/"), 302

    if ws["sso_enabled"] and ws["sso_type"] == "saml" and ws["sso_idp_url"]:
        # Build a minimal SAML AuthnRequest redirect
        return _saml_redirect(ws)

    # Fallback — send to normal login with workspace context embedded
    return redirect(f"/?action=login&ws={ws_id}&ws_name={ws['name']}")


@app.route("/<ws_name>/<ws_id>/sso/callback", methods=["GET", "POST"])
def ws_sso_callback(ws_name, ws_id):
    """Receive the SAML assertion from the IdP and log the user in."""
    with get_db() as db:
        ws = db.execute(
            "SELECT * FROM workspaces WHERE id=?", (ws_id,)
        ).fetchone()

    if not ws:
        return redirect("/"), 302

    result = _saml_process_response(request, ws)
    if "error" in result:
        return redirect(f"/?action=login&error={result['error']}&ws={ws_id}")

    email = result.get("email", "").lower().strip()
    name  = result.get("name", email)

    with get_db() as db:
        u = db.execute(
            "SELECT * FROM users WHERE email=? AND workspace_id=?",
            (email, ws_id)
        ).fetchone()

        if not u:
            # Auto-provision the user (JIT provisioning)
            uid = f"u{int(datetime.now().timestamp()*1000)}"
            av  = "".join(w[0] for w in name.split())[:2].upper()
            c   = random.choice(CLRS)
            db.execute(
                "INSERT INTO users VALUES (?,?,?,?,?,?,?,?,?,?)",
                (uid, ws_id, name, email, hash_pw(secrets.token_hex(16)),
                 "Developer", av, c, ts(), None)
            )
            _audit("sso_jit_provision", uid, f"JIT provisioned {name} ({email}) via SSO")
            u = db.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
        else:
            uid = u["id"]

        db.execute("UPDATE users SET last_active=? WHERE id=?", (ts(), uid))

    session.permanent = True
    session["user_id"]      = uid
    session["workspace_id"] = ws_id
    session["role"]         = u["role"] if u else "Developer"
    _audit("sso_login", uid, f"{name} ({email}) logged in via SSO/SAML")

    # Redirect to workspace-scoped dashboard URL
    slug = _slugify(ws["name"])
    return redirect(f"/{slug}/{ws_id}/dashboard")


# ── Workspace-scoped app pages  /<ws_name>/<ws_id>/<page>  ──────────────────

@app.route("/<ws_name>/<ws_id>/dashboard")
@app.route("/<ws_name>/<ws_id>/projects")
@app.route("/<ws_name>/<ws_id>/projects/<proj_id>")
@app.route("/<ws_name>/<ws_id>/tasks")
@app.route("/<ws_name>/<ws_id>/kanban")
@app.route("/<ws_name>/<ws_id>/messages")
@app.route("/<ws_name>/<ws_id>/channels")
@app.route("/<ws_name>/<ws_id>/dm")
@app.route("/<ws_name>/<ws_id>/dm/<other_user>")
@app.route("/<ws_name>/<ws_id>/settings")
@app.route("/<ws_name>/<ws_id>/profile")
@app.route("/<ws_name>/<ws_id>/analytics")
@app.route("/<ws_name>/<ws_id>/tickets")
@app.route("/<ws_name>/<ws_id>/timeline")
@app.route("/<ws_name>/<ws_id>/reminders")
@app.route("/<ws_name>/<ws_id>/team")
@app.route("/<ws_name>/<ws_id>/productivity")
@app.route("/<ws_name>/<ws_id>/ai-docs")
@app.route("/<ws_name>/<ws_id>/timesheet")
@app.route("/<ws_name>/<ws_id>/vault")
@app.route("/<ws_name>/<ws_id>/password-generator")
@app.route("/<ws_name>/<ws_id>/app")
def ws_app_page(ws_name, ws_id, **kwargs):
    """Serve the main SPA for workspace-scoped URLs.
    If not authenticated, redirect to the workspace SSO/login flow."""
    if "user_id" not in session:
        # Check if this workspace has SSO enabled
        with get_db() as db:
            ws = db.execute(
                "SELECT id, name, sso_enabled, sso_type "
                "FROM workspaces WHERE id=?", (ws_id,)
            ).fetchone()
        if ws and ws["sso_enabled"]:
            return redirect(f"/{ws_name}/{ws_id}/sso/login")
        return redirect(f"/?action=login&ws={ws_id}&ws_name={ws_name}")

    # Ensure the logged-in user actually belongs to this workspace
    if session.get("workspace_id") != ws_id:
        return redirect(f"/?action=login&ws={ws_id}&ws_name={ws_name}")

    return _serve_html()


# ── SSO configuration API  ────────────────────────────────────────────────────

@app.route("/api/sso/config", methods=["GET"])
@login_required
def get_sso_config():
    """Return SSO configuration for the current workspace (admin only)."""
    if session.get("role") not in ("Admin", "Owner"):
        return jsonify({"error": "Admin access required"}), 403
    with get_db() as db:
        ws = db.execute(
            "SELECT sso_enabled, sso_type, sso_idp_url, sso_entity_id, "
            "sso_attr_email, sso_attr_name, sso_allow_password_login, workspace_slug "
            "FROM workspaces WHERE id=?", (wid(),)
        ).fetchone()
    if not ws:
        return jsonify({"error": "Workspace not found"}), 404
    # Never expose the raw x509 cert — just a presence flag
    return jsonify(dict(ws))


@app.route("/api/sso/config", methods=["PUT"])
@login_required
def update_sso_config():
    """Save SAML/SSO settings for the current workspace."""
    if session.get("role") not in ("Admin", "Owner"):
        return jsonify({"error": "Admin access required"}), 403
    d = request.json or {}
    allowed = {
        "sso_enabled", "sso_type", "sso_idp_url", "sso_entity_id",
        "sso_x509_cert", "sso_attr_email", "sso_attr_name",
        "sso_allow_password_login", "workspace_slug",
    }
    updates = {k: v for k, v in d.items() if k in allowed}
    if not updates:
        return jsonify({"error": "Nothing to update"}), 400
    set_clause = ", ".join(f"{k}=?" for k in updates)
    params = list(updates.values()) + [wid()]
    with get_db() as db:
        db.execute(f"UPDATE workspaces SET {set_clause} WHERE id=?", params)
    _audit("sso_config_update", session["user_id"],
           f"SSO config updated: {list(updates.keys())}")
    return jsonify({"ok": True})


@app.route("/api/sso/test-metadata", methods=["POST"])
@login_required
def test_sso_metadata():
    """Validate that an IdP metadata URL is reachable and parse the SSO URL."""
    if session.get("role") not in ("Admin", "Owner"):
        return jsonify({"error": "Admin access required"}), 403
    d = request.json or {}
    metadata_url = d.get("metadata_url", "").strip()
    if not metadata_url:
        return jsonify({"error": "metadata_url required"}), 400
    try:
        import urllib.request
        with urllib.request.urlopen(metadata_url, timeout=8) as resp:
            body = resp.read().decode("utf-8", errors="replace")
        # Very lightweight extraction — production code should use xmlschema/lxml
        import re
        idp_sso = ""
        entity_id = ""
        m = re.search(r'entityID=["\']([^"\']+)["\']', body)
        if m:
            entity_id = m.group(1)
        m = re.search(
            r'<(?:\w+:)?SingleSignOnService[^>]+Binding[^=]*=[^"]*"[^"]*POST"[^>]+Location=["\']([^"\']+)',
            body
        )
        if not m:
            m = re.search(
                r'<(?:\w+:)?SingleSignOnService[^>]+Location=["\']([^"\']+)',
                body
            )
        if m:
            idp_sso = m.group(1)
        return jsonify({
            "ok": True,
            "entity_id": entity_id,
            "idp_sso_url": idp_sso,
            "metadata_snippet": body[:400],
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@app.route("/api/sso/workspace-url")
@login_required
def get_workspace_url():
    """Return the full workspace-scoped dashboard URL for the current workspace."""
    with get_db() as db:
        ws = db.execute(
            "SELECT id, name, workspace_slug FROM workspaces WHERE id=?",
            (wid(),)
        ).fetchone()
    if not ws:
        return jsonify({"error": "Workspace not found"}), 404
    slug = ws["workspace_slug"] or _slugify(ws["name"])
    base = request.host_url.rstrip("/")
    return jsonify({
        "workspace_id":   ws["id"],
        "workspace_name": ws["name"],
        "slug":           slug,
        "dashboard_url":  f"{base}/{slug}/{ws['id']}/dashboard",
        "sso_login_url":  f"{base}/{slug}/{ws['id']}/sso/login",
        "sso_callback_url": f"{base}/{slug}/{ws['id']}/sso/callback",
    })


# ── Internal SAML helpers  ────────────────────────────────────────────────────

def _saml_redirect(ws):
    """Build a minimal SAML AuthnRequest and redirect to the IdP.
    For production deployments replace this with python3-saml or pysaml2."""
    import base64, zlib, urllib.parse
    from datetime import datetime as _dt
    request_id  = f"id-{secrets.token_hex(10)}"
    issue_instant = _dt.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    acs_url = f"{request.host_url.rstrip('/')}/{_slugify(ws['name'])}/{ws['id']}/sso/callback"
    entity  = ws["sso_entity_id"] or request.host_url.rstrip("/")
    authn = (
        f'<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" '
        f'xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" '
        f'ID="{request_id}" Version="2.0" IssueInstant="{issue_instant}" '
        f'AssertionConsumerServiceURL="{acs_url}" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST">'
        f'<saml:Issuer>{entity}</saml:Issuer>'
        f'</samlp:AuthnRequest>'
    )
    deflated  = zlib.compress(authn.encode("utf-8"))[2:-4]
    encoded   = base64.b64encode(deflated).decode("utf-8")
    params    = urllib.parse.urlencode({"SAMLRequest": encoded, "RelayState": acs_url})
    idp_url   = ws["sso_idp_url"]
    sep       = "&" if "?" in idp_url else "?"
    return redirect(f"{idp_url}{sep}{params}", 302)


def _saml_process_response(req, ws):
    """Decode a SAML Response POST and extract email + name.
    For production use python3-saml which validates signatures & conditions."""
    import base64
    try:
        raw_response = req.form.get("SAMLResponse", "")
        if not raw_response:
            return {"error": "missing_saml_response"}
        decoded = base64.b64decode(raw_response).decode("utf-8", errors="replace")

        import re
        email_attr = ws["sso_attr_email"] or "email"
        name_attr  = ws["sso_attr_name"]  or "name"

        def _extract_attr(xml, attr_name):
            patterns = [
                rf'Name=["\'](?:.*?:)?{re.escape(attr_name)}["\'][^>]*>.*?<.*?AttributeValue[^>]*>([^<]+)',
                rf'<(?:\w+:)?Attribute\s+Name=["\'](?:.*?:)?{re.escape(attr_name)}["\'][^>]*>\s*<(?:\w+:)?AttributeValue[^>]*>([^<]+)',
            ]
            for p in patterns:
                m = re.search(p, xml, re.DOTALL | re.IGNORECASE)
                if m:
                    return m.group(1).strip()
            return ""

        def _extract_nameid(xml):
            m = re.search(r'<(?:\w+:)?NameID[^>]*>([^<]+)', xml)
            return m.group(1).strip() if m else ""

        email = _extract_attr(decoded, email_attr) or _extract_nameid(decoded)
        name  = _extract_attr(decoded, name_attr)  or email.split("@")[0]

        if not email:
            return {"error": "saml_no_email"}
        return {"email": email, "name": name}
    except Exception as e:
        return {"error": str(e)}
_ADMIN_TOKENS = {}       # token -> expiry (datetime)
_ADMIN_FAIL_LOG = {}     # ip -> [fail_timestamp, ...] — brute-force lockout

def _admin_check_lockout(ip):
    """Return True if this IP is locked out (5+ failures in last 15 min)."""
    now = datetime.utcnow()
    cutoff = now - timedelta(minutes=15)
    hits = [t for t in _ADMIN_FAIL_LOG.get(ip, []) if t > cutoff]
    _ADMIN_FAIL_LOG[ip] = hits
    return len(hits) >= 5

def _admin_record_failure(ip):
    """Record a failed login attempt for this IP."""
    _ADMIN_FAIL_LOG.setdefault(ip, []).append(datetime.utcnow())

def _admin_clear_failures(ip):
    """Clear failure log on successful login."""
    _ADMIN_FAIL_LOG.pop(ip, None)

def _require_admin():
    """Return True if request carries a valid admin token."""
    token = request.headers.get("X-Admin-Token", "")
    exp   = _ADMIN_TOKENS.get(token)
    return bool(exp and datetime.utcnow() < exp)

def _audit(action, target="", detail=""):
    """Write an entry to audit_log. Fire-and-forget — never raises."""
    try:
        admin_email = os.environ.get("ADMIN_EMAIL", "admin@project-tracker.in")
        entry_id    = secrets.token_hex(8)
        with get_db() as db:
            db.execute(
                "INSERT INTO audit_log (id, admin_email, action, target, detail, created) "
                "VALUES (?,?,?,?,?,?)",
                (entry_id, admin_email, action, target, detail,
                 ts())
            )
            db.commit()
    except Exception as _ae:
        log.error("[audit] write error: %s", _ae)

@app.route("/api/admin/totp-security-stats")
@login_required
def admin_api_totp_security_stats():
    if not _require_admin():
        return jsonify({"error": "Unauthorized"}), 401
    try:
        with get_db() as db:
            try:
                # Cast to int to handle both boolean TRUE and integer 1 stored in pg
                enabled  = db.execute(
                    "SELECT COUNT(*) FROM users WHERE totp_verified = 1"
                ).fetchone()[0]
                disabled = db.execute(
                    "SELECT COUNT(*) FROM users WHERE totp_verified IS NULL OR totp_verified = 0"
                ).fetchone()[0]
                no_totp  = db.execute("""
    SELECT u.id, u.name, u.email, u.role, w.name AS workspace_name
                    FROM users u
                    LEFT JOIN workspaces w ON w.id = u.workspace_id
                    WHERE u.totp_verified IS NULL OR u.totp_verified = 0
                    ORDER BY u.created DESC LIMIT 100
                """).fetchall()
            except Exception:
                enabled, disabled, no_totp = 0, 0, []
        return jsonify({
            "totp_enabled":  enabled,
            "totp_disabled": disabled,
            "no_totp": [dict(r) for r in no_totp],
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/admin/plans-stats")
def admin_api_plans_stats():
    if not _require_admin():
        return jsonify({"error": "Unauthorized"}), 401
    try:
        with get_db() as db:
            rows = db.execute("""
    SELECT w.id, w.name, w.plan, COUNT(u.id) AS member_count
                FROM workspaces w
                LEFT JOIN users u ON u.workspace_id = w.id
                GROUP BY w.id, w.name, w.plan
                ORDER BY w.created DESC
            """).fetchall()
            starter    = sum(1 for r in rows if (r["plan"] or "starter") == "starter")
            team       = sum(1 for r in rows if r["plan"] == "team")
            enterprise = sum(1 for r in rows if r["plan"] == "enterprise")
        return jsonify({
            "starter_count":    starter,
            "team_count":       team,
            "enterprise_count": enterprise,
            "workspaces":       [dict(r) for r in rows],
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/admin/users/<uid>/reset-password", methods=["POST"])
def admin_api_user_reset_password(uid):
    if not _require_admin():
        return jsonify({"error": "Unauthorized"}), 401
    data = request.get_json(silent=True) or {}
    pw = data.get("password", "")
    if len(pw) < 8:
        return jsonify({"error": "Password must be at least 8 characters"}), 400
    try:
        with get_db() as db:
            db.execute("UPDATE users SET password=? WHERE id=?", (hash_pw(pw), uid))
            db.commit()
        _audit("reset_user_password", uid, "Password reset by admin")
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/admin/users/<uid>/reset-totp", methods=["POST"])
def admin_api_user_reset_totp(uid):
    if not _require_admin():
        return jsonify({"error": "Unauthorized"}), 401
    try:
        with get_db() as db:
            db.execute(
                "UPDATE users SET totp_secret='', totp_verified=0, two_fa_enabled=0 WHERE id=?",
                (uid,)
            )
            db.commit()
        _audit("reset_user_totp", uid, "2FA cleared by admin")
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/admin/users/<uid>/change-role", methods=["POST"])
def admin_api_user_change_role(uid):
    if not _require_admin():
        return jsonify({"error": "Unauthorized"}), 401
    data = request.get_json(silent=True) or {}
    role = data.get("role", "")
    valid_roles = ("Admin","Manager","TeamLead","Developer","Tester","Viewer")
    if role not in valid_roles:
        return jsonify({"error": "Invalid role"}), 400
    try:
        with get_db() as db:
            db.execute("UPDATE users SET role=? WHERE id=?", (role, uid))
            db.commit()
        _audit("change_user_role", uid, f"Role changed to {role}")
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ── Admin Panel ────────────────────────────────────────────────────────────────

@app.route("/adminpanel")
@app.route("/adminpanel/<path:workspace>")
def admin_panel_page(workspace=None):
    """Serve the admin panel HTML."""
    return _inject_nonce(ADMIN_HTML)

@app.route("/api/admin/login", methods=["POST"])
def admin_api_login():
    """Super-admin login — returns a short-lived bearer token."""
    data = request.get_json(silent=True) or {}
    email    = (data.get("email") or "").strip().lower()
    password = (data.get("password") or "")

    admin_email = os.environ.get("ADMIN_EMAIL", "admin@project-tracker.in").strip().lower()
    admin_pass  = os.environ.get("ADMIN_PASSWORD", "")

    client_ip = request.headers.get("X-Forwarded-For", request.remote_addr or "")[:60]

    if _admin_check_lockout(client_ip):
        return jsonify({"error": "Too many failed attempts. Try again in 15 minutes."}), 429

    if not admin_pass:
        return jsonify({"error": "Admin password not configured. Set ADMIN_PASSWORD env var."}), 503

    if email != admin_email or password != admin_pass:
        _admin_record_failure(client_ip)
        remaining = 5 - len(_ADMIN_FAIL_LOG.get(client_ip, []))
        return jsonify({"error": f"Invalid credentials. {max(remaining,0)} attempt(s) remaining before lockout."}), 401

    _admin_clear_failures(client_ip)
    token = secrets.token_hex(32)
    _ADMIN_TOKENS[token] = datetime.utcnow() + timedelta(hours=8)
    _audit("admin_login", "system", f"Admin logged in: {email}")
    return jsonify({"token": token})

@app.route("/api/admin/session")
def admin_api_session():
    """Validate an existing admin token — called on page load to restore session."""
    if not _require_admin():
        return jsonify({"error": "Unauthorized"}), 401
    admin_email = os.environ.get("ADMIN_EMAIL", "admin@project-tracker.in")
    return jsonify({"ok": True, "email": admin_email})

@app.route("/api/admin/logout", methods=["POST"])
def admin_api_logout():
    """Invalidate the admin token."""
    token = request.headers.get("X-Admin-Token", "")
    if token and token in _ADMIN_TOKENS:
        _audit("admin_logout", "system", "Admin signed out")
        _ADMIN_TOKENS.pop(token, None)
    return jsonify({"ok": True})

@app.route("/api/admin/dashboard")
def admin_api_dashboard():
    if not _require_admin():
        return jsonify({"error": "Unauthorized"}), 401
    try:
        with get_db() as db:
            total_users = db.execute("SELECT COUNT(*) FROM users").fetchone()[0]
            total_ws    = db.execute("SELECT COUNT(*) FROM workspaces").fetchone()[0]
            # active = logged in within last 7 days (if last_active column exists)
            try:
                cutoff = (datetime.utcnow() - timedelta(days=7)).isoformat()
                active = db.execute(
                    "SELECT COUNT(*) FROM users WHERE last_active > ?", (cutoff,)
                ).fetchone()[0]
            except Exception:
                active = total_users
            # revenue placeholder — extend when billing is wired
            revenue = 0
        return jsonify({
            "total_users": total_users,
            "total_workspaces": total_ws,
            "active_users": active,
            "revenue": revenue,
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/admin/workspaces")
def admin_api_workspaces():
    if not _require_admin():
        return jsonify({"error": "Unauthorized"}), 401
    try:
        with get_db() as db:
            rows = db.execute("""
    SELECT w.id, w.name, w.invite_code, w.plan, w.created,
                       COUNT(u.id) AS member_count
                FROM workspaces w
                LEFT JOIN users u ON u.workspace_id = w.id
                GROUP BY w.id, w.name, w.invite_code, w.plan, w.created
                ORDER BY w.created DESC
            """).fetchall()
        return jsonify({"workspaces": [dict(r) for r in rows]})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/admin/workspaces/<ws_id>")
def admin_api_workspace_detail(ws_id):
    if not _require_admin():
        return jsonify({"error": "Unauthorized"}), 401
    try:
        with get_db() as db:
            ws = db.execute("SELECT * FROM workspaces WHERE id=?", (ws_id,)).fetchone()
            if not ws:
                return jsonify({"error": "Workspace not found"}), 404
            members = db.execute(
                "SELECT id, name, email, role, created FROM users WHERE workspace_id=? ORDER BY created",
                (ws_id,)
            ).fetchall()
        return jsonify({"workspace": dict(ws), "members": [dict(m) for m in members]})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/admin/users")
def admin_api_users():
    if not _require_admin():
        return jsonify({"error": "Unauthorized"}), 401
    try:
        with get_db() as db:
            rows = db.execute("""
    SELECT u.id, u.name, u.email, u.role, u.created,
                       w.name AS workspace_name
                FROM users u
                LEFT JOIN workspaces w ON w.id = u.workspace_id
                ORDER BY u.created DESC
            """).fetchall()
        return jsonify({"users": [dict(r) for r in rows]})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/admin/users/<uid>/delete", methods=["POST"])
def admin_api_delete_user(uid):
    if not _require_admin():
        return jsonify({"error": "Unauthorized"}), 401
    try:
        with get_db() as db:
            db.execute("DELETE FROM users WHERE id=?", (uid,))
            db.commit()
        _audit("delete_user", uid, "User deleted by admin")
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/admin/audit")
def admin_api_audit():
    if not _require_admin():
        return jsonify({"error": "Unauthorized"}), 401
    try:
        with get_db() as db:
            rows = db.execute(
                "SELECT * FROM audit_log ORDER BY created DESC LIMIT 200"
            ).fetchall()
        return jsonify({"logs": [dict(r) for r in rows]})
    except Exception as e:
        return jsonify({"logs": [], "warning": str(e)}), 200

@app.route("/api/admin/workspace/set-plan", methods=["POST"])
def admin_api_set_plan():
    if not _require_admin():
        return jsonify({"error": "Unauthorized"}), 401
    data = request.get_json(silent=True) or {}
    ws_id = data.get("workspace_id")
    plan  = data.get("plan", "starter")
    if plan not in ("starter", "team", "enterprise"):
        return jsonify({"error": "Invalid plan"}), 400
    try:
        with get_db() as db:
            db.execute("UPDATE workspaces SET plan=? WHERE id=?", (plan, ws_id))
            db.commit()
        _audit("set_plan", ws_id, f"Plan changed to {plan}")
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/admin/workspace/suspend", methods=["POST"])
def admin_api_suspend_workspace():
    if not _require_admin():
        return jsonify({"error": "Unauthorized"}), 401
    data = request.get_json(silent=True) or {}
    ws_id = data.get("workspace_id")
    try:
        with get_db() as db:
            db.execute("UPDATE workspaces SET suspended=1 WHERE id=?", (ws_id,))
            db.commit()
        _audit("suspend_workspace", ws_id, "Workspace suspended")
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/admin/workspace/reset-invite", methods=["POST"])
def admin_api_reset_invite():
    if not _require_admin():
        return jsonify({"error": "Unauthorized"}), 401
    data = request.get_json(silent=True) or {}
    ws_id = data.get("workspace_id")
    new_code = secrets.token_urlsafe(8).upper()[:8]
    try:
        with get_db() as db:
            db.execute("UPDATE workspaces SET invite_code=? WHERE id=?", (new_code, ws_id))
            db.commit()
        _audit("reset_invite_code", ws_id, f"New code: {new_code}")
        return jsonify({"ok": True, "invite_code": new_code})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/admin/workspace/reset-all-passwords", methods=["POST"])
def admin_api_reset_all_passwords():
    if not _require_admin():
        return jsonify({"error": "Unauthorized"}), 401
    data = request.get_json(silent=True) or {}
    ws_id = data.get("workspace_id")
    pw    = data.get("password", "")
    if len(pw) < 8:
        return jsonify({"error": "Password must be at least 8 characters"}), 400
    try:
        with get_db() as db:
            db.execute(
                "UPDATE users SET password=? WHERE workspace_id=?",
                (hash_pw(pw), ws_id)
            )
            cur = db.execute("SELECT COUNT(*) FROM users WHERE workspace_id=?", (ws_id,))
            count = cur.fetchone()[0]
            db.commit()
        _audit("reset_all_passwords", ws_id, f"Bulk password reset for {count} users")
        return jsonify({"ok": True, "count": count})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/admin/workspace/reset-all-totp", methods=["POST"])
def admin_api_reset_all_totp():
    if not _require_admin():
        return jsonify({"error": "Unauthorized"}), 401
    data = request.get_json(silent=True) or {}
    ws_id = data.get("workspace_id")
    try:
        with get_db() as db:
            db.execute(
                "UPDATE users SET totp_secret='', totp_verified=0, two_fa_enabled=0 WHERE workspace_id=?",
                (ws_id,)
            )
            cur = db.execute("SELECT COUNT(*) FROM users WHERE workspace_id=?", (ws_id,))
            count = cur.fetchone()[0]
            db.commit()
        _audit("reset_all_totp", ws_id, f"Bulk 2FA reset for {count} users")
        return jsonify({"ok": True, "count": count})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/admin/workspace/toggle-2fa", methods=["POST"])
def admin_api_toggle_2fa():
    if not _require_admin():
        return jsonify({"error": "Unauthorized"}), 401
    data = request.get_json(silent=True) or {}
    ws_id   = data.get("workspace_id")
    enabled = bool(data.get("enabled", False))
    try:
        with get_db() as db:
            db.execute(
                "UPDATE workspaces SET otp_enabled=? WHERE id=?",
                (1 if enabled else 0, ws_id)
            )
            db.commit()
        _audit("toggle_2fa", ws_id, f"2FA requirement {'enabled' if enabled else 'disabled'}")
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/admin/workspace/add-user", methods=["POST"])
def admin_api_add_user():
    if not _require_admin():
        return jsonify({"error": "Unauthorized"}), 401
    data  = request.get_json(silent=True) or {}
    ws_id = data.get("workspace_id")
    name  = (data.get("name") or "").strip()
    email = (data.get("email") or "").strip().lower()
    pw    = data.get("password", "")
    role  = data.get("role", "Developer")
    if not name or not email or len(pw) < 8:
        return jsonify({"error": "Name, email and password (min 8 chars) are required"}), 400
    uid = secrets.token_hex(8)
    try:
        with get_db() as db:
            db.execute(
                "INSERT INTO users (id, name, email, password, role, workspace_id, created) "
                "VALUES (?,?,?,?,?,?,?)",
                (uid, name, email, hash_pw(pw), role, ws_id, ts())
            )
            db.commit()
        _audit("add_user", ws_id, f"User {name} ({email}) created with role {role}")
        return jsonify({"ok": True, "id": uid})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/", methods=["GET", "HEAD"])
def public_landing():
    """Serve the marketing landing page at the bare domain.

    `/` serves the landing page to unauthenticated visitors.
    Any URL with an app-specific action param (task, project, ticket, dm, etc.)
    always opens the SPA shell so deep-links from emails work even when already
    logged in.  The SPA's deepLinkFromSearch() reads the ?action=task&id=... params.
    """
    if request.method == "HEAD":
        return Response(status=200, headers={"Cache-Control": "no-store"})
    action = (request.args.get("action") or "").strip().lower()
    # App-entry actions — serve SPA shell (logged-in users land on their dashboard
    # with the deep-link applied; logged-out users see the login screen)
    _APP_ACTIONS = {
        "login", "signin", "sign-in", "signup", "register",
        "task", "project", "ticket", "dm", "message",
        "reminder", "notification", "dashboard", "settings",
    }
    if action in _APP_ACTIONS:
        return _serve_html()
    # If the user is already authenticated, skip the marketing page entirely
    if "user_id" in session:
        return _serve_html()
    return _serve_landing()

@app.route("/dashboard", methods=["GET", "HEAD"])
@app.route("/login", methods=["GET", "HEAD"])
@app.route("/app", methods=["GET", "HEAD"])
def root_app():
    """Serve the authenticated SPA shell for app/login/dashboard routes."""
    if request.method == "HEAD":
        return Response(status=200, headers={"Cache-Control": "no-store"})
    return _serve_html()

@app.route("/<path:path>")
def catch_all(path):
    """Catch-all route for SPA client-side routing."""

    # Block sensitive paths — never serve .git, .env, config files, etc.
    _lower = path.lower()
    _segments = [s for s in _lower.split("/") if s]
    _BLOCKED_PREFIXES = (
        ".git", ".env", ".htaccess", ".DS_Store", "wp-admin", "wp-login",
        ".aws", ".gcp", ".azure", ".ssh", ".docker", ".kube",   # cloud credential dirs
    )
    _BLOCKED_EXTENSIONS = (
        ".env", ".config", ".cfg", ".bak", ".sql", ".log", ".key",
        ".pem", ".crt", ".cer", ".p12", ".pfx",  # cert/key files
    )
    # Block if ANY segment is a known sensitive prefix
    if any(_lower == p or _lower.startswith(p + "/") or any(seg == p.lstrip(".") or seg.startswith(p.lstrip(".")) for seg in _segments) for p in _BLOCKED_PREFIXES):
        return "", 404
    _last = _segments[-1] if _segments else ""
    if any(_last.endswith(ext) for ext in _BLOCKED_EXTENSIONS):
        return "", 404
    # Block any path where ANY segment starts with a dot (e.g. .aws/credentials)
    if any(seg.startswith(".") for seg in _segments):
        return "", 404

    # Reject file requests (have an extension) that weren't caught above
    if "." in _last:
        return "", 404

    # Reject unresolved JS template literals like ${imgSrc}, ${variable}
    # These happen when a variable is used as a URL before it has a value
    if path.startswith("${") or "${" in path:
        return "", 400

    # Let explicitly registered routes handle /<ws_name>/<ws_id>/... paths
    parts = path.strip("/").split("/")
    if len(parts) >= 2:
        potential_ws_id = parts[1] if len(parts) >= 2 else ""
        if potential_ws_id.startswith("ws"):
            return _serve_html()

    # Otherwise serve the app (for client-side routing)
    return _serve_html()

import os as _os

# ── Load HTML templates from separate files ────────────────────────────────────
_BASE = _os.path.dirname(_os.path.abspath(__file__))

def _load_template(filename, fallback=''):
    """Load an HTML template file, return fallback string if not found."""
    path = _os.path.join(_BASE, filename)
    try:
        with open(path, 'r', encoding='utf-8') as _f:
            return _f.read()
    except FileNotFoundError:
        print(f"  ⚠ Template not found: {filename}")
        return fallback

HTML                    = _load_template('template.html')

_RE_SCRIPT_TAG = __import__('re').compile(r'<script([^>]*)>', __import__('re').IGNORECASE)

def _inject_nonce(html_content):
    """Inject CSP nonce into every <script> tag in an HTML string.
    Skips tags that already have a nonce or type=application/ld+json (structured data)."""
    nonce = getattr(_g, "csp_nonce", "")
    if not nonce:
        return html_content
    def _stamp(m):
        attrs = m.group(1)
        if 'nonce=' in attrs:
            return m.group(0)
        # Don't stamp JSON-LD or other non-JS script types
        if 'application/ld+json' in attrs or 'application/json' in attrs:
            return m.group(0)
        return f'<script nonce="{nonce}"{attrs}>'
    return _RE_SCRIPT_TAG.sub(_stamp, html_content)

def _serve_html():
    """Return template.html with CSP nonce stamped onto every <script> tag."""
    nonce = getattr(_g, "csp_nonce", "")
    body = HTML if not nonce else _inject_nonce(HTML)
    return Response(body, mimetype="text/html", headers={"Cache-Control":"no-cache, no-store, must-revalidate", "Pragma":"no-cache", "Expires":"0"})

def _serve_landing():
    """Return landing.html with CSP nonce stamped onto every <script> tag."""
    nonce = getattr(_g, "csp_nonce", "")
    if not nonce:
        return LANDING_HTML
    return _inject_nonce(LANDING_HTML)

LANDING_HTML            = _load_template('landing.html')
PASSWORD_GENERATOR_HTML = _load_template('password-generator.html')
ADMIN_HTML              = _load_template('adminpanel.html')


# ── Utilities ─────────────────────────────────────────────────────────────────
# Module-level init — runs when gunicorn imports app, ensures DB is ready
try:
    os.makedirs(DATA_DIR, exist_ok=True)
    os.makedirs(UPLOAD_DIR, exist_ok=True)
    os.makedirs(JS_DIR, exist_ok=True)
    init_db()
    ensure_timelog_schema()   # always run — adds any missing time_log columns
    _ensure_logout_column()    # add logged_out_at if upgrading from older deploy
    _close_ddl_conn()         # release shared DDL connection after all migrations
    _prewarm_pool(8)          # pre-open 8 pool connections so first requests are fast
except Exception as _ie:
    import traceback
    print(f"  ⚠ Init error: {_ie}")
    traceback.print_exc()
def find_free_port(preferred=5000):
    for port in range(preferred, preferred+10):
        try:
            s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
            s.bind(("",port)); s.close(); return port
        except: pass
    return preferred

def download_js():
    os.makedirs(JS_DIR,exist_ok=True)
    libs=[
        ("react.min.js", "https://unpkg.com/react@18/umd/react.production.min.js"), ("react-dom.min.js", "https://unpkg.com/react-dom@18/umd/react-dom.production.min.js"), ("prop-types.min.js","https://unpkg.com/prop-types@15/prop-types.min.js"), ("recharts.min.js", "https://unpkg.com/recharts@2/umd/Recharts.js"), ("htm.min.js", "https://unpkg.com/htm@3/dist/htm.js"), ]
    all_ok=True
    for fn,url in libs:
        path=os.path.join(JS_DIR,fn)
        if os.path.exists(path) and os.path.getsize(path)>1000: continue
        print(f"  Downloading {fn}...",end="",flush=True)
        try:
            with urllib.request.urlopen(url,timeout=15) as r:
                with open(path,"wb") as f: f.write(r.read())
            print(" ✓")
        except Exception as e:
            print(f" ✗ ({e})"); all_ok=False
    return all_ok

def open_browser(port):
    time.sleep(1.4)
    webbrowser.open(f"http://localhost:{port}")

# ═══════════════════════════════════════════════════════════════
#  STRIPE BILLING
# ═══════════════════════════════════════════════════════════════
import hmac as _hmac, hashlib as _hashlib

STRIPE_SECRET = os.environ.get("STRIPE_SECRET_KEY","")
STRIPE_WEBHOOK_SECRET = os.environ.get("STRIPE_WEBHOOK_SECRET","")
STRIPE_PRICES = {
    "team":       os.environ.get("STRIPE_PRICE_TEAM","price_team"),
    "enterprise": os.environ.get("STRIPE_PRICE_ENTERPRISE","price_enterprise"),
}

def _stripe_headers():
    return {"Authorization":f"Bearer {STRIPE_SECRET}","Content-Type":"application/x-www-form-urlencoded"}

def _stripe_post(path, data):
    import urllib.parse as _up
    body = _up.urlencode(data).encode()
    req  = urllib.request.Request(f"https://api.stripe.com/v1{path}", data=body, headers=_stripe_headers(), method="POST")
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return json.loads(r.read())
    except Exception as e:
        return {"error":{"message":str(e)}}

def _stripe_get(path):
    req = urllib.request.Request(f"https://api.stripe.com/v1{path}", headers=_stripe_headers())
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return json.loads(r.read())
    except Exception as e:
        return {"error":{"message":str(e)}}

@app.route("/api/billing/create-checkout", methods=["POST"])
@login_required
def billing_create_checkout():
    d    = request.get_json(force=True)
    plan = d.get("plan","team")
    if plan not in STRIPE_PRICES:
        return jsonify(error="Invalid plan"), 400
    if not STRIPE_SECRET:
        return jsonify(error="Stripe not configured. Set STRIPE_SECRET_KEY env var."), 503
    db = get_db()
    ws = db.execute("SELECT * FROM workspaces WHERE id=?", (wid(),)).fetchone()
    user = db.execute("SELECT * FROM users WHERE id=?", (session["user_id"],)).fetchone()
    cust_id = ws["stripe_customer_id"] if ws and ws["stripe_customer_id"] else ""
    if not cust_id:
        c = _stripe_post("/customers", {"email": user["email"], "name": ws["name"] if ws else "", "metadata[workspace_id]": wid()})
        if "error" in c:
            return jsonify(error=c["error"]["message"]), 502
        cust_id = c["id"]
        db.execute("UPDATE workspaces SET stripe_customer_id=? WHERE id=?", (cust_id, wid()))
        db.commit()
    base = request.host_url.rstrip("/")
    sess = _stripe_post("/checkout/sessions", {
        "customer": cust_id,
        "mode": "subscription",
        "line_items[0][price]": STRIPE_PRICES[plan],
        "line_items[0][quantity]": "1",
        "success_url": f"{base}/settings?billing=success",
        "cancel_url":  f"{base}/settings?billing=cancel",
        "metadata[workspace_id]": wid(),
        "metadata[plan]": plan,
    })
    if "error" in sess:
        return jsonify(error=sess["error"]["message"]), 502
    return jsonify(url=sess["checkout_session"]["url"] if "checkout_session" in sess else sess.get("url",""))

@app.route("/api/billing/portal", methods=["POST"])
@login_required
def billing_portal():
    if not STRIPE_SECRET:
        return jsonify(error="Stripe not configured"), 503
    db = get_db()
    ws = db.execute("SELECT stripe_customer_id FROM workspaces WHERE id=?", (wid(),)).fetchone()
    if not ws or not ws["stripe_customer_id"]:
        return jsonify(error="No billing account found"), 400
    base = request.host_url.rstrip("/")
    portal = _stripe_post("/billing_portal/sessions", {
        "customer": ws["stripe_customer_id"],
        "return_url": f"{base}/settings",
    })
    if "error" in portal:
        return jsonify(error=portal["error"]["message"]), 502
    return jsonify(url=portal.get("url",""))

@app.route("/api/billing/status")
@login_required
def billing_status():
    db = get_db()
    ws = db.execute("SELECT plan, stripe_subscription_id, plan_expires, trial_ends, seat_count, stripe_customer_id FROM workspaces WHERE id=?", (wid(),)).fetchone()
    if not ws:
        return jsonify(plan="starter", active=True, trial=False)
    members = db.execute("SELECT COUNT(*) as c FROM users WHERE workspace_id=? AND deleted_at=''", (wid(),)).fetchone()
    usage   = _get_month_usage(wid())
    return jsonify(
        plan=ws["plan"] or "starter",
        stripe_customer=bool(ws["stripe_customer_id"]),
        subscription_id=ws["stripe_subscription_id"] or "",
        plan_expires=ws["plan_expires"] or "",
        trial_ends=ws["trial_ends"] or "",
        seat_count=ws["seat_count"] or 5,
        member_count=members["c"] if members else 0,
        usage=usage,
    )

@app.route("/api/billing/webhook", methods=["POST"])
def stripe_webhook():
    payload = request.get_data()
    sig     = request.headers.get("Stripe-Signature","")
    if STRIPE_WEBHOOK_SECRET:
        parts = {p.split("=")[0]: p.split("=")[1] for p in sig.split(",") if "=" in p}
        signed_payload = f"{parts.get('t','')}".encode() + b"." + payload
        expected = _hmac.new(STRIPE_WEBHOOK_SECRET.encode(), signed_payload, _hashlib.sha256).hexdigest()
        if not _hmac.compare_digest(expected, parts.get("v1","")):
            return "Bad signature", 400
    event = request.get_json(force=True)
    etype = event.get("type","")
    obj   = event.get("data",{}).get("object",{})
    db    = get_db(autocommit=True)
    ws_id = obj.get("metadata",{}).get("workspace_id","")
    if etype == "checkout.session.completed":
        plan = obj.get("metadata",{}).get("plan","team")
        sub  = obj.get("subscription","")
        if ws_id:
            db.execute("UPDATE workspaces SET plan=?, stripe_subscription_id=? WHERE id=?", (plan, sub, ws_id))
    elif etype in ("customer.subscription.updated","customer.subscription.deleted"):
        status = obj.get("status","")
        sub_id = obj.get("id","")
        ws_row = db.execute("SELECT id FROM workspaces WHERE stripe_subscription_id=?", (sub_id,)).fetchone()
        if ws_row:
            new_plan = "starter" if status in ("canceled","unpaid","past_due") else (obj.get("metadata",{}).get("plan","team"))
            exp      = datetime.fromtimestamp(obj.get("current_period_end", 0)).isoformat() if obj.get("current_period_end") else ""
            db.execute("UPDATE workspaces SET plan=?, plan_expires=? WHERE id=?", (new_plan, exp, ws_row["id"]))
    return "ok", 200

# ═══════════════════════════════════════════════════════════════
#  USAGE METERING
# ═══════════════════════════════════════════════════════════════
PLAN_LIMITS = {
    "starter":    {"members": 5,   "projects": 3,  "ai_calls_month": 50,  "storage_mb": 500},
    "team":       {"members": 50,  "projects": 50, "ai_calls_month": 500, "storage_mb": 10000},
    "enterprise": {"members": 999, "projects": 999,"ai_calls_month": 9999,"storage_mb": 100000},
}

def _get_month_usage(workspace_id):
    month_start = datetime.now().replace(day=1,hour=0,minute=0,second=0).isoformat()
    db = get_db()
    rows = db.execute(
        "SELECT event_type, SUM(quantity) as total FROM usage_events WHERE workspace_id=? AND created>=? GROUP BY event_type",
        (workspace_id, month_start)
    ).fetchall()
    return {r["event_type"]: r["total"] for r in rows}

def _record_usage(workspace_id, event_type, quantity=1, meta=None):
    _raw_pg("INSERT INTO usage_events VALUES (?,?,?,?,?,?)",
            (secrets.token_hex(8), workspace_id, event_type, quantity,
             json.dumps(meta or {}), ts()))

@app.route("/api/usage")
@login_required
def get_usage():
    db  = get_db()
    ws  = db.execute("SELECT plan FROM workspaces WHERE id=?", (wid(),)).fetchone()
    plan = (ws["plan"] or "starter") if ws else "starter"
    limits = PLAN_LIMITS.get(plan, PLAN_LIMITS["starter"])
    usage  = _get_month_usage(wid())
    members = db.execute("SELECT COUNT(*) as c FROM users WHERE workspace_id=? AND deleted_at=''", (wid(),)).fetchone()
    projects = db.execute("SELECT COUNT(*) as c FROM projects WHERE workspace_id=? AND deleted_at=''", (wid(),)).fetchone()
    return jsonify(
        plan=plan, limits=limits,
        usage={
            "members":       members["c"] if members else 0,
            "projects":      projects["c"] if projects else 0,
            "ai_calls_month": usage.get("ai_call", 0),
            "storage_mb":    usage.get("storage_mb", 0),
        }
    )

# ═══════════════════════════════════════════════════════════════
#  PUBLIC API KEYS
# ═══════════════════════════════════════════════════════════════
VALID_SCOPES = ["tasks:read","tasks:write","projects:read","projects:write",
                "tickets:read","tickets:write","users:read","webhooks:manage"]

def _api_key_auth():
    """Returns (workspace_id, user_id) if valid API key in header, else (None,None)"""
    auth = request.headers.get("Authorization","")
    if not auth.startswith("Bearer pt_"):
        return None, None
    raw_key = auth[7:]
    prefix  = raw_key[:12]
    key_hash = _hashlib.sha256(raw_key.encode()).hexdigest()
    db   = get_db()
    row  = db.execute("SELECT * FROM api_keys WHERE key_hash=? AND key_prefix=?", (key_hash, prefix)).fetchone()
    if not row:
        return None, None
    if row["expires"] and row["expires"] < ts():
        return None, None
    db.execute("UPDATE api_keys SET last_used=? WHERE id=?", (ts(), row["id"]))
    return row["workspace_id"], row["user_id"]

@app.route("/api/keys", methods=["GET"])
@login_required
def list_api_keys():
    db   = get_db()
    rows = db.execute("SELECT id, name, key_prefix, scopes, last_used, created, expires FROM api_keys WHERE workspace_id=? ORDER BY created DESC", (wid(),)).fetchall()
    return jsonify([dict(r) for r in rows])

@app.route("/api/keys", methods=["POST"])
@login_required
def create_api_key():
    d      = request.get_json(force=True)
    name   = (d.get("name","") or "").strip()[:80]
    scopes = [s for s in d.get("scopes",[]) if s in VALID_SCOPES]
    expires = d.get("expires","")
    if not name:
        return jsonify(error="Name required"), 400
    if not scopes:
        scopes = ["tasks:read","projects:read"]
    raw_key  = "pt_" + secrets.token_hex(28)
    prefix   = raw_key[:12]
    key_hash = _hashlib.sha256(raw_key.encode()).hexdigest()
    kid      = secrets.token_hex(8)
    _raw_pg("INSERT INTO api_keys VALUES (?,?,?,?,?,?,?,?,?,?)",
            (kid, wid(), session["user_id"], name, key_hash, prefix, json.dumps(scopes), "", ts(), expires))
    _log_audit("api_key_created", session["user_id"], kid)
    return jsonify(id=kid, key=raw_key, prefix=prefix, name=name, scopes=scopes, created=ts())

@app.route("/api/keys/<kid>", methods=["DELETE"])
@login_required
def delete_api_key(kid):
    db = get_db()
    row = db.execute("SELECT id FROM api_keys WHERE id=? AND workspace_id=?", (kid, wid())).fetchone()
    if not row:
        return jsonify(error="Not found"), 404
    _raw_pg("DELETE FROM api_keys WHERE id=?", (kid,))
    _log_audit("api_key_deleted", session["user_id"], kid)
    return jsonify(ok=True)

# ── Public API v1 endpoints (bearer token auth) ──
@app.route("/api/v1/tasks", methods=["GET"])
def public_list_tasks():
    ws_id, uid = _api_key_auth()
    if not ws_id:
        return jsonify(error="Invalid or missing API key"), 401
    db    = get_db()
    tasks = db.execute("SELECT id,title,stage,priority,assignee,due_date,created FROM tasks WHERE workspace_id=? AND deleted_at='' ORDER BY created DESC LIMIT 200", (ws_id,)).fetchall()
    return jsonify(data=[dict(t) for t in tasks])

@app.route("/api/v1/tasks", methods=["POST"])
def public_create_task():
    ws_id, uid = _api_key_auth()
    if not ws_id:
        return jsonify(error="Unauthorized"), 401
    d = request.get_json(force=True)
    tid = secrets.token_hex(6)
    _raw_pg("INSERT INTO tasks(id,workspace_id,project_id,title,stage,priority,assignee,due_date,created,deleted_at) VALUES (?,?,?,?,?,?,?,?,?,'')",
            (tid, ws_id, d.get("project_id",""), d.get("title","Untitled"), d.get("stage","planning"),
             d.get("priority","medium"), d.get("assignee",""), d.get("due_date",""), ts()))
    _fire_webhooks(ws_id, "task.created", {"id":tid,"title":d.get("title","")})
    return jsonify(id=tid, created=True), 201

@app.route("/api/v1/projects", methods=["GET"])
def public_list_projects():
    ws_id, _ = _api_key_auth()
    if not ws_id:
        return jsonify(error="Unauthorized"), 401
    db   = get_db()
    rows = db.execute("SELECT id,name,description,start_date,target_date,progress,color FROM projects WHERE workspace_id=? AND deleted_at='' ORDER BY created DESC LIMIT 100", (ws_id,)).fetchall()
    return jsonify(data=[dict(r) for r in rows])

@app.route("/api/v1/tickets", methods=["GET"])
def public_list_tickets():
    ws_id, _ = _api_key_auth()
    if not ws_id:
        return jsonify(error="Unauthorized"), 401
    db   = get_db()
    rows = db.execute("SELECT id,title,status,priority,assignee,created FROM tickets WHERE workspace_id=? ORDER BY created DESC LIMIT 200", (ws_id,)).fetchall()
    return jsonify(data=[dict(r) for r in rows])

# ═══════════════════════════════════════════════════════════════
#  WEBHOOKS
# ═══════════════════════════════════════════════════════════════
def _fire_webhooks(workspace_id, event, payload):
    try:
        db   = get_db()
        hooks = db.execute("SELECT * FROM webhooks WHERE workspace_id=? AND enabled=1", (workspace_id,)).fetchall()
        for hook in hooks:
            events = json.loads(hook["events"] or "[]")
            if event not in events and "*" not in events:
                continue
            body = json.dumps({"event": event, "workspace_id": workspace_id, "data": payload, "timestamp": ts()}).encode()
            headers = {"Content-Type":"application/json","X-PT-Event":event,"X-PT-Delivery":secrets.token_hex(8)}
            if hook["secret"]:
                sig = _hmac.new(hook["secret"].encode(), body, _hashlib.sha256).hexdigest()
                headers["X-PT-Signature"] = f"sha256={sig}"
            req = urllib.request.Request(hook["url"], data=body, headers=headers, method="POST")
            status_code, resp_text = 0, ""
            try:
                with urllib.request.urlopen(req, timeout=10) as r:
                    status_code = r.status
                    resp_text   = r.read(500).decode(errors="replace")
            except Exception as e:
                resp_text = str(e)
            log_id = secrets.token_hex(8)
            _raw_pg("INSERT INTO webhook_logs VALUES (?,?,?,?,?,?)",
                    (log_id, hook["id"], event, status_code, resp_text[:500], ts()))
            fail_inc = "" if 200 <= status_code < 300 else ", fail_count=fail_count+1"
            _raw_pg(f"UPDATE webhooks SET last_triggered=? {fail_inc} WHERE id=?", (ts(), hook["id"]))
    except Exception as e:
        print(f"Webhook fire error: {e}")

@app.route("/api/webhooks", methods=["GET"])
@login_required
def list_webhooks():
    db   = get_db()
    rows = db.execute("SELECT id,name,url,events,enabled,last_triggered,fail_count,created FROM webhooks WHERE workspace_id=? ORDER BY created DESC", (wid(),)).fetchall()
    return jsonify([dict(r) for r in rows])

@app.route("/api/webhooks", methods=["POST"])
@login_required
def create_webhook():
    d      = request.get_json(force=True)
    url    = (d.get("url","") or "").strip()
    name   = (d.get("name","") or "Webhook").strip()[:80]
    events = d.get("events", ["*"])
    secret = secrets.token_hex(16)
    if not url.startswith("http"):
        return jsonify(error="Valid URL required"), 400
    wh_id = secrets.token_hex(8)
    _raw_pg("INSERT INTO webhooks VALUES (?,?,?,?,?,?,?,?,?,?)",
            (wh_id, wid(), name, url, json.dumps(events), secret, 1, "", 0, ts()))
    _log_audit("webhook_created", session["user_id"], wh_id)
    return jsonify(id=wh_id, secret=secret, name=name, url=url, events=events, created=ts())

@app.route("/api/webhooks/<wh_id>", methods=["PUT"])
@login_required
def update_webhook(wh_id):
    row = get_db().execute("SELECT id FROM webhooks WHERE id=? AND workspace_id=?", (wh_id, wid())).fetchone()
    if not row:
        return jsonify(error="Not found"), 404
    d = request.get_json(force=True)
    _raw_pg("UPDATE webhooks SET name=?,url=?,events=?,enabled=? WHERE id=?",
            (d.get("name","Webhook"), d.get("url",""), json.dumps(d.get("events",["*"])), int(d.get("enabled",1)), wh_id))
    return jsonify(ok=True)

@app.route("/api/webhooks/<wh_id>", methods=["DELETE"])
@login_required
def delete_webhook(wh_id):
    row = get_db().execute("SELECT id FROM webhooks WHERE id=? AND workspace_id=?", (wh_id, wid())).fetchone()
    if not row:
        return jsonify(error="Not found"), 404
    _raw_pg("DELETE FROM webhooks WHERE id=?", (wh_id,))
    _raw_pg("DELETE FROM webhook_logs WHERE webhook_id=?", (wh_id,))
    return jsonify(ok=True)

@app.route("/api/webhooks/<wh_id>/logs", methods=["GET"])
@login_required
def webhook_logs(wh_id):
    row = get_db().execute("SELECT id FROM webhooks WHERE id=? AND workspace_id=?", (wh_id, wid())).fetchone()
    if not row:
        return jsonify(error="Not found"), 404
    rows = get_db().execute("SELECT * FROM webhook_logs WHERE webhook_id=? ORDER BY created DESC LIMIT 50", (wh_id,)).fetchall()
    return jsonify([dict(r) for r in rows])

@app.route("/api/webhooks/<wh_id>/test", methods=["POST"])
@login_required
def test_webhook(wh_id):
    row = get_db().execute("SELECT id FROM webhooks WHERE id=? AND workspace_id=?", (wh_id, wid())).fetchone()
    if not row:
        return jsonify(error="Not found"), 404
    _fire_webhooks(wid(), "ping", {"message":"Test delivery from Project Tracker"})
    return jsonify(ok=True)

# ═══════════════════════════════════════════════════════════════
#  CUSTOM FIELDS
# ═══════════════════════════════════════════════════════════════
@app.route("/api/custom-fields", methods=["GET"])
@login_required
def list_custom_fields():
    entity = request.args.get("entity","task")
    db  = get_db()
    rows = db.execute("SELECT * FROM custom_fields WHERE workspace_id=? AND entity_type=? ORDER BY created", (wid(), entity)).fetchall()
    return jsonify([dict(r) for r in rows])

@app.route("/api/custom-fields", methods=["POST"])
@login_required
def create_custom_field():
    d = request.get_json(force=True)
    name = (d.get("name","") or "").strip()[:60]
    ftype = d.get("field_type","text")
    if ftype not in ("text","number","date","checkbox","dropdown","url"):
        return jsonify(error="Invalid field type"), 400
    if not name:
        return jsonify(error="Name required"), 400
    fid = secrets.token_hex(6)
    _raw_pg("INSERT INTO custom_fields VALUES (?,?,?,?,?,?,?,?)",
            (fid, wid(), d.get("entity_type","task"), name, ftype,
             json.dumps(d.get("options",[])), int(d.get("required",0)), ts()))
    return jsonify(id=fid, name=name, field_type=ftype)

@app.route("/api/custom-fields/<fid>", methods=["DELETE"])
@login_required
def delete_custom_field(fid):
    _raw_pg("DELETE FROM custom_fields WHERE id=? AND workspace_id=?", (fid, wid()))
    _raw_pg("DELETE FROM custom_field_values WHERE field_id=? AND workspace_id=?", (fid, wid()))
    return jsonify(ok=True)

@app.route("/api/custom-field-values/<entity_id>", methods=["GET"])
@login_required
def get_field_values(entity_id):
    db   = get_db()
    rows = db.execute("SELECT field_id, value FROM custom_field_values WHERE entity_id=? AND workspace_id=?", (entity_id, wid())).fetchall()
    return jsonify({r["field_id"]: r["value"] for r in rows})

@app.route("/api/custom-field-values/<entity_id>", methods=["POST"])
@login_required
def set_field_values(entity_id):
    d   = request.get_json(force=True)
    now = ts()
    for fid, val in d.items():
        existing = get_db().execute("SELECT id FROM custom_field_values WHERE field_id=? AND entity_id=? AND workspace_id=?", (fid, entity_id, wid())).fetchone()
        if existing:
            _raw_pg("UPDATE custom_field_values SET value=?,updated=? WHERE id=?", (str(val), now, existing["id"]))
        else:
            _raw_pg("INSERT INTO custom_field_values VALUES (?,?,?,?,?,?,?)",
                    (secrets.token_hex(6), wid(), fid, entity_id, str(val), now, now))
    return jsonify(ok=True)

# ═══════════════════════════════════════════════════════════════
#  TIME TRACKING
# ═══════════════════════════════════════════════════════════════
@app.route("/api/time-entries", methods=["GET"])
@login_required
def list_time_entries():
    task_id = request.args.get("task_id","")
    user_filter = request.args.get("user_id","")
    since = request.args.get("since","")
    db   = get_db()
    sql  = "SELECT te.*, u.name as user_name FROM time_entries te LEFT JOIN users u ON te.user_id=u.id WHERE te.workspace_id=?"
    params = [wid()]
    if task_id:
        sql += " AND te.task_id=?"; params.append(task_id)
    if user_filter:
        sql += " AND te.user_id=?"; params.append(user_filter)
    if since:
        sql += " AND te.date>=?"; params.append(since)
    sql += " ORDER BY te.date DESC, te.created DESC LIMIT 500"
    rows = db.execute(sql, params).fetchall()
    return jsonify([dict(r) for r in rows])

@app.route("/api/time-entries", methods=["POST"])
@login_required
def create_time_entry():
    d   = request.get_json(force=True)
    tid = secrets.token_hex(6)
    minutes = max(1, int(d.get("minutes", 0) or 0))
    task_id = d.get("task_id","")
    _raw_pg("INSERT INTO time_entries VALUES (?,?,?,?,?,?,?,?,?,?)",
            (tid, wid(), task_id, session["user_id"],
             d.get("description","")[:200], minutes, int(d.get("billable",1)),
             d.get("date", now_ist().strftime("%Y-%m-%d")), ts(), ts()))
    if task_id:
        _fire_webhooks(wid(), "time.logged", {"task_id":task_id,"minutes":minutes})
    return jsonify(id=tid, minutes=minutes, created=True), 201

@app.route("/api/time-entries/<eid>", methods=["PUT"])
@login_required
def update_time_entry(eid):
    row = get_db().execute("SELECT id FROM time_entries WHERE id=? AND workspace_id=?", (eid, wid())).fetchone()
    if not row:
        return jsonify(error="Not found"), 404
    d = request.get_json(force=True)
    _raw_pg("UPDATE time_entries SET description=?,minutes=?,billable=?,date=?,updated=? WHERE id=?",
            (d.get("description",""), max(1,int(d.get("minutes",1))), int(d.get("billable",1)), d.get("date",""), ts(), eid))
    return jsonify(ok=True)

@app.route("/api/time-entries/<eid>", methods=["DELETE"])
@login_required
def delete_time_entry(eid):
    row = get_db().execute("SELECT id FROM time_entries WHERE id=? AND workspace_id=?", (eid, wid())).fetchone()
    if not row:
        return jsonify(error="Not found"), 404
    _raw_pg("DELETE FROM time_entries WHERE id=?", (eid,))
    return jsonify(ok=True)

@app.route("/api/time-entries/summary", methods=["GET"])
@login_required
def time_summary():
    since = request.args.get("since", now_ist().replace(day=1).strftime("%Y-%m-%d"))
    db    = get_db()
    rows  = db.execute(
        "SELECT te.user_id, u.name, SUM(te.minutes) as total_min, SUM(CASE WHEN te.billable=1 THEN te.minutes ELSE 0 END) as billable_min, COUNT(*) as entries FROM time_entries te LEFT JOIN users u ON te.user_id=u.id WHERE te.workspace_id=? AND te.date>=? GROUP BY te.user_id, u.name ORDER BY total_min DESC",
        (wid(), since)).fetchall()
    return jsonify([dict(r) for r in rows])

# ═══════════════════════════════════════════════════════════════
#  SLA TRACKING FOR TICKETS
# ═══════════════════════════════════════════════════════════════
SLA_HOURS = {"critical":4,"high":8,"medium":24,"low":72}

def _set_sla_due(ticket_id, priority, created):
    hours = SLA_HOURS.get(priority, 24)
    try:
        created_dt = datetime.fromisoformat(created)
    except Exception:
        created_dt = datetime.now()
    due = (created_dt + timedelta(hours=hours)).isoformat()
    _raw_pg("UPDATE tickets SET sla_hours=?, sla_due_at=? WHERE id=?", (hours, due, ticket_id))

@app.route("/api/tickets/sla-report", methods=["GET"])
@login_required
def sla_report():
    db  = get_db()
    now = ts()
    rows = db.execute(
        "SELECT t.*, u.name as assignee_name FROM tickets t LEFT JOIN users u ON t.assignee=u.id WHERE t.workspace_id=? ORDER BY t.created DESC LIMIT 200",
        (wid(),)).fetchall()
    result = []
    for r in rows:
        d = dict(r)
        sla_due = r["sla_due_at"] or ""
        if sla_due and r["status"] not in ("resolved","closed"):
            d["sla_breached"]   = sla_due < now
            d["sla_remaining_min"] = max(0, int((datetime.fromisoformat(sla_due) - datetime.now()).total_seconds() / 60)) if sla_due > now else 0
        else:
            d["sla_breached"]    = False
            d["sla_remaining_min"] = None
        result.append(d)
    return jsonify(result)

@app.route("/api/tickets/sla-stats", methods=["GET"])
@login_required
def sla_stats():
    db  = get_db()
    now = ts()
    total   = db.execute("SELECT COUNT(*) as c FROM tickets WHERE workspace_id=?", (wid(),)).fetchone()["c"]
    breached = db.execute("SELECT COUNT(*) as c FROM tickets WHERE workspace_id=? AND sla_due_at!='' AND sla_due_at<? AND status NOT IN ('resolved','closed')", (wid(), now)).fetchone()["c"]
    resolved = db.execute("SELECT COUNT(*) as c FROM tickets WHERE workspace_id=? AND status IN ('resolved','closed')", (wid(),)).fetchone()["c"]
    avg_row = db.execute("SELECT AVG(CAST((JULIANDAY(resolved_at) - JULIANDAY(created)) * 24 * 60 AS INTEGER)) as avg_min FROM tickets WHERE workspace_id=? AND resolved_at!=''", (wid(),)).fetchone()
    return jsonify(total=total, breached=breached, resolved=resolved, breach_rate=round(breached/max(total,1)*100,1), avg_resolve_minutes=int(avg_row["avg_min"] or 0))

# ═══════════════════════════════════════════════════════════════
#  ONBOARDING
# ═══════════════════════════════════════════════════════════════
@app.route("/api/onboarding/status", methods=["GET"])
@login_required
def onboarding_status():
    db  = get_db()
    ws  = db.execute("SELECT onboarding_done, onboarding_step FROM workspaces WHERE id=?", (wid(),)).fetchone()
    user = db.execute("SELECT * FROM users WHERE id=?", (session["user_id"],)).fetchone()
    members  = db.execute("SELECT COUNT(*) as c FROM users WHERE workspace_id=? AND deleted_at=''", (wid(),)).fetchone()
    projects = db.execute("SELECT COUNT(*) as c FROM projects WHERE workspace_id=? AND deleted_at=''", (wid(),)).fetchone()
    has_ai   = bool(db.execute("SELECT ai_key FROM workspaces WHERE id=?", (wid(),)).fetchone() or {})
    steps = [
        {"id":"workspace",   "label":"Create your workspace",    "done": True},
        {"id":"profile",     "label":"Set up your profile",      "done": bool(user and user["name"])},
        {"id":"invite",      "label":"Invite a team member",     "done": (members["c"] if members else 0) > 1},
        {"id":"project",     "label":"Create your first project","done": (projects["c"] if projects else 0) > 0},
        {"id":"ai_key",      "label":"Connect AI assistant",     "done": False},
    ]
    done_count = sum(1 for s in steps if s["done"])
    return jsonify(
        onboarding_done=bool(ws and ws["onboarding_done"]),
        step=ws["onboarding_step"] if ws else 0,
        steps=steps,
        progress=round(done_count/len(steps)*100),
        complete=done_count==len(steps),
    )

@app.route("/api/onboarding/complete", methods=["POST"])
@login_required
def complete_onboarding():
    _raw_pg("UPDATE workspaces SET onboarding_done=1 WHERE id=?", (wid(),))
    return jsonify(ok=True)

@app.route("/api/onboarding/step", methods=["POST"])
@login_required
def update_onboarding_step():
    d = request.get_json(force=True)
    _raw_pg("UPDATE workspaces SET onboarding_step=? WHERE id=?", (d.get("step",0), wid()))
    return jsonify(ok=True)

# ═══════════════════════════════════════════════════════════════
#  ENHANCED AUDIT LOG
# ═══════════════════════════════════════════════════════════════
def _log_audit(action, user_id, target="", old_val="", new_val="", entity_type="", entity_id=""):
    try:
        _raw_pg("INSERT INTO audit_log(id,workspace_id,user_id,action,target,created,ip,entity_type,entity_id,old_value,new_value) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (secrets.token_hex(8), wid(), user_id, action, target, ts(),
                 request.remote_addr or "", entity_type, entity_id, str(old_val)[:500], str(new_val)[:500]))
    except Exception:
        pass

@app.route("/api/audit", methods=["GET"])
@login_required
def full_audit_log():
    role = get_user_role()
    if role not in ("Admin","Owner"):
        return jsonify(error="Admins only"), 403
    db     = get_db()
    page   = max(1, int(request.args.get("page",1)))
    limit  = 50
    offset = (page-1)*limit
    action_filter = request.args.get("action","")
    user_filter   = request.args.get("user_id","")
    entity_filter = request.args.get("entity_type","")
    since  = request.args.get("since","")
    sql    = "SELECT a.*, u.name as user_name FROM audit_log a LEFT JOIN users u ON a.user_id=u.id WHERE a.workspace_id=?"
    params = [wid()]
    if action_filter:
        sql += " AND a.action LIKE ?"; params.append(f"%{action_filter}%")
    if user_filter:
        sql += " AND a.user_id=?"; params.append(user_filter)
    if entity_filter:
        sql += " AND a.entity_type=?"; params.append(entity_filter)
    if since:
        sql += " AND a.created>=?"; params.append(since)
    sql += f" ORDER BY a.created DESC LIMIT {limit} OFFSET {offset}"
    rows = db.execute(sql, params).fetchall()
    total = db.execute("SELECT COUNT(*) as c FROM audit_log WHERE workspace_id=?", (wid(),)).fetchone()["c"]
    return jsonify(rows=[dict(r) for r in rows], total=total, page=page, pages=max(1, -(-total//limit)))

# ═══════════════════════════════════════════════════════════════
#  REAL-TIME SERVER-SENT EVENTS
# ═══════════════════════════════════════════════════════════════
import queue as _queue
_sse_clients: dict[str, list] = {}
_sse_lock = threading.Lock()

def _sse_publish(workspace_id, event_type, data):
    with _sse_lock:
        queues = _sse_clients.get(workspace_id, [])
        dead   = []
        for q in queues:
            try:
                q.put_nowait({"type": event_type, "data": data})
            except Exception:
                dead.append(q)
        for q in dead:
            queues.remove(q)

@app.route("/api/stream")
@login_required
def sse_stream():
    """Server-Sent Events endpoint with periodic session re-validation.

    Every SSE_REAUTH_INTERVAL heartbeats the generator checks that the user
    is still active and not logged out/deactivated. If the check fails it
    pushes a "force_logout" event so the client redirects to the login page,
    then terminates the stream. This prevents a browser tab that stayed open
    after logout (or account deactivation) from continuing to receive
    workspace events indefinitely.

    Tuning:
      SSE_REAUTH_INTERVAL — how many heartbeat cycles between auth checks
                            (default 15, i.e. every ~2 min with an 8s timeout).
    """
    ws_id = wid()
    uid   = session.get("user_id", "")
    login_at = session.get("login_at", "")
    q = _queue.Queue(maxsize=50)
    with _sse_lock:
        _sse_clients.setdefault(ws_id, []).append(q)

    # How often to re-check the session (in heartbeat cycles, each ~8 s)
    _SSE_REAUTH_INTERVAL = int(os.environ.get("SSE_REAUTH_INTERVAL", "15"))

    def _session_still_valid():
        """Return True if the user is still active and not remotely logged out."""
        if not uid:
            return False
        try:
            rows = _raw_pg(
                "SELECT deleted_at, logged_out_at FROM users WHERE id=?",
                (uid,), fetch=True
            )
            if not rows:
                return False
            u = rows[0]
            # Account deactivated
            if u.get("deleted_at", ""):
                return False
            # Remote logout: server recorded a logout_at newer than login_at
            logged_out_at = u.get("logged_out_at", "") or ""
            if logged_out_at and login_at and logged_out_at > login_at:
                return False
            return True
        except Exception as _e:
            log.warning("[SSE] session check error for uid=%s: %s", uid, _e)
            return True  # fail-open: keep stream alive if DB is momentarily unavailable

    def generate():
        yield "data: {\"type\":\"connected\"}\n\n"
        heartbeat_count = 0
        try:
            while True:
                try:
                    msg = q.get(timeout=8)   # 8s: survives Railway/nginx 30s proxy idle timeout
                    yield f"data: {json.dumps(msg)}\n\n"
                except _queue.Empty:
                    heartbeat_count += 1
                    # Periodic session re-validation (every ~2 min by default)
                    if heartbeat_count % _SSE_REAUTH_INTERVAL == 0:
                        if not _session_still_valid():
                            log.info("[SSE] uid=%s session invalid — closing stream", uid)
                            yield "data: {\"type\":\"force_logout\"}\n\n"
                            return
                    # Heartbeat keeps connection alive through proxies
                    yield ": heartbeat\n\n"
        except (GeneratorExit, Exception):
            pass
        finally:
            with _sse_lock:
                clients = _sse_clients.get(ws_id, [])
                if q in clients:
                    clients.remove(q)

    resp = app.response_class(
        generate(),
        mimetype="text/event-stream",
        headers={
            "Cache-Control":    "no-cache",
            "X-Accel-Buffering":"no",
            "Connection":       "keep-alive",
        }
    )
    return resp

# ═══════════════════════════════════════════════════════════════
#  ONBOARDING PAGE ROUTE
# ═══════════════════════════════════════════════════════════════
@app.route("/onboarding")
def onboarding_page():
    if "user_id" not in session:
        return redirect("/?action=login")
    return send_from_directory(".", "onboarding.html")

# ═══════════════════════════════════════════════════════════════════════════════
# SLACK INTEGRATION
# ═══════════════════════════════════════════════════════════════════════════════
def send_slack_notification(workspace_id, message, channel="#general"):
    try:
        rows = _raw_pg("SELECT slack_webhook_url FROM workspaces WHERE id=?", (workspace_id,), fetch=True)
        if not rows or not rows[0].get("slack_webhook_url"):
            return False
        payload = json.dumps({"text": message, "channel": channel}).encode()
        req = urllib.request.Request(rows[0]["slack_webhook_url"], data=payload,
                                     headers={"Content-Type": "application/json"}, method="POST")
        with urllib.request.urlopen(req, timeout=8):
            return True
    except Exception as e:
        log.error("[Slack] %s", e)
        return False

# ═══════════════════════════════════════════════════════════════════════════════
# SMART SEARCH
# ═══════════════════════════════════════════════════════════════════════════════
@app.route("/api/search")
@login_required
def smart_search():
    q = request.args.get("q", "").strip()
    entity_type = request.args.get("type", "all")
    if not q or len(q) < 2:
        return jsonify({"results": [], "total": 0})
    like = f"%{q.lower()}%"
    results = []
    with get_db() as db:
        if entity_type in ("all", "tasks"):
            rows = db.execute(
                "SELECT id,title,stage,priority,assignee,project,'task' as type FROM tasks "
                "WHERE workspace_id=? AND deleted_at='' AND (LOWER(title) LIKE ? OR LOWER(description) LIKE ?) LIMIT 10",
                (wid(), like, like)).fetchall()
            results.extend([{"type": "task", **dict(r)} for r in rows])
        if entity_type in ("all", "projects"):
            rows = db.execute(
                "SELECT id,name as title,description,color,'project' as type FROM projects "
                "WHERE workspace_id=? AND deleted_at='' AND (LOWER(name) LIKE ? OR LOWER(description) LIKE ?) LIMIT 10",
                (wid(), like, like)).fetchall()
            results.extend([{"type": "project", **dict(r)} for r in rows])
        if entity_type in ("all", "tickets"):
            rows = db.execute(
                "SELECT id,title,status,priority,'ticket' as type FROM tickets "
                "WHERE workspace_id=? AND (LOWER(title) LIKE ? OR LOWER(description) LIKE ?) LIMIT 10",
                (wid(), like, like)).fetchall()
            results.extend([{"type": "ticket", **dict(r)} for r in rows])
        if entity_type in ("all", "users"):
            rows = db.execute(
                "SELECT id,name as title,email,role,'user' as type FROM users "
                "WHERE workspace_id=? AND deleted_at='' AND (LOWER(name) LIKE ? OR LOWER(email) LIKE ?) LIMIT 5",
                (wid(), like, like)).fetchall()
            results.extend([{"type": "user", **dict(r)} for r in rows])
    return jsonify({"results": results[:30], "total": len(results), "query": q})

# ═══════════════════════════════════════════════════════════════════════════════
# INCIDENT MANAGEMENT
# ═══════════════════════════════════════════════════════════════════════════════
@app.route("/api/incidents", methods=["GET"])
@login_required
def get_incidents():
    status = request.args.get("status", "")
    with get_db() as db:
        sql = "SELECT i.*,u.name as assignee_name FROM incidents i LEFT JOIN users u ON i.assignee=u.id WHERE i.workspace_id=?"
        params = [wid()]
        if status:
            sql += " AND i.status=?"; params.append(status)
        sql += " ORDER BY i.created DESC"
        rows = db.execute(sql, params).fetchall()
        return jsonify([dict(r) for r in rows])

@app.route("/api/incidents", methods=["POST"])
@login_required
def create_incident():
    d = request.json or {}
    if not d.get("title"):
        return jsonify({"error": "title required"}), 400
    iid = f"inc{int(datetime.now().timestamp()*1000)}"
    now = ts()
    severity = d.get("severity", "medium")
    timeline = json.dumps([{"ts": now, "message": "Incident created", "user": session["user_id"]}])
    _raw_pg(
        "INSERT INTO incidents(id,workspace_id,title,severity,status,description,"
        "affected_systems,timeline,assignee,reporter,created,updated,resolved_at,rca,postmortem) "
        "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (iid, wid(), d["title"], severity, "open", d.get("description", ""),
         json.dumps(d.get("affected_systems", [])), timeline,
         d.get("assignee", ""), session["user_id"], now, now, "", "", "")
    )
    if severity in ("critical", "high"):
        send_slack_notification(wid(), f"{'🔴' if severity=='critical' else '🟠'} *INCIDENT [{severity.upper()}]* — {d['title']}\n> {d.get('description','')}")
    _audit("incident_created", iid, f"{d['title']} [{severity}]")
    with get_db() as db:
        return jsonify(dict(db.execute("SELECT * FROM incidents WHERE id=?", (iid,)).fetchone()))

@app.route("/api/incidents/<iid>", methods=["PUT"])
@login_required
def update_incident(iid):
    d = request.json or {}
    with get_db() as db:
        inc = db.execute("SELECT * FROM incidents WHERE id=? AND workspace_id=?", (iid, wid())).fetchone()
        if not inc: return jsonify({"error": "Not found"}), 404
        now = ts()
        resolved_at = now if d.get("status") == "resolved" and inc["status"] != "resolved" else (inc["resolved_at"] or "")
        timeline = json.loads(inc["timeline"] or "[]")
        if d.get("status") and d["status"] != inc["status"]:
            timeline.append({"ts": now, "message": f"Status → {d['status']}", "user": session["user_id"]})
        if d.get("update_message"):
            timeline.append({"ts": now, "message": d["update_message"], "user": session["user_id"]})
        db.execute(
            "UPDATE incidents SET title=?,severity=?,status=?,description=?,affected_systems=?,"
            "timeline=?,assignee=?,updated=?,resolved_at=?,rca=?,postmortem=? WHERE id=? AND workspace_id=?",
            (d.get("title", inc["title"]), d.get("severity", inc["severity"]),
             d.get("status", inc["status"]), d.get("description", inc["description"]),
             json.dumps(d.get("affected_systems", json.loads(inc["affected_systems"] or "[]"))),
             json.dumps(timeline), d.get("assignee", inc["assignee"]),
             now, resolved_at, d.get("rca", inc.get("rca", "") or ""),
             d.get("postmortem", inc.get("postmortem", "") or ""), iid, wid()))
        return jsonify(dict(db.execute("SELECT * FROM incidents WHERE id=?", (iid,)).fetchone()))

@app.route("/api/incidents/<iid>", methods=["DELETE"])
@login_required
def delete_incident(iid):
    if get_user_role() not in ("Admin", "Manager"):
        return jsonify({"error": "Admin only"}), 403
    _raw_pg("DELETE FROM incidents WHERE id=? AND workspace_id=?", (iid, wid()))
    return jsonify({"ok": True})

@app.route("/api/incidents/stats")
@login_required
def incident_stats():
    with get_db() as db:
        total = db.execute("SELECT COUNT(*) as c FROM incidents WHERE workspace_id=?", (wid(),)).fetchone()["c"]
        open_cnt = db.execute("SELECT COUNT(*) as c FROM incidents WHERE workspace_id=? AND status='open'", (wid(),)).fetchone()["c"]
        critical = db.execute("SELECT COUNT(*) as c FROM incidents WHERE workspace_id=? AND severity='critical' AND status!='resolved'", (wid(),)).fetchone()["c"]
        return jsonify(total=total, open=open_cnt, critical=critical)

# ═══════════════════════════════════════════════════════════════════════════════
# APPROVAL WORKFLOWS
# ═══════════════════════════════════════════════════════════════════════════════
@app.route("/api/approvals", methods=["GET"])
@login_required
def get_approvals():
    status = request.args.get("status", "")
    with get_db() as db:
        sql = "SELECT a.*,u.name as requester_name FROM approvals a LEFT JOIN users u ON a.requested_by=u.id WHERE a.workspace_id=?"
        params = [wid()]
        if status: sql += " AND a.status=?"; params.append(status)
        sql += " ORDER BY a.created DESC"
        return jsonify([dict(r) for r in db.execute(sql, params).fetchall()])

@app.route("/api/approvals", methods=["POST"])
@login_required
def create_approval():
    d = request.json or {}
    if not d.get("title"): return jsonify({"error": "title required"}), 400
    aid = f"apv{int(datetime.now().timestamp()*1000)}"
    now = ts()
    approvers = d.get("approvers", [])
    _raw_pg(
        "INSERT INTO approvals(id,workspace_id,entity_type,entity_id,title,description,"
        "status,requested_by,approvers,approved_by,rejected_by,rejection_reason,created,updated,expires_at) "
        "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (aid, wid(), d.get("entity_type", "task"), d.get("entity_id", ""),
         d["title"], d.get("description", ""), "pending", session["user_id"],
         json.dumps(approvers), json.dumps([]), "", "", now, now, d.get("expires_at", ""))
    )
    with get_db() as db:
        for approver_id in approvers:
            nid = f"n{int(datetime.now().timestamp()*1000)}{secrets.token_hex(2)}"
            db.execute("INSERT INTO notifications(id,workspace_id,type,content,user_id,read,ts) VALUES (?,?,?,?,?,?,?)",
                       (nid, wid(), "approval_requested", f"Your approval needed: {d['title']}", approver_id, 0, now))
        return jsonify(dict(db.execute("SELECT * FROM approvals WHERE id=?", (aid,)).fetchone()))

@app.route("/api/approvals/<aid>/approve", methods=["POST"])
@login_required
def approve_request(aid):
    with get_db() as db:
        apv = db.execute("SELECT * FROM approvals WHERE id=? AND workspace_id=?", (aid, wid())).fetchone()
        if not apv: return jsonify({"error": "Not found"}), 404
        approvers = json.loads(apv["approvers"] or "[]")
        if session["user_id"] not in approvers: return jsonify({"error": "Not an approver"}), 403
        approved_by = json.loads(apv["approved_by"] or "[]")
        if session["user_id"] not in approved_by: approved_by.append(session["user_id"])
        status = "approved" if set(approved_by) >= set(approvers) else "pending"
        now = ts()
        db.execute("UPDATE approvals SET approved_by=?,status=?,updated=? WHERE id=?",
                   (json.dumps(approved_by), status, now, aid))
        if status == "approved":
            nid = f"n{int(datetime.now().timestamp()*1000)}"
            db.execute("INSERT INTO notifications(id,workspace_id,type,content,user_id,read,ts) VALUES (?,?,?,?,?,?,?)",
                       (nid, wid(), "approval_approved", f"✅ Approved: {apv['title']}", apv["requested_by"], 0, now))
        _audit("approval_action", aid, f"Approved by {session['user_id']}, status={status}")
        return jsonify({"ok": True, "status": status})

@app.route("/api/approvals/<aid>/reject", methods=["POST"])
@login_required
def reject_request(aid):
    d = request.json or {}
    with get_db() as db:
        apv = db.execute("SELECT * FROM approvals WHERE id=? AND workspace_id=?", (aid, wid())).fetchone()
        if not apv: return jsonify({"error": "Not found"}), 404
        approvers = json.loads(apv["approvers"] or "[]")
        if session["user_id"] not in approvers: return jsonify({"error": "Not an approver"}), 403
        now = ts()
        db.execute("UPDATE approvals SET rejected_by=?,rejection_reason=?,status=?,updated=? WHERE id=?",
                   (session["user_id"], d.get("reason", ""), "rejected", now, aid))
        nid = f"n{int(datetime.now().timestamp()*1000)}"
        db.execute("INSERT INTO notifications(id,workspace_id,type,content,user_id,read,ts) VALUES (?,?,?,?,?,?,?)",
                   (nid, wid(), "approval_rejected", f"❌ Rejected: {apv['title']}", apv["requested_by"], 0, now))
        return jsonify({"ok": True, "status": "rejected"})

# ═══════════════════════════════════════════════════════════════════════════════
# RECURRING TASKS
# ═══════════════════════════════════════════════════════════════════════════════
def _calc_next_run(frequency, day_of_week=1, day_of_month=1):
    now = datetime.now()
    if frequency == "daily":
        return (now + timedelta(days=1)).strftime("%Y-%m-%d")
    elif frequency == "weekly":
        days_ahead = (int(day_of_week) - now.weekday()) % 7 or 7
        return (now + timedelta(days=days_ahead)).strftime("%Y-%m-%d")
    elif frequency == "monthly":
        dom = int(day_of_month)
        if now.day < dom:
            return now.replace(day=dom).strftime("%Y-%m-%d")
        if now.month == 12:
            return now.replace(year=now.year+1, month=1, day=dom).strftime("%Y-%m-%d")
        return now.replace(month=now.month+1, day=dom).strftime("%Y-%m-%d")
    return (now + timedelta(days=1)).strftime("%Y-%m-%d")

@app.route("/api/recurring-tasks", methods=["GET"])
@login_required
def get_recurring_tasks():
    with get_db() as db:
        rows = db.execute("SELECT * FROM recurring_tasks WHERE workspace_id=? ORDER BY created DESC", (wid(),)).fetchall()
        return jsonify([dict(r) for r in rows])

@app.route("/api/recurring-tasks", methods=["POST"])
@login_required
def create_recurring_task():
    d = request.json or {}
    if not d.get("title"): return jsonify({"error": "title required"}), 400
    rid = f"rt{int(datetime.now().timestamp()*1000)}"
    freq = d.get("frequency", "weekly")
    next_run = _calc_next_run(freq, d.get("day_of_week", 1), d.get("day_of_month", 1))
    _raw_pg(
        "INSERT INTO recurring_tasks(id,workspace_id,title,description,project,assignee,priority,stage,"
        "frequency,day_of_week,day_of_month,next_run,last_run,enabled,created_by,created) "
        "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (rid, wid(), d["title"], d.get("description", ""), d.get("project", ""),
         d.get("assignee", ""), d.get("priority", "medium"), d.get("stage", "backlog"),
         freq, d.get("day_of_week", 1), d.get("day_of_month", 1), next_run, "", 1, session["user_id"], ts())
    )
    with get_db() as db:
        return jsonify(dict(db.execute("SELECT * FROM recurring_tasks WHERE id=?", (rid,)).fetchone()))

@app.route("/api/recurring-tasks/<rid>", methods=["PUT"])
@login_required
def update_recurring_task(rid):
    d = request.json or {}
    with get_db() as db:
        rt = db.execute("SELECT * FROM recurring_tasks WHERE id=? AND workspace_id=?", (rid, wid())).fetchone()
        if not rt: return jsonify({"error": "Not found"}), 404
        freq = d.get("frequency", rt["frequency"])
        next_run = _calc_next_run(freq, d.get("day_of_week", rt["day_of_week"]), d.get("day_of_month", rt["day_of_month"]))
        db.execute(
            "UPDATE recurring_tasks SET title=?,description=?,project=?,assignee=?,priority=?,"
            "frequency=?,day_of_week=?,day_of_month=?,next_run=?,enabled=? WHERE id=? AND workspace_id=?",
            (d.get("title", rt["title"]), d.get("description", rt["description"]),
             d.get("project", rt["project"]), d.get("assignee", rt["assignee"]),
             d.get("priority", rt["priority"]), freq, d.get("day_of_week", rt["day_of_week"]),
             d.get("day_of_month", rt["day_of_month"]), next_run,
             int(d.get("enabled", rt["enabled"])), rid, wid()))
        return jsonify(dict(db.execute("SELECT * FROM recurring_tasks WHERE id=?", (rid,)).fetchone()))

@app.route("/api/recurring-tasks/<rid>", methods=["DELETE"])
@login_required
def delete_recurring_task(rid):
    _raw_pg("DELETE FROM recurring_tasks WHERE id=? AND workspace_id=?", (rid, wid()))
    return jsonify({"ok": True})

def _recurring_task_runner():
    while True:
        try:
            time.sleep(3600)
            today = datetime.now().strftime("%Y-%m-%d")
            due = _raw_pg("SELECT * FROM recurring_tasks WHERE enabled=1 AND next_run<=?", (today,), fetch=True)
            for rt in (due or []):
                tid = f"T-r{secrets.token_hex(4)}"
                _raw_pg(
                    "INSERT INTO tasks(id,workspace_id,title,description,project,assignee,priority,stage,"
                    "created,due,pct,comments,team_id,deleted_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (tid, rt["workspace_id"], rt["title"], rt["description"], rt["project"],
                     rt["assignee"], rt["priority"], rt["stage"], ts(), "", 0, "[]", "", ""))
                next_run = _calc_next_run(rt["frequency"], rt["day_of_week"], rt["day_of_month"])
                _raw_pg("UPDATE recurring_tasks SET last_run=?,next_run=? WHERE id=?", (today, next_run, rt["id"]))
        except Exception as e:
            log.error("[recurring] %s", e)


# ── 10-minute unread notification follow-up emailer ──────────────────────────
def _send_unread_followup_email(user_email, user_name, notif_type, content, entity_id, entity_type, workspace_id):
    """Send a plain follow-up reminder for an unread notification after 10 minutes."""
    accent = "#f59e0b"
    subject = f"⏰ Reminder: You have an unread notification"
    safe_user = _email_escape(user_name)
    safe_content = _email_escape(content)
    # Build deep-link
    if entity_type == "task" and entity_id:
        link = f"{APP_URL}/?action=task&id={entity_id}"
        cta  = "Open Task →"
    elif entity_type == "ticket" and entity_id:
        link = f"{APP_URL}/?action=ticket&id={entity_id}"
        cta  = "Open Ticket →"
    elif entity_type == "project" and entity_id:
        link = f"{APP_URL}/?action=project&id={entity_id}"
        cta  = "Open Project →"
    else:
        link = f"{APP_URL}/?action=tasks"
        cta  = "Open Dashboard →"

    body = f"""
      <h1 class="pt-h1" style="margin:0 0 10px;font-size:26px;font-weight:900;
          color:#ffffff;letter-spacing:-.6px;line-height:1.2;">
        ⏰ You have an unread notification
      </h1>
      <p style="margin:0 0 20px;font-size:15px;line-height:1.7;color:rgba(255,255,255,.55);">
        Hi <strong style="color:#ffffff;">{safe_user}</strong>, this notification
        has been waiting for you for over 10 minutes.
      </p>
      <div style="padding:16px 20px;background:rgba(245,158,11,.08);border:1px solid
          rgba(245,158,11,.25);border-radius:14px;font-size:14px;color:rgba(255,255,255,.8);
          line-height:1.6;margin-bottom:20px;">
        {safe_content}
      </div>"""
    html = _email_base(
        subject_label="REMINDER", accent=accent, header_icon="⏰",
        header_badge="UNREAD NOTIFICATION REMINDER", inner_html=body,
        cta_url=link, cta_text=cta, warning=True,
    )
    send_email(user_email, subject, html, workspace_id)


def _unread_followup_runner():
    """Background thread: every 5 minutes, find notifications unread for >10 min
    and send one follow-up email per user (deduped by followup_sent flag)."""
    import time as _time
    while True:
        _time.sleep(300)  # run every 5 minutes
        try:
            cutoff = datetime.utcnow().replace(microsecond=0)
            from dateutil.parser import parse as _parse_dt
            # Find all workspaces
            workspaces = _raw_pg("SELECT id FROM workspaces", (), fetch=True) or []
            for ws in workspaces:
                ws_id = ws["id"]
                # Find notifications older than 10 min, unread, no followup sent yet
                rows = _raw_pg(
                    """SELECT n.id, n.type, n.content, n.user_id, n.ts,
                              n.entity_id, n.entity_type,
                              u.email, u.name
                       FROM notifications n
                       JOIN users u ON u.id = n.user_id
                       WHERE n.workspace_id=?
                         AND n.read=0
                         AND (n.followup_sent IS NULL OR n.followup_sent=0)
                         AND n.type IN ('task_assigned','status_change','comment','task_due','ticket_assigned')""",
                    (ws_id,), fetch=True
                ) or []
                for row in rows:
                    try:
                        notif_ts = _parse_dt(row["ts"]).replace(tzinfo=None)
                        age_mins = (cutoff - notif_ts).total_seconds() / 60
                        if age_mins < 10:
                            continue
                        if not row["email"]:
                            continue
                        _send_unread_followup_email(
                            row["email"], row["name"], row["type"],
                            row["content"], row["entity_id"], row["entity_type"],
                            ws_id
                        )
                        # Mark followup sent
                        _raw_pg(
                            "UPDATE notifications SET followup_sent=1 WHERE id=?",
                            (row["id"],)
                        )
                    except Exception as _e:
                        log.warning("[followup] row error: %s", _e)
        except Exception as e:
            log.error("[followup_runner] %s", e)


threading.Thread(target=_unread_followup_runner, daemon=True).start()

threading.Thread(target=_recurring_task_runner, daemon=True).start()

# ═══════════════════════════════════════════════════════════════════════════════
# GITHUB INTEGRATION
# ═══════════════════════════════════════════════════════════════════════════════
@app.route("/api/github/repos", methods=["GET"])
@login_required
def list_github_repos():
    with get_db() as db:
        rows = db.execute("SELECT id,workspace_id,repo_full_name,repo_url,connected_by,created FROM github_repos WHERE workspace_id=? ORDER BY created DESC", (wid(),)).fetchall()
        return jsonify([dict(r) for r in rows])

@app.route("/api/github/repos", methods=["POST"])
@login_required
def link_github_repo():
    d = request.json or {}
    repo_full_name = d.get("repo_full_name", "").strip()
    if not repo_full_name: return jsonify({"error": "repo_full_name required"}), 400
    rid = f"ghrepo{int(datetime.now().timestamp()*1000)}"
    token = d.get("github_token", "")
    _raw_pg(
        "INSERT INTO github_repos(id,workspace_id,repo_full_name,repo_url,github_token,connected_by,created) VALUES (?,?,?,?,?,?,?)",
        (rid, wid(), repo_full_name, f"https://github.com/{repo_full_name}", token, session["user_id"], ts()))
    _audit("github_repo_linked", rid, f"Linked: {repo_full_name}")
    return jsonify({"ok": True, "id": rid, "repo_full_name": repo_full_name})

@app.route("/api/github/repos/<repo_id>", methods=["DELETE"])
@login_required
def unlink_github_repo(repo_id):
    if get_user_role() not in ("Admin", "Manager"): return jsonify({"error": "Admin only"}), 403
    _raw_pg("DELETE FROM github_repos WHERE id=? AND workspace_id=?", (repo_id, wid()))
    return jsonify({"ok": True})

@app.route("/api/github/webhook", methods=["POST"])
def github_webhook():
    event_type = request.headers.get("X-GitHub-Event", "")
    payload = request.get_data()
    try: data = json.loads(payload)
    except Exception: return "Bad JSON", 400
    ws_id = request.args.get("ws", "")
    repo_id = request.args.get("repo", "")
    text_to_search = ""
    if event_type == "push":
        text_to_search = " ".join(c.get("message","") for c in data.get("commits", []))
    elif event_type in ("pull_request", "issues"):
        obj = data.get("pull_request") or data.get("issue") or {}
        text_to_search = f"{obj.get('title','')} {obj.get('body','')}"
    task_id = ""
    m = re.search(r'T-\d{3,}(?:-\d+)?', text_to_search)
    if m: task_id = m.group(0)
    if ws_id:
        eid = f"ghe{int(datetime.now().timestamp()*1000)}"
        _raw_pg("INSERT INTO github_events(id,workspace_id,repo_id,event_type,payload,task_id,created) VALUES (?,?,?,?,?,?,?)",
                (eid, ws_id, repo_id, event_type, json.dumps(data)[:4000], task_id, ts()))
    return "ok", 200

@app.route("/api/github/events")
@login_required
def get_github_events():
    task_id = request.args.get("task_id", "")
    with get_db() as db:
        if task_id:
            rows = db.execute("SELECT * FROM github_events WHERE workspace_id=? AND task_id=? ORDER BY created DESC LIMIT 50", (wid(), task_id)).fetchall()
        else:
            rows = db.execute("SELECT * FROM github_events WHERE workspace_id=? ORDER BY created DESC LIMIT 100", (wid(),)).fetchall()
        return jsonify([dict(r) for r in rows])

# ═══════════════════════════════════════════════════════════════════════════════
# GDPR — DATA EXPORT & DELETION
# ═══════════════════════════════════════════════════════════════════════════════
import zipfile, io

@app.route("/api/gdpr/export")
@login_required
def gdpr_export():
    uid = session["user_id"]
    ws = wid()
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as zf:
        with get_db() as db:
            u = db.execute("SELECT id,name,email,role,avatar,color,created,last_active FROM users WHERE id=?", (uid,)).fetchone()
            zf.writestr("profile.json", json.dumps(dict(u) if u else {}, indent=2))
            tasks = db.execute("SELECT * FROM tasks WHERE workspace_id=? AND assignee=? AND deleted_at=''", (ws, uid)).fetchall()
            zf.writestr("tasks.json", json.dumps([dict(t) for t in tasks], indent=2))
            messages = db.execute("SELECT * FROM messages WHERE workspace_id=? AND sender=?", (ws, uid)).fetchall()
            zf.writestr("messages.json", json.dumps([dict(m) for m in messages], indent=2))
            dms = db.execute("SELECT * FROM direct_messages WHERE workspace_id=? AND (sender=? OR recipient=?)", (ws, uid, uid)).fetchall()
            zf.writestr("direct_messages.json", json.dumps([dict(d) for d in dms], indent=2))
            timelogs = db.execute("SELECT * FROM time_logs WHERE workspace_id=? AND user_id=?", (ws, uid)).fetchall()
            zf.writestr("time_logs.json", json.dumps([dict(t) for t in timelogs], indent=2))
        zf.writestr("README.txt", f"GDPR Export for {uid}\nGenerated: {datetime.now().isoformat()}\n")
    buf.seek(0)
    _log_audit("gdpr_export", uid, "GDPR data export")
    return send_file(buf, download_name=f"my_data_{uid}.zip", as_attachment=True, mimetype="application/zip")

@app.route("/api/gdpr/delete", methods=["POST"])
@login_required
def gdpr_delete():
    d = request.json or {}
    if d.get("confirm") != "DELETE MY DATA":
        return jsonify({"error": "Confirm with 'DELETE MY DATA'"}), 400
    uid = session["user_id"]
    ws = wid()
    with get_db() as db:
        anon_name = f"Deleted User {secrets.token_hex(4)}"
        anon_email = f"deleted_{secrets.token_hex(6)}@deleted.invalid"
        db.execute("UPDATE users SET name=?,email=?,password=?,avatar='?',color='#999',deleted_at=? WHERE id=?",
                   (anon_name, anon_email, hash_pw(secrets.token_hex(32)), ts(), uid))
        db.execute("DELETE FROM direct_messages WHERE workspace_id=? AND sender=?", (ws, uid))
        db.execute("DELETE FROM push_subscriptions WHERE user_id=?", (uid,))
        db.execute("DELETE FROM vault_cards WHERE user_id=?", (uid,))
    session.clear()
    _log_audit("gdpr_delete", uid, "User data deleted (GDPR)")
    return jsonify({"ok": True, "message": "Your data has been anonymized."})

# ═══════════════════════════════════════════════════════════════════════════════
# FEATURE FLAGS
# ═══════════════════════════════════════════════════════════════════════════════
DEFAULT_FLAGS = {
    "github_integration": True, "slack_integration": True,
    "incident_management": True, "approval_workflows": True,
    "recurring_tasks": True, "smart_search": True, "time_tracking": True,
    "public_api": True, "ai_assistant": True, "billing": False, "public_roadmap": False,
}

@app.route("/api/feature-flags", methods=["GET"])
@login_required
def get_feature_flags():
    flags = dict(DEFAULT_FLAGS)
    try:
        with get_db() as db:
            rows = db.execute("SELECT flag_name,enabled FROM feature_flags WHERE workspace_id=?", (wid(),)).fetchall()
            for r in rows:
                flags[r["flag_name"]] = bool(r["enabled"])
    except Exception: pass
    return jsonify(flags)

@app.route("/api/feature-flags", methods=["PUT"])
@login_required
def update_feature_flags():
    if get_user_role() not in ("Admin", "Owner"): return jsonify({"error": "Admin only"}), 403
    d = request.json or {}
    with get_db() as db:
        for flag_name, enabled in d.items():
            if flag_name not in DEFAULT_FLAGS: continue
            existing = db.execute("SELECT id FROM feature_flags WHERE workspace_id=? AND flag_name=?", (wid(), flag_name)).fetchone()
            if existing:
                db.execute("UPDATE feature_flags SET enabled=?,updated=? WHERE id=?", (1 if enabled else 0, ts(), existing["id"]))
            else:
                _raw_pg("INSERT INTO feature_flags(id,workspace_id,flag_name,enabled,config,updated) VALUES (?,?,?,?,?,?)",
                        (secrets.token_hex(6), wid(), flag_name, 1 if enabled else 0, "{}", ts()))
    return jsonify({"ok": True})

# ═══════════════════════════════════════════════════════════════════════════════
# RELEASE CALENDAR
# ═══════════════════════════════════════════════════════════════════════════════
@app.route("/api/releases", methods=["GET"])
@login_required
def get_releases():
    with get_db() as db:
        rows = db.execute("SELECT r.*,u.name as created_by_name FROM release_calendar r LEFT JOIN users u ON r.created_by=u.id WHERE r.workspace_id=? ORDER BY r.release_date ASC", (wid(),)).fetchall()
        return jsonify([dict(r) for r in rows])

@app.route("/api/releases", methods=["POST"])
@login_required
def create_release():
    d = request.json or {}
    if not d.get("title") or not d.get("release_date"): return jsonify({"error": "title and release_date required"}), 400
    rid = f"rel{int(datetime.now().timestamp()*1000)}"
    _raw_pg("INSERT INTO release_calendar(id,workspace_id,title,release_date,project,status,environment,notes,created_by,created) VALUES (?,?,?,?,?,?,?,?,?,?)",
            (rid, wid(), d["title"], d["release_date"], d.get("project", ""),
             d.get("status", "planned"), d.get("environment", "production"),
             d.get("notes", ""), session["user_id"], ts()))
    with get_db() as db:
        return jsonify(dict(db.execute("SELECT * FROM release_calendar WHERE id=?", (rid,)).fetchone()))

@app.route("/api/releases/<rid>", methods=["PUT"])
@login_required
def update_release(rid):
    d = request.json or {}
    with get_db() as db:
        r = db.execute("SELECT * FROM release_calendar WHERE id=? AND workspace_id=?", (rid, wid())).fetchone()
        if not r: return jsonify({"error": "Not found"}), 404
        db.execute("UPDATE release_calendar SET title=?,release_date=?,project=?,status=?,environment=?,notes=? WHERE id=?",
                   (d.get("title", r["title"]), d.get("release_date", r["release_date"]),
                    d.get("project", r["project"]), d.get("status", r["status"]),
                    d.get("environment", r["environment"]), d.get("notes", r["notes"]), rid))
        return jsonify(dict(db.execute("SELECT * FROM release_calendar WHERE id=?", (rid,)).fetchone()))

@app.route("/api/releases/<rid>", methods=["DELETE"])
@login_required
def delete_release(rid):
    _raw_pg("DELETE FROM release_calendar WHERE id=? AND workspace_id=?", (rid, wid()))
    return jsonify({"ok": True})

@app.route("/api/roadmap/public/<ws_id>")
def public_roadmap(ws_id):
    rows = _raw_pg("SELECT id,title,release_date,status,environment,notes FROM release_calendar WHERE workspace_id=? AND status IN ('planned','in_progress','released') ORDER BY release_date ASC LIMIT 50", (ws_id,), fetch=True)
    ws_rows = _raw_pg("SELECT name FROM workspaces WHERE id=?", (ws_id,), fetch=True)
    return jsonify({"workspace": ws_rows[0]["name"] if ws_rows else "Unknown", "releases": rows or []})

# ═══════════════════════════════════════════════════════════════════════════════
# ON-CALL SCHEDULE
# ═══════════════════════════════════════════════════════════════════════════════
@app.route("/api/oncall", methods=["GET"])
@login_required
def get_oncall():
    with get_db() as db:
        rows = db.execute("SELECT * FROM on_call_schedules WHERE workspace_id=? ORDER BY created DESC", (wid(),)).fetchall()
        return jsonify([dict(r) for r in rows])

@app.route("/api/oncall", methods=["POST"])
@login_required
def create_oncall():
    d = request.json or {}
    if not d.get("name") or not d.get("members"): return jsonify({"error": "name and members required"}), 400
    oid = f"oc{int(datetime.now().timestamp()*1000)}"
    members = d.get("members", [])
    _raw_pg("INSERT INTO on_call_schedules(id,workspace_id,name,members,current_oncall,rotation_days,started_at,created) VALUES (?,?,?,?,?,?,?,?)",
            (oid, wid(), d["name"], json.dumps(members), members[0] if members else "", d.get("rotation_days", 7), ts(), ts()))
    with get_db() as db:
        return jsonify(dict(db.execute("SELECT * FROM on_call_schedules WHERE id=?", (oid,)).fetchone()))

@app.route("/api/oncall/<oid>/rotate", methods=["POST"])
@login_required
def rotate_oncall(oid):
    with get_db() as db:
        s = db.execute("SELECT * FROM on_call_schedules WHERE id=? AND workspace_id=?", (oid, wid())).fetchone()
        if not s: return jsonify({"error": "Not found"}), 404
        members = json.loads(s["members"] or "[]")
        if not members: return jsonify({"error": "No members"}), 400
        idx = members.index(s["current_oncall"]) if s["current_oncall"] in members else -1
        new_oncall = members[(idx + 1) % len(members)]
        db.execute("UPDATE on_call_schedules SET current_oncall=? WHERE id=?", (new_oncall, oid))
        return jsonify({"ok": True, "current_oncall": new_oncall})

# ═══════════════════════════════════════════════════════════════════════════════
# RISK DASHBOARD & PROJECT HEALTH
# ═══════════════════════════════════════════════════════════════════════════════
@app.route("/api/projects/<pid>/health")
@login_required
def project_health(pid):
    with get_db() as db:
        p = db.execute("SELECT * FROM projects WHERE id=? AND workspace_id=?", (pid, wid())).fetchone()
        if not p: return jsonify({"error": "Not found"}), 404
        tasks = db.execute("SELECT * FROM tasks WHERE project=? AND workspace_id=? AND deleted_at=''", (pid, wid())).fetchall()
        today = datetime.now().strftime("%Y-%m-%d")
        total = len(tasks)
        completed = len([t for t in tasks if t["stage"] == "completed"])
        blocked = len([t for t in tasks if t["stage"] == "blocked"])
        overdue = len([t for t in tasks if t["due"] and t["due"][:10] < today and t["stage"] != "completed"])
        completion_rate = (completed / total * 100) if total > 0 else 0
        score = max(0, min(100, int(100 - (blocked/max(total,1))*30 - (overdue/max(total,1))*25 - max(0, 100-completion_rate)*0.3)))
        status = "healthy" if score >= 80 else ("at_risk" if score >= 60 else ("warning" if score >= 40 else "critical"))
        return jsonify({"project_id": pid, "score": score, "status": status, "total_tasks": total,
                        "completed": completed, "blocked": blocked, "overdue": overdue,
                        "completion_rate": round(completion_rate, 1)})

@app.route("/api/risk-dashboard")
@login_required
def risk_dashboard():
    with get_db() as db:
        today = datetime.now().strftime("%Y-%m-%d")
        risky = db.execute(
            "SELECT t.*,u.name as assignee_name,p.name as project_name FROM tasks t "
            "LEFT JOIN users u ON t.assignee=u.id LEFT JOIN projects p ON t.project=p.id "
            "WHERE t.workspace_id=? AND t.deleted_at='' AND ("
            "(t.due!='' AND t.due<? AND t.stage!='completed') OR t.stage='blocked' OR t.priority='critical'"
            ") ORDER BY t.priority DESC, t.due ASC LIMIT 20",
            (wid(), today)).fetchall()
        blocked_by = db.execute(
            "SELECT project,COUNT(*) as cnt FROM tasks WHERE workspace_id=? AND stage='blocked' AND deleted_at='' GROUP BY project",
            (wid(),)).fetchall()
        return jsonify({
            "risky_tasks": [dict(t) for t in risky],
            "blocked_by_project": [dict(r) for r in blocked_by],
            "summary": {"total_risky": len(risky),
                        "overdue": len([t for t in risky if t["due"] and t["due"][:10] < today]),
                        "blocked": len([t for t in risky if t["stage"] == "blocked"]),
                        "critical": len([t for t in risky if t["priority"] == "critical"])}
        })

# ═══════════════════════════════════════════════════════════════════════════════
# EMAIL-TO-TASK & CSV IMPORT/EXPORT
# ═══════════════════════════════════════════════════════════════════════════════
@app.route("/api/email-to-task", methods=["POST"])
def email_to_task():
    d = request.json or {}
    token = request.headers.get("X-Email-Token", "") or d.get("token", "")
    if not token: return jsonify({"error": "Token required"}), 401
    rows = _raw_pg("SELECT id FROM workspaces WHERE invite_code=?", (token.upper(),), fetch=True)
    if not rows: return jsonify({"error": "Invalid token"}), 401
    ws_id = rows[0]["id"]
    subject = d.get("subject", "Task from email")[:200]
    body = d.get("body", "")[:2000]
    from_email = d.get("from", "")
    user_rows = _raw_pg("SELECT id FROM users WHERE workspace_id=? AND email=? LIMIT 1", (ws_id, from_email), fetch=True)
    reporter_id = user_rows[0]["id"] if user_rows else ""
    tid = f"T-email-{secrets.token_hex(4)}"
    _raw_pg("INSERT INTO tasks(id,workspace_id,title,description,project,assignee,priority,stage,created,due,pct,comments,team_id,deleted_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (tid, ws_id, subject, body, "", reporter_id, "medium", "backlog", ts(), "", 0, "[]", "", ""))
    return jsonify({"ok": True, "task_id": tid})

# ═══════════════════════════════════════════════════════════════════════════════
# OPENAPI DOCS
# ═══════════════════════════════════════════════════════════════════════════════
@app.route("/api/docs")
def openapi_docs():
    spec = {
        "openapi": "3.0.0",
        "info": {"title": "Project Tracker API", "version": "5.0.0",
                 "description": "Enterprise project management API — projectflow.app"},
        "servers": [{"url": APP_URL or "/", "description": "Production"}],
        "security": [{"bearerAuth": []}],
        "components": {"securitySchemes": {
            "bearerAuth": {"type": "http", "scheme": "bearer", "bearerFormat": "pt_..."},
            "sessionAuth": {"type": "apiKey", "in": "cookie", "name": "pf_session"}
        }},
        "paths": {
            "/api/v1/tasks": {"get": {"summary": "List tasks", "tags": ["Tasks"]},
                              "post": {"summary": "Create task", "tags": ["Tasks"]}},
            "/api/v1/projects": {"get": {"summary": "List projects", "tags": ["Projects"]}},
            "/api/incidents": {"get": {"summary": "List incidents", "tags": ["Incidents"]},
                               "post": {"summary": "Create incident", "tags": ["Incidents"]}},
            "/api/approvals": {"get": {"summary": "List approvals", "tags": ["Approvals"]},
                               "post": {"summary": "Create approval", "tags": ["Approvals"]}},
            "/api/releases": {"get": {"summary": "Release calendar", "tags": ["Releases"]}},
            "/api/search": {"get": {"summary": "Full-text search", "tags": ["Search"],
                                    "parameters": [{"name": "q", "in": "query", "required": True,
                                                    "schema": {"type": "string"}}]}},
            "/api/gdpr/export": {"get": {"summary": "Export personal data (GDPR)", "tags": ["GDPR"]}},
            "/api/gdpr/delete": {"post": {"summary": "Delete personal data (GDPR)", "tags": ["GDPR"]}},
        }
    }
    return jsonify(spec)


# ── Weekly / bi-weekly Apple-inspired status summary emails ──────────────────
def _pct_bar(percent, color="#5a8cff"):
    try:
        pct = max(0, min(100, int(percent or 0)))
    except Exception:
        pct = 0
    return f"""<div style="height:10px;background:#e9eef7;border-radius:999px;overflow:hidden;box-shadow:inset 0 1px 2px rgba(31,41,55,.08);"><div style="width:{pct}%;height:10px;background:linear-gradient(90deg,{color},#9b5cff);border-radius:999px;"></div></div>"""


def _email_stat_card(label, value, note="", color="#5a8cff"):
    return f"""<td class="pt-two-col" width="50%" style="padding:6px;vertical-align:top;">
      <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" class="pt-stat" style="background:linear-gradient(180deg,#ffffff,#f7faff);border:1px solid #e7edf8;border-radius:22px;box-shadow:0 14px 30px rgba(31,41,55,.08);">
        <tr><td style="padding:18px 18px 16px;">
          <div style="font-size:12px;color:#7b8496;font-weight:800;letter-spacing:.5px;text-transform:uppercase;">{_email_escape(label)}</div>
          <div style="margin-top:8px;font-size:30px;line-height:34px;font-weight:900;color:#111827;letter-spacing:-.8px;">{_email_escape(value)}</div>
          <div style="margin-top:6px;font-size:12px;line-height:17px;color:{_email_escape(color)};font-weight:800;">{_email_escape(note)}</div>
        </td></tr>
      </table>
    </td>"""


def _build_status_summary_email(user, tasks, role="individual", period_label="Weekly"):
    name = user.get("name") or user.get("email") or "there"
    total = len(tasks)
    done = sum(1 for t in tasks if (t.get("stage") or "").lower() in ("completed", "production", "done"))
    blocked = sum(1 for t in tasks if (t.get("stage") or "").lower() == "blocked")
    avg = round(sum(int(t.get("pct") or 0) for t in tasks) / total) if total else 0
    today = now_ist().strftime("%Y-%m-%d")
    overdue = sum(1 for t in tasks if (t.get("due") or "") and (t.get("due") or "")[:10] < today and (t.get("stage") or "").lower() not in ("completed", "production", "done"))

    task_rows = ""
    for t in tasks[:8]:
        title = _email_escape(t.get("title") or "Untitled task")
        project = _email_escape(t.get("project") or "No project")
        due = _email_escape(t.get("due") or "No deadline")
        stage = _email_escape(t.get("stage") or "Backlog")
        pct = int(t.get("pct") or 0)
        task_rows += f"""<tr><td style="padding:14px 0;border-bottom:1px solid #edf2fb;">
          <table role="presentation" width="100%"><tr>
            <td style="padding-right:12px;">
              <div style="font-size:15px;font-weight:900;color:#111827;line-height:20px;">{title}</div>
              <div style="font-size:12px;color:#7b8496;line-height:18px;">{project} · {stage} · Due {due}</div>
              <div style="margin-top:9px;">{_pct_bar(pct)}</div>
            </td>
            <td width="46" align="right" style="font-size:14px;font-weight:900;color:#5a8cff;vertical-align:top;">{pct}%</td>
          </tr></table>
        </td></tr>"""
    if not task_rows:
        task_rows = '<tr><td style="padding:18px;color:#7b8496;background:#f8fbff;border-radius:18px;">No active tasks for this period.</td></tr>'

    manager_extra = ""
    if role.lower() in ("admin", "manager"):
        manager_extra = f"""
        <h2 style="margin:30px 0 12px;font-size:20px;line-height:26px;color:#111827;letter-spacing:-.3px;">Manager overview</h2>
        <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0"><tr>
          {_email_stat_card("Team KPIs", f"{avg}%", "average completion")}
          {_email_stat_card("Blockers", blocked, "needs attention", "#ff3b30")}
        </tr></table>"""

    lead_extra = ""
    if role.lower() in ("admin", "manager", "teamlead", "team lead"):
        risk = "High" if blocked or overdue else "Low"
        lead_extra = f"""
        <h2 style="margin:30px 0 12px;font-size:20px;line-height:26px;color:#111827;letter-spacing:-.3px;">Team lead view</h2>
        <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="background:linear-gradient(180deg,#ffffff,#f8fbff);border:1px solid #e7edf8;border-radius:24px;box-shadow:0 14px 30px rgba(31,41,55,.08);">
          <tr><td style="padding:18px;">
            <div style="font-size:13px;font-weight:900;color:#111827;margin-bottom:8px;">Milestones & burndown</div>
            {_pct_bar(avg, "#34c759")}
            <div style="margin-top:10px;font-size:12px;color:#7b8496;">Risk level: <strong style="color:#ff9500;">{risk}</strong> · Overdue: {overdue} · Completed: {done}/{total}</div>
          </td></tr>
        </table>"""

    body = f"""
      <h1 class="pt-title" style="margin:0 0 8px;font-size:32px;line-height:38px;color:#111827;letter-spacing:-1px;">{_email_escape(period_label)} status summary</h1>
      <p style="margin:0 0 24px;font-size:15px;line-height:23px;color:#5d6678;">Hi <strong style="color:#111827;">{_email_escape(name)}</strong>, here is your personalized project/task snapshot with progress, deadlines, blockers and next actions.</p>
      <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0"><tr>
        {_email_stat_card("Tasks", total, "active items")}
        {_email_stat_card("Progress", f"{avg}%", "overall completion")}
      </tr><tr>
        {_email_stat_card("Completed", done, "shipped")}
        {_email_stat_card("Overdue", overdue, "deadline risk", "#ff3b30")}
      </tr></table>
      <h2 style="margin:30px 0 8px;font-size:20px;line-height:26px;color:#111827;letter-spacing:-.3px;">Individual tasks</h2>
      <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="background:#ffffff;border:1px solid #e7edf8;border-radius:24px;padding:4px 18px;box-shadow:0 14px 30px rgba(31,41,55,.08);">{task_rows}</table>
      {manager_extra}
      {lead_extra}
    """
    return _email_base(_header_strip("#5a8cff", "📊", "Status Summary"), body, APP_URL, "View Dashboard", "#5a8cff")


def send_status_summary_digest(user_id, frequency="weekly"):
    """Send one personalized weekly/bi-weekly status summary email. Call from cron/job runner."""
    with get_db() as db:
        user = db.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
        if not user:
            return False
        rows = db.execute("""
            SELECT * FROM tasks
            WHERE workspace_id=? AND (assignee=? OR assignee=? OR assignee='')
            ORDER BY due IS NULL, due ASC, created DESC
            LIMIT 50
        """, (user["workspace_id"], user["id"], user["name"])).fetchall()
    html = _build_status_summary_email(dict(user), [dict(r) for r in rows], user.get("role", "individual"), "Bi-weekly" if frequency == "bi-weekly" else "Weekly")
    subject = f"📊 {('Bi-weekly' if frequency == 'bi-weekly' else 'Weekly')} Project Tracker status summary"
    return send_email(user["email"], subject, html, user["workspace_id"])

@app.route("/api/email/status-summary", methods=["POST"])
@login_required
def api_send_status_summary_digest():
    """Manual trigger for testing weekly/bi-weekly dynamic email summaries."""
    data = request.get_json(silent=True) or {}
    user_id = data.get("user_id") or session.get("user_id")
    frequency = data.get("frequency", "weekly")
    if frequency not in ("weekly", "bi-weekly"):
        frequency = "weekly"
    ok = send_status_summary_digest(user_id, frequency)
    return jsonify({"ok": bool(ok)})

# ═══════════════════════════════════════════════════════════════════════════════
# DB MIGRATIONS FOR NEW TABLES
# ═══════════════════════════════════════════════════════════════════════════════
def _run_v5_migrations():
    new_ddls = [
        "ALTER TABLE workspaces ADD COLUMN slack_webhook_url TEXT DEFAULT ''",
        "ALTER TABLE workspaces ADD COLUMN github_client_id TEXT DEFAULT ''",
        "ALTER TABLE workspaces ADD COLUMN github_client_secret TEXT DEFAULT ''",
        "ALTER TABLE workspaces ADD COLUMN github_org TEXT DEFAULT ''",
        """CREATE TABLE IF NOT EXISTS incidents (
            id TEXT PRIMARY KEY, workspace_id TEXT, title TEXT,
            severity TEXT DEFAULT 'medium', status TEXT DEFAULT 'open',
            description TEXT DEFAULT '', affected_systems TEXT DEFAULT '[]',
            timeline TEXT DEFAULT '[]', assignee TEXT DEFAULT '',
            reporter TEXT, created TEXT, updated TEXT,
            resolved_at TEXT DEFAULT '', rca TEXT DEFAULT '', postmortem TEXT DEFAULT '')""",
        """CREATE TABLE IF NOT EXISTS approvals (
            id TEXT PRIMARY KEY, workspace_id TEXT, entity_type TEXT,
            entity_id TEXT, title TEXT, description TEXT DEFAULT '',
            status TEXT DEFAULT 'pending', requested_by TEXT,
            approvers TEXT DEFAULT '[]', approved_by TEXT DEFAULT '[]',
            rejected_by TEXT DEFAULT '', rejection_reason TEXT DEFAULT '',
            created TEXT, updated TEXT, expires_at TEXT DEFAULT '')""",
        """CREATE TABLE IF NOT EXISTS recurring_tasks (
            id TEXT PRIMARY KEY, workspace_id TEXT, title TEXT,
            description TEXT DEFAULT '', project TEXT DEFAULT '',
            assignee TEXT DEFAULT '', priority TEXT DEFAULT 'medium',
            stage TEXT DEFAULT 'backlog', frequency TEXT DEFAULT 'weekly',
            day_of_week INTEGER DEFAULT 1, day_of_month INTEGER DEFAULT 1,
            next_run TEXT, last_run TEXT DEFAULT '', enabled INTEGER DEFAULT 1,
            created_by TEXT, created TEXT)""",
        """CREATE TABLE IF NOT EXISTS github_repos (
            id TEXT PRIMARY KEY, workspace_id TEXT, repo_full_name TEXT,
            repo_url TEXT, github_token TEXT DEFAULT '',
            connected_by TEXT, created TEXT)""",
        """CREATE TABLE IF NOT EXISTS github_events (
            id TEXT PRIMARY KEY, workspace_id TEXT, repo_id TEXT,
            event_type TEXT, payload TEXT DEFAULT '{}',
            task_id TEXT DEFAULT '', created TEXT)""",
        """CREATE TABLE IF NOT EXISTS feature_flags (
            id TEXT PRIMARY KEY, workspace_id TEXT, flag_name TEXT,
            enabled INTEGER DEFAULT 0, config TEXT DEFAULT '{}', updated TEXT)""",
        """CREATE TABLE IF NOT EXISTS release_calendar (
            id TEXT PRIMARY KEY, workspace_id TEXT, title TEXT,
            release_date TEXT, project TEXT DEFAULT '',
            status TEXT DEFAULT 'planned', environment TEXT DEFAULT 'production',
            notes TEXT DEFAULT '', created_by TEXT, created TEXT)""",
        """CREATE TABLE IF NOT EXISTS on_call_schedules (
            id TEXT PRIMARY KEY, workspace_id TEXT, name TEXT,
            members TEXT DEFAULT '[]', current_oncall TEXT DEFAULT '',
            rotation_days INTEGER DEFAULT 7, started_at TEXT, created TEXT)""",
        "CREATE INDEX IF NOT EXISTS idx_incidents_ws ON incidents(workspace_id,status)",
        "CREATE INDEX IF NOT EXISTS idx_approvals_ws ON approvals(workspace_id,status)",
        "CREATE INDEX IF NOT EXISTS idx_recurring_ws ON recurring_tasks(workspace_id,next_run)",
        "CREATE INDEX IF NOT EXISTS idx_github_repos ON github_repos(workspace_id)",
    ]
    for ddl in new_ddls:
        _run_ddl(ddl)

try:
    _run_v5_migrations()
    _close_ddl_conn()   # release shared DDL conn after v5 migrations
except Exception as _v5e:
    log.warning("[v5_migrations] %s", _v5e)


if __name__=="__main__":
    print("\n⚡ Project Tracker v5.0 — Enterprise Edition — Multi-Tenant | AI | Workspaces")
    print("="*54)
    print("  Initializing database...")
    init_db()
    print("  Ensuring timelog schema...")
    ensure_timelog_schema()
    print("  Checking JS libraries...")
    if not download_js():
        print("  ⚠ Some libraries failed. Check your internet connection.")
    port=find_free_port(5000)
    print(f"\n  ✓ Running at  http://localhost:{port}")
    print(f"  ✓ Database:   {DATABASE_URL[:40]}...")
    print(f"  ✓ Uploads:    {UPLOAD_DIR}")
    print(f"\n  Demo: alice@dev.io / pass123 (Admin)")
    print(f"  New company? Click 'Create Account' → 'New Workspace'")
    print(f"  Invite others? Share your code from Settings ⚙\n")
    threading.Thread(target=open_browser,args=(port,),daemon=True).start()
    app.run(host="0.0.0.0",port=port,debug=False,use_reloader=False)
