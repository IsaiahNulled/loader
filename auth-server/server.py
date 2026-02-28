#!/usr/bin/env python3
"""
Self-hosted authentication server for license key management.
Uses Flask + SQLite. Designed to run on a personal machine 24/7.
"""

import os
import sys
import uuid
import time
import hmac
import json
import hashlib
import secrets
import sqlite3
import logging
from datetime import datetime, timedelta
from functools import wraps

from flask import Flask, request, jsonify, g, abort, render_template, session, redirect, url_for

# ── Configuration ────────────────────────────────────────────────────
ADMIN_API_KEY = os.environ.get("AUTH_ADMIN_KEY", "CHANGE_ME_" + secrets.token_hex(16))
DB_PATH       = os.path.join(os.path.dirname(os.path.abspath(__file__)), "auth.db")
HOST          = "0.0.0.0"
PORT          = int(os.environ.get("AUTH_PORT", 7777))
SESSION_TTL   = 300   # seconds before a session expires without heartbeat
MAX_ATTEMPTS  = 5     # max failed attempts before temporary ban
BAN_DURATION  = 600   # seconds to ban after too many failures
MAX_REQUEST   = 4096  # max request body size in bytes
SIGNATURE_TTL = 30    # seconds before a signed request expires

# ── HMAC Shared Secret ──────────────────────────────────────────────
# This MUST match the secret compiled into the loader (self_auth.h).
# Change this to your own random string and update self_auth.h to match.
HMAC_SECRET   = os.environ.get("AUTH_HMAC_SECRET", "x9K#mP2$vL8nQ4wR7jT0yF5bN3hA6cD1")

app = Flask(__name__)
app.logger.setLevel(logging.INFO)
app.config["MAX_CONTENT_LENGTH"] = MAX_REQUEST
app.secret_key = os.environ.get("FLASK_SECRET_KEY", secrets.token_hex(32))
WEB_ADMIN_PASSWORD = os.environ.get("WEB_ADMIN_PASSWORD", "admin")

# Debug: Show what password we're using
print(f"[DEBUG] WEB_ADMIN_PASSWORD = '{WEB_ADMIN_PASSWORD}'")
print(f"[DEBUG] Length: {len(WEB_ADMIN_PASSWORD)}")

# ── Security Middleware ──────────────────────────────────────────────
@app.before_request
def security_checks():
    # Block oversized requests
    if request.content_length and request.content_length > MAX_REQUEST:
        abort(413)

    # Admin endpoints: protected by X-Admin-Key header (no HMAC needed)
    if request.path.startswith("/api/admin"):
        return

    # Public endpoints require HMAC signature (except /api/status and /admin)
    if request.path == "/api/status" or request.path.startswith("/admin") or request.path.startswith("/login") or request.path == "/logout":
        return

    # Verify HMAC signature on /api/auth and /api/heartbeat
    sig = request.headers.get("X-Signature", "")
    ts  = request.headers.get("X-Timestamp", "")

    if not sig or not ts:
        return jsonify({"success": False, "message": "Bad request."}), 403

    # Anti-replay: reject old timestamps
    try:
        req_time = int(ts)
    except ValueError:
        return jsonify({"success": False, "message": "Bad request."}), 403

    if abs(time.time() - req_time) > SIGNATURE_TTL:
        return jsonify({"success": False, "message": "Request expired."}), 403

    # Verify HMAC: sha256(secret + timestamp + body)
    body = request.get_data(as_text=True) or ""
    expected = hmac.new(
        HMAC_SECRET.encode(),
        (ts + body).encode(),
        hashlib.sha256
    ).hexdigest()

    if not hmac.compare_digest(sig, expected):
        return jsonify({"success": False, "message": "Bad request."}), 403

# Return nothing useful for unknown routes
@app.errorhandler(404)
def not_found(e):
    return "", 404

@app.errorhandler(405)
def method_not_allowed(e):
    return "", 404

@app.errorhandler(413)
def too_large(e):
    return "", 413

# ── Database ─────────────────────────────────────────────────────────
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA journal_mode=WAL")
        g.db.execute("PRAGMA foreign_keys=ON")
    return g.db

@app.teardown_appcontext
def close_db(exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()

def init_db():
    db = sqlite3.connect(DB_PATH)
    db.execute("PRAGMA journal_mode=WAL")
    db.executescript("""
        CREATE TABLE IF NOT EXISTS license_keys (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            key         TEXT    UNIQUE NOT NULL,
            hwid        TEXT    DEFAULT NULL,
            created_at  REAL    NOT NULL,
            expires_at  REAL    NOT NULL,
            max_sessions INTEGER DEFAULT 1,
            enabled     INTEGER DEFAULT 1,
            note        TEXT    DEFAULT '',
            last_login  REAL    DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS sessions (
            id          TEXT    PRIMARY KEY,
            key_id      INTEGER NOT NULL,
            hwid        TEXT    NOT NULL,
            ip          TEXT    NOT NULL,
            created_at  REAL    NOT NULL,
            last_seen   REAL    NOT NULL,
            FOREIGN KEY (key_id) REFERENCES license_keys(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS auth_log (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            key_text    TEXT,
            hwid        TEXT,
            ip          TEXT,
            action      TEXT    NOT NULL,
            success     INTEGER NOT NULL,
            message     TEXT,
            timestamp   REAL    NOT NULL
        );

        CREATE TABLE IF NOT EXISTS rate_limits (
            ip          TEXT    PRIMARY KEY,
            failures    INTEGER DEFAULT 0,
            banned_until REAL   DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS injection_logs (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id  TEXT,
            key_text    TEXT,
            hwid        TEXT,
            ip          TEXT,
            discord_id  TEXT    DEFAULT '',
            windows_email TEXT  DEFAULT '',
            action      TEXT    DEFAULT 'inject',
            timestamp   REAL    NOT NULL
        );

        CREATE TABLE IF NOT EXISTS kill_commands (
            session_id  TEXT    PRIMARY KEY,
            issued_at   REAL    NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_sessions_key ON sessions(key_id);
        CREATE INDEX IF NOT EXISTS idx_sessions_seen ON sessions(last_seen);
        CREATE INDEX IF NOT EXISTS idx_log_time ON auth_log(timestamp);
        CREATE INDEX IF NOT EXISTS idx_inject_time ON injection_logs(timestamp);
    """)
    db.commit()
    db.close()

# ── Helpers ──────────────────────────────────────────────────────────
def log_auth(db, key_text, hwid, ip, action, success, message=""):
    db.execute(
        "INSERT INTO auth_log (key_text, hwid, ip, action, success, message, timestamp) VALUES (?,?,?,?,?,?,?)",
        (key_text, hwid, ip, action, 1 if success else 0, message, time.time())
    )

def cleanup_sessions(db):
    cutoff = time.time() - SESSION_TTL
    db.execute("DELETE FROM sessions WHERE last_seen < ?", (cutoff,))

def check_rate_limit(db, ip):
    row = db.execute("SELECT failures, banned_until FROM rate_limits WHERE ip = ?", (ip,)).fetchone()
    if row and row["banned_until"] > time.time():
        return False, int(row["banned_until"] - time.time())
    return True, 0

def record_failure(db, ip):
    now = time.time()
    row = db.execute("SELECT failures FROM rate_limits WHERE ip = ?", (ip,)).fetchone()
    if row:
        failures = row["failures"] + 1
        banned_until = (now + BAN_DURATION) if failures >= MAX_ATTEMPTS else 0
        db.execute("UPDATE rate_limits SET failures = ?, banned_until = ? WHERE ip = ?",
                   (failures, banned_until, ip))
    else:
        db.execute("INSERT INTO rate_limits (ip, failures, banned_until) VALUES (?, 1, 0)", (ip,))

def clear_failures(db, ip):
    db.execute("DELETE FROM rate_limits WHERE ip = ?", (ip,))

def hash_hwid(hwid):
    return hashlib.sha256(hwid.encode()).hexdigest()

def sign_response(data):
    """Sign response JSON with HMAC so loader can verify authenticity."""
    body = json.dumps(data, separators=(',', ':'), sort_keys=True)
    sig = hmac.new(HMAC_SECRET.encode(), body.encode(), hashlib.sha256).hexdigest()
    data["sig"] = sig
    return data

# ── Auth decorators ──────────────────────────────────────────────────
def require_admin(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        # Accept session-based auth (web login) OR API key header
        if session.get("admin_logged_in"):
            return f(*args, **kwargs)
        key = request.headers.get("X-Admin-Key", "")
        if not secrets.compare_digest(key, ADMIN_API_KEY):
            return jsonify({"success": False, "message": "Unauthorized"}), 401
        return f(*args, **kwargs)
    return decorated

# ── Routes: Authentication ───────────────────────────────────────────
@app.route("/api/auth", methods=["POST"])
def auth_login():
    db = get_db()
    ip = request.remote_addr
    cleanup_sessions(db)

    allowed, wait = check_rate_limit(db, ip)
    if not allowed:
        return jsonify({"success": False, "message": f"Rate limited. Try again in {wait}s."})

    data = request.get_json(silent=True) or {}
    key_text = data.get("key", "").strip()
    hwid_raw = data.get("hwid", "").strip()

    if not key_text or not hwid_raw:
        return jsonify({"success": False, "message": "Missing key or hwid."})

    hwid = hash_hwid(hwid_raw)

    row = db.execute("SELECT * FROM license_keys WHERE key = ?", (key_text,)).fetchone()

    if not row:
        record_failure(db, ip)
        log_auth(db, key_text, hwid, ip, "login", False, "Invalid key")
        db.commit()
        return jsonify({"success": False, "message": "Invalid license key."})

    if not row["enabled"]:
        log_auth(db, key_text, hwid, ip, "login", False, "Key disabled")
        db.commit()
        return jsonify({"success": False, "message": "License key has been disabled."})

    now = time.time()
    if row["expires_at"] < now:
        log_auth(db, key_text, hwid, ip, "login", False, "Key expired")
        db.commit()
        return jsonify({"success": False, "message": "License key has expired."})

    # HWID binding
    if row["hwid"] is None:
        db.execute("UPDATE license_keys SET hwid = ? WHERE id = ?", (hwid, row["id"]))
    elif row["hwid"] != hwid:
        record_failure(db, ip)
        log_auth(db, key_text, hwid, ip, "login", False, "HWID mismatch")
        db.commit()
        return jsonify({"success": False, "message": "License bound to different machine."})

    # Check active sessions
    active = db.execute("SELECT COUNT(*) as cnt FROM sessions WHERE key_id = ?", (row["id"],)).fetchone()["cnt"]
    if active >= row["max_sessions"]:
        log_auth(db, key_text, hwid, ip, "login", False, "Max sessions reached")
        db.commit()
        return jsonify({"success": False, "message": "Maximum active sessions reached."})

    # Create session
    session_id = secrets.token_hex(32)
    db.execute(
        "INSERT INTO sessions (id, key_id, hwid, ip, created_at, last_seen) VALUES (?,?,?,?,?,?)",
        (session_id, row["id"], hwid, ip, now, now)
    )
    db.execute("UPDATE license_keys SET last_login = ? WHERE id = ?", (now, row["id"]))
    clear_failures(db, ip)
    log_auth(db, key_text, hwid, ip, "login", True)
    db.commit()

    return jsonify(sign_response({
        "success": True,
        "message": "Authenticated.",
        "session": session_id,
        "expiry": str(int(row["expires_at"])),
    }))

@app.route("/api/select-build", methods=["POST"])
@require_admin
def select_build():
    """Return download URLs for the selected build type."""
    data = request.get_json(silent=True) or {}
    build_type = data.get("build", "safe")  # safe or full
    
    if build_type not in ["safe", "full"]:
        return jsonify({"success": False, "message": "Invalid build type."})
    
    # GitHub URLs for each build
    base_url = "https://github.com/IsaiahNulled/Needed/raw/refs/heads/main"
    urls = {
        "safe": {
            "user": f"{base_url}/safe/User.exe",
            "loader": f"{base_url}/safe/Loader.exe",
            "driver": f"{base_url}/safe/driver.sys"
        },
        "full": {
            "user": f"{base_url}/full/User.exe", 
            "loader": f"{base_url}/full/Loader.exe",
            "driver": f"{base_url}/full/driver.sys"
        }
    }
    
    return jsonify({
        "success": True,
        "build": build_type,
        "urls": urls[build_type]
    })

@app.route("/api/heartbeat", methods=["POST"])
def heartbeat():
    db = get_db()
    cleanup_sessions(db)

    data = request.get_json(silent=True) or {}
    session_id = data.get("session", "")

    if not session_id:
        return jsonify({"success": False, "message": "Missing session."})

    row = db.execute("SELECT * FROM sessions WHERE id = ?", (session_id,)).fetchone()
    if not row:
        return jsonify({"success": False, "message": "Invalid or expired session."})

    # Verify the key is still valid
    key_row = db.execute("SELECT * FROM license_keys WHERE id = ? AND enabled = 1", (row["key_id"],)).fetchone()
    if not key_row or key_row["expires_at"] < time.time():
        db.execute("DELETE FROM sessions WHERE id = ?", (session_id,))
        db.commit()
        return jsonify({"success": False, "message": "License expired or revoked."})

    # Check if this session has a kill command
    kill_row = db.execute("SELECT * FROM kill_commands WHERE session_id = ?", (session_id,)).fetchone()
    if kill_row:
        db.execute("DELETE FROM kill_commands WHERE session_id = ?", (session_id,))
        db.execute("DELETE FROM sessions WHERE id = ?", (session_id,))
        db.commit()
        return jsonify(sign_response({"success": True, "message": "OK", "action": "kill"}))

    db.execute("UPDATE sessions SET last_seen = ? WHERE id = ?", (time.time(), session_id))
    db.commit()

    return jsonify(sign_response({"success": True, "message": "OK", "expiry": str(int(key_row["expires_at"]))}))

@app.route("/api/status", methods=["GET"])
def server_status():
    return jsonify({"success": True, "message": "Auth server online.", "time": int(time.time())})

# ── Dashboard (localhost only) ──────────────────────────────────────
@app.route("/login", methods=["GET", "POST"])
def login_page():
    if request.method == "POST":
        password = request.form.get("password", "")
        if password == WEB_ADMIN_PASSWORD:
            session["admin_logged_in"] = True
            session.permanent = True
            app.permanent_session_lifetime = timedelta(hours=24)
            return redirect(url_for("admin_dashboard"))
        return render_template("login.html", error="Invalid password")
    if session.get("admin_logged_in"):
        return redirect(url_for("admin_dashboard"))
    return render_template("login.html", error=None)

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login_page"))

@app.route("/admin", methods=["GET"])
@app.route("/admin/", methods=["GET"])
def admin_dashboard():
    if not session.get("admin_logged_in"):
        return redirect(url_for("login_page"))
    return render_template("dashboard.html")

# ── Routes: Admin ────────────────────────────────────────────────────
@app.route("/api/admin/keys", methods=["GET"])
@require_admin
def list_keys():
    db = get_db()
    rows = db.execute("SELECT * FROM license_keys ORDER BY created_at DESC").fetchall()
    keys = []
    for r in rows:
        active = db.execute("SELECT COUNT(*) as cnt FROM sessions WHERE key_id = ?", (r["id"],)).fetchone()["cnt"]
        keys.append({
            "id": r["id"],
            "key": r["key"],
            "hwid_bound": r["hwid"] is not None,
            "created": datetime.fromtimestamp(r["created_at"]).isoformat(),
            "expires": datetime.fromtimestamp(r["expires_at"]).isoformat(),
            "enabled": bool(r["enabled"]),
            "note": r["note"],
            "active_sessions": active,
            "last_login": datetime.fromtimestamp(r["last_login"]).isoformat() if r["last_login"] else None,
        })
    return jsonify({"success": True, "keys": keys})

@app.route("/api/admin/keys", methods=["POST"])
@require_admin
def create_key():
    db = get_db()
    data = request.get_json(silent=True) or {}

    days = data.get("days", 30)
    count = min(data.get("count", 1), 100)
    note = data.get("note", "")
    max_sessions = data.get("max_sessions", 1)
    prefix = data.get("prefix", "EXT")

    now = time.time()
    expires = now + (days * 86400)
    created = []

    for _ in range(count):
        key_text = f"{prefix}-{uuid.uuid4().hex[:8].upper()}-{uuid.uuid4().hex[:8].upper()}"
        db.execute(
            "INSERT INTO license_keys (key, created_at, expires_at, max_sessions, note) VALUES (?,?,?,?,?)",
            (key_text, now, expires, max_sessions, note)
        )
        created.append(key_text)

    db.commit()
    return jsonify({"success": True, "keys": created, "expires_in_days": days})

@app.route("/api/admin/keys/<int:key_id>", methods=["DELETE"])
@require_admin
def revoke_key(key_id):
    db = get_db()
    db.execute("UPDATE license_keys SET enabled = 0 WHERE id = ?", (key_id,))
    db.execute("DELETE FROM sessions WHERE key_id = ?", (key_id,))
    db.commit()
    return jsonify({"success": True, "message": "Key revoked."})

@app.route("/api/admin/keys/<int:key_id>/delete", methods=["DELETE"])
@require_admin
def delete_key(key_id):
    """Permanently delete a key and all associated data."""
    db = get_db()
    # Get key text for cleaning up injection logs
    row = db.execute("SELECT key FROM license_keys WHERE id = ?", (key_id,)).fetchone()
    if not row:
        return jsonify({"success": False, "message": "Key not found."})
    key_text = row["key"]
    # Delete all related data
    sessions = db.execute("SELECT id FROM sessions WHERE key_id = ?", (key_id,)).fetchall()
    for s in sessions:
        db.execute("DELETE FROM kill_commands WHERE session_id = ?", (s["id"],))
    db.execute("DELETE FROM sessions WHERE key_id = ?", (key_id,))
    db.execute("DELETE FROM injection_logs WHERE key_text = ?", (key_text,))
    db.execute("DELETE FROM auth_log WHERE key_text = ?", (key_text,))
    db.execute("DELETE FROM license_keys WHERE id = ?", (key_id,))
    db.commit()
    return jsonify({"success": True, "message": "Key permanently deleted."})

@app.route("/api/admin/keys/<int:key_id>/reset-hwid", methods=["POST"])
@require_admin
def reset_hwid(key_id):
    db = get_db()
    db.execute("UPDATE license_keys SET hwid = NULL WHERE id = ?", (key_id,))
    db.execute("DELETE FROM sessions WHERE key_id = ?", (key_id,))
    db.commit()
    return jsonify({"success": True, "message": "HWID reset."})

@app.route("/api/admin/keys/<int:key_id>/extend", methods=["POST"])
@require_admin
def extend_key(key_id):
    db = get_db()
    data = request.get_json(silent=True) or {}
    days = data.get("days", 30)
    db.execute("UPDATE license_keys SET expires_at = expires_at + ? WHERE id = ?", (days * 86400, key_id))
    db.commit()
    return jsonify({"success": True, "message": f"Extended by {days} days."})

@app.route("/api/inject-log", methods=["POST"])
def log_injection():
    """Loader reports a successful injection with user identity data."""
    db = get_db()
    data = request.get_json(silent=True) or {}
    session_id = data.get("session", "")
    discord_id = data.get("discord_id", "")
    windows_email = data.get("windows_email", "")

    if not session_id:
        return jsonify({"success": False, "message": "Missing session."})

    row = db.execute("""
        SELECT s.*, k.key as license_key
        FROM sessions s
        JOIN license_keys k ON s.key_id = k.id
        WHERE s.id = ?
    """, (session_id,)).fetchone()
    if not row:
        return jsonify({"success": False, "message": "Invalid session."})

    db.execute(
        "INSERT INTO injection_logs (session_id, key_text, hwid, ip, discord_id, windows_email, action, timestamp) VALUES (?,?,?,?,?,?,?,?)",
        (session_id, row["license_key"], row["hwid"], request.remote_addr, discord_id, windows_email, "inject", time.time())
    )
    db.commit()
    return jsonify(sign_response({"success": True, "message": "Logged."}))

@app.route("/api/admin/sessions", methods=["GET"])
@require_admin
def list_sessions():
    db = get_db()
    cleanup_sessions(db)
    db.commit()
    rows = db.execute("""
        SELECT s.*, k.key as license_key, k.note
        FROM sessions s
        JOIN license_keys k ON s.key_id = k.id
        ORDER BY s.last_seen DESC
    """).fetchall()
    sessions = []
    for r in rows:
        # Check if kill is already pending
        kill_pending = db.execute("SELECT 1 FROM kill_commands WHERE session_id = ?", (r["id"],)).fetchone() is not None
        # Get latest injection log for this session (discord_id, email)
        inject = db.execute(
            "SELECT discord_id, windows_email FROM injection_logs WHERE session_id = ? ORDER BY timestamp DESC LIMIT 1",
            (r["id"],)
        ).fetchone()
        sessions.append({
            "session_id": r["id"],
            "session_short": r["id"][:16] + "...",
            "license": r["license_key"],
            "hwid": (r["hwid"] or "")[:16] + "...",
            "ip": r["ip"],
            "discord_id": inject["discord_id"] if inject else "",
            "windows_email": inject["windows_email"] if inject else "",
            "created": datetime.fromtimestamp(r["created_at"]).isoformat(),
            "last_seen": datetime.fromtimestamp(r["last_seen"]).isoformat(),
            "note": r["note"],
            "kill_pending": kill_pending,
        })
    return jsonify({"success": True, "sessions": sessions})

@app.route("/api/admin/sessions/terminate", methods=["POST"])
@require_admin
def terminate_session():
    """Mark a specific session for kill. Next heartbeat triggers self-destruct on client."""
    db = get_db()
    data = request.get_json(silent=True) or {}
    session_id = data.get("session_id", "")
    if not session_id:
        return jsonify({"success": False, "message": "Missing session_id."})

    row = db.execute("SELECT * FROM sessions WHERE id = ?", (session_id,)).fetchone()
    if not row:
        return jsonify({"success": False, "message": "Session not found."})

    # Insert kill command (will be picked up on next heartbeat)
    db.execute("INSERT OR REPLACE INTO kill_commands (session_id, issued_at) VALUES (?, ?)",
               (session_id, time.time()))
    db.commit()
    return jsonify({"success": True, "message": "Kill command issued. Will execute on next heartbeat."})

@app.route("/api/admin/sessions/kill", methods=["POST"])
@require_admin
def kill_sessions():
    """Kill all sessions immediately (no self-destruct, just disconnect)."""
    db = get_db()
    data = request.get_json(silent=True) or {}
    key_id = data.get("key_id")
    if key_id:
        db.execute("DELETE FROM sessions WHERE key_id = ?", (key_id,))
    else:
        db.execute("DELETE FROM sessions")
    db.commit()
    return jsonify({"success": True, "message": "Sessions killed."})

@app.route("/api/admin/injection-logs", methods=["GET"])
@require_admin
def get_injection_logs():
    db = get_db()
    limit = min(int(request.args.get("limit", 50)), 500)
    rows = db.execute("SELECT * FROM injection_logs ORDER BY timestamp DESC LIMIT ?", (limit,)).fetchall()
    logs = [{
        "id": r["id"],
        "key": r["key_text"],
        "hwid": (r["hwid"] or "")[:16] + "...",
        "ip": r["ip"],
        "discord_id": r["discord_id"],
        "windows_email": r["windows_email"],
        "action": r["action"],
        "time": datetime.fromtimestamp(r["timestamp"]).isoformat(),
    } for r in rows]
    return jsonify({"success": True, "logs": logs})

@app.route("/api/admin/logs", methods=["GET"])
@require_admin
def get_logs():
    db = get_db()
    limit = min(int(request.args.get("limit", 50)), 500)
    rows = db.execute("SELECT * FROM auth_log ORDER BY timestamp DESC LIMIT ?", (limit,)).fetchall()
    logs = [{
        "key": r["key_text"],
        "hwid": (r["hwid"] or "")[:12] + "..." if r["hwid"] else "",
        "ip": r["ip"],
        "action": r["action"],
        "success": bool(r["success"]),
        "message": r["message"],
        "time": datetime.fromtimestamp(r["timestamp"]).isoformat(),
    } for r in rows]
    return jsonify({"success": True, "logs": logs})

# ── Main ─────────────────────────────────────────────────────────────
if __name__ == "__main__":
    init_db()

    print(f"\n  +------------------------------------------+")
    print(f"  |         AUTH SERVER — SECURED           |")
    print(f"  +------------------------------------------+\n")

    if ADMIN_API_KEY.startswith("CHANGE_ME_"):
        print(f"  [!] No AUTH_ADMIN_KEY set. Generated temporary key:")
        print(f"      {ADMIN_API_KEY}")
        print(f"      Set AUTH_ADMIN_KEY environment variable for persistence.\n")
    else:
        print(f"  [+] Admin key loaded from environment.")

    print(f"  [+] HMAC signing: ENABLED (shared secret loaded)")
    print(f"  [+] Admin endpoints: LOGIN PROTECTED (accessible from any IP)")
    print(f"  [+] Anti-replay: {SIGNATURE_TTL}s window")
    print(f"  [+] Rate limiting: {MAX_ATTEMPTS} failures = {BAN_DURATION}s ban")
    print(f"  [+] Max request size: {MAX_REQUEST} bytes")
    print(f"  [+] Session TTL: {SESSION_TTL}s without heartbeat\n")

    print(f"  Listening on {HOST}:{PORT}")
    print(f"  Dashboard: http://YOUR_IP:{PORT}/admin (login required)")
    print(f"  Database: {DB_PATH}\n")

    app.run(host=HOST, port=PORT, debug=False)
