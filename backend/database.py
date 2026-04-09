"""
database.py — SQLite persistence layer
Tables: users, whitelist, scans, password_reset_tokens
"""
import sqlite3, json, os, datetime, hashlib, secrets, bcrypt, re

DB_PATH = os.path.join(os.path.dirname(__file__), "..", "data", "rogue_ap.db")

def _conn():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    return con

def _hash(pw: str) -> str:
    return bcrypt.hashpw(pw.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def _verify(pw: str, hashed: str) -> bool:
    return bcrypt.checkpw(pw.encode('utf-8'), hashed.encode('utf-8'))

def _valid_bssid(bssid: str) -> bool:
    return bool(re.match(r'^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$', bssid.strip()))

def _valid_email(email: str) -> bool:
    pattern = r'^[a-zA-Z0-9._%+-]+@gmail\.com$'
    return bool(re.match(pattern, email.strip()))

def init_db():
    with _conn() as con:
        con.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                username      TEXT NOT NULL UNIQUE,
                email         TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                role          TEXT DEFAULT 'admin',
                created_at    TEXT NOT NULL,
                last_login    TEXT
            );
            CREATE TABLE IF NOT EXISTS whitelist (
                id        INTEGER PRIMARY KEY AUTOINCREMENT,
                bssid     TEXT NOT NULL UNIQUE,
                label     TEXT DEFAULT '',
                ssid      TEXT DEFAULT '',
                added_at  TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS scans (
                id             INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id        TEXT NOT NULL UNIQUE,
                timestamp      TEXT NOT NULL,
                source_files   TEXT NOT NULL,
                rogue_count    INTEGER DEFAULT 0,
                susp_count     INTEGER DEFAULT 0,
                total_frames   INTEGER DEFAULT 0,
                total_findings INTEGER DEFAULT 0,
                result_json    TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS password_reset_tokens (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id     INTEGER NOT NULL,
                token       TEXT NOT NULL UNIQUE,
                created_at  TEXT NOT NULL,
                expires_at  TEXT NOT NULL,
                used        INTEGER DEFAULT 0,
                FOREIGN KEY (user_id) REFERENCES users(id)
            );
            CREATE INDEX IF NOT EXISTS idx_reset_token ON password_reset_tokens(token);
            CREATE TABLE IF NOT EXISTS two_factor_codes (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id     INTEGER NOT NULL,
                code        TEXT NOT NULL,
                created_at  TEXT NOT NULL,
                expires_at  TEXT NOT NULL,
                attempts    INTEGER DEFAULT 0,
                FOREIGN KEY (user_id) REFERENCES users(id)
            );
            CREATE TABLE IF NOT EXISTS account_locks (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id     INTEGER NOT NULL UNIQUE,
                locked_until TEXT NOT NULL,
                attempts    INTEGER DEFAULT 0,
                FOREIGN KEY (user_id) REFERENCES users(id)
            );
        """)
    # Default admin account
    now = datetime.datetime.now().isoformat(timespec="seconds")
    try:
        with _conn() as con:
            con.execute(
                "INSERT INTO users (username,email,password_hash,role,created_at) VALUES (?,?,?,?,?)",
                ("admin", "admin@gmail.com", _hash("Admin@1234"), "admin", now)
            )
    except sqlite3.IntegrityError:
        pass

# ── Auth ──────────────────────────────────────────────────────────────────────
def verify_user(username: str, password: str):
    with _conn() as con:
        row = con.execute(
            "SELECT * FROM users WHERE username=?",
            (username.strip(),)
        ).fetchone()
    if row and _verify(password, row["password_hash"]):
        with _conn() as con:
            con.execute("UPDATE users SET last_login=? WHERE username=?",
                        (datetime.datetime.now().isoformat(timespec="seconds"), username))
        return dict(row)
    return None

def register_user(username: str, email: str, password: str) -> dict:
    if not _valid_email(email):
        return {"ok": False, "error": "Only Gmail addresses (@gmail.com) are allowed"}
    now = datetime.datetime.now().isoformat(timespec="seconds")
    try:
        with _conn() as con:
            con.execute(
                "INSERT INTO users (username,email,password_hash,role,created_at) VALUES (?,?,?,?,?)",
                (username.strip(), email.strip().lower(), _hash(password), "admin", now)
            )
        return {"ok": True}
    except sqlite3.IntegrityError as e:
        msg = "Username already exists" if "username" in str(e) else "Email already registered"
        return {"ok": False, "error": msg}

def user_change_password(username: str, new_password: str) -> bool:
    with _conn() as con:
        cur = con.execute(
            "UPDATE users SET password_hash=? WHERE username=?",
            (_hash(new_password), username)
        )
    return bool(cur.rowcount)

def get_user(username: str) -> dict | None:
    with _conn() as con:
        row = con.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
    return dict(row) if row else None

def get_user_by_id(user_id: int) -> dict | None:
    with _conn() as con:
        row = con.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
    return dict(row) if row else None

def get_all_users():
    """Get all users (for admin management)."""
    with _conn() as con:
        rows = con.execute("SELECT id, username, email, role, created_at, last_login FROM users ORDER BY created_at DESC").fetchall()
    return [dict(r) for r in rows]

def update_user_role(user_id: int, new_role: str) -> bool:
    """Update a user's role (admin only)."""
    valid_roles = {"admin", "analyst", "viewer"}
    if new_role not in valid_roles:
        return False
    with _conn() as con:
        cur = con.execute("UPDATE users SET role=? WHERE id=?", (new_role, user_id))
    return bool(cur.rowcount)

def get_user_by_email(email: str) -> dict | None:
    with _conn() as con:
        row = con.execute("SELECT * FROM users WHERE email=?", (email.strip().lower(),)).fetchone()
    return dict(row) if row else None

def create_reset_token(email: str, token: str, expires_in_hours: int = 1) -> dict:
    """Create a password reset token for the given email."""
    if not _valid_email(email):
        return {"ok": False, "error": "Only Gmail addresses (@gmail.com) are allowed"}
    user = get_user_by_email(email)
    if not user:
        return {"ok": False, "error": "No account found with this email"}
    
    now = datetime.datetime.now()
    expires_at = now + datetime.timedelta(hours=expires_in_hours)
    
    with _conn() as con:
        con.execute("DELETE FROM password_reset_tokens WHERE user_id=?", (user["id"],))
        con.execute(
            "INSERT INTO password_reset_tokens (user_id, token, created_at, expires_at) VALUES (?,?,?,?)",
            (user["id"], token, now.isoformat(), expires_at.isoformat())
        )
    
    return {"ok": True, "username": user["username"], "email": user["email"]}

def verify_reset_token(token: str) -> dict | None:
    """Verify a reset token and return user info if valid."""
    now = datetime.datetime.now().isoformat()
    with _conn() as con:
        row = con.execute(
            """SELECT u.id, u.username, u.email, prt.expires_at, prt.used
               FROM password_reset_tokens prt
               JOIN users u ON u.id = prt.user_id
               WHERE prt.token=? AND prt.used=0 AND prt.expires_at>??""",
            (token, now)
        ).fetchone()
    return dict(row) if row else None

def use_reset_token(token: str, new_password: str) -> dict:
    """Mark token as used and update password."""
    token_info = verify_reset_token(token)
    if not token_info:
        return {"ok": False, "error": "Invalid or expired reset token"}
    
    with _conn() as con:
        con.execute("UPDATE password_reset_tokens SET used=1 WHERE token=?", (token,))
        con.execute("UPDATE users SET password_hash=? WHERE id=?", 
                   (_hash(new_password), token_info["id"]))
    
    return {"ok": True}

# ── Whitelist ─────────────────────────────────────────────────────────────────
def whitelist_add(bssid, label="", ssid=""):
    bssid = bssid.strip().lower()
    if not _valid_bssid(bssid):
        return {"ok": False, "error": "Invalid BSSID format. Use XX:XX:XX:XX:XX:XX"}
    now   = datetime.datetime.now().isoformat(timespec="seconds")
    try:
        with _conn() as con:
            con.execute("INSERT INTO whitelist (bssid,label,ssid,added_at) VALUES (?,?,?,?)",
                        (bssid, label, ssid, now))
        return {"ok": True, "bssid": bssid}
    except sqlite3.IntegrityError:
        return {"ok": False, "error": f"{bssid} is already in the whitelist"}

def whitelist_remove(bssid):
    with _conn() as con:
        cur = con.execute("DELETE FROM whitelist WHERE bssid=?", (bssid.strip().lower(),))
    return {"ok": bool(cur.rowcount)}

def whitelist_all():
    with _conn() as con:
        rows = con.execute("SELECT bssid,label,ssid,added_at FROM whitelist ORDER BY added_at DESC").fetchall()
    return [dict(r) for r in rows]

def whitelist_all_paged(limit=20, offset=0):
    with _conn() as con:
        rows = con.execute(
            "SELECT bssid,label,ssid,added_at FROM whitelist ORDER BY added_at DESC LIMIT ? OFFSET ?",
            (limit, offset)
        ).fetchall()
    return [dict(r) for r in rows]

def whitelist_bssids():
    with _conn() as con:
        rows = con.execute("SELECT bssid FROM whitelist").fetchall()
    return {r["bssid"] for r in rows}

# ── Scans ─────────────────────────────────────────────────────────────────────
def scan_save(scan_id, result):
    s = result.get("stats", {})
    with _conn() as con:
        con.execute(
            """INSERT OR REPLACE INTO scans
               (scan_id,timestamp,source_files,rogue_count,susp_count,
                total_frames,total_findings,result_json)
               VALUES (?,?,?,?,?,?,?,?)""",
            (scan_id,
             result.get("timestamp", datetime.datetime.now().isoformat()),
             ", ".join(result.get("source_files", [])),
             s.get("rogue_count", 0), s.get("suspicious_count", 0),
             s.get("total_frames", 0), s.get("total_findings", 0),
             json.dumps(result))
        )

def scan_list(limit=100):
    with _conn() as con:
        rows = con.execute(
            """SELECT scan_id,timestamp,source_files,rogue_count,susp_count,
                      total_frames,total_findings
               FROM scans ORDER BY timestamp DESC LIMIT ?""", (limit,)
        ).fetchall()
    return [dict(r) for r in rows]

def scan_list_paged(limit=20, offset=0):
    with _conn() as con:
        rows = con.execute(
            """SELECT scan_id,timestamp,source_files,rogue_count,susp_count,
                      total_frames,total_findings
               FROM scans ORDER BY timestamp DESC LIMIT ? OFFSET ?""", (limit, offset)
        ).fetchall()
    return [dict(r) for r in rows]

def scan_get(scan_id):
    with _conn() as con:
        row = con.execute("SELECT result_json FROM scans WHERE scan_id=?", (scan_id,)).fetchone()
    return json.loads(row["result_json"]) if row else None

def scan_delete(scan_id):
    with _conn() as con:
        cur = con.execute("DELETE FROM scans WHERE scan_id=?", (scan_id,))
    return {"ok": bool(cur.rowcount)}

# ── Two-Factor Authentication ────────────────────────────────────────────────
def generate_2fa_code(user_id: int) -> str:
    """Generate a 6-digit 2FA code and store it in the database."""
    code = str(secrets.randbelow(900000) + 100000)
    now = datetime.datetime.now()
    expires_at = now + datetime.timedelta(minutes=10)
    
    with _conn() as con:
        con.execute("DELETE FROM two_factor_codes WHERE user_id=?", (user_id,))
        con.execute(
            "INSERT INTO two_factor_codes (user_id, code, created_at, expires_at) VALUES (?,?,?,?)",
            (user_id, code, now.isoformat(), expires_at.isoformat())
        )
    
    return code

def verify_2fa_code(user_id: int, code: str) -> dict:
    """
    Verify a 2FA code for a user.
    Returns dict with 'valid' boolean and 'error' message if invalid.
    """
    now = datetime.datetime.now().isoformat()
    
    with _conn() as con:
        row = con.execute(
            """SELECT * FROM two_factor_codes WHERE user_id=? AND expires_at>? ORDER BY created_at DESC LIMIT 1""",
            (user_id, now)
        ).fetchone()
    
    if not row:
        return {"valid": False, "error": "Code expired or not found. Please request a new code."}
    
    if row["attempts"] >= 5:
        return {"valid": False, "error": "Too many failed attempts. Please request a new code."}
    
    with _conn() as con:
        con.execute("UPDATE two_factor_codes SET attempts = attempts + 1 WHERE id=?", (row["id"],))
    
    if row["code"] != code:
        remaining = 5 - row["attempts"] - 1
        if remaining > 0:
            return {"valid": False, "error": f"Invalid code. {remaining} attempts remaining."}
        else:
            return {"valid": False, "error": "Invalid code. Too many failed attempts."}
    
    return {"valid": True}

def invalidate_2fa_codes(user_id: int):
    """Remove all 2FA codes for a user after successful verification."""
    with _conn() as con:
        con.execute("DELETE FROM two_factor_codes WHERE user_id=?", (user_id,))

def is_account_locked(user_id: int) -> dict:
    """Check if an account is locked due to too many failed attempts."""
    now = datetime.datetime.now().isoformat()
    
    with _conn() as con:
        row = con.execute(
            "SELECT * FROM account_locks WHERE user_id=? AND locked_until>?",
            (user_id, now)
        ).fetchone()
    
    if row:
        locked_until = datetime.datetime.fromisoformat(row["locked_until"])
        remaining = int((locked_until - datetime.datetime.now()).total_seconds() / 60) + 1
        return {"locked": True, "remaining_minutes": remaining}
    
    return {"locked": False}

def lock_account(user_id: int, minutes: int = 15):
    """Lock an account for a specified duration."""
    locked_until = datetime.datetime.now() + datetime.timedelta(minutes=minutes)
    
    with _conn() as con:
        con.execute(
            "INSERT OR REPLACE INTO account_locks (user_id, locked_until, attempts) VALUES (?,?,?)",
            (user_id, locked_until.isoformat(), 0)
        )

def unlock_account(user_id: int):
    """Unlock an account and clear any failed attempts."""
    with _conn() as con:
        con.execute("DELETE FROM account_locks WHERE user_id=?", (user_id,))
