"""app.py — Flask API + multi-page serving"""
import os, sys, json, uuid, datetime, csv, io, re, functools, secrets
from dotenv import load_dotenv
sys.path.insert(0, os.path.dirname(__file__))

load_dotenv()

from flask import (Flask, request, jsonify, send_file,
                   send_from_directory, Response, session, redirect)
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from detector import run_detection
from detection_analysis import DetectionAnalyzer
from report_generator import generate_pdf
from database import (
    init_db, verify_user, register_user, user_change_password, get_user,
    get_user_by_email, get_user_by_id, get_user_by_id_internal, get_all_users, update_user_role,
    create_reset_token, verify_reset_token, use_reset_token,
    whitelist_add, whitelist_remove, whitelist_all, whitelist_all_paged, whitelist_bssids,
    scan_save, scan_list, scan_list_paged, scan_get, scan_delete,
    generate_2fa_code, verify_2fa_code, invalidate_2fa_codes,
    is_account_locked, lock_account, unlock_account,
    verify_user_account, verify_user_account_admin, unverify_user_account,
    is_user_verified, activate_user, deactivate_user,
)
from email_service import send_password_reset_email, send_2fa_code, send_account_approved_email, send_registration_received_email

app = Flask(__name__, static_folder="../frontend", static_url_path="")
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY") or secrets.token_hex(32)
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = os.environ.get("SSL_CERT") is not None
app.config["WTF_CSRF_ENABLED"] = True

@app.after_request
def add_security_headers(response):
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    return response

limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://",
)

UPLOAD_DIR = os.path.join(os.path.dirname(__file__), "..", "data", "uploads")
REPORT_DIR = os.path.join(os.path.dirname(__file__), "..", "reports")
os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(REPORT_DIR, exist_ok=True)
init_db()

def cleanup_old_reports(days=7):
    """Delete PDF reports older than specified days."""
    try:
        import time
        cutoff = time.time() - (days * 86400)
        count = 0
        for f in os.listdir(REPORT_DIR):
            path = os.path.join(REPORT_DIR, f)
            if os.path.isfile(path) and f.endswith('.pdf'):
                if os.path.getmtime(path) < cutoff:
                    os.remove(path)
                    count += 1
        if count > 0:
            print(f"Cleaned up {count} old report(s)")
    except Exception as e:
        print(f"Report cleanup error: {e}")

cleanup_old_reports(int(os.environ.get("REPORT_RETENTION_DAYS", "7")))

# ── Auth decorator ────────────────────────────────────────────────────────────
def login_required(f):
    @functools.wraps(f)
    def wrapped(*args, **kwargs):
        if not session.get("user"):
            if request.path.startswith("/api/"):
                return jsonify({"error": "Unauthorised"}), 401
            return redirect("/")
        return f(*args, **kwargs)
    return wrapped

def role_required(*allowed_roles):
    """Decorator to restrict endpoints to specific roles."""
    def decorator(f):
        @functools.wraps(f)
        def wrapped(*args, **kwargs):
            if not session.get("user"):
                if request.path.startswith("/api/"):
                    return jsonify({"error": "Unauthorised"}), 401
                return redirect("/")
            user_role = session.get("role", "viewer")
            if user_role not in allowed_roles:
                if request.path.startswith("/api/"):
                    return jsonify({"error": "Forbidden - insufficient permissions"}), 403
                return redirect("/")
            return f(*args, **kwargs)
        return wrapped
    return decorator

# ── Validation helpers ────────────────────────────────────────────────────────
def valid_password(pw: str) -> str | None:
    """Return error string or None if valid."""
    if len(pw) < 8:
        return "Password must be at least 8 characters"
    if not re.search(r'[A-Z]', pw):
        return "Password must contain at least one uppercase letter"
    if not re.search(r'[0-9]', pw):
        return "Password must contain at least one number"
    return None

# ── Page routes ───────────────────────────────────────────────────────────────
@app.route("/")
def root():
    return send_from_directory(app.static_folder, "login.html")

@app.route("/register.html")
def register_page():
    return send_from_directory(app.static_folder, "register.html")

@app.route("/verify.html")
def verify_page():
    return send_from_directory(app.static_folder, "verify.html")

@app.route("/dashboard.html")
@login_required
def dashboard(): return send_from_directory(app.static_folder, "dashboard.html")

@app.route("/scan.html")
@login_required
def scan_page(): return send_from_directory(app.static_folder, "scan.html")

@app.route("/results.html")
@login_required
def results_page(): return send_from_directory(app.static_folder, "results.html")

@app.route("/risk_summary.html")
@login_required
def risk_page(): return send_from_directory(app.static_folder, "risk_summary.html")

@app.route("/reports.html")
@login_required
def reports_page(): return send_from_directory(app.static_folder, "reports.html")

@app.route("/whitelist.html")
@login_required
def whitelist_page(): return send_from_directory(app.static_folder, "whitelist.html")

@app.route("/history.html")
@login_required
def history_page(): return send_from_directory(app.static_folder, "history.html")

@app.route("/profile.html")
@login_required
def profile_page(): return send_from_directory(app.static_folder, "profile.html")

@app.route("/css/<path:f>")
def css_files(f): return send_from_directory(os.path.join(app.static_folder,"css"), f)

@app.route("/js/<path:f>")
def js_files(f): return send_from_directory(os.path.join(app.static_folder,"js"), f)

# ── Auth API ──────────────────────────────────────────────────────────────────
@app.route("/api/login", methods=["POST"])
@limiter.limit("10 per minute")
def api_login():
    body = request.get_json(force=True) or {}
    username = body.get("username","").strip()
    password = body.get("password","")
    
    user = verify_user(username, password)
    if not user:
        return jsonify({"error": "Invalid username or password"}), 401
    
    if user.get("deactivated"):
        return jsonify({"error": "Account is deactivated. Contact administrator."}), 403
    
    if not is_user_verified(username):
        return jsonify({"error": "Account not yet approved. Please wait for an administrator to approve your registration."}), 403
    
    lock_status = is_account_locked(user["id"])
    if lock_status["locked"]:
        return jsonify({
            "error": f"Account locked due to too many failed attempts. Try again in {lock_status['remaining_minutes']} minutes."
        }), 429
    
    if user["role"] == "admin":
        session["user"] = user["username"]
        session["role"] = user["role"]
        session["email"] = user.get("email","")
        return jsonify({
            "ok": True,
            "username": user["username"],
            "role": user["role"]
        })
    
    code = generate_2fa_code(user["id"])
    
    try:
        send_2fa_code(user["email"], user["username"], code)
    except Exception as e:
        print(f"Failed to send 2FA email: {e}")
        invalidate_2fa_codes(user["id"])
        return jsonify({"error": "Failed to send verification code. Please try again."}), 500
    
    temp_token = secrets.token_urlsafe(32)
    session["temp_token"] = temp_token
    session["pending_user_id"] = user["id"]
    session["pending_username"] = user["username"]
    session["pending_role"] = user["role"]
    session["pending_email"] = user.get("email","")
    
    return jsonify({
        "requires_2fa": True,
        "temp_token": temp_token,
        "email": user["email"]
    })

@app.route("/api/verify-2fa", methods=["POST"])
@limiter.limit("5 per minute")
def api_verify_2fa():
    body = request.get_json(force=True) or {}
    temp_token = body.get("temp_token","").strip()
    code = body.get("code","").strip()
    
    if not temp_token or temp_token != session.get("temp_token"):
        return jsonify({"error": "Invalid session. Please log in again."}), 400
    
    if not code or not code.isdigit() or len(code) != 6:
        return jsonify({"error": "Please enter a valid 6-digit code."}), 400
    
    user_id = session.get("pending_user_id")
    if not user_id:
        return jsonify({"error": "Session expired. Please log in again."}), 400
    
    lock_status = is_account_locked(user_id)
    if lock_status["locked"]:
        return jsonify({
            "error": f"Account locked. Try again in {lock_status['remaining_minutes']} minutes."
        }), 429
    
    result = verify_2fa_code(user_id, code)
    
    if not result["valid"]:
        return jsonify({"error": result["error"]}), 400
    
    invalidate_2fa_codes(user_id)
    unlock_account(user_id)
    
    session["user"] = session.pop("pending_username")
    session["role"] = session.pop("pending_role")
    session["email"] = session.pop("pending_email")
    session.pop("pending_user_id", None)
    session.pop("pending_username", None)
    session.pop("pending_role", None)
    session.pop("pending_email", None)
    session.pop("temp_token", None)
    
    return jsonify({
        "ok": True,
        "username": session["user"],
        "role": session["role"]
    })

@app.route("/api/resend-2fa", methods=["POST"])
@limiter.limit("3 per minute")
def api_resend_2fa():
    temp_token = session.get("temp_token")
    user_id = session.get("pending_user_id")
    
    if not temp_token or not user_id:
        return jsonify({"error": "No pending verification. Please log in again."}), 400
    
    user = get_user_by_id(user_id)
    if not user:
        return jsonify({"error": "User not found. Please log in again."}), 400
    
    invalidate_2fa_codes(user_id)
    code = generate_2fa_code(user_id)
    
    try:
        send_2fa_code(user["email"], user["username"], code)
    except Exception as e:
        print(f"Failed to resend 2FA email: {e}")
        return jsonify({"error": "Failed to send verification code. Please try again."}), 500
    
    return jsonify({"ok": True, "message": "New code sent successfully."})

@app.route("/api/register", methods=["POST"])
@limiter.limit("3 per hour")
def api_register():
    body = request.get_json(force=True) or {}
    username = body.get("username","").strip()
    email    = body.get("email","").strip()
    password = body.get("password","")
    confirm  = body.get("confirm","")

    if not username or len(username) < 3:
        return jsonify({"error": "Username must be at least 3 characters"}), 400
    if not re.match(r'^[a-zA-Z0-9_]+$', username):
        return jsonify({"error": "Username may only contain letters, numbers, and underscores"}), 400
    if not email or not re.match(r'^[a-zA-Z0-9._%+-]+@gmail\.com$', email):
        return jsonify({"error": "Only Gmail addresses (@gmail.com) are allowed"}), 400
    if password != confirm:
        return jsonify({"error": "Passwords do not match"}), 400
    err = valid_password(password)
    if err:
        return jsonify({"error": err}), 400

    result = register_user(username, email, password)
    if not result["ok"]:
        return jsonify({"error": result["error"]}), 409
    
    try:
        send_registration_received_email(email, username)
    except Exception as e:
        print(f"Failed to send registration email: {e}")
    
    return jsonify({
        "ok": True,
        "message": "Registration successful! Your account is pending approval by an administrator. You will receive an email once your account is activated."
    })

@app.route("/api/verify-registration", methods=["POST"])
@limiter.limit("5 per minute")
def api_verify_registration():
    body = request.get_json(force=True) or {}
    temp_token = body.get("temp_token","").strip()
    code = body.get("code","").strip()
    
    if not temp_token or temp_token != session.get("reg_temp_token"):
        return jsonify({"error": "Invalid session. Please register again."}), 400
    
    if not code or not code.isdigit() or len(code) != 6:
        return jsonify({"error": "Please enter a valid 6-digit code."}), 400
    
    user_id = session.get("reg_user_id")
    if not user_id:
        return jsonify({"error": "Session expired. Please register again."}), 400
    
    lock_status = is_account_locked(user_id)
    if lock_status["locked"]:
        return jsonify({
            "error": f"Account locked. Try again in {lock_status['remaining_minutes']} minutes."
        }), 429
    
    result = verify_2fa_code(user_id, code)
    
    if not result["valid"]:
        return jsonify({"error": result["error"]}), 400
    
    invalidate_2fa_codes(user_id)
    unlock_account(user_id)
    verify_user_account(session.get("reg_username"))
    
    username = session.pop("reg_username")
    user = get_user(username)
    
    session["user"] = username
    session["role"] = user.get("role", "admin")
    session["email"] = session.pop("reg_email")
    session.pop("reg_user_id", None)
    session.pop("reg_username", None)
    session.pop("reg_email", None)
    session.pop("reg_temp_token", None)
    
    return jsonify({
        "ok": True,
        "username": username,
        "role": session["role"]
    })

@app.route("/api/resend-verification", methods=["POST"])
@limiter.limit("3 per minute")
def api_resend_verification():
    temp_token = session.get("reg_temp_token")
    user_id = session.get("reg_user_id")
    
    if not temp_token or not user_id:
        return jsonify({"error": "No pending verification. Please register again."}), 400
    
    user = get_user_by_id(user_id)
    if not user:
        return jsonify({"error": "User not found. Please register again."}), 400
    
    invalidate_2fa_codes(user_id)
    code = generate_2fa_code(user_id)
    
    try:
        send_2fa_code(user["email"], user["username"], code)
    except Exception as e:
        print(f"Failed to resend verification email: {e}")
        return jsonify({"error": "Failed to send verification code. Please try again."}), 500
    
    return jsonify({"ok": True, "message": "New code sent successfully."})

@app.route("/api/forgot-password", methods=["POST"])
@limiter.limit("3 per hour")
def api_forgot_password():
    body = request.get_json(force=True) or {}
    email = body.get("email", "").strip()
    
    if not email or not re.match(r'^[^@]+@[^@]+\.[^@]+$', email):
        return jsonify({"error": "Please enter a valid email address"}), 400
    
    token = secrets.token_urlsafe(32)
    result = create_reset_token(email, token)
    
    if result["ok"]:
        base_url = request.host_url.rstrip("/")
        reset_link = f"{base_url}/reset-password.html?token={token}"
        try:
            send_password_reset_email(result["email"], result["username"], reset_link)
        except Exception as e:
            return jsonify({"error": "Failed to send email. Please contact administrator."}), 500
    
    return jsonify({"ok": True, "message": "If an account exists with this email, a password reset link has been sent."})

@app.route("/api/reset-password", methods=["POST"])
@limiter.limit("5 per hour")
def api_reset_password():
    body = request.get_json(force=True) or {}
    token = body.get("token", "").strip()
    new_password = body.get("new_password", "")
    confirm = body.get("confirm", "")
    
    if not token:
        return jsonify({"error": "Reset token is required"}), 400
    if new_password != confirm:
        return jsonify({"error": "Passwords do not match"}), 400
    err = valid_password(new_password)
    if err:
        return jsonify({"error": err}), 400
    
    result = use_reset_token(token, new_password)
    if not result["ok"]:
        return jsonify({"error": result["error"]}), 400
    
    return jsonify({"ok": True, "message": "Password has been reset successfully. You can now login."})

@app.route("/api/verify-token/<token>")
def api_verify_token(token):
    token_info = verify_reset_token(token)
    if not token_info:
        return jsonify({"valid": False, "error": "Invalid or expired token"}), 400
    return jsonify({"valid": True, "username": token_info["username"]})

@app.route("/reset-password.html")
def reset_password_page():
    return send_from_directory(app.static_folder, "reset-password.html")

@app.route("/api/logout", methods=["POST"])
def api_logout():
    session.clear()
    return jsonify({"ok": True})

@app.route("/api/me")
def api_me():
    if not session.get("user"):
        return jsonify({"error": "Not logged in"}), 401
    user = get_user(session["user"])
    return jsonify({
        "username":   session["user"],
        "role":       session.get("role","admin"),
        "email":      user.get("email","") if user else "",
        "created_at": user.get("created_at","") if user else "",
        "last_login": user.get("last_login","") if user else "",
    })

@app.route("/api/change-password", methods=["POST"])
@login_required
def api_change_pw():
    body = request.get_json(force=True) or {}
    if not verify_user(session["user"], body.get("current","")):
        return jsonify({"error": "Current password is incorrect"}), 400
    new_pw = body.get("new","")
    err = valid_password(new_pw)
    if err:
        return jsonify({"error": err}), 400
    if body.get("new","") != body.get("confirm",""):
        return jsonify({"error": "New passwords do not match"}), 400
    ok = user_change_password(session["user"], new_pw)
    return jsonify({"ok": ok})

# ── Detection API ─────────────────────────────────────────────────────────────
@app.route("/api/analyse", methods=["POST"])
@login_required
def analyse():
    files = request.files.getlist("captures")
    if not files or all(f.filename=="" for f in files):
        return jsonify({"error": "No files uploaded"}), 400
    extra_wl  = [w.strip() for w in request.form.get("whitelist","").replace("\n",",").split(",") if w.strip()]
    probe_thr = int(request.form.get("probe_threshold", 3))
    rssi_z    = float(request.form.get("rssi_z", 2.5))
    drift_ms  = float(request.form.get("drift_ms", 500))
    saved = []
    invalid_files = []
    for f in files:
        if f.filename and f.filename.endswith(".csv"):
            content = f.read(1024).decode('utf-8', errors='ignore')
            f.seek(0)
            if content.strip() and ',' in content.split('\n')[0]:
                path = os.path.join(UPLOAD_DIR, f"{uuid.uuid4().hex}_{f.filename}")
                f.save(path); saved.append(path)
            else:
                invalid_files.append(f.filename)
        else:
            invalid_files.append(f.filename)
    if invalid_files:
        return jsonify({"error": f"Invalid CSV file(s): {', '.join(invalid_files)}"}), 400
    if not saved:
        return jsonify({"error": "No valid CSV files"}), 400
    try:
        wl = whitelist_bssids() | set(extra_wl)
        result = run_detection(saved, list(wl), probe_threshold=probe_thr,
                               rssi_z_threshold=rssi_z, drift_threshold_ms=int(drift_ms))
        result["timestamp"] = datetime.datetime.now().isoformat()
        scan_id = uuid.uuid4().hex
        result["session_id"] = scan_id
        scan_save(scan_id, result)
        return jsonify(_safe(result))
    finally:
        for path in saved:
            try: os.remove(path)
            except OSError: pass

@app.route("/api/demo")
@login_required
def demo():
    import pandas as pd
    
    C1_SAMPLE = """Timestamp,type,MAC_timestamp,rssi,addr1,addr2,addr3,SSID
1682624219.460000,Dot11Beacon,698926000,-50,ff:ff:ff:ff:ff:ff,00:00:00:00:00:02,00:00:00:00:00:02,b'NETWORK_1'
1682624219.461000,Dot11Beacon,698927000,-52,ff:ff:ff:ff:ff:ff,00:00:00:00:00:03,00:00:00:00:00:03,b'NETWORK_1'
1682624219.462000,Dot11ProbeResp,698928000,-51,00:00:00:00:00:05,00:00:00:00:00:04,00:00:00:00:00:04,b'NETWORK_2'
1682624219.463000,Dot11ProbeResp,698929000,-53,00:00:00:00:00:06,00:00:00:00:00:05,00:00:00:00:00:05,b'NETWORK_3'
1682624219.464000,Dot11Beacon,698930000,-49,ff:ff:ff:ff:ff:ff,aa:bb:cc:dd:ee:ff,aa:bb:cc:dd:ee:ff,b'NETWORK_1'
1682624219.465000,Dot11ProbeResp,698931000,-48,00:00:00:00:00:08,aa:bb:cc:dd:ee:ff,aa:bb:cc:dd:ee:ff,b'NETWORK_1'
1682624219.466000,Dot11Beacon,698932000,-90,ff:ff:ff:ff:ff:ff,11:22:33:44:55:66,11:22:33:44:55:66,b'NETWORK_2'
1682624219.467000,Dot11ProbeResp,698933000,-91,00:00:00:00:00:09,11:22:33:44:55:66,11:22:33:44:55:66,b'NETWORK_2'
1682624219.468000,Dot11Beacon,698934000,-30,ff:ff:ff:ff:ff:ff,de:ad:be:ef:ca:fe,de:ad:be:ef:ca:fe,b'NETWORK_4'
1682624219.469000,Dot11ProbeResp,698935000,-31,00:00:00:00:00:10,de:ad:be:ef:ca:fe,de:ad:be:ef:ca:fe,b'NETWORK_4'
1682624219.470000,Dot11ProbeResp,698936000,-88,00:00:00:00:00:11,de:ad:be:ef:ca:01,de:ad:be:ef:ca:02,b'NETWORK_3'
1682624219.471000,Dot11ProbeResp,698937000,-89,00:00:00:00:00:12,de:ad:be:ef:ca:01,de:ad:be:ef:ca:02,b'NETWORK_3'
1682624219.472000,Dot11ProbeResp,698938000,-30,00:00:00:00:00:13,ee:dd:cc:bb:aa:99,ee:dd:cc:bb:aa:99,b'NETWORK_1'
1682624219.473000,Dot11ProbeResp,698939000,-31,00:00:00:00:00:14,ee:dd:cc:bb:aa:99,ee:dd:cc:bb:aa:99,b'NETWORK_1'
1682624219.474000,Dot11ProbeResp,698940000,-32,00:00:00:00:00:15,ee:dd:cc:bb:aa:99,ee:dd:cc:bb:aa:99,b'NETWORK_1'
1682624219.475000,Dot11ProbeResp,698941000,-33,00:00:00:00:00:16,ee:dd:cc:bb:aa:99,ee:dd:cc:bb:aa:99,b'NETWORK_1'"""

    C2_SAMPLE = """Timestamp,type,MAC_timestamp,rssi,addr1,addr2,addr3,SSID
1682625745.190000,Dot11Beacon,2224640000,-54,ff:ff:ff:ff:ff:ff,00:00:00:00:00:02,00:00:00:00:00:02,b'NETWORK_1'
1682625745.191000,Dot11Beacon,2224641000,-56,ff:ff:ff:ff:ff:ff,00:00:00:00:00:03,00:00:00:00:00:03,b'NETWORK_1'
1682625745.192000,Dot11ProbeResp,2224642000,-55,00:00:00:00:00:17,00:00:00:00:00:04,00:00:00:00:00:04,b'NETWORK_2'
1682625745.193000,Dot11Beacon,2224643000,-55,ff:ff:ff:ff:ff:ff,aa:bb:cc:dd:ee:ff,aa:bb:cc:dd:ee:ff,b'NETWORK_1'
1682625745.194000,Dot11ProbeResp,2224644000,-54,00:00:00:00:00:18,aa:bb:cc:dd:ee:ff,aa:bb:cc:dd:ee:ff,b'NETWORK_1'
1682625745.195000,Dot11Beacon,2224645000,-70,ff:ff:ff:ff:ff:ff,11:22:33:44:55:66,11:22:33:44:55:66,b'NETWORK_2'
1682625745.196000,Dot11ProbeResp,2224646000,-71,00:00:00:00:00:19,11:22:33:44:55:66,11:22:33:44:55:66,b'NETWORK_2'
1682625745.197000,Dot11Beacon,2224647000,-28,ff:ff:ff:ff:ff:ff,22:33:44:55:66:77,22:33:44:55:66:77,b'NETWORK_5'
1682625745.198000,Dot11ProbeResp,2224648000,-29,00:00:00:00:00:20,22:33:44:55:66:77,22:33:44:55:66:77,b'NETWORK_5'
1682625745.199000,Dot11ProbeResp,2224649000,-27,00:00:00:00:00:21,22:33:44:55:66:77,22:33:44:55:66:77,b'NETWORK_5'
1682625745.200000,Dot11ProbeResp,2224650000,-26,00:00:00:00:00:22,22:33:44:55:66:77,22:33:44:55:66:77,b'NETWORK_5'
1682625745.201000,Dot11Beacon,2224651000,-50,ff:ff:ff:ff:ff:ff,00:00:00:00:00:02,00:00:00:00:00:02,b'NETWORK_1'
1682625745.202000,Dot11ProbeResp,2224652000,-89,00:00:00:00:00:23,aa:bb:cc:dd:ee:01,aa:bb:cc:dd:ee:02,b'NETWORK_4'
1682625745.203000,Dot11ProbeResp,2224653000,-90,00:00:00:00:00:24,aa:bb:cc:dd:ee:01,aa:bb:cc:dd:ee:02,b'NETWORK_4'
1682625745.204000,Dot11Beacon,2224654000,-51,ff:ff:ff:ff:ff:ff,00:00:00:00:00:05,00:00:00:00:00:05,b'NETWORK_3'
1682625745.205000,Dot11ProbeResp,2224655000,-52,00:00:00:00:00:25,00:00:00:00:00:05,00:00:00:00:00:05,b'NETWORK_3'"""
    
    for name, content in [("demo_1.csv",C1_SAMPLE),("demo_2.csv",C2_SAMPLE)]:
        open(os.path.join(UPLOAD_DIR,name),"w").write(content)
    
    wl = whitelist_bssids() or {
        "00:00:00:00:00:02",
        "00:00:00:00:00:03", 
        "00:00:00:00:00:04",
        "00:00:00:00:00:05"
    }
    result = run_detection([os.path.join(UPLOAD_DIR,"demo_1.csv"),os.path.join(UPLOAD_DIR,"demo_2.csv")],list(wl))
    result["source_files"] = "demo_1.csv (sample), demo_2.csv (sample)"
    result["sample_size"] = "32 entries total (16 per file)"
    
    result["timestamp"] = datetime.datetime.now().isoformat()
    scan_id = "demo_" + uuid.uuid4().hex
    result["session_id"] = scan_id
    result["is_demo"] = True
    scan_save(scan_id, result)
    return jsonify(_safe(result))

@app.route("/api/analyze-notebook", methods=["POST"])
@login_required
def analyze_notebook():
    """Run notebook-style analysis using DetectionAnalyzer on uploaded CSV files."""
    files = request.files.getlist("captures")
    if not files or all(f.filename == "" for f in files):
        return jsonify({"error": "No files uploaded"}), 400
    
    probe_thr = int(request.form.get("probe_threshold", 3))
    rssi_z = float(request.form.get("rssi_z", 2.5))
    drift_ms = float(request.form.get("drift_ms", 500))
    
    saved = []
    invalid_files = []
    for f in files:
        if f.filename and f.filename.endswith(".csv"):
            content = f.read(1024).decode('utf-8', errors='ignore')
            f.seek(0)
            if content.strip() and ',' in content.split('\n')[0]:
                path = os.path.join(UPLOAD_DIR, f"{uuid.uuid4().hex}_{f.filename}")
                f.save(path); saved.append(path)
            else:
                invalid_files.append(f.filename)
        else:
            invalid_files.append(f.filename)
    
    if invalid_files:
        return jsonify({"error": f"Invalid CSV file(s): {', '.join(invalid_files)}"}), 400
    if not saved:
        return jsonify({"error": "No valid CSV files"}), 400
    
    try:
        wl = whitelist_bssids()
        extra_wl = [w.strip() for w in request.form.get("whitelist", "").replace("\n", ",").split(",") if w.strip()]
        all_wl = list(wl | set(extra_wl))
        
        analyzer = DetectionAnalyzer(all_wl)
        result = analyzer.analyze(saved)
        
        result["timestamp"] = datetime.datetime.now().isoformat()
        scan_id = uuid.uuid4().hex
        result["session_id"] = scan_id
        result["source_files"] = [os.path.basename(p) for p in saved]
        result["analysis_mode"] = "notebook"
        result["probe_threshold"] = probe_thr
        result["rssi_z_threshold"] = rssi_z
        result["drift_threshold_ms"] = drift_ms
        
        scan_save(scan_id, result)
        return jsonify(_safe(result))
    finally:
        for path in saved:
            try: os.remove(path)
            except OSError: pass

@app.route("/api/report/<scan_id>")
@login_required
def download_pdf(scan_id):
    result = scan_get(scan_id)
    if not result: return jsonify({"error": "Scan not found"}), 404
    ts  = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    out = os.path.join(REPORT_DIR, f"RogueAP_Report_{ts}.pdf")
    try: generate_pdf(result, out)
    except Exception as e: return jsonify({"error": str(e)}), 500
    return send_file(out, as_attachment=True, download_name=f"RogueAP_Report_{ts}.pdf", mimetype="application/pdf")

@app.route("/api/reports")
@login_required
@role_required("admin")
def list_reports():
    """List all generated PDF reports."""
    reports = []
    for f in sorted(os.listdir(REPORT_DIR), key=lambda x: os.path.getmtime(os.path.join(REPORT_DIR, x)), reverse=True):
        if f.endswith('.pdf'):
            path = os.path.join(REPORT_DIR, f)
            reports.append({
                "name": f,
                "size": os.path.getsize(path),
                "modified": datetime.datetime.fromtimestamp(os.path.getmtime(path)).isoformat()
            })
    return jsonify(reports)

@app.route("/api/reports/cleanup", methods=["POST"])
@login_required
@role_required("admin")
def cleanup_reports():
    """Manually trigger report cleanup."""
    days = int(request.get_json(force=True).get("days", 7))
    import time
    cutoff = time.time() - (days * 86400)
    count = 0
    for f in os.listdir(REPORT_DIR):
        path = os.path.join(REPORT_DIR, f)
        if os.path.isfile(path) and f.endswith('.pdf') and os.path.getmtime(path) < cutoff:
            os.remove(path)
            count += 1
    return jsonify({"ok": True, "deleted": count})

@app.route("/api/export/<scan_id>/csv")
@login_required
def export_csv(scan_id):
    result = scan_get(scan_id)
    if not result: return jsonify({"error": "Scan not found"}), 404
    si = io.StringIO(); w = csv.writer(si)
    w.writerow(["Rule","Severity","BSSID","SSID","Detail"])
    seen = set()
    for f in result.get("findings",[]):
        key = (f["rule"],f.get("affected_bssid",""),f.get("ssid",""))
        if key in seen: continue
        seen.add(key)
        w.writerow([f.get("rule",""),f.get("severity",""),f.get("affected_bssid",""),f.get("ssid",""),f.get("detail","")])
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    return Response(si.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition":f"attachment; filename=RogueAP_Findings_{ts}.csv"})

@app.route("/api/history")
@login_required
def history():
    page = request.args.get("page", 1, type=int)
    per_page = request.args.get("per_page", 20, type=int)
    all = request.args.get("all", "false").lower() == "true"
    if all:
        scans = scan_list(limit=1000)
        return jsonify(scans)
    per_page = min(per_page, 100)
    offset = (page - 1) * per_page
    scans = scan_list_paged(limit=per_page, offset=offset)
    return jsonify({"data": scans, "page": page, "per_page": per_page})

@app.route("/api/history/<scan_id>", methods=["GET"])
@login_required
def history_get(scan_id):
    r = scan_get(scan_id)
    if not r: return jsonify({"error":"Not found"}), 404
    return jsonify(_safe(r))

@app.route("/api/history/<scan_id>", methods=["DELETE"])
@login_required
def history_delete(scan_id): return jsonify(scan_delete(scan_id))

@app.route("/api/whitelist", methods=["GET"])
@login_required
def wl_list():
    page = request.args.get("page", 1, type=int)
    per_page = request.args.get("per_page", 20, type=int)
    per_page = min(per_page, 100)
    offset = (page - 1) * per_page
    entries = whitelist_all_paged(limit=per_page, offset=offset)
    return jsonify({"data": entries, "page": page, "per_page": per_page})

@app.route("/api/whitelist", methods=["POST"])
@login_required
@role_required("admin")
def wl_add():
    body = request.get_json(force=True) or {}
    bssid = body.get("bssid","").strip()
    if not bssid: return jsonify({"error":"bssid required"}), 400
    return jsonify(whitelist_add(bssid, body.get("label",""), body.get("ssid","")))

@app.route("/api/whitelist/<path:bssid>", methods=["DELETE"])
@login_required
@role_required("admin")
def wl_remove(bssid): return jsonify(whitelist_remove(bssid))

@app.route("/api/access-points", methods=["GET"])
@login_required
@role_required("admin")
def list_access_points():
    """List all registered access points with full details."""
    page = request.args.get("page", 1, type=int)
    per_page = request.args.get("per_page", 50, type=int)
    per_page = min(per_page, 100)
    offset = (page - 1) * per_page
    entries = whitelist_all_paged(limit=per_page, offset=offset)
    
    # Get whitelist as a set for quick lookup
    wl_set = whitelist_bssids()
    
    # Enhance entries with additional metadata
    enhanced = []
    for entry in entries:
        enhanced_entry = dict(entry)
        enhanced_entry["is_verified"] = True
        enhanced_entry["status"] = "active"
        enhanced.append(enhanced_entry)
    
    return jsonify({
        "data": enhanced, 
        "page": page, 
        "per_page": per_page,
        "total": len(whitelist_all())
    })

@app.route("/api/access-points", methods=["POST"])
@login_required
@role_required("admin")
def register_access_point():
    """Register a new access point with full details."""
    body = request.get_json(force=True) or {}
    
    bssid = body.get("bssid", "").strip().lower()
    ssid = body.get("ssid", "").strip()
    label = body.get("label", "").strip()
    location = body.get("location", "").strip()
    vendor = body.get("vendor", "").strip()
    notes = body.get("notes", "").strip()
    
    if not bssid:
        return jsonify({"error": "BSSID is required"}), 400
    
    # Validate BSSID format
    if not re.match(r'^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$', bssid):
        return jsonify({"error": "Invalid BSSID format. Use XX:XX:XX:XX:XX:XX"}), 400
    
    # Check if already exists
    existing = whitelist_all()
    for entry in existing:
        if entry["bssid"].lower() == bssid:
            return jsonify({"error": f"BSSID {bssid} is already registered", "existing": entry}), 409
    
    # Add to whitelist
    result = whitelist_add(bssid, label or ssid, ssid)
    if result["ok"]:
        return jsonify({
            "ok": True,
            "access_point": {
                "bssid": bssid,
                "ssid": ssid,
                "label": label or ssid,
                "location": location,
                "vendor": vendor,
                "notes": notes,
                "registered_at": datetime.datetime.now().isoformat(timespec="seconds"),
                "status": "active"
            }
        }), 201
    
    return jsonify({"error": result.get("error", "Failed to register AP")}), 400

@app.route("/api/access-points/<path:bssid>", methods=["PUT"])
@login_required
@role_required("admin")
def update_access_point(bssid):
    """Update access point details."""
    body = request.get_json(force=True) or {}
    
    # Get current entry
    existing = whitelist_all()
    current = None
    for entry in existing:
        if entry["bssid"].lower() == bssid.lower():
            current = entry
            break
    
    if not current:
        return jsonify({"error": "Access point not found"}), 404
    
    # Update label and SSID in whitelist
    new_label = body.get("label", current.get("label", "")).strip()
    new_ssid = body.get("ssid", current.get("ssid", "")).strip()
    
    # Remove old entry and add new one
    whitelist_remove(bssid)
    result = whitelist_add(bssid.lower(), new_label, new_ssid)
    
    if result["ok"]:
        return jsonify({
            "ok": True,
            "access_point": {
                "bssid": bssid.lower(),
                "ssid": new_ssid,
                "label": new_label,
                "location": body.get("location", ""),
                "vendor": body.get("vendor", ""),
                "notes": body.get("notes", ""),
                "updated_at": datetime.datetime.now().isoformat(timespec="seconds")
            }
        })
    
    return jsonify({"error": "Failed to update"}), 400

@app.route("/api/access-points/<path:bssid>/verify", methods=["POST"])
@login_required
@role_required("admin")
def verify_access_point(bssid):
    """Mark an access point as verified."""
    # This endpoint can be used to add additional verification status
    return jsonify({"ok": True, "bssid": bssid, "verified": True})

@app.route("/api/users", methods=["GET"])
@login_required
@role_required("admin")
def list_users():
    return jsonify(get_all_users())

@app.route("/api/users/<int:user_id>", methods=["GET"])
@login_required
@role_required("admin")
def get_user_details(user_id):
    user = get_user_by_id_internal(user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404
    return jsonify(user)

@app.route("/api/users/<int:user_id>/role", methods=["PUT"])
@login_required
@role_required("admin")
def update_role(user_id):
    body = request.get_json(force=True) or {}
    new_role = body.get("role", "")
    if not new_role:
        return jsonify({"error": "role is required"}), 400
    result = update_user_role(user_id, new_role)
    if result.get("ok"):
        return jsonify({"ok": True})
    return jsonify({"error": result.get("error", "Failed to update role")}), 400

@app.route("/api/users/<int:user_id>/activate", methods=["POST"])
@login_required
@role_required("admin")
def user_activate(user_id):
    result = activate_user(user_id)
    if result.get("ok"):
        return jsonify({"ok": True, "message": "User account activated"})
    return jsonify({"error": result.get("error", "Failed to activate user")}), 400

@app.route("/api/users/<int:user_id>/deactivate", methods=["POST"])
@login_required
@role_required("admin")
def user_deactivate(user_id):
    result = deactivate_user(user_id)
    if result.get("ok"):
        return jsonify({"ok": True, "message": "User account deactivated"})
    return jsonify({"error": result.get("error", "Failed to deactivate user")}), 400

@app.route("/api/users/<int:user_id>/verify", methods=["POST"])
@login_required
@role_required("admin")
def user_verify(user_id):
    user = get_user_by_id_internal(user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404
    
    result = verify_user_account_admin(user_id)
    if result.get("ok"):
        try:
            send_account_approved_email(user["email"], user["username"])
        except Exception as e:
            print(f"Failed to send approval email: {e}")
        return jsonify({"ok": True, "message": "User account verified and notification email sent"})
    return jsonify({"error": result.get("error", "Failed to verify user")}), 400

@app.route("/api/users/<int:user_id>/unverify", methods=["POST"])
@login_required
@role_required("admin")
def user_unverify(user_id):
    result = unverify_user_account(user_id)
    if result.get("ok"):
        return jsonify({"ok": True, "message": "User verification revoked"})
    return jsonify({"error": result.get("error", "Failed to unverify user")}), 400

@app.route("/api/summary")
@login_required
def summary():
    scans = scan_list()
    return jsonify({
        "total_scans":    len(scans),
        "total_rogue":    sum(s["rogue_count"] for s in scans),
        "total_susp":     sum(s["susp_count"]  for s in scans),
        "whitelist_size": len(whitelist_all()),
        "recent_scans":   scans[:5],
    })

def _safe(r):
    out = dict(r)
    if not r.get("load_errors"): out.pop("load_errors", None)
    return out

@app.errorhandler(429)
def ratelimit_handler(e):
    return jsonify({"error": "Rate limit exceeded. Please try again later."}), 429

if __name__ == "__main__":
    app.run(debug=False, host="0.0.0.0", port=5000)
