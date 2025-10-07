import logging
from logging.handlers import RotatingFileHandler
from flask import (
    Flask, request, make_response, jsonify,
    redirect, url_for, render_template_string, abort
)
from datetime import datetime
from markupsafe import escape
import secrets
import time
import re

# ===============================================================
# KONFIGURASI LOGGING
# ===============================================================
log_formatter = logging.Formatter("[%(asctime)s] [%(levelname)s] %(message)s")

file_handler = RotatingFileHandler(
    "app.log", maxBytes=1 * 1024 * 1024, backupCount=5, encoding="utf-8"
)
file_handler.setFormatter(log_formatter)
file_handler.setLevel(logging.DEBUG)

security_handler = RotatingFileHandler(
    "security.log", maxBytes=512 * 1024, backupCount=3, encoding="utf-8"
)
security_handler.setFormatter(log_formatter)
security_handler.setLevel(logging.INFO)

console_handler = logging.StreamHandler()
console_handler.setFormatter(log_formatter)
console_handler.setLevel(logging.DEBUG)

log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)
log.addHandler(file_handler)
log.addHandler(console_handler)
log.addHandler(security_handler)

# ===============================================================
# INISIALISASI FLASK APP
# ===============================================================
app = Flask(__name__)
app.secret_key = secrets.token_hex(16)

# ===============================================================
# SIMULASI DATA DAN KONFIGURASI
# ===============================================================
USER_DATA = {"sample": "sample123", "admin": "admin123"}
ACTIVE_TOKENS = {}
CSRF_TOKENS = {}
TEMP_CSRF = {}
LOGIN_ATTEMPTS = {}

LOGIN_LIMIT = 5
LOGIN_WINDOW = 300  # 5 menit
COOKIE_AGE = 120  # 2 menit

# ===============================================================
# TEMPLATE HTML
# ===============================================================
LOGIN_PAGE = """
<!DOCTYPE html>
<html>
<head><title>Login</title></head>
<body style="font-family: Arial; margin: 50px;">
    <h2>Login Form</h2>
    <form method="POST" action="{{ url_for('login') }}">
        <input type="hidden" name="csrf_login_token" value="{{ csrf_login_value }}">
        <label>Username:</label><br>
        <input type="text" name="username" required maxlength="64"><br><br>
        <label>Password:</label><br>
        <input type="password" name="password" required maxlength="128"><br><br>
        <button type="submit">Login</button>
    </form>
    {% if error %}
        <p style="color:red;">{{ error }}</p>
    {% endif %}
</body>
</html>
"""

DASHBOARD_PAGE = """
<!DOCTYPE html>
<html>
<head><title>Dashboard</title></head>
<body style="font-family: Arial; margin: 50px;">
    <h2>Halo, {{ username }} 👋</h2>
    <p>Selamat datang di dashboard!</p>
    <form method="POST" action="{{ url_for('logout') }}">
        <input type="hidden" name="csrf_logout_token" value="{{ csrf_logout_value }}">
        <button type="submit">Logout</button>
    </form>
    <hr>
    <small>Anda login sejak: {{ created_at }}</small>
</body>
</html>
"""

# ===============================================================
# HELPER FUNCTIONS
# ===============================================================
def is_production():
    return not app.debug

def set_cookie(resp, key, value, **kwargs):
    kwargs.setdefault("secure", is_production())
    kwargs.setdefault("httponly", True)
    kwargs.setdefault("samesite", "Strict")
    kwargs.setdefault("max_age", COOKIE_AGE)
    resp.set_cookie(key, value, **kwargs)
    log.debug(f"Set cookie: {key}={value[:8]}..., max_age={kwargs['max_age']}\n")

def generate_csrf_token():
    token = secrets.token_hex(16)
    log.debug(f"Generate CSRF token: {token}\n")
    return token

def cleanup_temp_csrf():
    now = time.time()
    expired = [k for k, (_, exp) in TEMP_CSRF.items() if exp <= now]
    for k in expired:
        TEMP_CSRF.pop(k, None)
        log.debug(f"Cleanup TEMP_CSRF expired: {k}\n")

def check_login_rate_limit(ip: str) -> bool:
    now = time.time()
    rec = LOGIN_ATTEMPTS.get(ip)
    if not rec:
        LOGIN_ATTEMPTS[ip] = [1, now]
        log.debug(f"Percobaan login pertama dari {ip}\n")
        return True
    count, first_ts = rec
    if now - first_ts > LOGIN_WINDOW:
        LOGIN_ATTEMPTS[ip] = [1, now]
        log.debug(f"Reset percobaan login untuk IP {ip}\n")
        return True
    if count >= LOGIN_LIMIT:
        log.warning(f"Rate limit tercapai untuk IP {ip}\n")
        return False
    LOGIN_ATTEMPTS[ip][0] += 1
    log.debug(f"Percobaan login ke-{LOGIN_ATTEMPTS[ip][0]} dari IP {ip}\n")
    return True

def detect_xss(payload: str):
    """Deteksi sederhana untuk payload XSS."""
    if not payload:
        return False
    patterns = [
        r"<script.*?>", r"onerror=", r"onload=", r"javascript:", r"<img", r"<iframe"
    ]
    for p in patterns:
        if re.search(p, payload, re.IGNORECASE):
            log.warning(f"Deteksi potensi XSS: '{payload}' dari IP {request.remote_addr}\n")
            return True
    return False

# ===============================================================
# SECURITY HEADERS
# ===============================================================
@app.after_request
def add_headers(resp):
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    resp.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self'; "
        "style-src 'self' 'unsafe-inline'; form-action 'self'; "
        "base-uri 'none'; frame-ancestors 'none';"
    )
    return resp

# ===============================================================
# ROUTES APLIKASI
# ===============================================================
@app.route("/")
def home():
    token = request.cookies.get("session_token")
    log.debug(f"Akses / token={token}\n")
    if token and token in ACTIVE_TOKENS:
        log.debug(f"Token valid. Redirect ke dashboard user={ACTIVE_TOKENS[token]['username']}\n")
        return redirect(url_for("dashboard"))
    return redirect(url_for("login_form"))

@app.route("/login", methods=["GET"])
def login_form():
    cleanup_temp_csrf()
    csrf_token = generate_csrf_token()
    csrf_id = secrets.token_hex(8)
    TEMP_CSRF[csrf_id] = (csrf_token, time.time() + COOKIE_AGE)
    log.debug(f"Generate TEMP_CSRF id={csrf_id}\n")
    resp = make_response(render_template_string(LOGIN_PAGE, csrf_login_value=csrf_token))
    set_cookie(resp, "csrf_id", csrf_id, httponly=True, samesite="Lax")
    return resp

@app.route("/login", methods=["POST"])
def login():
    ip = request.remote_addr or "unknown"
    log.info(f"Login POST dari {ip}\n")

    if not check_login_rate_limit(ip):
        abort(429, "Terlalu banyak percobaan login. Coba lagi nanti.")

    form_token = request.form.get("csrf_login_token")
    csrf_id = request.cookies.get("csrf_id")
    log.debug(f"Form token={form_token}, csrf_id={csrf_id}\n")

    if not csrf_id or csrf_id not in TEMP_CSRF:
        log.warning(f"Percobaan CSRF dari {ip}: csrf_id tidak valid\n")
        abort(403, "CSRF token tidak valid atau kedaluwarsa")

    server_token, _ = TEMP_CSRF.pop(csrf_id, (None, 0))
    if not secrets.compare_digest(form_token or "", server_token or ""):
        log.warning(f"Percobaan CSRF dari {ip}: token tidak cocok\n")
        abort(403, "CSRF token tidak valid!")

    username = request.form.get("username", "")
    password_raw = request.form.get("password", "")
    if detect_xss(username) or detect_xss(password_raw):
        abort(400, "Input mengandung potensi XSS")

    username = escape(username)
    log.debug(f"Login attempt user={username}\n")

    stored = USER_DATA.get(username)
    if not stored or not secrets.compare_digest(stored, password_raw):
        log.warning(f"Login gagal untuk user={username}\n")
        csrf_token = generate_csrf_token()
        csrf_id = secrets.token_hex(8)
        TEMP_CSRF[csrf_id] = (csrf_token, time.time() + COOKIE_AGE)
        resp = make_response(render_template_string(LOGIN_PAGE, error="Username/password salah!", csrf_login_value=csrf_token))
        set_cookie(resp, "csrf_id", csrf_id, httponly=True, samesite="Lax")
        return resp

    session_token = secrets.token_hex(16)
    ACTIVE_TOKENS[session_token] = {"username": username, "created_at": datetime.utcnow()}
    CSRF_TOKENS[session_token] = generate_csrf_token()
    log.info(f"Login sukses user={username}, session_token={session_token}\n")

    resp = make_response(redirect(url_for("dashboard")))
    set_cookie(resp, "session_token", session_token, httponly=True, samesite="Strict")
    resp.delete_cookie("csrf_id")
    return resp

@app.route("/dashboard")
def dashboard():
    token = request.cookies.get("session_token")
    if not token or token not in ACTIVE_TOKENS:
        log.warning("Token tidak valid, redirect ke login\n")
        return redirect(url_for("login_form"))

    username = ACTIVE_TOKENS[token]["username"]
    created_at = ACTIVE_TOKENS[token]["created_at"].strftime("%Y-%m-%d %H:%M:%S UTC")
    csrf_logout_value = CSRF_TOKENS.get(token) or generate_csrf_token()
    CSRF_TOKENS[token] = csrf_logout_value

    log.debug(f"Render dashboard untuk {username}\n")
    return make_response(render_template_string(
        DASHBOARD_PAGE,
        username=username,
        created_at=created_at,
        csrf_logout_value=csrf_logout_value
    ))

# ===============================================================
# ROUTE LOGOUT
# ===============================================================
@app.route("/logout", methods=["POST"])
def logout():
    token = request.cookies.get("session_token")
    form_token = request.form.get("csrf_logout_token")
    log.info(f"Logout request token={token}\n")

    if not token or token not in CSRF_TOKENS or not secrets.compare_digest(CSRF_TOKENS[token], form_token or ""):
        abort(403, "CSRF logout tidak valid")

    user = ACTIVE_TOKENS.get(token, {}).get("username")
    ACTIVE_TOKENS.pop(token, None)
    CSRF_TOKENS.pop(token, None)
    log.info(f"User {user} logout berhasil\n")

    resp = make_response(redirect(url_for("login_form")))
    resp.delete_cookie("session_token")
    return resp

# ===============================================================
# SIMULASI PENYERANGAN UNTUK TEST KEAMANAN
# ===============================================================
@app.route("/simulate/xss")
def simulate_xss():
    payload = request.args.get("payload", "<script>alert('XSS')</script>")
    log.info(f"[SIMULASI] Uji XSS dengan payload: {payload}\n")

    if detect_xss(payload):
        log.warning(f"Payload XSS diblokir dari IP {request.remote_addr}\n")
        return jsonify({"status": "blocked", "message": "Payload terdeteksi sebagai XSS"}), 400
    
    safe_output = escape(payload)
    return render_template_string(f"<h3>Output aman:</h3><p>{safe_output}</p>")

@app.route("/simulate/csrf", methods=["GET", "POST"])
def simulate_csrf():
    """
    GET: render form uji (auto-submit) agar bisa dites lewat browser tanpa curl.
    POST: proses token CSRF dan log ke security.log.
    Hanya aktif saat debug (GET akan abort di production).
    """
    if request.method == "GET":
        if not app.debug:
            abort(404)
        test_form = """
        <!doctype html>
        <html>
        <head><meta charset="utf-8"><title>Simulasi CSRF (Test)</title></head>
        <body>
          <h3>Simulasi CSRF (auto-submit)</h3>
          <p>Form ini akan mengirim POST dengan field <code>csrf_fake=fake_token_123</code></p>
          <form id="frm" method="POST" action="{{ url_for('simulate_csrf') }}">
            <input type="hidden" name="csrf_fake" value="fake_token_123">
            <noscript><button type="submit">Kirim (JS dimatikan)</button></noscript>
          </form>
          <script>
            setTimeout(function(){ document.getElementById('frm').submit(); }, 200);
          </script>
        </body>
        </html>
        """
        return render_template_string(test_form)

    # POST
    fake_token = request.form.get("csrf_fake", "invalid_token")
    log.info(f"[SIMULASI] Uji CSRF dengan token palsu: {fake_token}\n")

    if fake_token not in CSRF_TOKENS.values():
        log.warning(f"Simulasi CSRF berhasil dideteksi dari IP {request.remote_addr}\n")
        return jsonify({"status": "blocked", "message": "CSRF token invalid"}), 403

    return jsonify({"status": "pass", "message": "Token valid (seharusnya tidak!)"}), 200

@app.route("/debug")
def debug():
    log.debug("Akses /debug\n")
    return jsonify({
        "active_sessions": len(ACTIVE_TOKENS),
        "active_users": [v["username"] for v in ACTIVE_TOKENS.values()],
        "temp_csrf_count": len(TEMP_CSRF)
    })

# ===============================================================
# MAIN ENTRY
# ===============================================================
if __name__ == "__main__":
    log.info("Menjalankan Flask app di http://0.0.0.0:5000\n")
    app.run(debug=True, host="0.0.0.0", port=5000)
