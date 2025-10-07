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
import os

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
# SIMULASI DATA
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
# HTML TEMPLATE
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
    <small>Anda login sejak: {{ created_at }}</small><br><br>
    <a href="{{ url_for('security_dashboard') }}">🛡️ Buka Security Dashboard</a>
</body>
</html>
"""

SECURITY_DASHBOARD_PAGE = """
<!DOCTYPE html>
<html>
<head>
    <title>Security Dashboard</title>
    <style>
        body { font-family: monospace; background-color: #f5f5f5; margin: 30px; }
        h2 { color: #333; }
        pre {
            background: #fff;
            border: 1px solid #ccc;
            border-radius: 8px;
            padding: 10px;
            max-height: 75vh;
            overflow-y: auto;
            white-space: pre-wrap;
            word-wrap: break-word;
        }
        .logline:hover { background: #eef6ff; }
    </style>
</head>
<body>
    <h2>🛡️ Security Dashboard</h2>
    <p>Menampilkan 50 baris terakhir dari <code>security.log</code></p>
    <hr>
    <pre>
{% for line in lines %}
<span class="logline">{{ line }}</span>
{% endfor %}
    </pre>
    <hr>
    <small>Update terakhir: {{ timestamp }}</small>
</body>
</html>
"""

# ===============================================================
# HELPER FUNCTIONS
# ===============================================================
def is_local_request():
    return request.remote_addr in ("127.0.0.1", "::1", "localhost")

def set_cookie(resp, key, value, **kwargs):
    kwargs.setdefault("secure", False)
    kwargs.setdefault("httponly", True)
    kwargs.setdefault("samesite", "Strict")
    kwargs.setdefault("max_age", COOKIE_AGE)
    resp.set_cookie(key, value, **kwargs)
    log.debug(f"Set cookie: {key}={value[:8]}..., max_age={kwargs['max_age']}\n")

def generate_csrf_token():
    token = secrets.token_hex(16)
    log.debug(f"Generate CSRF token: {token}\n")
    return token

def detect_xss(payload: str):
    if not payload:
        return False
    patterns = [r"<script.*?>", r"onerror=", r"onload=", r"javascript:", r"<img", r"<iframe"]
    for p in patterns:
        if re.search(p, payload, re.IGNORECASE):
            log.warning(f"Deteksi potensi XSS: '{payload}' dari {request.remote_addr}\n")
            return True
    return False

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
# ROUTES
# ===============================================================
@app.route("/")
def home():
    token = request.cookies.get("session_token")
    log.debug(f"Akses / token={token}\n")
    if token and token in ACTIVE_TOKENS:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login_form"))

@app.route("/login", methods=["GET"])
def login_form():
    cleanup_temp_csrf()
    csrf_token = generate_csrf_token()
    csrf_id = secrets.token_hex(8)
    TEMP_CSRF[csrf_id] = (csrf_token, time.time() + COOKIE_AGE)
    resp = make_response(render_template_string(LOGIN_PAGE, csrf_login_value=csrf_token))
    set_cookie(resp, "csrf_id", csrf_id, httponly=True, samesite="Lax")
    return resp

@app.route("/login", methods=["POST"])
def login():
    ip = request.remote_addr or "unknown"
    log.info(f"Login POST dari {ip}\n")

    if not check_login_rate_limit(ip):
        abort(429, "Terlalu banyak percobaan login.")

    form_token = request.form.get("csrf_login_token")
    csrf_id = request.cookies.get("csrf_id")

    if not csrf_id or csrf_id not in TEMP_CSRF:
        abort(403, "CSRF token tidak valid atau kedaluwarsa")

    server_token, _ = TEMP_CSRF.pop(csrf_id, (None, 0))
    if not secrets.compare_digest(form_token or "", server_token or ""):
        abort(403, "CSRF token tidak valid!")

    username = escape(request.form.get("username", ""))
    password_raw = request.form.get("password", "")

    if detect_xss(username) or detect_xss(password_raw):
        log.warning(f"Potensi XSS pada input login dari {ip}\n")
        abort(400, "Input berbahaya terdeteksi")

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
        return redirect(url_for("login_form"))

    username = ACTIVE_TOKENS[token]["username"]
    created_at = ACTIVE_TOKENS[token]["created_at"].strftime("%Y-%m-%d %H:%M:%S UTC")
    csrf_logout_value = CSRF_TOKENS.get(token) or generate_csrf_token()
    CSRF_TOKENS[token] = csrf_logout_value

    return make_response(render_template_string(
        DASHBOARD_PAGE,
        username=username,
        created_at=created_at,
        csrf_logout_value=csrf_logout_value
    ))

@app.route("/logout", methods=["POST"])
def logout():
    token = request.cookies.get("session_token")
    form_token = request.form.get("csrf_logout_token")
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
# SECURITY DASHBOARD
# ===============================================================
@app.route("/security_dashboard")
def security_dashboard():
    if not is_local_request():
        log.warning(f"Akses ilegal ke /security_dashboard dari {request.remote_addr}\n")
        abort(403, "Hanya bisa diakses dari localhost.")

    log_path = "security.log"
    if not os.path.exists(log_path):
        return render_template_string(SECURITY_DASHBOARD_PAGE, lines=["(Belum ada log keamanan)"], timestamp=datetime.utcnow())

    with open(log_path, "r", encoding="utf-8") as f:
        lines = f.readlines()[-50:]

    escaped_lines = [escape(line.rstrip()) for line in lines]
    return render_template_string(
        SECURITY_DASHBOARD_PAGE,
        lines=escaped_lines,
        timestamp=datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    )

# ===============================================================
# DEBUG INFO
# ===============================================================
@app.route("/debug")
def debug():
    return jsonify({
        "active_sessions": len(ACTIVE_TOKENS),
        "active_users": [v["username"] for v in ACTIVE_TOKENS.values()],
        "temp_csrf_count": len(TEMP_CSRF)
    })

# ===============================================================
# MAIN ENTRY
# ===============================================================
if __name__ == "__main__":
    # log.info("Menjalankan Flask app dengan Security Dashboard di http://127.0.0.1:5000/security_dashboard\n")
    app.run(debug=True, host="0.0.0.0", port=5000)
