# Struktur proyek yang lebih modular:
# ├── app/
# │   ├── __init__.py
# │   ├── security/
# │   │   ├── __init__.py
# │   │   ├── cookie_security.py
# │   │   ├── csrf_protection.py
# │   │   ├── session_manager.py
# │   │   └── security_headers.py
# │   └── routes.py
# └── run.py

# ===============================================================
# File: app/security/cookie_security.py
# ===============================================================

from flask import Response

class CookieSecurity:
    def __init__(self, secure: bool = True, httponly: bool = True, samesite: str = "Lax"):
        # Inisialisasi konfigurasi keamanan cookie
        self.secure = secure
        self.httponly = httponly
        self.samesite = samesite

    def set_cookie(self, resp: Response, key: str, value: str, max_age: int | None = None, path: str = "/", domain: str | None = None):
        # Menetapkan cookie dengan atribut keamanan seperti HttpOnly, Secure, dan SameSite
        resp.set_cookie(
            key,
            value,
            max_age=max_age,
            path=path,
            domain=domain,
            secure=self.secure,      # Hanya dikirim melalui HTTPS
            httponly=self.httponly,  # Tidak bisa diakses oleh JavaScript
            samesite=self.samesite,  # Mencegah pengiriman lintas situs
        )

# ===============================================================
# File: app/security/csrf_protection.py
# ===============================================================

from flask import request, session, abort
import secrets

class CSRFProtection:
    def __init__(self, session_key: str = "_csrf_token", cookie_name: str = "csrf_token"):
        # Inisialisasi nama session key dan nama cookie untuk token CSRF
        self.session_key = session_key
        self.cookie_name = cookie_name

    def generate_token(self) -> str:
        # Membuat token acak dan menyimpannya di session
        token = secrets.token_urlsafe(32)
        session[self.session_key] = token
        return token

    def get_token(self) -> str | None:
        # Mengambil token dari session jika ada
        return session.get(self.session_key)

    def validate_request(self):
        # Mengecek token dari header, form, atau JSON body
        token = (
            request.headers.get("X-CSRF-Token")
            or request.form.get("csrf_token")
            or ((request.json or {}).get("csrf_token") if request.is_json else None)
        )
        expected = self.get_token()
        # Jika token tidak ada atau tidak sama, tolak permintaan
        if not token or not expected or not secrets.compare_digest(token, expected):
            abort(403, description="Invalid CSRF token")

    def inject_token(self):
        # Menyediakan token ke template (Jinja context processor)
        token = self.get_token() or self.generate_token()
        return {"csrf_token": token}

# ===============================================================
# File: app/security/session_manager.py
# ===============================================================

import secrets, time

class SessionManager:
    def __init__(self, cookie_name: str = "sid", lifetime: int = 86400):
        # Menentukan nama cookie session dan waktu hidup session
        self.cookie_name = cookie_name
        self.lifetime = lifetime
        self._store: dict[str, dict] = {}  # Penyimpanan sementara session di memori

    def create(self, data: dict | None = None) -> str:
        # Membuat session ID acak baru dan menyimpannya
        sid = secrets.token_urlsafe(32)
        now = int(time.time())
        self._store[sid] = {"data": data or {}, "created": now, "last_seen": now}
        return sid

    def get(self, sid: str | None) -> dict | None:
        # Mengambil data session berdasarkan session ID
        if not sid:
            return None
        s = self._store.get(sid)
        if s:
            s["last_seen"] = int(time.time())  # Update waktu akses terakhir
        return s

    def destroy(self, sid: str | None):
        # Menghapus session dari penyimpanan
        if sid:
            self._store.pop(sid, None)

    def rotate(self, sid: str | None) -> str | None:
        # Mengganti session ID (mitigasi session fixation)
        old = self.get(sid)
        if not old:
            return None
        new_sid = self.create(old["data"].copy())
        self.destroy(sid)
        return new_sid

    def set_cookie(self, resp, sid: str, cookie_security):
        # Menetapkan cookie session menggunakan helper CookieSecurity
        cookie_security.set_cookie(resp, self.cookie_name, sid, max_age=self.lifetime)

# ===============================================================
# File: app/security/security_headers.py
# ===============================================================

class SecurityHeaders:
    def __init__(self, csp: str | None = None):
        # Inisialisasi dengan Content Security Policy (CSP) default
        self.csp = csp or "default-src 'self'; script-src 'self'"

    def apply(self, response):
        # Menambahkan berbagai header keamanan pada setiap response
        response.headers["Content-Security-Policy"] = self.csp
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains; preload"
        response.headers["Referrer-Policy"] = "no-referrer-when-downgrade"
        response.headers["Permissions-Policy"] = "geolocation=()"
        return response

# ===============================================================
# File: app/__init__.py
# ===============================================================

from flask import Flask, g, request
from .security.cookie_security import CookieSecurity
from .security.csrf_protection import CSRFProtection
from .security.session_manager import SessionManager
from .security.security_headers import SecurityHeaders

# Fungsi inisialisasi keamanan modular
def create_security_layers(app: Flask):
    # Membuat instance tiap komponen keamanan
    cookie_sec = CookieSecurity()
    csrf = CSRFProtection()
    sess_mgr = SessionManager()
    headers = SecurityHeaders()

    # Middleware sebelum request: memuat session
    @app.before_request
    def load_session():
        sid = request.cookies.get(sess_mgr.cookie_name)
        g.sid = sid
        g.session = sess_mgr.get(sid)

    # Middleware setelah request: menambahkan security headers
    @app.after_request
    def add_headers(response):
        return headers.apply(response)

    # Menyuntikkan token CSRF ke template
    @app.context_processor
    def inject_csrf():
        return csrf.inject_token()

    return cookie_sec, csrf, sess_mgr, headers

# ===============================================================
# File: app/routes.py
# ===============================================================

from flask import make_response, render_template_string, request, g
import secrets
from . import create_security_layers

def register_routes(app):
    # Inisialisasi layer keamanan untuk app
    cookie_sec, csrf, sess_mgr, _ = create_security_layers(app)

    # Route utama
    @app.route("/")
    def index():
        html = """
        <h2>Modular Security Demo</h2>
        <form method='post' action='/login'><button>Login</button></form>
        <form method='post' action='/transfer'>
          <input type='hidden' name='csrf_token' value='{{ csrf_token }}'>
          <input name='amount' value='100'>
          <button>Transfer</button>
        </form>
        <form method='post' action='/logout'><button>Logout</button></form>
        <p>Session: {{ 'Active' if g.session else 'None' }}</p>
        """
        return render_template_string(html)

    # Route login
    @app.route("/login", methods=["POST"])
    def login():
        user = {"id": 1, "username": "alice"}
        sid = sess_mgr.create({"user": user})
        resp = make_response("logged in")
        sess_mgr.set_cookie(resp, sid, cookie_sec)
        return resp

    # Route transfer (dilindungi CSRF)
    @app.route("/transfer", methods=["POST"])
    def transfer():
        csrf.validate_request()
        amount = request.form.get("amount")
        return f"Transferred {amount}"

    # Route logout
    @app.route("/logout", methods=["POST"])
    def logout():
        sid = g.get("sid")
        sess_mgr.destroy(sid)
        resp = make_response("logged out")
        resp.set_cookie(sess_mgr.cookie_name, "", max_age=0, path="/")
        return resp

# ===============================================================
# File: run.py
# ===============================================================

from app.routes import register_routes
from flask import Flask
import secrets

# Membuat instance Flask
app = Flask(__name__)
app.secret_key = secrets.token_urlsafe(32)  # Digunakan untuk session dan CSRF

# Mendaftarkan semua route ke app
register_routes(app)

if __name__ == '__main__':
    app.run(debug=True)
