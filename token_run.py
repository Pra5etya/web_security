# token_run.py
from flask import request, g, render_template_string
from front_secure.tokens import create_app
from front_secure.tokens.middleware import token_required, validate_csrf
from front_secure.tokens.services import handle_login, handle_refresh, handle_logout

# -----------------------------------------------------
# Inisialisasi Flask app dari modular package tokens
# -----------------------------------------------------
app = create_app()

# -----------------------------------------------------
# TEMPLATE HTML DASAR — menggunakan render_template_string
# -----------------------------------------------------
HTML_PAGE = """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Flask Token Demo</title>
  <style>
    body { font-family: Arial, sans-serif; margin: 40px; background: #fafafa; }
    h1 { color: #333; }
    form { margin-bottom: 20px; }
    input { margin: 4px; padding: 6px; }
    button { padding: 6px 10px; margin: 4px; }
    .msg { margin-top: 10px; color: green; }
  </style>
</head>
<body>
  <h1>Flask Secure Token Demo (Server-Side)</h1>

  {% if not user %}
  <form action="/register" method="POST">
    <h3>Register</h3>
    <input name="username" placeholder="Username" required>
    <input name="password" type="password" placeholder="Password" required>
    <button type="submit">Register</button>
  </form>

  <form action="/login" method="POST">
    <h3>Login</h3>
    <input name="username" placeholder="Username" required>
    <input name="password" type="password" placeholder="Password" required>
    <button type="submit">Login</button>
  </form>
  {% endif %}

  {% if user %}
  <h3>Hello, {{ user }}!</h3>
  <form action="/me" method="GET">
    <button type="submit">View Profile</button>
  </form>

  <form action="/refresh" method="POST">
    <button type="submit">Refresh Token</button>
  </form>

  <form action="/logout" method="POST">
    <button type="submit">Logout</button>
  </form>
  {% endif %}

  {% if msg %}
    <div class="msg">{{ msg }}</div>
  {% endif %}
</body>
</html>
"""

# -----------------------------------------------------
# ROUTES
# -----------------------------------------------------

@app.route("/", methods=["GET"])
def index():
    """Halaman utama — menampilkan form register/login atau profil."""
    user = getattr(g, "current_user", None)
    return render_template_string(HTML_PAGE, msg=None, user=user)


@app.route("/register", methods=["POST"])
def register():
    """Registrasi user baru."""
    username = request.form.get("username")
    password = request.form.get("password")

    if not username or not password:
        return render_template_string(HTML_PAGE, msg="Username/password required.", user=None)

    # Simpan user baru ke TokenStore
    success = app.token_store.create_user(username, password)
    msg = "Registration successful!" if success else "Username already exists."
    return render_template_string(HTML_PAGE, msg=msg, user=None)


@app.route("/login", methods=["POST"])
def login():
    """Login user dan set cookies JWT (HttpOnly)."""
    username = request.form.get("username")
    password = request.form.get("password")

    # Verifikasi kredensial user
    if not app.token_store.verify_user(username, password):
        return render_template_string(HTML_PAGE, msg="Invalid credentials.", user=None)

    # Jalankan logika login dari service (buat access & refresh token)
    service_result = handle_login(app, username, password)

    # Pastikan hasilnya adalah Response, bukan tuple
    resp = service_result if not isinstance(service_result, tuple) else service_result[0]

    # Ganti body response dengan HTML hasil render
    html = render_template_string(HTML_PAGE, msg="Login success.", user=username)
    resp.set_data(html)
    resp.mimetype = "text/html"  # ✅ pastikan browser menampilkan HTML, bukan source text
    return resp


@app.route("/me", methods=["GET"])
@token_required
@validate_csrf
def me():
    """Halaman profil user (protected route)."""
    return render_template_string(HTML_PAGE, msg=f"Welcome back, {g.current_user}!", user=g.current_user)


@app.route("/refresh", methods=["POST"])
def refresh():
    """Rotasi refresh token (mitigasi reuse token & XSS exposure)."""
    refresh_cookie = request.cookies.get(app.config["REFRESH_COOKIE"])

    # Jalankan service handler
    service_result = handle_refresh(app, refresh_cookie)

    # Pastikan hasilnya adalah Response, bukan tuple
    resp = service_result if not isinstance(service_result, tuple) else service_result[0]

    # Tampilkan hasil HTML
    html = render_template_string(HTML_PAGE, msg="Token refreshed.", user=g.get("current_user", None))
    resp.set_data(html)
    resp.mimetype = "text/html"  # ✅ ubah Content-Type
    return resp


@app.route("/logout", methods=["POST"])
def logout():
    """Logout user dan hapus cookie token (HttpOnly)."""
    refresh_cookie = request.cookies.get(app.config["REFRESH_COOKIE"])

    # Jalankan service handler logout
    service_result = handle_logout(app, refresh_cookie)

    # Pastikan hasilnya adalah Response, bukan tuple
    resp = service_result if not isinstance(service_result, tuple) else service_result[0]

    # Tampilkan halaman HTML setelah logout
    html = render_template_string(HTML_PAGE, msg="Logged out successfully.", user=None)
    resp.set_data(html)
    resp.mimetype = "text/html"  # ✅ agar HTML dirender
    return resp


# -----------------------------------------------------
# MAIN RUNNER
# -----------------------------------------------------
if __name__ == "__main__":
    # Jalankan server HTTPS self-signed (simulasi HttpOnly cookie)
    app.run(debug=True, ssl_context="adhoc")
