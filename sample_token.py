from flask import Flask, request, render_template_string, session, redirect, url_for
from basic_token.jwt_service import create_jwt_detailed, decode_jwt
from basic_token.errors import TokenError
import datetime

app = Flask(__name__)

# =====================================================
# KONFIGURASI FLASK & SESSION (AMAN)
# =====================================================
app.secret_key = "super_secret_flask_session_67890"

# Cookie aman — tidak bisa dibaca lewat JS atau dikirim cross-site
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,   # tidak bisa diakses via document.cookie
    SESSION_COOKIE_SECURE=False,    # ubah ke True di mode HTTPS
    SESSION_COOKIE_SAMESITE="Lax"   # cegah CSRF dari domain lain
)

# =====================================================
# KONFIGURASI BACKEND JWT
# =====================================================
HARDCODED_SECRET = "super_secret_key_12345"
DEFAULT_ROLE = "user"
TOKEN_DURATION_MINUTES = 1  # ubah ke 30 jika ingin durasi lebih lama

# =====================================================
# TEMPLATE HALAMAN GENERATE (REGISTRASI)
# =====================================================
GENERATE_TEMPLATE = """
<!doctype html>
<html lang="id">
<head>
  <meta charset="utf-8">
  <title>Generate JWT (Session-Safe)</title>
  <style>
    body { font-family: Arial, sans-serif; margin: 40px; background: #fafafa; }
    form { background: #fff; padding: 20px; border-radius: 10px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); max-width: 480px; }
    input { width: 100%; padding: 8px; margin: 8px 0; box-sizing: border-box; }
    label { font-weight: bold; display:block; margin-top: 8px; }
    button { background: #007bff; color: white; border: none; padding: 10px 15px; border-radius: 6px; cursor: pointer; }
    button:hover { background: #0056b3; }
    pre { background: #f5f5f5; padding: 10px; border-radius: 6px; overflow-x: auto; }
    .section { margin-top: 30px; }
    .error { color: red; }
  </style>
</head>
<body>
  <h2>🔐 Registrasi User (Token disimpan di Session)</h2>
  <form method="POST">
    <label>Username:</label>
    <input type="text" name="username" required>

    <label>Email:</label>
    <input type="email" name="email" required>

    <label>Password:</label>
    <input type="password" name="password" required>

    <button type="submit">Generate Token</button>
  </form>

  {% if result %}
    {% if result.error %}
      <p class="error">Error: {{ result.error }}</p>
    {% else %}
      <hr>
      <div class="section">
        <h3>Header (decoded)</h3>
        <pre>{{ result.header | tojson(indent=2) }}</pre>

        <h3>Payload (decoded)</h3>
        <pre>{{ result.payload | tojson(indent=2) }}</pre>

        <h3>Signature</h3>
        <pre>{{ result.signature_b64 }}</pre>
      </div>

      <div class="section">
        <h3>JWT disimpan di session</h3>
        <p>Token tersimpan di sisi server sampai masa berlakunya habis.</p>
        <form action="/decode" method="GET">
          <button type="submit">🔍 Decode Token dari Session</button>
        </form>
      </div>
    {% endif %}
  {% endif %}

  <hr>
  <a href="/decode">Pergi ke halaman Decode Manual</a>
</body>
</html>
"""

# =====================================================
# TEMPLATE HALAMAN DECODE
# =====================================================
DECODE_TEMPLATE = """
<!doctype html>
<html lang="id">
<head>
  <meta charset="utf-8">
  <title>Decode JWT (Session-Aware)</title>
  <style>
    body { font-family: Arial, sans-serif; margin: 40px; background: #fafafa; }
    textarea { width: 100%; height: 100px; }
    pre { background: #f5f5f5; padding: 10px; border-radius: 6px; overflow-x: auto; }
    .error { color: red; }
  </style>
</head>
<body>
  <h2>🔍 Decode JWT Token</h2>

  <form method="POST">
    <label><strong>Masukkan Token (opsional):</strong></label><br>
    <textarea name="token" placeholder="Kosongkan untuk pakai token dari session"></textarea><br><br>
    <button type="submit">Decode</button>
  </form>

  {% if decoded %}
    <hr>
    <h3>Header</h3>
    <pre>{{ decoded.header | tojson(indent=2) }}</pre>

    <h3>Payload</h3>
    <pre>{{ decoded.payload | tojson(indent=2) }}</pre>

    <h3>Signature</h3>
    <pre>{{ decoded.signature }}</pre>
  {% endif %}

  {% if error %}
    <hr>
    <p class="error">Error: {{ error }}</p>
  {% endif %}

  <hr>
  <a href="/">⬅️ Kembali ke halaman Generate</a>
</body>
</html>
"""

# =====================================================
# ROUTE: GENERATE TOKEN
# =====================================================
@app.route("/", methods=["GET", "POST"])
def generate():
    result = None
    if request.method == "POST":
        username = request.form.get("username")
        email = request.form.get("email")
        password = request.form.get("password")

        exp_time = datetime.datetime.utcnow() + datetime.timedelta(minutes=TOKEN_DURATION_MINUTES)
        exp_ts = int(exp_time.timestamp())

        payload = {
            "username": username,
            "email": email,
            "password": password,  # ⚠️ hanya untuk belajar
            "role": DEFAULT_ROLE,
            "exp": exp_ts
        }

        try:
            result = create_jwt_detailed(payload, secret=HARDCODED_SECRET)
            session["jwt_token"] = result["token"]
            session["token_expiry"] = exp_ts
        except Exception as e:
            result = {"error": str(e)}

    return render_template_string(GENERATE_TEMPLATE, result=result)

# =====================================================
# ROUTE: DECODE TOKEN
# =====================================================
@app.route("/decode", methods=["GET", "POST"])
def decode():
    decoded = None
    error = None
    token = None

    # --- Cek apakah session sudah kadaluarsa ---
    now_ts = int(datetime.datetime.utcnow().timestamp())
    if session.get("token_expiry") and now_ts > session["token_expiry"]:
        session.clear()  # hapus session jika token kadaluarsa
        error = "❌ Session telah kadaluarsa (token expired). Silakan generate ulang."
        return render_template_string(DECODE_TEMPLATE, error=error)

    # --- Ambil token dari form atau session ---
    if request.method == "POST":
        token = request.form.get("token") or session.get("jwt_token")
    else:
        token = session.get("jwt_token")

    if token:
        try:
            decoded = decode_jwt(token, secret=HARDCODED_SECRET)
        except TokenError as e:
            error = str(e)
        except Exception as e:
            error = f"Error parsing token: {str(e)}"
    else:
        error = "Tidak ada token di session atau form."

    return render_template_string(DECODE_TEMPLATE, decoded=decoded, error=error)

# =====================================================
# ROUTE: LOGOUT / CLEAR SESSION
# =====================================================
@app.route("/logout")
def logout():
    """Hapus token & session dari server"""
    session.clear()
    return redirect(url_for("generate"))

if __name__ == "__main__":
    app.run(debug=True)
