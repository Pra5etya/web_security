from flask import Flask, request, render_template_string
from basic_token.jwt_service import create_jwt_detailed, decode_jwt
from basic_token.errors import TokenError
import datetime

app = Flask(__name__)

# ---------------------------
# Hardcoded config (backend)
# ---------------------------
HARDCODED_SECRET = "super_secret_key_12345"   # gunakan ini secara konsisten
DEFAULT_ROLE = "user"
TOKEN_DURATION_MINUTES = 30

# ===============================
# TEMPLATE UNTUK HALAMAN GENERATE (FORM REGISTRASI)
# ===============================
GENERATE_TEMPLATE = """
<!doctype html>
<html lang="id">
<head>
  <meta charset="utf-8">
  <title>Generate JWT - Registrasi User</title>
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
  <h2>🔐 Form Registrasi User</h2>
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
        <strong>Header Base64URL:</strong>
        <pre>{{ result.header_b64 }}</pre>
      </div>

      <div class="section">
        <h3>Payload (decoded)</h3>
        <pre>{{ result.payload | tojson(indent=2) }}</pre>
        <strong>Payload Base64URL:</strong>
        <pre>{{ result.payload_b64 }}</pre>
      </div>

      <div class="section">
        <h3>Signature</h3>
        <pre>{{ result.signature_b64 }}</pre>
      </div>

      <div class="section">
        <h3>JWT Lengkap</h3>
        <pre>{{ result.token }}</pre>
      </div>

      <a href="/decode?token={{ result.token }}">🔍 Decode Token Ini</a>
    {% endif %}
  {% endif %}

  <hr>
  <a href="/decode">Pergi ke halaman Decode</a>
</body>
</html>
"""

# ==============================
# TEMPLATE UNTUK HALAMAN DECODE
# ==============================
DECODE_TEMPLATE = """
<!doctype html>
<html lang="id">
<head>
  <meta charset="utf-8">
  <title>Decode JWT</title>
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
    <label><strong>Masukkan Token:</strong></label><br>
    <textarea name="token">{{ request.args.get('token', '') }}</textarea><br><br>
    <button type="submit">Decode Token</button>
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

# ==============================
# ROUTES
# ==============================
@app.route("/", methods=["GET", "POST"])
def generate():
    result = None
    if request.method == "POST":
        username = request.form.get("username")
        email = request.form.get("email")
        password = request.form.get("password")

        # === Hardcoded Config (used internally only)===
        secret = HARDCODED_SECRET
        role = DEFAULT_ROLE
        token_duration_minutes = TOKEN_DURATION_MINUTES

        # expiry menggunakan timestamp (numeric) agar sesuai spesifikasi
        exp_time = datetime.datetime.utcnow() + datetime.timedelta(minutes=token_duration_minutes)
        exp_ts = int(exp_time.timestamp())

        # PAYLOAD: hanya fields yang berasal dari user input + server-side defaults
        payload = {
            "username": username,
            "email": email,
            # NOTE: Untuk pembelajaran saja; di lingkungan nyata jangan letakkan raw password di JWT.
            "password": password,
            "role": role,
            # exp sebagai integer UNIX timestamp (umumnya dipakai di JWT)
            "exp": exp_ts
        }

        try:
            # gunakan arg name 'secret' sesuai definisi create_jwt_detailed(...)
            result = create_jwt_detailed(payload, secret=secret)
        except Exception as e:
            result = {"error": str(e)}

    return render_template_string(GENERATE_TEMPLATE, result=result)


@app.route("/decode", methods=["GET", "POST"])
def decode():
    decoded = None
    error = None
    if request.method == "POST":
        token = request.form.get("token")
        try:
            # decode menggunakan same hardcoded secret supaya verifikasi signature berhasil
            decoded = decode_jwt(token, secret=HARDCODED_SECRET)
        except TokenError as e:
            error = str(e)
        except Exception as e:
            error = f"Error parsing token: {str(e)}"
    return render_template_string(DECODE_TEMPLATE, decoded=decoded, error=error)


if __name__ == "__main__":
    app.run(debug=True)
