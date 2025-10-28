from flask import Flask, request, render_template_string, session, redirect, url_for
from flask_session import Session
from basic_token.jwt_service import create_jwt, decode_jwt
from basic_token.token_html import GENERATE_TEMPLATE, DECODE_TEMPLATE
from datetime import datetime, timezone, timedelta
import os

app = Flask(__name__)

# =====================================================
# KONFIGURASI FLASK & SERVER-SIDE SESSION
# =====================================================
app.secret_key = "super_secret_flask_session_67890"

# Pastikan folder untuk menyimpan session server-side tersedia
SESSION_DIR = "./sessions_server"
os.makedirs(SESSION_DIR, exist_ok=True)

app.config.update(
    SESSION_TYPE="filesystem",         # Gunakan filesystem untuk menyimpan session di server
    SESSION_FILE_DIR=SESSION_DIR,      # Folder tempat Flask menyimpan file session

    SESSION_PERMANENT=False,           # Session hanya aktif selama browser hidup
    SESSION_USE_SIGNER=True,           # Tambah tanda tangan digital agar session tidak dimanipulasi

    SESSION_COOKIE_HTTPONLY=True,      # Tidak bisa diakses lewat JavaScript
    SESSION_COOKIE_SECURE=False,       # Set True jika HTTPS
    
    SESSION_COOKIE_SAMESITE="Lax"      # Cegah CSRF dasar
)

# Inisialisasi Flask-Session
Session(app)

# =====================================================
# KONFIGURASI BACKEND JWT
# =====================================================
HARDCODED_SECRET = "super_secret_key_12345"
DEFAULT_ROLE = "user"
TOKEN_DURATION_MINUTES = 1  # ubah ke 30 jika ingin durasi lebih lama

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

        # Hitung waktu sekarang & waktu kadaluarsa
        now = datetime.now(timezone.utc)
        exp_time = now + timedelta(minutes=TOKEN_DURATION_MINUTES)
        exp_ts = int(exp_time.timestamp())

        # Buat payload JWT
        payload = {
            "username": username,
            "email": email,
            "password": password,  # ⚠️ hanya untuk belajar
            "role": DEFAULT_ROLE,
            "iat": int(now.timestamp()),
            "nbf": int(now.timestamp()),
            "exp": exp_ts
        }

        try:
            # Buat JWT
            result = create_jwt(payload, secret=HARDCODED_SECRET)

            # Simpan ke session server-side
            session["jwt_token"] = result["token"]
            session["token_expiry"] = exp_ts

            # 🔍 Debug
            print("\n===== TOKEN DIBUAT =====")
            print(f"Token JWT: {result['token']}\n")
            print(f"Header: {result['header']}\n")
            print(f"Payload: {result['payload']}\n")
            print(f"Signature (base64): {result['signature_b64']}")
            print("========================\n")

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
    token_source = None  # untuk mencatat asal token

    # Cek apakah session masih valid
    now_ts = int(datetime.now(timezone.utc).timestamp())
    if session.get("token_expiry") and now_ts > session["token_expiry"]:
        session.clear()
        error = "❌ Session telah kadaluarsa (token expired). Silakan generate ulang."
        return render_template_string(DECODE_TEMPLATE, error=error)

    # Ambil token dari form atau session server
    if request.method == "POST" and request.form.get("token"):
        token = request.form.get("token").strip()
        token_source = "form"
    elif session.get("jwt_token"):
        token = session.get("jwt_token")
        token_source = "server session"

    print("\n===== DEBUG DECODE =====")
    print(f"Token dari form: {request.form.get('token')}\n")
    print(f"Token dari session: {session.get('jwt_token')}\n")
    print("========================\n")

    # Validasi token
    if not token:
        error = "Tidak ada token di session atau form."
    elif not token.count(".") == 2:
        error = (
            "Format token tidak valid. "
            "Pastikan kamu menempelkan JWT yang benar "
            "(harus mengandung 3 bagian: header.payload.signature)."
        )
    else:
        try:
            decoded = decode_jwt(token, secret=HARDCODED_SECRET)
            print("Hasil decode JWT:", decoded)
            print("========================\n")
        except Exception as e:
            error = f"Error parsing token: {str(e)}"

    # Tambahkan info sumber token untuk debug
    if decoded and token_source:
        decoded["token_source"] = token_source

    return render_template_string(DECODE_TEMPLATE, decoded=decoded, error=error)

# =====================================================
# ROUTE: LOGOUT / CLEAR SESSION
# =====================================================
@app.route("/logout")
def logout():
    """Hapus token & session dari server"""
    session.clear()
    return redirect(url_for("generate"))

# =====================================================
# MAIN ENTRY POINT
# =====================================================
if __name__ == "__main__":
    app.run(debug=True)
