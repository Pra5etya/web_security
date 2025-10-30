from flask import Flask, request, render_template_string, session, redirect, url_for
from flask_session import Session
from basic_token.jwt_service import create_jwt, decode_jwt
from basic_token.token_html import GENERATE_TEMPLATE, DECODE_TEMPLATE
from basic_token.token_db import (
    init_db,
    save_tokens,
    update_access_token,
    revoke_user_tokens,
    get_all_tokens,
)
from datetime import datetime, timezone, timedelta
import os
from functools import wraps
import shutil

# =====================================================
# KONFIGURASI APLIKASI
# =====================================================
app = Flask(__name__)
app.secret_key = "super_secret_flask_session_67890"

SESSION_DIR = "./sessions_server"
os.makedirs(SESSION_DIR, exist_ok=True)

app.config.update(
    SESSION_TYPE="filesystem",
    SESSION_FILE_DIR=SESSION_DIR,
    SESSION_PERMANENT=False,
    SESSION_USE_SIGNER=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=False,
    SESSION_COOKIE_SAMESITE="Lax",
)
Session(app)


# =====================================================
# KONFIGURASI TOKEN
# =====================================================
HARDCODED_SECRET = "super_secret_key_12345"
DEFAULT_ROLE = "user"
TOKEN_DURATION_MINUTES = 1
REFRESH_DURATION_MINUTES = 5


# =====================================================
# HELPER: Ambil Bearer Token dari Authorization Header
# =====================================================
def get_bearer_token():
    """Ambil token dari header Authorization (format: Bearer <token>)"""
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        return auth_header.split(" ")[1].strip()
    return None


# =====================================================
# HELPER: Hapus semua session di direktori SESSION_DIR
# =====================================================
def clear_all_sessions():
    """Menghapus seluruh file session di ./sessions_server"""
    try:
        for f in os.listdir(SESSION_DIR):
            file_path = os.path.join(SESSION_DIR, f)
            if os.path.isfile(file_path):
                os.remove(file_path)
        print("🧹 Semua session dihapus dari folder sessions_server")
    except Exception as e:
        print(f"⚠️ Gagal menghapus session files: {e}")


# =====================================================
# DECORATOR: token_required
# =====================================================
def token_required(f):
    """Decorator untuk memeriksa validitas token di setiap endpoint"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        now_ts = int(datetime.now(timezone.utc).timestamp())
        username = session.get("username")
        refresh_token = session.get("refresh_token")
        token_expiry = session.get("token_expiry", 0)
        refresh_expiry = session.get("refresh_expiry", 0)

        # Jika access token dan refresh token keduanya sudah expired
        if now_ts > token_expiry and now_ts > refresh_expiry:
            print("⚠️ Kedua token kadaluarsa → hapus session dan revoke DB")
            if username:
                revoke_user_tokens(username)
            session.clear()
            clear_all_sessions()  # <--- tambahkan di sini
            return redirect(url_for("generate"))

        # Jika access token expired tapi refresh masih valid → redirect ke refresh
        if now_ts > token_expiry and now_ts < refresh_expiry:
            print("♻️ Access token kadaluarsa → redirect ke /refresh")
            return redirect(url_for("refresh"))

        return f(*args, **kwargs)
    return decorated_function


# =====================================================
# ROUTE: GENERATE TOKEN BARU
# =====================================================
@app.route("/", methods=["GET", "POST"])
def generate():
    result = None
    if request.method == "POST":
        username = request.form.get("username")
        email = request.form.get("email")
        password = request.form.get("password")

        now = datetime.now(timezone.utc)
        exp_time = now + timedelta(minutes=TOKEN_DURATION_MINUTES)
        exp_ts = int(exp_time.timestamp())

        # Access Token
        payload = {
            "username": username,
            "email": email,
            "password": password,  # ⚠️ hanya untuk pembelajaran
            "role": DEFAULT_ROLE,
            "iat": int(now.timestamp()),
            "nbf": int(now.timestamp()),
            "exp": exp_ts,
        }

        try:
            result = create_jwt(payload, secret=HARDCODED_SECRET)
            session["jwt_token"] = result["token"]
            session["token_expiry"] = exp_ts

            # Refresh Token
            refresh_exp_time = now + timedelta(minutes=REFRESH_DURATION_MINUTES)
            refresh_payload = {
                "sub": username,
                "type": "refresh",
                "iat": int(now.timestamp()),
                "exp": int(refresh_exp_time.timestamp()),
            }
            refresh_result = create_jwt(refresh_payload, secret=HARDCODED_SECRET)

            session["refresh_token"] = refresh_result["token"]
            session["refresh_expiry"] = int(refresh_exp_time.timestamp())
            session["username"] = username
            session.modified = True

            # Simpan ke SQLite
            save_tokens(
                username=username,
                access_token=result["token"],
                refresh_token=refresh_result["token"],
                token_expiry=exp_ts,
                refresh_expiry=int(refresh_exp_time.timestamp()),
            )

            print("\n===== TOKEN DIBUAT =====")
            print(f"👤 Username       : {username}")
            print(f"🕒 Access Expiry  : {exp_ts}")
            print(f"🔐 Access Token   : {result['token']}")
            print(f"♻️  Refresh Token  : {refresh_result['token']}")
            print(f"💾 Simpan DB SQLite: session_tokens.sqlite")
            print("Session state:")
            for k, v in dict(session).items():
                print(f"  {k:<15}: {v}")
            print("========================\n")

        except Exception as e:
            result = {"error": str(e)}

    return render_template_string(GENERATE_TEMPLATE, result=result)


# =====================================================
# ROUTE: DECODE TOKEN (dengan debug per baris)
# =====================================================
@app.route("/decode", methods=["GET", "POST"])
@token_required
def decode():
    decoded = None
    error = None
    token = None
    token_source = None

    now_ts = int(datetime.now(timezone.utc).timestamp())

    print("\n===== DEBUG DECODE =====")
    print("Session saat ini:")
    for k, v in dict(session).items():
        print(f"  {k:<15}: {v} \n")
    print("========================")

    # Token kadaluarsa → coba refresh
    if session.get("token_expiry") and now_ts > session["token_expiry"]:
        print("⚠️ Access token kadaluarsa, memeriksa refresh token...")
        if session.get("refresh_token") and now_ts < session.get("refresh_expiry", 0):
            print("✅ Refresh token masih valid → redirect ke /refresh\n")
            return redirect(url_for("refresh"))
        else:
            print("❌ Kedua token kadaluarsa, hapus session dan file session\n")
            session.clear()
            clear_all_sessions()  # <--- tambahkan di sini juga
            error = "❌ Token dan refresh token telah kadaluarsa."
            return render_template_string(DECODE_TEMPLATE, error=error)

    # Pilih sumber token
    if request.method == "POST" and request.form.get("token"):
        token = request.form.get("token").strip()
        token_source = "form"
    elif get_bearer_token():
        token = get_bearer_token()
        token_source = "Authorization header"
    elif session.get("jwt_token"):
        token = session.get("jwt_token")
        token_source = "session"

    print(f"Token diambil dari : {token_source or 'tidak ada'}")
    if token:
        print(f"Token (potongan)   : {token[:40]}...")

    # Decode JWT
    if not token:
        error = "Tidak ada token di session atau form."
    else:
        try:
            decoded = decode_jwt(token, secret=HARDCODED_SECRET)
            print("✅ Token berhasil didecode:")
            for k, v in decoded["payload"].items():
                print(f"  {k:<10}: {v}")
        except Exception as e:
            error = f"Error parsing token: {str(e)}"
            print(f"❌ Gagal decode token: {error}")
            clear_all_sessions()  # <--- jika token invalid

    print("========================\n")

    if decoded and token_source:
        decoded["token_source"] = token_source
    return render_template_string(DECODE_TEMPLATE, decoded=decoded, error=error)


# =====================================================
# ROUTE: REFRESH TOKEN
# =====================================================
@app.route("/refresh")
@token_required
def refresh():
    now_ts = int(datetime.now(timezone.utc).timestamp())

    print("\n===== DEBUG REFRESH =====")
    print("Session sebelum refresh:")
    for k, v in dict(session).items():
        print(f"  {k:<15}: {v}")

    refresh_token = session.get("refresh_token")
    username = session.get("username")

    if not refresh_token or not username:
        print("❌ Tidak ada refresh token atau username dalam session\n")
        clear_all_sessions()
        return redirect(url_for("generate"))

    if now_ts > session.get("refresh_expiry", 0):
        print("❌ Refresh token kadaluarsa → hapus session & revoke DB\n")
        revoke_user_tokens(username)
        session.clear()
        clear_all_sessions()
        return redirect(url_for("generate"))

    try:
        refresh_decoded = decode_jwt(refresh_token, secret=HARDCODED_SECRET)
        now = datetime.now(timezone.utc)
        new_exp_time = now + timedelta(minutes=TOKEN_DURATION_MINUTES)
        new_payload = {
            "username": username,
            "role": DEFAULT_ROLE,
            "iat": int(now.timestamp()),
            "nbf": int(now.timestamp()),
            "exp": int(new_exp_time.timestamp()),
        }
        new_token = create_jwt(new_payload, secret=HARDCODED_SECRET)

        session["jwt_token"] = new_token["token"]
        session["token_expiry"] = int(new_exp_time.timestamp())
        session.modified = True

        update_access_token(username, new_token["token"], int(new_exp_time.timestamp()))

        print("✅ TOKEN BERHASIL DIREFRESH")
        print(f"🔐 Access Token Baru: {new_token['token']}")
        print(f"🕒 Expiry Baru       : {int(new_exp_time.timestamp())}")
        print("💾 Database diperbarui")
        print("Session sesudah refresh:")
        for k, v in dict(session).items():
            print(f"  {k:<15}: {v}")
        print("=========================\n")

        return redirect(url_for("decode"))

    except Exception as e:
        print(f"❌ Gagal decode refresh token: {e}\n")
        revoke_user_tokens(username)
        session.clear()
        clear_all_sessions()
        return f"Refresh token tidak valid: {str(e)}"


# =====================================================
# ROUTE: LOGOUT
# =====================================================
@app.route("/logout")
def logout():
    username = session.get("username")
    if username:
        revoke_user_tokens(username)
    session.clear()
    clear_all_sessions()
    print("🔒 Logout → token direvoke & semua session dihapus\n")
    return redirect(url_for("generate"))


# =====================================================
# ROUTE: CEK ISI DATABASE (debug)
# =====================================================
@app.route("/db")
@token_required
def show_db():
    rows = get_all_tokens()
    print("\n===== DEBUG DATABASE =====")
    for row in rows:
        print(row)
    print("==========================\n")
    return f"<pre>{rows}</pre>"


# =====================================================
# ROUTE: PROTECTED API (harus pakai Bearer token)
# =====================================================
@app.route("/protected")
@token_required
def protected():
    # Bisa ambil token dari Authorization header atau session
    token = get_bearer_token() or session.get("jwt_token")
    token_source = "Authorization header" if get_bearer_token() else "session"

    if not token:
        clear_all_sessions()
        return {"error": "Missing Bearer or session token"}, 401

    try:
        decoded = decode_jwt(token, secret=HARDCODED_SECRET)
        username = decoded["payload"].get("username", "Unknown")
        role = decoded["payload"].get("role", "user")
        return {
            "message": f"Welcome, {username}! You have {role} access.",
            "token_source": token_source,
            "issued_at": decoded["payload"].get("iat"),
            "expires_at": decoded["payload"].get("exp"),
        }
    except Exception as e:
        clear_all_sessions()
        return {"error": f"Invalid or expired token: {str(e)}"}, 401


# =====================================================
# ENTRY POINT
# =====================================================
if __name__ == "__main__":
    init_db()
    app.run(debug=True)
