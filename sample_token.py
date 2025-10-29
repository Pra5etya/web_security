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
            print("❌ Kedua token kadaluarsa, hapus session\n")
            session.clear()
            error = "❌ Token dan refresh token telah kadaluarsa."
            return render_template_string(DECODE_TEMPLATE, error=error)

    # Pilih sumber token
    if request.method == "POST" and request.form.get("token"):
        token = request.form.get("token").strip()
        token_source = "form"
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

    print("========================\n")

    if decoded and token_source:
        decoded["token_source"] = token_source
    return render_template_string(DECODE_TEMPLATE, decoded=decoded, error=error)


# =====================================================
# ROUTE: REFRESH TOKEN
# =====================================================
@app.route("/refresh")
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
        return redirect(url_for("generate"))

    if now_ts > session.get("refresh_expiry", 0):
        print("❌ Refresh token kadaluarsa → hapus session & revoke DB\n")
        revoke_user_tokens(username)
        session.clear()
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
    print("🔒 Logout → token direvoke & session dihapus\n")
    return redirect(url_for("generate"))


# =====================================================
# ROUTE: CEK ISI DATABASE (debug)
# =====================================================
@app.route("/db")
def show_db():
    rows = get_all_tokens()
    print("\n===== DEBUG DATABASE =====")
    for row in rows:
        print(row)
    print("==========================\n")
    return f"<pre>{rows}</pre>"


# =====================================================
# ENTRY POINT
# =====================================================
if __name__ == "__main__":
    init_db()
    app.run(debug=True)
