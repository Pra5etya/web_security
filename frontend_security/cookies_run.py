from flask import Flask, jsonify, request
from cookies.middleware import register_security_middleware
from cookies.csrf_protection import verify_csrf_request
from cookies.session_protection import verify_secure_session_cookie

app = Flask(__name__)
app.secret_key = "super-secret-key-change-me"

# ✅ Daftarkan middleware keamanan otomatis
register_security_middleware(app)

# ============================================================
# ROUTE TERPROTEKSI
# ============================================================

@app.route("/update-profile", methods=["POST"])
def update_profile():
    """
    Endpoint contoh:
    - CSRF dan session akan diverifikasi otomatis
    - Middleware sudah meng-set cookie aman di setiap response
    """

    # 1️⃣ Verifikasi CSRF
    if not verify_csrf_request(request):
        return {"error": "CSRF verification failed"}, 403

    # 2️⃣ Verifikasi session
    if not verify_secure_session_cookie(request):
        return {"error": "Invalid session"}, 401

    return {"message": "Profil berhasil diperbarui"}


# ============================================================
# ENTRY POINT
# ============================================================
if __name__ == "__main__":
    app.run(debug=True, ssl_context="adhoc")
