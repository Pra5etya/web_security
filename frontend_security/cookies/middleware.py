from flask import request, g
from .cookies_xss import mitigate_cookie_theft_via_xss
from .csrf_protection import set_csrf_cookie
from .session_protection import create_secure_session_cookie

def register_security_middleware(app):
    """
    Fungsi untuk mendaftarkan middleware pada Flask app
    """

    # ============================================================
    # 1️⃣ Sebelum request: bisa digunakan untuk logging / fingerprint
    # ============================================================
    @app.before_request
    def before_request():
        # Simpan fingerprint di g untuk route lain jika diperlukan
        ua = request.headers.get("User-Agent", "")[:100]
        ip = request.headers.get("X-Forwarded-For", request.remote_addr)
        g.fingerprint = f"{ip}|{ua}"
        # Bisa tambahkan logging keamanan, deteksi bot, dsb
        return None  # tidak memblokir request

    # ============================================================
    # 2️⃣ Setelah request: otomatis set semua cookie aman
    # ============================================================
    @app.after_request
    def after_request(response):
        """
        Set cookie security otomatis untuk semua response.
        - Lindungi session dari XSS
        - Buat CSRF token
        - Rotasi session jika perlu
        """

        # 1️⃣ Cookie theft via XSS
        response = mitigate_cookie_theft_via_xss(response)

        # 2️⃣ CSRF token cookie (bisa dibaca JS untuk double-submit)
        response, csrf_token = set_csrf_cookie(response)

        # 3️⃣ Rotasi session dan buat session cookie aman
        response = create_secure_session_cookie(response)

        return response
