from flask import Response
from .utils import generate_token

# ============================================================
# 🍪 PROTEKSI COOKIE DARI AKSES JAVASCRIPT (ANTI-XSS)
# ============================================================

def mitigate_cookie_theft_via_xss(
    response: Response,
    cookie_name: str = "session_id",
    session_value: str = None,
    max_age: int = 1800
):
    """
    Mencegah pencurian cookie oleh script berbahaya (XSS)
    dengan cara menonaktifkan akses JavaScript ke cookie.
    """

    # Jika belum ada nilai session, buat token acak aman
    if session_value is None:
        session_value = generate_token(32)

    # Konfigurasi cookie dengan parameter keamanan maksimal
    response.set_cookie(
        key=cookie_name,       # Nama cookie (misal: session_id)
        value=session_value,   # Nilai session/token
        max_age=max_age,       # Masa hidup cookie dalam detik
        secure=True,           # ✅ Hanya dikirim melalui HTTPS
        httponly=True,         # ✅ Tidak bisa diakses lewat document.cookie (JavaScript)
        samesite="Strict",     # ✅ Tidak dikirim ke domain lain (anti-CSRF dasar)
        path="/",              # ✅ Berlaku untuk semua path di domain
    )

    # Setelah ini, cookie hanya dapat dikirim otomatis oleh browser via HTTPS
    # dan tidak dapat dibaca oleh JavaScript apa pun di halaman.
    return response
