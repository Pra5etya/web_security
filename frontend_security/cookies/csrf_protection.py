from flask import request, Response
import hmac
from .utils import generate_token

# ============================================================
# 🛡️ CSRF PROTECTION
# ============================================================

def set_csrf_cookie(response: Response, cookie_name="csrf_token", max_age=1800):
    """
    Menetapkan CSRF token di cookie agar frontend (JS) bisa mengaksesnya.
    Token ini kemudian dikirim ulang lewat header X-CSRF-Token oleh klien.
    """

    # Buat token acak aman
    csrf_token = generate_token(32)

    # Simpan di cookie agar JS bisa baca → HttpOnly=False
    response.set_cookie(
        key=cookie_name,       # Nama cookie CSRF
        value=csrf_token,      # Nilai token CSRF
        secure=True,           # ✅ Hanya lewat HTTPS
        httponly=False,        # ❌ Bisa diakses JS (diperlukan untuk dikirim via header)
        samesite="Lax",        # ✅ Aman untuk navigasi top-level (form submit)
        path="/",              # Berlaku untuk semua endpoint
        max_age=max_age,       # Token berlaku 30 menit
    )

    # Kembalikan response dan token agar frontend bisa menggunakannya
    return response, csrf_token


def verify_csrf_request(request, cookie_name="csrf_token", header_name="X-CSRF-Token") -> bool:
    """
    Verifikasi CSRF:
    Pastikan nilai token di cookie dan header request sama persis.
    """
    # Ambil token dari cookie
    cookie_token = request.cookies.get(cookie_name)
    # Ambil token dari header (dikirim oleh JS)
    header_token = request.headers.get(header_name)

    # Jika salah satu tidak ada → gagal
    if not cookie_token or not header_token:
        return False

    # Bandingkan secara aman untuk menghindari timing attack
    return hmac.compare_digest(cookie_token, header_token)
