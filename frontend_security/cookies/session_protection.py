from flask import Response, request
from .utils import generate_token, generate_fingerprint, sign_data, verify_signature

# ============================================================
# 🔐 SESSION SECURITY
# ============================================================

def create_secure_session_cookie(
    response: Response,
    cookie_name="session_id",
    max_age=1800,
    old_session=None
):
    """
    Membuat session cookie aman dengan:
    1. Rotasi session ID (anti-fixation)
    2. Fingerprint browser/IP
    3. HMAC signature untuk verifikasi integritas
    """

    # 1️⃣ Buat session ID baru (token acak)
    session_id = generate_token(24)

    # 2️⃣ Buat fingerprint unik dari IP dan User-Agent
    fingerprint = generate_fingerprint()

    # 3️⃣ Gabungkan session ID dan fingerprint
    session_data = f"{session_id}|{fingerprint}"

    # 4️⃣ Tambahkan tanda tangan (HMAC) agar cookie tidak bisa diubah klien
    sig = sign_data(session_data)
    session_value = f"{session_data}|{sig}"

    # 5️⃣ Jika ada session lama, hapus untuk mencegah reuse
    if old_session:
        response.set_cookie(
            key=cookie_name,
            value="",        # Kosongkan nilai lama
            max_age=0,       # Expire segera
            path="/",
            secure=True,
            httponly=True,
            samesite="Strict"
        )

    # 6️⃣ Simpan session baru di cookie
    response.set_cookie(
        key=cookie_name,      # Nama cookie
        value=session_value,  # Nilai berisi ID + fingerprint + signature
        secure=True,          # ✅ Hanya via HTTPS
        httponly=True,        # ✅ Tidak bisa diakses JS
        samesite="Strict",    # ✅ Tidak dikirim ke domain lain
        path="/",             # ✅ Berlaku global
        max_age=max_age,      # Berlaku 30 menit
    )

    # Cookie ini sekarang aman dari manipulasi & reuse.
    return response


def verify_secure_session_cookie(request, cookie_name="session_id") -> bool:
    """
    Verifikasi session cookie:
    - Pastikan struktur cookie valid (3 bagian)
    - Pastikan HMAC signature benar
    - Pastikan fingerprint cocok (tidak dicuri dari browser lain)
    """

    # 1️⃣ Ambil cookie session dari request
    cookie_val = request.cookies.get(cookie_name)
    if not cookie_val:
        return False

    # 2️⃣ Pastikan cookie memiliki format benar: id|fingerprint|sig
    parts = cookie_val.split("|")
    if len(parts) != 3:
        return False

    # Pisahkan komponennya
    session_id, fingerprint, sig = parts

    # 3️⃣ Verifikasi tanda tangan (HMAC)
    if not verify_signature(f"{session_id}|{fingerprint}", sig):
        return False  # Signature salah → cookie diubah manual

    # 4️⃣ Verifikasi fingerprint cocok dengan perangkat saat ini
    current_fingerprint = generate_fingerprint()
    if current_fingerprint != fingerprint:
        return False  # Kemungkinan cookie dicuri dari browser lain

    # ✅ Semua valid
    return True
