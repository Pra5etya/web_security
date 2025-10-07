import secrets
import hashlib
import hmac
from flask import request, current_app

# ============================================================
# 🔧 UTILITAS KEAMANAN UMUM
# ============================================================

def generate_token(length=32):
    """
    Membuat token acak aman (misal untuk CSRF atau session ID)
    - secrets.token_urlsafe() menghasilkan token base64 aman untuk URL
    """
    return secrets.token_urlsafe(length)


def generate_fingerprint():
    """
    Membuat fingerprint unik dari kombinasi IP + User-Agent.
    Digunakan untuk mengikat session cookie ke perangkat pengguna tertentu.
    """
    # Ambil header User-Agent, batasi 100 karakter (menghindari payload panjang)
    ua = request.headers.get("User-Agent", "")[:100]
    # Ambil alamat IP dari header X-Forwarded-For jika ada (proxy-aware)
    ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    # Hash kombinasi IP dan UA untuk hasil tetap namun aman
    return hashlib.sha256(f"{ip}|{ua}".encode()).hexdigest()[:32]


def sign_data(data: str) -> str:
    """
    Menandatangani data menggunakan HMAC-SHA256.
    Tujuannya agar data (misal session) tidak bisa dimodifikasi oleh klien.
    """
    # Ambil secret key Flask
    secret = current_app.secret_key.encode()
    # Buat signature HMAC
    return hmac.new(secret, data.encode(), "sha256").hexdigest()


def verify_signature(data: str, signature: str) -> bool:
    """
    Verifikasi apakah tanda tangan HMAC valid.
    """
    # Hitung ulang signature dari data
    expected = sign_data(data)
    # Bandingkan secara aman (hindari timing attack)
    return hmac.compare_digest(expected, signature)
