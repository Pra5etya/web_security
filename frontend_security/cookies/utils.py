import secrets
import hashlib
import hmac
from flask import request, current_app

# ============================================================
# 🔧 UTILITAS KEAMANAN UMUM
# ============================================================

def generate_token(length=32):
    """
    Membuat token acak aman untuk CSRF atau session
    """
    return secrets.token_urlsafe(length)  # token url-safe acak


def generate_fingerprint():
    """
    Membuat fingerprint unik dari IP + User-Agent untuk mengikat session
    """
    ua = request.headers.get("User-Agent", "")[:100]  # ambil 100 karakter pertama
    ip = request.headers.get("X-Forwarded-For", request.remote_addr)  # ambil IP client
    return hashlib.sha256(f"{ip}|{ua}".encode()).hexdigest()[:32]  # hash fingerprint


def sign_data(data: str) -> str:
    """
    HMAC signature untuk data (misal session) agar tidak dimodifikasi
    """
    secret = current_app.secret_key.encode()  # ambil secret key Flask
    return hmac.new(secret, data.encode(), "sha256").hexdigest()


def verify_signature(data: str, signature: str) -> bool:
    """
    Verifikasi HMAC signature data
    """
    expected = sign_data(data)
    return hmac.compare_digest(expected, signature)
