import secrets
import hashlib
import hmac
from flask import request, current_app

# ============================================================
# 🔧 UTILITAS KEAMANAN UMUM
# ============================================================

def generate_token(length = 32):
    return secrets.token_urlsafe(length)  # generate token


def generate_fingerprint():

    ua = request.headers.get("User-Agent", "")[:100]                    # ambil 100 karakter pertama
    ip = request.headers.get("X-Forwarded-For", request.remote_addr)    # ambil IP client

    return hashlib.sha256(f"{ip}|{ua}".encode()).hexdigest()[:32]       # hash fingerprint


def sign_data(data: str) -> str:
    secret = current_app.secret_key.encode()                            # ambil secret key Flask
    
    return hmac.new(secret, data.encode(), "sha256").hexdigest()


def verify_signature(data: str, signature: str) -> bool:
    expected = sign_data(data)

    return hmac.compare_digest(expected, signature)
