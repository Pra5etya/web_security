from .claims import token_standard_claims
from .base64url import base64url_decode
from .jwt_core import (build_header, encode_segment, sign_token, 
                       verify_signature, verify_timestamps)

import os, json

SECRET_KEY = os.getenv("SECRET_KEY", "supersecretkey")
ALGORITHM = "HS256"

# ------------------------------------------------------------
# 1️⃣ CREATE JWT (ENCODING)
# ------------------------------------------------------------
def create_jwt(payload: dict, secret: str = None, algorithm: str = None) -> dict:

    # Gunakan secret dan algoritma default dari Config jika tidak diberikan
    secret = secret or SECRET_KEY
    algorithm = algorithm or ALGORITHM

    # Membuat header
    header = build_header(algorithm)

    # membuat payload (isi dari token)
    payload = token_standard_claims(payload)

    # Encode header dan payload ke format Base64URL (tanpa '=')
    header_b64 = encode_segment(header)
    payload_b64 = encode_segment(payload)

    # Buat signature berdasarkan HMAC-SHA256 dari "header.payload"
    signature_b64 = sign_token(header_b64, payload_b64, secret)

    # Gabungkan ketiganya menjadi JWT utuh (header.payload.signature)
    token = f"{header_b64}.{payload_b64}.{signature_b64}"

    # Kembalikan semua bagian untuk keperluan debug atau visualisasi
    return {
        "token": token,                  # JWT final
        "header": header,                # header dict mentah
        "payload": payload,              # payload dict mentah
        "header_b64": header_b64,        # header dalam Base64URL
        "payload_b64": payload_b64,      # payload dalam Base64URL
        "signature_b64": signature_b64   # signature dalam Base64URL
    }


# ------------------------------------------------------------
# 2️⃣ DECODE JWT (DECODING + VERIFIKASI)
# ------------------------------------------------------------
def decode_jwt(token: str, secret: str = None) -> dict:

    secret = secret or SECRET_KEY

    # JWT valid memiliki 3 bagian: header.payload.signature
    try:
        header_b64, payload_b64, signature_b64 = token.split(".")

    except ValueError:
        raise Exception("Format token tidak valid")

    # Decode Base64URL menjadi JSON bytes, lalu parse ke dict Python
    header_json = base64url_decode(header_b64)
    payload_json = base64url_decode(payload_b64)

    # Konversi JSON bytes menjadi dict
    header = json.loads(header_json)
    payload = json.loads(payload_json)

    # Verifikasi signature untuk memastikan integritas token
    verify_signature(header_b64, payload_b64, signature_b64, secret)

    # Verifikasi waktu token (expired atau belum aktif)
    verify_timestamps(payload)

    # Return hasil decode lengkap
    return {
        "header": header,
        "payload": payload,
        "signature": signature_b64
    }
