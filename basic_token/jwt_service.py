import json  # Untuk konversi dict <-> JSON string
from .jwt_core import (
    build_header, encode_segment, sign_token,
    verify_signature, verify_timestamps
)
from .claims import generate_standard_claims
from .base64_utils import base64url_decode
from .config import Config
from .errors import InvalidTokenFormat


# ------------------------------------------------------------
# 1️⃣ CREATE JWT (ENCODING)
# ------------------------------------------------------------
def create_jwt_detailed(payload: dict, secret: str = None, algorithm: str = None) -> dict:
    """
    Membuat JWT secara manual dan menampilkan detail setiap bagiannya:
    header, payload, dan signature (beserta versi Base64-nya).

    Parameter:
    ----------
    payload : dict
        Data klaim yang ingin dimasukkan ke dalam token.
        Misalnya: {"user_id": 1, "username": "raka", "role": "admin"}

    secret : str | None
        Secret key untuk proses signing.
        Jika tidak diberikan, akan menggunakan Config.SECRET_KEY.

    algorithm : str | None
        Algoritma untuk signing (default "HS256").
        Jika None, akan mengambil dari Config.ALGORITHM.

    Return:
    -------
    dict
        Mengembalikan dictionary berisi token dan detail komponennya:
        {
            "token": <JWT lengkap>,
            "header": <header dict>,
            "payload": <payload dict>,
            "header_b64": <header encoded>,
            "payload_b64": <payload encoded>,
            "signature_b64": <signature encoded>
        }
    """

    # Gunakan secret dan algoritma default dari Config jika tidak diberikan
    secret = secret or Config.SECRET_KEY
    algorithm = algorithm or Config.ALGORITHM

    # Bangun header JWT (mis. {"alg": "HS256", "typ": "JWT"})
    header = build_header(algorithm)

    # Tambahkan klaim standar ke payload (iss, aud, iat, nbf, exp, dsb)
    payload = generate_standard_claims(payload)

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
    """
    Decode JWT menjadi objek Python dan verifikasi keasliannya.

    Langkah-langkah:
    ----------------
    1. Pisahkan token menjadi 3 bagian (header, payload, signature).
    2. Decode dari Base64URL → JSON → Python dict.
    3. Verifikasi tanda tangan (signature) dengan secret key.
    4. Verifikasi waktu kadaluarsa (exp) dan waktu mulai berlaku (nbf).

    Parameter:
    ----------
    token : str
        JWT string dalam format "header.payload.signature"

    secret : str | None
        Secret key yang sama dengan saat token dibuat.
        Jika None, ambil dari Config.SECRET_KEY.

    Return:
    -------
    dict
        Berisi hasil decode JWT:
        {
            "header": <dict>,
            "payload": <dict>,
            "signature": <string>
        }

    Raise:
    ------
    InvalidTokenFormat : Jika token tidak memiliki 3 bagian.
    InvalidSignature    : Jika tanda tangan tidak cocok.
    ExpiredToken        : Jika waktu 'exp' sudah lewat.
    NotYetValid         : Jika waktu 'nbf' belum tercapai.
    """
    secret = secret or Config.SECRET_KEY

    # JWT valid memiliki 3 bagian: header.payload.signature
    try:
        header_b64, payload_b64, signature_b64 = token.split(".")
    except ValueError:
        # Jika jumlah bagiannya tidak tepat → token rusak
        raise InvalidTokenFormat("Format token tidak valid")

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
