import json          # Untuk serialisasi dan deserialisasi JSON (header/payload JWT)
import hmac          # Untuk operasi HMAC (hash-based message authentication code)
import hashlib       # Untuk algoritma hash seperti SHA256
from .base64_utils import base64url_encode, base64url_decode  # Fungsi utilitas untuk Base64URL
from .errors import InvalidSignature, InvalidTokenFormat, ExpiredToken, NotYetValid
import datetime      # Untuk pengecekan waktu token (exp, nbf)


# ------------------------------------------------------------
# 1️⃣ HEADER
# ------------------------------------------------------------
def build_header(algorithm: str = "HS256") -> dict:
    """
    Membangun struktur header JWT.

    Parameter:
    ----------
    algorithm : str
        Algoritma yang digunakan untuk signing (default: HS256).

    Return:
    -------
    dict
        Header JWT standar dengan kunci 'alg' dan 'typ'.
        Contoh: {"alg": "HS256", "typ": "JWT"}
    """
    return {"alg": algorithm, "typ": "JWT"}


# ------------------------------------------------------------
# 2️⃣ ENCODE HEADER & PAYLOAD
# ------------------------------------------------------------
def encode_segment(obj: dict) -> str:
    """
    Mengubah dictionary (header/payload) menjadi string Base64URL.

    Proses:
    1. Konversi dict ke JSON string.
    2. Encode ke bytes UTF-8.
    3. Encode ke Base64URL tanpa padding '='.

    Parameter:
    ----------
    obj : dict
        Objek Python yang ingin dijadikan bagian JWT (header atau payload).

    Return:
    -------
    str
        String Base64URL yang aman untuk dimasukkan ke JWT.
    """
    # json.dumps dengan separators=(",", ":") menghasilkan JSON tanpa spasi,
    # supaya token lebih pendek dan konsisten.
    json_bytes = json.dumps(obj, separators=(",", ":")).encode()
    return base64url_encode(json_bytes)


# ------------------------------------------------------------
# 3️⃣ SIGN TOKEN (MEMBUAT SIGNATURE)
# ------------------------------------------------------------
def sign_token(header_b64: str, payload_b64: str, secret: str) -> str:
    """
    Membuat signature untuk JWT menggunakan algoritma HMAC-SHA256.

    Proses:
    1. Gabungkan header dan payload (dipisah dengan titik '.').
    2. Lakukan hashing HMAC-SHA256 menggunakan secret key.
    3. Encode hasil digest ke Base64URL.

    Parameter:
    ----------
    header_b64 : str
        Header JWT yang sudah di-encode Base64URL.
    payload_b64 : str
        Payload JWT yang sudah di-encode Base64URL.
    secret : str
        Secret key yang digunakan untuk membuat tanda tangan.

    Return:
    -------
    str
        Signature hasil Base64URL encoding.
    """
    # 1️⃣ Bentuk string input: "header.payload"
    signing_input = f"{header_b64}.{payload_b64}".encode()

    # 2️⃣ HMAC dengan algoritma SHA256 menggunakan secret
    signature = hmac.new(secret.encode(), signing_input, hashlib.sha256).digest()

    # 3️⃣ Encode hasil hash ke Base64URL
    return base64url_encode(signature)


# ------------------------------------------------------------
# 4️⃣ VERIFIKASI SIGNATURE
# ------------------------------------------------------------
def verify_signature(header_b64, payload_b64, signature_b64, secret):
    """
    Memverifikasi apakah signature yang diberikan valid.

    Proses:
    1. Buat ulang signature berdasarkan header & payload & secret.
    2. Bandingkan dengan signature yang ada di token.
    3. Jika tidak sama → lempar InvalidSignature.

    Parameter:
    ----------
    header_b64 : str
        Bagian header dari token (Base64URL).
    payload_b64 : str
        Bagian payload dari token (Base64URL).
    signature_b64 : str
        Signature yang ingin diverifikasi.
    secret : str
        Secret key yang digunakan untuk menandatangani token.

    Raise:
    ------
    InvalidSignature : Jika tanda tangan token tidak cocok.
    """
    # Buat ulang signature dari header & payload menggunakan secret
    valid_sig = sign_token(header_b64, payload_b64, secret)

    # Gunakan compare_digest agar aman terhadap timing attack
    if not hmac.compare_digest(valid_sig, signature_b64):
        raise InvalidSignature("Signature tidak valid")


# ------------------------------------------------------------
# 5️⃣ VERIFIKASI WAKTU (exp dan nbf)
# ------------------------------------------------------------
def verify_timestamps(payload):
    """
    Memverifikasi klaim waktu pada payload JWT.

    Pengecekan:
    - 'exp' (Expiration Time): token kadaluarsa?
    - 'nbf' (Not Before): token belum aktif?

    Parameter:
    ----------
    payload : dict
        Payload JWT yang sudah di-decode dari Base64URL dan JSON.

    Raise:
    ------
    ExpiredToken : Jika waktu saat ini melewati 'exp'.
    NotYetValid  : Jika waktu saat ini masih sebelum 'nbf'.
    """
    # Dapatkan waktu sekarang dalam UTC (format detik UNIX)
    now = datetime.datetime.utcnow().timestamp()

    # Jika waktu sekarang lebih besar dari exp → token sudah kadaluarsa
    if now > payload.get("exp", 0):
        raise ExpiredToken("Token kadaluarsa")

    # Jika waktu sekarang lebih kecil dari nbf → token belum berlaku
    if now < payload.get("nbf", 0):
        raise NotYetValid("Token belum aktif")
