import json                                     # Untuk serialisasi dan deserialisasi JSON (header/payload JWT)
import hmac                                     # Untuk operasi HMAC (hash-based message authentication code)
import hashlib                                  # Untuk algoritma hash seperti SHA256

from .base64url import base64url_encode      
from datetime import datetime, timezone


# ------------------------------------------------------------
# 1️⃣ HEADER
# ------------------------------------------------------------
"""
List Algoritma Umum

| Algoritma | Jenis Kunci     | Keamanan                      | Kecepatan       | Ukuran Token | Cocok Untuk                   |
| --------- | --------------- | ----------------------------- | --------------- | ------------ | ----------------------------- |
| **HS256** | Simetris        | Cukup aman (asal secret kuat) | 🔥 Sangat cepat | Kecil        | Sistem tunggal / internal     |
| **RS512** | Asimetris (RSA) | Sangat aman                   | 🐢 Lambat       | Besar        | Sistem terdistribusi / publik |
| **ES256** | Asimetris (EC)  | Sangat aman                   | ⚡ Cepat         | Kecil        | Sistem modern / efisien       |

List Algoritma Detail

| Algoritma             | Jenis               | Deskripsi                                           |
| --------------------- | ------------------- | --------------------------------------------------- |
| **HS256**             | Simetris            | HMAC-SHA256                                         |
| **HS384**             | Simetris            | HMAC-SHA384                                         |
| **HS512**             | Simetris            | HMAC-SHA512                                         |
| **RS256/RS384/RS512** | Asimetris (RSA)     | RSA-SHAxxx                                          |
| **ES256/ES384/ES512** | Asimetris (ECDSA)   | ECDSA-SHAxxx                                        |
| **PS256/PS384/PS512** | Asimetris (RSA-PSS) | RSA-PSS dengan SHAxxx                               |


List Parameter Header

| Nama       | Arti                                                                        | Contoh                                        |
| ---------- | --------------------------------------------------------------------------- | --------------------------------------------- |
| `alg`      | Algoritma untuk menandatangani atau mengenkripsi JWT                        | `"HS256"`, `"RS512"`, `"ES256"`, `"none"`     |
| `typ`      | Tipe token, biasanya `"JWT"`                                                | `"JWT"`                                       |
| `cty`      | Content Type – digunakan jika JWT dibungkus (nested JWT)                    | `"JWT"`                                       |
| `kid`      | Key ID – untuk mengidentifikasi kunci mana yang digunakan                   | `"key-01"`                                    |
| `jku`      | JWK Set URL – URL untuk mengambil public keys (JWK Set)                     | `"https://example.com/.well-known/jwks.json"` |
| `crit`     | Critical – daftar parameter yang penerima **harus pahami** agar token valid | `["exp", "aud"]`                              |
| `ver`      | Versi token                                                                 | `"1.0"`                                       |
| `iss`      | Issuer di header (biasanya di payload, tapi bisa di header)                 | `"auth.example.com"`                          |
| `env`      | Lingkungan aplikasi (dev/staging/prod)                                      | `"production"`                                |
| `ts`       | Timestamp pembuatan JWT                                                     | `1730262000`                                  |
| `app`      | Nama aplikasi penerbit                                                      | `"MyAppAPI"`                                  |

"""
def build_header(algorithm: str = "HS256") -> dict:
    return {"alg": algorithm, 
            "typ": "JWT"}


# ------------------------------------------------------------
# 2️⃣ ENCODE HEADER & PAYLOAD
# ------------------------------------------------------------
def encode_segment(obj: dict) -> str:
    """
        json.dumps dengan separators=(",", ":") menghasilkan JSON tanpa spasi,
        supaya token lebih pendek dan konsisten.  
    """
    
    json_bytes = json.dumps(obj, separators=(",", ":")).encode()
    return base64url_encode(json_bytes)


# ------------------------------------------------------------
# 3️⃣ SIGN TOKEN (MEMBUAT SIGNATURE)
# ------------------------------------------------------------
def sign_token(header_b64: str, payload_b64: str, secret: str) -> str:
    """
    header_b64 : str
        Header JWT yang sudah di-encode Base64URL.

    payload_b64 : str
        Payload JWT yang sudah di-encode Base64URL.

    secret : str
        Secret key yang digunakan untuk membuat tanda tangan.
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
    # Buat ulang signature dari header & payload menggunakan secret
    valid_sig = sign_token(header_b64, payload_b64, secret)

    # Gunakan compare_digest agar aman terhadap timing attack
    if not hmac.compare_digest(valid_sig, signature_b64):
        raise Exception("Signature tidak valid")


# ------------------------------------------------------------
# 5️⃣ VERIFIKASI WAKTU (exp dan nbf)
# ------------------------------------------------------------
def verify_timestamps(payload):

    # Dapatkan waktu sekarang dalam UTC (format detik UNIX)
    now = datetime.now(timezone.utc).timestamp()

    # Jika waktu sekarang lebih besar dari exp → token sudah kadaluarsa
    if now > payload.get("exp", 0):
        raise Exception("Token kadaluarsa")

    # Jika waktu sekarang lebih kecil dari nbf → token belum berlaku
    if now < payload.get("nbf", 0):
        raise Exception("Token belum aktif")

