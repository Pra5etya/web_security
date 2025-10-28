from datetime import datetime, timezone, timedelta

def generate_standard_claims(custom_payload: dict,
                             issuer: str | None = None,
                             audience: str | None = None,
                             expires_delta: timedelta | None = None) -> dict:

    ACCESS_EXPIRES = timedelta(minutes=5)
    ISSUER = "jwt-learning-app"
    AUDIENCE = "jwt-clients"


    # Waktu saat ini (UTC), karena JWT standar menggunakan UTC, bukan lokal time.
    now = datetime.now(timezone.utc)

    # Gunakan nilai default dari konfigurasi jika parameter opsional tidak diberikan.
    issuer = issuer or ISSUER
    audience = audience or AUDIENCE
    expires_delta = expires_delta or ACCESS_EXPIRES

    # Waktu kadaluarsa dihitung dari waktu sekarang + durasi expire
    exp_time = now + expires_delta

    # Konversi ke timestamp (float detik UNIX UTC)
    # JWT menggunakan waktu berbasis detik, bukan datetime object.
    iat = now.timestamp()   # issued-at (token dibuat)
    nbf = now.timestamp()   # not-before (token berlaku mulai kapan)
    exp = exp_time.timestamp()  # expiration (token berakhir kapan)

    # Gabungkan klaim standar dengan payload kustom pengguna
    payload = {
        **custom_payload,   # unpack dictionary milik user
        "iss": issuer,      # siapa yang mengeluarkan token
        "aud": audience,    # siapa yang boleh menerima token
        "iat": iat,         # waktu token diterbitkan
        "nbf": nbf,         # waktu mulai berlaku
        "exp": exp          # waktu kedaluwarsa
    }

    return payload
