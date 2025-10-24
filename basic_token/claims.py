import datetime
from .config import Config


def generate_standard_claims(custom_payload: dict,
                             issuer: str | None = None,
                             audience: str | None = None,
                             expires_delta: datetime.timedelta | None = None) -> dict:
    """
    Membuat payload JWT lengkap dengan klaim standar (standard claims)
    sesuai spesifikasi RFC 7519.

    Parameter:
    ----------
    custom_payload : dict
        Data kustom tambahan yang ingin disertakan di payload JWT
        (misalnya: {"user_id": 1, "role": "admin"}).

    issuer : str | None, default=None
        Nilai klaim "iss" (issuer) — pihak yang mengeluarkan token.
        Jika None, akan menggunakan Config.ISSUER.

    audience : str | None, default=None
        Nilai klaim "aud" (audience) — pihak yang menjadi target token.
        Jika None, akan menggunakan Config.AUDIENCE.

    expires_delta : datetime.timedelta | None, default=None
        Durasi waktu sebelum token kedaluwarsa.
        Jika None, akan menggunakan Config.ACCESS_EXPIRES.

    Return:
    -------
    dict : Payload JWT lengkap yang siap dikodekan menjadi token.
    """

    # Waktu saat ini (UTC), karena JWT standar menggunakan UTC, bukan lokal time.
    now = datetime.datetime.utcnow()

    # Gunakan nilai default dari konfigurasi jika parameter opsional tidak diberikan.
    issuer = issuer or Config.ISSUER
    audience = audience or Config.AUDIENCE
    expires_delta = expires_delta or Config.ACCESS_EXPIRES

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
