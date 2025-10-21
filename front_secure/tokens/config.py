# tokens/config.py
# Centralized configuration for token system.
# Use environment variables to override defaults in production.

import os
from datetime import timedelta

class Config:
    # Secret key untuk menandatangani JWT (ganti dengan secret strong di production)
    SECRET_KEY = os.environ.get("SECRET_KEY", "dev-secret-key-change-me")

    # Issuer claim untuk JWT (membantu validasi bahwa token berasal dari app ini)
    JWT_ISSUER = os.environ.get("JWT_ISSUER", "my-flask-app")

    # Lifetime access token (disarankan singkat, mis. 5 menit)
    ACCESS_EXPIRES = timedelta(minutes=int(os.environ.get("ACCESS_EXPIRES_MIN", 5)))

    # Lifetime refresh token (lebih panjang, tetapi kita gunakan rotation)
    REFRESH_EXPIRES = timedelta(days=int(os.environ.get("REFRESH_EXPIRES_DAYS", 7)))

    # Salt server-side untuk HMAC hashing refresh token (jangan bocorkan)
    REFRESH_TOKEN_SALT = os.environ.get("REFRESH_TOKEN_SALT", "refresh-salt-change-me")

    # Path SQLite database untuk penyimpanan refresh tokens / csrf map
    DATABASE_PATH = os.environ.get("TOKEN_DB_PATH", "./tokens_storage.db")

    # Nama cookie untuk access token (HttpOnly)
    ACCESS_COOKIE = os.environ.get("ACCESS_COOKIE_NAME", "access_token")

    # Nama cookie untuk refresh token (HttpOnly)
    REFRESH_COOKIE = os.environ.get("REFRESH_COOKIE_NAME", "refresh_token")

    # Nama cookie untuk CSRF token (non-HttpOnly so JS can read)
    CSRF_COOKIE = os.environ.get("CSRF_COOKIE_NAME", "csrf_token")

    # Header name yang harus dikirim client berisi nilai CSRF cookie (double-submit)
    CSRF_HEADER = os.environ.get("CSRF_HEADER_NAME", "X-CSRF-Token")

    # Cookie flags (production: COOKIE_SECURE True)
    COOKIE_SECURE = bool(int(os.environ.get("COOKIE_SECURE", "1")))  # 1 = True, 0 = False
    COOKIE_SAMESITE = os.environ.get("COOKIE_SAMESITE", "Lax")       # 'Lax' atau 'Strict' atau 'None'

    # Rate limiting settings (not implemented here, but recommended)
    MAX_LOGIN_ATTEMPTS = int(os.environ.get("MAX_LOGIN_ATTEMPTS", 5))
    LOGIN_LOCK_TIME_MINUTES = int(os.environ.get("LOGIN_LOCK_TIME_MINUTES", 15))
