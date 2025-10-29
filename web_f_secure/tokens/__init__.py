# tokens/__init__.py
# App factory: buat Flask app, load Config, dan inisialisasi TokenStore & TokenManager.
# Tujuan: keep initialization centralized so token_run.py stays minimal.

from flask import Flask
from .config import Config              # konfigurasi terpusat
from .token_manager import TokenManager # pengelola JWT
from .storage import TokenStore         # storage refresh token (SQLite default)

def create_app():
    """
    Factory function — membuat dan mengembalikan Flask app yang sudah di-bind
    dengan token_store dan token_manager. Routes di-register di token_run.py.
    """
    # buat instance Flask
    app = Flask(__name__)

    # load configuration dari Config class
    app.config.from_object(Config)

    # inisialisasi token storage (TokenStore) dan attach ke app
    # (TokenStore bertanggung jawab terhadap penyimpanan refresh token & CSRF map)
    app.token_store = TokenStore(app.config['DATABASE_PATH'])

    # inisialisasi TokenManager (encode/decode/rotate tokens)
    app.token_manager = TokenManager(
        secret_key=app.config['SECRET_KEY'],             # secret untuk sign JWT
        issuer=app.config['JWT_ISSUER'],                 # nilai iss claim
        salt=app.config['REFRESH_TOKEN_SALT']           # salt untuk hashing refresh token
    )

    # kembalikan aplikasi siap pakai
    return app
