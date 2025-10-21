# tokens/storage.py
# Abstraction layer for user and token storage.
# Token storage pakai SQLite, user storage sederhana (bisa dipindahkan ke DB juga).

import sqlite3
import time
from werkzeug.security import generate_password_hash, check_password_hash

# SQL schema untuk dua tabel utama:
# - refresh_tokens: menyimpan token refresh yang aktif
# - csrf_map: optional, untuk relasi CSRF double-submit
SCHEMA = """
CREATE TABLE IF NOT EXISTS refresh_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    jti TEXT UNIQUE NOT NULL,
    username TEXT NOT NULL,
    token_hash TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    revoked INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS csrf_map (
    jti TEXT PRIMARY KEY,
    csrf_value TEXT
);
"""

class TokenStore:
    """
    Abstraksi penyimpanan user + refresh token.
    - User disimpan di memori (dict), karena ini hanya contoh.
    - Refresh token disimpan di SQLite agar mudah dirotasi dan direvoke.
    """

    def __init__(self, db_path="tokens.db"):
        # path DB untuk token
        self.db_path = db_path
        # penyimpanan user sederhana di memori
        self.users = {}
        # inisialisasi DB schema
        self._init_db()

    def _conn(self):
        """Membuka koneksi SQLite (check_same_thread=False agar aman di dev server multi-thread)."""
        return sqlite3.connect(self.db_path, check_same_thread=False)

    def _init_db(self):
        """Membuat tabel jika belum ada."""
        with self._conn() as conn:
            conn.executescript(SCHEMA)

    # -----------------------------
    # Bagian User Management
    # -----------------------------

    def create_user(self, username, password):
        """
        Registrasi user baru.
        - Untuk production, sebaiknya user juga disimpan di DB.
        """
        if username in self.users:
            return False
        self.users[username] = generate_password_hash(password)
        return True

    def verify_user(self, username, password):
        """
        Verifikasi login user.
        - Return True jika username ada dan password cocok.
        """
        return username in self.users and check_password_hash(self.users[username], password)

    # -----------------------------
    # Bagian Refresh Token Management
    # -----------------------------

    def insert_refresh(self, jti, username, token_hash, expires_at):
        """
        Simpan data refresh token ke DB.
        - token_hash: hasil HMAC dari refresh token (tidak menyimpan token mentah!)
        - expires_at: epoch integer
        """
        now = int(time.time())
        with self._conn() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO refresh_tokens
                (jti, username, token_hash, created_at, expires_at, revoked)
                VALUES (?, ?, ?, ?, ?, 0)
                """,
                (jti, username, token_hash, now, int(expires_at))
            )

    def get_refresh_by_jti(self, jti):
        """Ambil data refresh token berdasarkan jti."""
        with self._conn() as conn:
            c = conn.execute("SELECT jti, username, token_hash, revoked FROM refresh_tokens WHERE jti = ?", (jti,))
            row = c.fetchone()
            if not row:
                return None
            return {"jti": row[0], "username": row[1], "token_hash": row[2], "revoked": bool(row[3])}

    def mark_revoked(self, jti):
        """Set revoked=1 pada refresh token tertentu."""
        with self._conn() as conn:
            conn.execute("UPDATE refresh_tokens SET revoked = 1 WHERE jti = ?", (jti,))

    def revoke_all_for_user(self, username):
        """Revoke semua refresh token milik user (bila terdeteksi reuse/theft)."""
        with self._conn() as conn:
            conn.execute("UPDATE refresh_tokens SET revoked = 1 WHERE username = ?", (username,))

    # -----------------------------
    # Bagian CSRF Mapping (optional)
    # -----------------------------

    def store_csrf_for_jti(self, jti, csrf_value):
        """Simpan relasi jti -> csrf_value untuk validasi double-submit."""
        with self._conn() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO csrf_map (jti, csrf_value) VALUES (?, ?)",
                (jti, csrf_value)
            )

    def get_csrf_for_jti(self, jti):
        """Ambil csrf_value untuk jti tertentu."""
        with self._conn() as conn:
            c = conn.execute("SELECT csrf_value FROM csrf_map WHERE jti = ?", (jti,))
            row = c.fetchone()
            return row[0] if row else None
