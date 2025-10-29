# basic_token/token_db.py
import sqlite3
from datetime import datetime

DB_PATH = "session_tokens.sqlite"

def get_connection():
    return sqlite3.connect(DB_PATH)

def init_db():
    """Membuat tabel tokens jika belum ada."""
    conn = get_connection()
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS tokens (
            id INTEGER PRIMARY KEY,
            username TEXT NOT NULL UNIQUE,
            access_token TEXT,
            refresh_token TEXT,
            token_expiry INTEGER,
            refresh_expiry INTEGER,
            status TEXT DEFAULT 'active',
            created_at TEXT
        )
    """)
    conn.commit()
    conn.close()


def save_tokens(username, access_token, refresh_token, token_expiry, refresh_expiry):
    """Simpan atau perbarui token user (UPSERT)."""
    conn = get_connection()
    c = conn.cursor()
    c.execute("""
        INSERT INTO tokens (username, access_token, refresh_token, token_expiry, refresh_expiry, status, created_at)
        VALUES (?, ?, ?, ?, ?, 'active', ?)
        ON CONFLICT(username) DO UPDATE SET
            access_token = excluded.access_token,
            refresh_token = excluded.refresh_token,
            token_expiry = excluded.token_expiry,
            refresh_expiry = excluded.refresh_expiry,
            status = 'active',
            created_at = excluded.created_at
    """, (
        username, access_token, refresh_token,
        token_expiry, refresh_expiry, datetime.utcnow().isoformat()
    ))
    conn.commit()
    conn.close()


def update_access_token(username, new_access_token, new_expiry):
    """Perbarui access token setelah refresh."""
    conn = get_connection()
    c = conn.cursor()
    c.execute("""
        UPDATE tokens
        SET access_token = ?, token_expiry = ?, created_at = ?
        WHERE username = ? AND status = 'active'
    """, (new_access_token, new_expiry, datetime.utcnow().isoformat(), username))
    conn.commit()
    conn.close()


def revoke_user_tokens(username):
    """Menonaktifkan semua token user (misal saat logout)."""
    conn = get_connection()
    c = conn.cursor()
    c.execute("""
        UPDATE tokens
        SET status = 'revoked'
        WHERE username = ? AND status = 'active'
    """, (username,))
    conn.commit()
    conn.close()


def get_all_tokens():
    """Ambil semua isi tabel tokens (untuk debugging)."""
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT id, username, status, token_expiry, refresh_expiry, created_at FROM tokens")
    rows = c.fetchall()
    conn.close()
    return rows
