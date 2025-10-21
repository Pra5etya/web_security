from flask import Response, request
from .utils import generate_token

def mitigate_cookie_theft_via_xss(
    response: Response,                      # Objek response Flask tempat cookie akan disisipkan
    cookie_name: str = "session_id",         # Nama cookie yang akan digunakan (default: "session_id")
    session_value: str | None = None,        # Nilai cookie (token sesi); akan dibuat acak jika None
    max_age: int = 1800,                     # Umur cookie dalam detik (default: 30 menit)
    expires: str | None = None,              # Waktu kedaluwarsa cookie dalam format datetime HTTP (opsional)
    path: str = "/",                         # Jalur di mana cookie berlaku (default: semua path)
    domain: str | None = None,               # Domain yang diizinkan menggunakan cookie (opsional)
    secure: bool = True,                     # Hanya kirim cookie lewat HTTPS (mencegah sniffing)
    http_only: bool = True,                  # Mencegah cookie diakses lewat JavaScript (anti-XSS)
    same_site: str = "Strict",               # Aturan SameSite (Strict, Lax, None) untuk mencegah CSRF
    priority: str | None = "High",           # Prioritas cookie (opsional; digunakan di browser modern)
    partitioned: bool = False,               # Aktifkan CHIPS (Partitioned cookies; untuk isolasi antar situs)
    same_party: bool = False,                # Tandai cookie hanya berlaku dalam konteks same-party
    ensure_domain_from_request: bool = True  # Jika domain None, otomatis gunakan domain dari request
):

    # Jika domain tidak diberikan, gunakan host dari request saat ini
    if domain is None and ensure_domain_from_request:
        domain = request.host  # ⚠️ bisa berisi port (localhost:5000) → potensi invalid cookie

    # Jika tidak ada nilai session, buat token acak untuk session_id
    if session_value is None:
        session_value = generate_token(32)  # gunakan token acak aman

    # Validasi nilai same_site agar hanya Strict, Lax, atau None
    if same_site not in {"Strict", "Lax", "None"}:
        raise ValueError("same_site harus 'Strict', 'Lax', atau 'None'")

    # Jika same_site=None → wajib secure=True
    if same_site == "None" and not secure:
        raise ValueError("Jika same_site='None', maka secure must be True")

    # Set cookie ke dalam response dengan flag keamanan dasar
    response.set_cookie(
    key = cookie_name,       # Nama cookie yang disisipkan ke browser
    value = session_value,   # Nilai token sesi (biasanya acak)
    max_age = max_age,       # Masa berlaku cookie dalam detik
    expires = expires,       # Tanggal kedaluwarsa cookie (opsional)
    path = path,             # Jalur di mana cookie berlaku (misal hanya di /api)
    domain = domain,         # Domain yang dapat mengakses cookie
    secure = secure,         # Wajib menggunakan HTTPS agar cookie tidak bocor lewat HTTP
    httponly = http_only,    # Tidak dapat diakses via JavaScript (mencegah XSS)
    samesite = same_site     # Aturan SameSite: Strict/Lax/None → mencegah pengiriman lintas situs
)


    # Ambil semua header Set-Cookie yang sudah ada
    cookie_headers = response.headers.getlist("Set-Cookie")

    # Jika ada header cookie, tambahkan atribut tambahan (Priority, Partitioned, SameParty)
    if cookie_headers:
        updated = []

        for h in cookie_headers:
            # Cari cookie dengan nama yang sesuai
            if h.startswith(f"{cookie_name}="):
                extras = ""

                if priority:
                    extras += f"; Priority={priority}"

                if partitioned:
                    extras += "; Partitioned"

                if same_party:
                    extras += "; SameParty"

                h = h + extras  # Tambahkan atribut tambahan

            updated.append(h)
        
        # ⚠️ Problem: Gabungan semua header menjadi satu, tidak sesuai standar HTTP
        response.headers.set("Set-Cookie", ", ".join(updated))

    return response
