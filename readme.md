# Penerapan value di web security

* Penerapan langsung di header disarankan seperti berikut:
```bash
# langsung
response.headers["X-Custom-Header"] = "Belajar Flask"

# pengecekan value dulu
old_value = response.headers.get("X-Custom-Header", "")

new_value = (old_value + "; " if old_value else "") + "Belajar Flask"   # Tambahkan value baru
response.headers["X-Custom-Header"] = new_value # Set ulang ke header

```

# Hal yang ada di header:

1. Content negotiation (klien minta format): 
    ```py
    """ 
    * Accept — format yang diterima client (application/json, text/html).
        Flask helper: request.accept_mimetypes → ada metode .best_match([...]).

    * Accept-Language — preferensi bahasa. Flask: request.accept_languages.
    """
    ```

2. Autentikasi / otorisasi:
    ```py
    # Authorization — tempat biasa untuk Bearer <token> atau Basic <credentials>.

    auth = request.headers.get("Authorization", "")
    
    if auth.startswith("Bearer "):
        token = auth.split(" ", 1)[1]
    ```

3. Cookie / Session:
    ```py
    # Cookie — semua cookie dikirim di header ini; di Flask gunakan request.cookies (dict) untuk akses yang sudah ter-parse.
    ```

4. CORS / Preflight:
    ```py
    """ 
    * Origin (saat browser melakukan cross-origin request.)
    
    * Saat browser mengirim header custom (atau non-simple request), 
        browser mengirim preflight OPTIONS dengan Access-Control-Request-Headers dan Access-Control-Request-Method. 
        Server harus merespon dengan Access-Control-Allow-*. 
    """
    ```

5. Proxy / Client IP:
    ```py
    """ 
    * X-Forwarded-For — daftar IP yang dilewati (proxy). BISA DISPOOF, jangan percaya tanpa konfigurasi proxy yang benar.

    * Forwarded / X-Forwarded-Proto — info proto (http/https). 
    """
    ```

6. Caching / Conditional
    ```py
    """ 
    * If-Modified-Since, If-None-Match (ETag) — dipakai untuk conditional GET / cache validation.
    * Range / If-Range — permintaan partial content. 
    """
    ```

7. AJAX / Browser metadata
    ```py
    """ 
    * X-Requested-With: XMLHttpRequest — sering dipakai untuk mendeteksi AJAX (legacy).
    * Referer / Referrer-Policy — URL asal request (bisa kosong karena privacy).
    * User-Agent — info browser / client. 
    """
    ```

8. Hop-by-hop & control (biasanya proxy / connection)
    ```py
    # Connection, Keep-Alive, Transfer-Encoding, Upgrade — bukan header yang seharusnya diteruskan oleh proxy; lebih untuk transport.
    ```


# Cheat Sheets

📥 Selain request.headers, Flask punya banyak hal terkait HTTP request:

1. **request.args** → ambil query parameter (data di URL setelah ?).
    * Contoh: /search?q=flask → request.args.get("q")

2. **request.form** → ambil data dari form (POST request dengan application/x-www-form-urlencoded).
    * Contoh: form login HTML.

3. **request.json** → ambil body request dalam format JSON (kalau Content-Type: application/json).
    * Contoh: API modern.

4.  **request.cookies** → ambil cookies yang dikirim client (cookies juga sebenarnya dikirim lewat header: Cookie: session_id=xxx).

5. **request.method** → lihat method request (GET, POST, PUT, DELETE).
    * Kadang dikombinasikan dengan header X-HTTP-Method-Override.

6. **request.remote_addr** → IP client (kadang berasal dari header X-Forwarded-For jika lewat proxy).

👉 Jadi headers adalah salah satu bagian dari request, selain query, form, JSON body, cookies.

# 🔐 Header Penting yang Wajib Dikuasai

Kalau mau jago, kamu harus ngerti peran tiap header (baik standar maupun custom):

1. Autentikasi / Security
    * Authorization: Bearer <token> → dipakai untuk JWT/OAuth.
    * Cookie: session=abc123 → session-based auth.
    * X-API-Key: <key> → custom API key.

2. Konten
    * Content-Type: application/json → tipe data body.
    * Accept: application/json → client minta balasan JSON.
    * Content-Length: 1234 → panjang body request.

3. Caching
    * Cache-Control: no-cache
    * ETag
    * Last-Modified

4. CORS (Cross-Origin Resource Sharing)
    * Access-Control-Allow-Origin: *
    * Access-Control-Allow-Headers: X-My-Header, Authorization

5. User Context
    * User-Agent: Mozilla/5.0
    * Accept-Language: en-US

# Flask punya helper berguna (lebih dari sekadar request.headers)

1. request.cookies — dict cookies.
2. request.authorization — object untuk Basic auth (username/password).
3. request.content_type, request.mimetype, request.content_length.
4. request.user_agent — object (browser, platform).
5. request.accept_mimetypes / request.accept_languages — untuk content negotiation.
6. request.get_json() — parse JSON body (lebih bagus daripada mengandalkan langsung request.data).