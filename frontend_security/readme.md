# Header (Response / Security headers)

1. Content-Security-Policy (CSP)
    * Mitigasi: pasang CSP ketat (default-src 'self'; batasi script-src, style-src, gunakan nonce/hash bila perlu). 

2. Strict-Transport-Security (HSTS)
    * Mitigasi: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload.

3. X-Frame-Options / frame-ancestors (Clickjacking)
    * Mitigasi: X-Frame-Options: DENY atau CSP frame-ancestors 'none'.

4. Referrer-Policy (Informasi referrer)
    * Mitigasi: Referrer-Policy: no-referrer-when-downgrade atau lebih ketat no-referrer.

5. Permissions-Policy
    * Mitigasi: menonaktifkan API yang tidak perlu (camera, microphone, geolocation).

## NOte

* penerapan security di header bisa di lihat pada ***frontend_security/header***
* penilaian header bisa di cek melalui: [security headers](https://securityheaders.com/)



# Cookie & Session (cookies, SameSite, HttpOnly)

1. Cookie theft via XSS (JS access / HTML Char Entities) 
    * Mitigasi: simpan session/token di cookie HttpOnly; Secure; SameSite=Strict — jangan di localStorage untuk token sensitif.

2. CSRF (dengan cookies otomatis dikirim)
    * Mitigasi: SameSite=Lax/Strict, CSRF token pada body/header, gunakan double-submit cookie atau SameSite + per-request token.

3. Session fixation / session hijacking
    * Mitigasi: regen session id setelah login, set short expiration, invalidate di server saat logout.

# Token / JWT (penanganan & validasi)

1. Token disclosure (localStorage) / XSS
    * Mitigasi: prefer HttpOnly cookies; jika pakai storage, minimalisasi lifetime & enkripsi (server-side refresh).

2. Invalid JWT usage (trusting client-sent claims)
    * Mitigasi: selalu verifikasi signature & claims di backend; jangan andalkan role/privilege di client.

3. Refresh token misuse
    * Mitigasi: refresh tokens di HttpOnly cookie, rotate refresh tokens, revocation list.

# DOM / Output (XSS, DOM-based XSS)

1. Stored/Reflected XSS & DOM XSS
    * Mitigasi: escape semua output → gunakan textContent/template escaping, sanitasi input bila perlu, hindari innerHTML. Gunakan library sanitasi yang aman bila perlu.

2. Dangerous frameworks usage
    * Mitigasi: hindari dangerouslySetInnerHTML, v-html, atau hanya gunakan dengan nonce/CSP.

# Network / Requests (MITM, insecure endpoints)

1. Man-in-the-Middle (HTTP)
    * Mitigasi: pakai HTTPS, HSTS, pin cert (opsional), force redirect HTTP→HTTPS.

2. Open CORS misconfiguration
    * Mitigasi: set Access-Control-Allow-Origin hanya ke domain yang dipercaya; jangan * jika auth diperlukan.

3. Sensitive data in query params
    * Mitigasi: kirim data sensitif di body (POST) atau header, bukan URL.

# Storage (localStorage, sessionStorage, IndexedDB)

1. Data theft via XSS
    * Mitigasi: hindari menyimpan credential/token; jika menyimpan data sensitif, pertimbangkan enkripsi & short TTL.

2. Persistent sensitive state leakage
    * Mitigasi: clear storage on logout, jangan menulis secrets di state yang di-serialize ke disk.

# Third-party Scripts & Dependencies

1. Malicious/compromised CDN or npm package
    * Mitigasi: audit dependencies (npm audit), pin versi, gunakan SRI (integrity) untuk CDN, gunakan subresource integrity & CSP.

2. Third-party trackers leaking data
    * Mitigasi: kaji vendor, minimalkan script pihak ketiga, gunakan Content Security Policy.

# UI/UX & Interaction (phishing, clickjacking, tabnabbing)

1. Tabnabbing / Phishing via target="_blank"
    * Mitigasi: gunakan rel="noopener noreferrer".

2. Deceptive UI (misleading forms, fake dialogs)
    * Mitigasi: desain jelas, konfirmasi untuk tindakan kritis, server-side authorization check untuk semua tindakan.

3. Clickjacking (UI overlay tricks)
    * Mitigasi: X-Frame-Options, CSP frame-ancestors.

# Client-side Logic & Authorization (business logic)

1. Trusting client for auth/authorization
    * Mitigasi: semua checks must be server-side; client-only: UX gating, bukan keamanan.

2. Feature flag manipulation / role escalation
    * Mitigasi: server enforces roles; sign/verify any client-sent privileged flags.

# Build / Deployment / Source Exposure

1. Exposed secrets in bundle / source maps
    * Mitigasi: jangan embed API secrets, hapus source maps di produksi atau proteksi aksesnya, gunakan env variables build-time.

2. Verbose logs in production
    * Mitigasi: disable console logs & debug data di produksi.