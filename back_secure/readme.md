# Autentikasi & sesi

* Risiko: credential compromise, session hijack, token misuse.
* Mitigasi praktis
    * Simpan session/token kritis di HttpOnly + Secure cookies (hindari localStorage untuk access/refresh token sensitif).
    * Password hashing menggunakan Argon2 / bcrypt / scrypt (work factor tinggi). Jangan gunakan MD5/SHA plain.
    * Terapkan multi-factor auth (2FA) untuk akun sensitif.
    * Regenerate session id setelah login / privilege change.
    * Batasi sesi: idle timeout + absolute timeout; support revocation (logout everywhere).
    * Implementasikan rate-limiting pada login endpoints, lockout bertingkat, dan monitoring login anomalies.

# Otorisasi (Authorization)

* Risiko: privilege escalation, broken access control.
* Mitigasi praktis
    * Gunakan prinsip least privilege (RBAC/ABAC).
    * Enforce authorization server-side untuk setiap endpoint (never rely on client flags).
    * Centralize authorization checks (middleware / policy layer) dan lakukan unit tests untuk rules.
    * Use object-level checks (e.g., only owner can edit resource X).

# Token & JWT management

* Risiko: forged tokens, long-lived tokens, leaked secrets.
* Mitigasi praktis
    * Validasi signature & claims server-side (iss/aud/exp/nbf).
    * Jangan trust alg: none — enforce allowed algorithms.
    * Gunakan short-lived access tokens + refresh tokens (refresh tokens rotate on use).
    * Store refresh tokens in HttpOnly cookies; maintain server-side revoke/blacklist or token versioning.
    * Key rotation + automated rollover; store signing keys in secure vault.

# Input validation & injection (SQLi, Command inj., LDAP inj.)

* Risiko: remote code/data manipulation via unsanitized input.
* Mitigasi praktis
    * Parameterized queries / prepared statements (never string-concat SQL).
    * Gunakan ORM dengan parameter binding.
    * Validate input types/length/patterns server-side (whitelisting > blacklisting).
    * Escape output when generating format-specific output (SQL, shell, LDAP, XML).
    * Use DB least privilege account (no superuser for app).

# Cross-Site Request Forgery (CSRF)

* Risiko: aksi state-changing dipicu tanpa user intent.
* Mitigasi praktis
    * Untuk cookie-based auth: implement CSRF tokens (synchronize token pattern) atau double-submit cookie.
    * Alternatif: gunakan SameSite=strict/lax untuk cookies dan require same-origin for unsafe methods.
    * Untuk APIs used by SPAs with tokens in headers, prefer header-based auth (CORS restriction + tokens in Authorization header) — CSRF less applicable.

# Cross-Site Scripting (XSS) — server role

* Risiko: server mengirim HTML yang mengandung input berbahaya.
* Mitigasi praktis
    * Escape output di server saat merender HTML (templating engines safe by default — gunakan fitur escaping).
    * Jangan memasukkan user-provided HTML tanpa sanitasi; jika perlu, gunakan sanitizer library (bleach, DOMPurify server-side) dan whitelist elemen/atribut.
    * Set CSP header untuk membatasi sumber script.

# CORS & API exposure

* Risiko: resource diakses dari domain tak dipercaya.
* Mitigasi praktis
    * Jangan gunakan Access-Control-Allow-Origin: * jika endpoint butuh auth.
    * Kirim header CORS hanya untuk origin trusted; pastikan Access-Control-Allow-Credentials di-set sesuai kebutuhan.
    * Audit endpoints publik vs internal; gunakan network segmentation (VPC, private subnets).

# Transport & network (TLS)

* Risiko: MITM, data leakage.
* Mitigasi praktis
    * Wajibkan HTTPS/TLS (TLS 1.2+), gunakan HSTS.
    * Redirect HTTP→HTTPS.
    * Miliki certificate management (Let's Encrypt automation or CA with rotation).
    * Jangan TLS-terminate di client side or misconfigured proxies.

# Rate limiting & brute-force / DoS mitigation

* Risiko: credential stuffing, resource exhaustion.
* Mitigasi praktis
    * Implement per-IP & per-account rate-limiting (burst + steady rate).
    * Use CAPTCHA for suspicious flows (login, signup).
    * Backpressure: queueing, circuit breakers; autoscaling plus WAF.

# Logging, monitoring & audit

* Risiko: tidak tahu ketika terjadi breach; sensitive data leak via logs.
* Mitigasi praktis
    * Log authentication events, admin actions, failed attempts, anomalies.
    * Don't log secrets (passwords, full tokens, PII). Redact or hash.
    * Centralized logging (ELK/Datadog) + alerts for suspicious patterns.
    * Maintain audit trails immutable if possible.

# Error handling & info disclosure

* Risiko: leaks (stack traces, debug info) yang membantu attacker.
* Mitigasi praktis
    * Return generic error messages to clients; include details only in internal logs.
    * Disable debug mode in production; sanitize exception handlers.

# File upload handling

* Risiko: upload malicious files (webshells), path traversal.
* Mitigasi praktis
    * Validate file type by content (MIME sniffing), not just extension.
    * Store uploads outside webroot or on object storage (S3) with randomized names.
    * Scan uploads with antivirus.
    * Enforce size limits and quotas.

# Secrets & config management

* Risiko: hardcoded creds or leaked keys.
* Mitigasi praktis
    * Use secret manager / vault (HashiCorp Vault, AWS Secrets Manager).
    * Keep secrets out of code and repo; rotate regularly.
    * Use environment variables or injected secrets from CI/CD runtime.

# Dependency & supply-chain security

* Risiko: compromised libraries.
* Mitigasi praktis
    * Automate dependency scanning (Snyk, Dependabot, npm audit).
    * Pin versions and review third-party libs; prefer minimal deps.
    * Use reproducible builds and signing where possible.

# CI/CD, build & deployment security

* Risiko: pipeline compromise, exposing artifacts.
* Mitigasi praktis
    * Protect CI secrets, limit who can change pipelines.
    * Scan images for vulnerabilities, use minimal base images.
    * Use infrastructure as code review & approvals.
    * Remove source maps or protect them.

#  Database & storage security

* Risiko: data leak, privilege abuse.
* Mitigasi praktis
    * Encrypt at rest + TLS to DB.
    * Principle of least privilege for DB accounts.
    * Regular backups + tested restore procedures.
    * Use field-level encryption for very sensitive data (PII).

# Infrastructure & container security

* Risiko: container escape, misconfigured hosts.
* Mitigasi praktis
    * Run containers with least privilege (non-root), read-only filesystem where possible.
    * Scan images, use runtime security (Falco).
    * Harden OS, patch frequently.

# Testing & validation (SAST/DAST)

* Risiko: unknown vulnerabilities.
* Mitigasi praktis
    * Integrate SAST (static) + DAST (dynamic) + dependency scans in CI.
    * Perform periodic pen testing and threat modeling.
    * Use fuzzing for parsers/APIs if relevant.

# Incident response & forensics

* Risiko: lambat tanggap saat breach.
* Mitigasi praktis
    * Siapkan playbook: containment, eradication, recovery, notification.
    * Simulate incident drills.
    * Store logs for sufficient retention for forensics.