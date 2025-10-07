def apply_legacy_modern_headers(response):
    # ==========================================================
    # 🧱 Legacy & Modern Security Headers
    # ==========================================================

    response.headers["X-Content-Type-Options"] = "nosniff"                   # anti MIME sniffing
    response.headers["X-Frame-Options"] = "DENY"                             # cegah clickjacking
    response.headers["X-Permitted-Cross-Domain-Policies"] = "none"           # blok plugin lama
    response.headers["Cross-Origin-Resource-Policy"] = "same-origin"         # batasi pengambilan resource
    response.headers["Cross-Origin-Opener-Policy"] = "same-origin"           # pisahkan context tab
    response.headers["Cross-Origin-Embedder-Policy"] = "require-corp"        # isolasi resource
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate" # kontrol caching
    response.headers["Pragma"] = "no-cache"                                  # kompatibilitas lama
    response.headers["X-XSS-Protection"] = "0"                               # nonaktifkan auditor lama
    return response
