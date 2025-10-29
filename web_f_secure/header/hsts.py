def apply_hsts(response):
    # --- Strict-Transport-Security (HSTS) ---
    response.headers["Strict-Transport-Security"] = (
        "max-age=31536000; "      # browser enforce HTTPS selama 1 tahun (satuan detik)
        "includeSubDomains; "     # juga terapkan ke semua subdomain
        "preload"                 # siap untuk masuk daftar preload browser
    )
    return response
