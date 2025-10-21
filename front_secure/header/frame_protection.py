def apply_x_frame_options(response):
    # --- X-Frame-Options / legacy clickjacking protection ---
    # Pilihan:
    #   - DENY → tidak boleh di-embed di iframe manapun.
    #   - SAMEORIGIN → hanya boleh di-embed dari domain yang sama.
    response.headers["X-Frame-Options"] = "DENY"
    return response
