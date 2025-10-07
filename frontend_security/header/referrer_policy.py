def apply_referrer_policy(response):
    # --- Referrer-Policy ---
    # 1️⃣ Privasi maksimal (tidak kirim referrer sama sekali)
    response.headers["Referrer-Policy"] = "no-referrer"     # untuk data sensitif

    # # Daftar endpoint sensitif (bisa kamu ubah sesuai kebutuhan)
    # sensitive_paths = (
    #     "/login",
    #     "/logout",
    #     "/register",
    #     "/reset-password",
    #     "/account",
    #     "/billing",
    #     "/settings/security"
    # )

    # 2️⃣ Alternatif aman modern:
    # response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

    # 3️⃣ Jika kamu hanya ingin kirim origin (tanpa path/query):
    # response.headers["Referrer-Policy"] = "origin"
    return response
