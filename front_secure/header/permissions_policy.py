def apply_permissions_policy(response):
    # --- Permissions-Policy ---
    response.headers["Permissions-Policy"] = (
        "geolocation=(), "              # Nonaktifkan GPS / lokasi pengguna
        "microphone=(), "               # Blokir akses mikrofon
        "camera=(), "                   # Blokir akses kamera
        "accelerometer=(), "            # Blokir sensor percepatan
        "gyroscope=(), "                # Blokir sensor orientasi
        "magnetometer=(), "             # Blokir sensor medan magnet
        "usb=(), "                      # Nonaktifkan WebUSB
        "bluetooth=(), "                # Nonaktifkan Web Bluetooth
        "midi=(), "                     # Nonaktifkan Web MIDI
        "payment=(), "                  # Nonaktifkan Web Payment API
        "xr-spatial-tracking=(), "      # Nonaktifkan WebXR (VR/AR)
        "ambient-light-sensor=(), "     # Nonaktifkan sensor cahaya
        "clipboard-read=(self), "       # Hanya izinkan baca clipboard di domain sendiri
        "clipboard-write=(self), "      # Hanya izinkan tulis clipboard di domain sendiri
        "fullscreen=(self), "           # Izinkan fullscreen hanya dari domain sendiri
        "picture-in-picture=(self)"     # Izinkan video PiP hanya di domain sendiri
    )
    return response
