# PENERAPAN TOKENS BELUM SEPENUHNYA DITERAPKAN
1. ANALISIS LEWAT DEV TOOLS BELUM DAPAT DIPAHAMI
2. SETELAH REGIS TOKENS DI TARUH DAN DAPAT DILIHAT DIMANA JIKA LEWAT DEV TOOLS
3. DATA TIDAK MASUK KE DATABASE

# NOTE

1. Struktur Token / JWT terdiri:
    ```bash
    Header.Payload.Signature
    ```
    * Header: Menentukan jenis token (JWT) dan algoritma penandatanganan yang digunakan.
    * Payload: Data spesifik pengguna yang ingin Anda sertakan. Payload ini dikodekan dalam Base64 untuk keamanan maksimum.
    * Signature: Kombinasi hash dari header, payload, dan kunci rahasia server.

    ```JSON
    {
    "header": {
        "alg": "HS256",
        "typ": "JWT"
    },
    "payload": {
        "sub": "1234567890",
        "name": "John Doe",
        "admin": true,
        "iat": 1516239022
    },
    "signature": "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    }
    ```
