# security_headers/csp.py
import secrets
import json
from flask import g, request

def generate_nonce():
    # Nonce unik per request untuk mengizinkan inline script/style yang kita kontrol
    g.nonce = secrets.token_urlsafe(16)


def apply_csp(response):
    # --- Content Security Policy (CSP) ---
    response.headers["Content-Security-Policy"] = (
        "default-src 'none'; "                                                              # blok semua, izinkan hanya yg disebut
        "base-uri 'self'; "                                                                 # cegah manipulasi <base>
        "object-src 'none'; "                                                               # blok plugin (Flash, Java)
        "frame-ancestors 'self' https://partner.example.com; "                              # cegah clickjacking + izinkan partner tertentu
        f"script-src 'self' 'nonce-{g.nonce}'; "                                            # izinkan script self + nonce
        "style-src 'self' 'unsafe-inline'; "                                                # style dari self (nonce lebih aman)
        "img-src 'self' data:; "                                                            # gambar dari self & data URI
        "font-src 'self' data:; "                                                           # font dari self
        "media-src 'self'; "                                                                # media hanya dari self
        "worker-src 'self' blob:; "                                                         # izinkan worker self/blob
        "connect-src 'self' https://api.myservice.example wss://api.myservice.example; "    # batasi fetch/ws
        "form-action 'self'; "                                                              # kirim form hanya ke self
        "upgrade-insecure-requests; "                                                       # paksa HTTPS
        "block-all-mixed-content; "                                                         # blok HTTP di halaman HTTPS
        "report-to csp-endpoint; report-uri /csp-report;"                                   # laporan pelanggaran CSP
    )

    # --- Endpoint laporan CSP ---
    report_to = {
        "group": "csp-endpoint",
        "max_age": 10886400,
        "endpoints": [
            {"url": f"{request.url_root.rstrip('/')}/csp-report"}
        ]
    }
    # json.dumps menghindarkan kita dari masalah escaping braces / quotes
    response.headers["Report-To"] = json.dumps(report_to)

    return response
