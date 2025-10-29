import base64  # Modul bawaan Python untuk operasi Base64 (encoding & decoding)


def base64url_encode(data: bytes) -> str:
    # Encode data bytes ke Base64 varian URL-safe (terdapat '=')
    encoded = base64.urlsafe_b64encode(data)
    return encoded.decode().rstrip("=")


def base64url_decode(data: str) -> bytes:
    # (-len(data) % 4) akan menghasilkan 0, 1, 2, atau 3.
    padding = '=' * (-len(data) % 4)

    # Gabungkan padding dan decode menggunakan varian URL-safe
    return base64.urlsafe_b64decode(data + padding)
