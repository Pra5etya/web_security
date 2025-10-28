import base64  # Modul bawaan Python untuk operasi Base64 (encoding & decoding)


def base64url_encode(data: bytes) -> str:
    # 1️⃣ Encode data bytes ke Base64 varian URL-safe (terdapat '=')
    encoded = base64.urlsafe_b64encode(data)

    """ 
        2️⃣ Ubah dari bytes ke string dan hilangkan '=' di akhir
        (padding dihapus agar format sesuai spesifikasi JWT)
    """
    return encoded.decode().rstrip("=")


def base64url_decode(data: str) -> bytes:
    """ 
        1️⃣ Hitung berapa padding '=' yang perlu ditambahkan.
        Base64 membutuhkan panjang data kelipatan 4 karakter.
    """

    # (-len(data) % 4) akan menghasilkan 0, 1, 2, atau 3.
    padding = '=' * (-len(data) % 4)

    # 2️⃣ Gabungkan padding dan decode menggunakan varian URL-safe
    return base64.urlsafe_b64decode(data + padding)
