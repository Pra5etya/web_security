import base64  # Modul bawaan Python untuk operasi Base64 (encoding & decoding)


def base64url_encode(data: bytes) -> str:
    """
    Encode bytes menjadi Base64URL tanpa padding '='.

    JWT tidak menggunakan Base64 standar karena karakter '+' dan '/' 
    bisa bermasalah di URL. Maka digunakan varian 'URL-safe' 
    dengan mengganti:
        '+' → '-'
        '/' → '_'

    Selain itu, padding '=' dihapus agar token lebih ringkas 
    dan tetap valid sesuai standar RFC 7515 (JWS Compact Serialization).

    Parameter:
    ----------
    data : bytes
        Data mentah (biasanya hasil JSON.encode atau hasil HMAC sign)
        yang akan dikonversi menjadi string Base64URL.

    Return:
    -------
    str : String hasil encode yang siap digabungkan di JWT.
    """

    # 1️⃣ Encode data bytes ke Base64 varian URL-safe
    encoded = base64.urlsafe_b64encode(data)

    # 2️⃣ Ubah dari bytes ke string dan hilangkan '=' di akhir
    # (padding dihapus agar format sesuai spesifikasi JWT)
    return encoded.decode().rstrip("=")


def base64url_decode(data: str) -> bytes:
    """
    Decode Base64URL string kembali ke bytes asli.

    Karena padding '=' dihapus saat encoding JWT, 
    maka sebelum decoding kita perlu menambahkannya kembali.
    Jumlah padding ditentukan agar panjang data kelipatan 4.

    Parameter:
    ----------
    data : str
        String Base64URL (tanpa padding) yang ingin di-decode 
        menjadi bytes asli.

    Return:
    -------
    bytes : Data asli hasil decoding.
    """

    # 1️⃣ Hitung berapa padding '=' yang perlu ditambahkan.
    # Base64 membutuhkan panjang data kelipatan 4 karakter.
    # (-len(data) % 4) akan menghasilkan 0, 1, 2, atau 3.
    padding = '=' * (-len(data) % 4)

    # 2️⃣ Gabungkan padding dan decode menggunakan varian URL-safe
    return base64.urlsafe_b64decode(data + padding)
