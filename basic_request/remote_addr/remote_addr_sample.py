from flask import Flask, request, jsonify
import ipaddress
import geoip2.database
from geoip2.errors import AddressNotFoundError

# pada kode ini terdapat hole (jika menggunakan proxy maka tidak bisa menemukan ip aslinya) serta membutuhkan database asli untuk deteksi geolocation

app = Flask(__name__)

# Path ke database GeoLite2 (ubah sesuai lokasi)
GEOIP_DB_PATH = "./geoip/GeoLite2-City.mmdb"

# Inisialisasi reader global
reader = geoip2.database.Reader(GEOIP_DB_PATH)

@app.route("/remote", methods=["GET"])
def test_remote():
    # Ambil IP dasar dari Flask
    ip_client = request.remote_addr

    # Ambil header X-Forwarded-For / X-Real-IP
    forwarded_for = request.headers.get("X-Forwarded-For", None)
    real_ip = request.headers.get("X-Real-IP", None)

    # Tentukan IP yang akan dicek geolokasi
    if real_ip:
        ip_to_check = real_ip
    elif forwarded_for:
        # Ambil IP pertama dari daftar
        ip_to_check = forwarded_for.split(",")[0].strip()
    else:
        ip_to_check = ip_client

    # Deteksi kategori IP (private / public / loopback)
    try:
        ip_obj = ipaddress.ip_address(ip_to_check)
        if ip_obj.is_loopback:
            ip_category = "loopback"
        elif ip_obj.is_private:
            ip_category = "private"
        else:
            ip_category = "public"
    except ValueError:
        ip_category = "invalid"

    # Lakukan geolocation lookup
    geo_info = {}
    if ip_category == "public":
        try:
            response = reader.city(ip_to_check)
            geo_info = {
                "country_code": response.country.iso_code,
                "country_name": response.country.name,
                "region": response.subdivisions.most_specific.name,
                "city": response.city.name,
                "latitude": response.location.latitude,
                "longitude": response.location.longitude,
                "postal_code": response.postal.code,
                "timezone": response.location.time_zone,
            }
        except AddressNotFoundError:
            geo_info = {"error": "Geolocation tidak ditemukan untuk IP ini"}

    # Jika IP private / loopback / invalid, tidak melakukan lookup
    return jsonify({
        "type": "remote_addr",
        "remote_addr": ip_client,
        "x_forwarded_for_raw": forwarded_for,
        "x_real_ip": real_ip,
        "detected_client_ip": ip_to_check,
        "ip_category": ip_category,
        "geo_info": geo_info,
        "message": f"Request datang dari IP {ip_to_check} (kategori: {ip_category})"
    })


if __name__ == "__main__":
    app.run(debug=True)