import base64
import hmac
import hashlib
import json
import time
from flask import Flask, request, jsonify

app = Flask(__name__)
SECRET_KEY = "mysecretkey"  # ganti dengan key aman

# --- Helper functions ---
def base64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('utf-8')

def base64url_decode(data: str) -> bytes:
    padding = '=' * (4 - (len(data) % 4))
    return base64.urlsafe_b64decode(data + padding)

def create_jwt(payload: dict, secret: str) -> str:
    header = {"alg": "HS256", "typ": "JWT"}

    header_b64 = base64url_encode(json.dumps(header).encode())
    payload_b64 = base64url_encode(json.dumps(payload).encode())

    signature_input = f"{header_b64}.{payload_b64}".encode()
    signature = hmac.new(secret.encode(), signature_input, hashlib.sha256).digest()
    signature_b64 = base64url_encode(signature)

    return f"{header_b64}.{payload_b64}.{signature_b64}"

def verify_jwt(token: str, secret: str) -> dict:
    try:
        header_b64, payload_b64, signature_b64 = token.split('.')

        signature_input = f"{header_b64}.{payload_b64}".encode()
        expected_signature = hmac.new(secret.encode(), signature_input, hashlib.sha256).digest()
        expected_signature_b64 = base64url_encode(expected_signature)

        if not hmac.compare_digest(expected_signature_b64, signature_b64):
            return None

        payload = json.loads(base64url_decode(payload_b64))
        if "exp" in payload and time.time() > payload["exp"]:
            return None  # Token expired

        return payload
    except Exception:
        return None


# --- Flask routes ---
@app.route("/login", methods=["POST"])
def login():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")

    # validasi sederhana
    if username == "admin" and password == "123":
        payload = {
            "user": username,
            "exp": time.time() + 60  # berlaku 1 menit
        }
        token = create_jwt(payload, SECRET_KEY)
        return jsonify({"token": token})
    return jsonify({"error": "invalid credentials"}), 401


@app.route("/protected", methods=["GET"])
def protected():
    auth_header = request.headers.get("Authorization")
    if not auth_header:
        return jsonify({"error": "Missing token"}), 401

    token = auth_header.split(" ")[1]
    payload = verify_jwt(token, SECRET_KEY)

    if not payload:
        return jsonify({"error": "Invalid or expired token"}), 403

    return jsonify({"message": "Access granted", "user": payload["user"]})


if __name__ == "__main__":
    app.run(debug=True)
