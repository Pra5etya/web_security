from flask import Flask, request, jsonify, make_response

import secrets

tokens = {}  # simpan token aktif

@app.route("/login-token", methods=["POST"])
def login_token():
    data = request.json
    username = data.get("username")
    password = data.get("password")

    if users.get(username) == password:
        token = secrets.token_hex(16)  # generate token random
        tokens[token] = username
        return {"access_token": token}
    return {"error": "Login gagal"}, 401

@app.route("/protected", methods=["GET"])
def protected():
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        return {"error": "Token tidak ada"}, 401

    token = auth_header.split(" ")[1]
    username = tokens.get(token)

    if not username:
        return {"error": "Token tidak valid"}, 401

    return {"message": f"Halo {username}, ini halaman rahasia!"}
