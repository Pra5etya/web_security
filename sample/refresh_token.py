refresh_tokens = {}

@app.route("/login-refresh", methods=["POST"])
def login_refresh():
    data = request.json
    username = data.get("username")
    password = data.get("password")

    if users.get(username) == password:
        access_payload = {
            "user": username,
            "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=1)
        }
        refresh_payload = {
            "user": username,
            "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=10)
        }

        access_token = jwt.encode(access_payload, SECRET_KEY, algorithm="HS256")
        refresh_token = jwt.encode(refresh_payload, SECRET_KEY, algorithm="HS256")

        refresh_tokens[refresh_token] = username

        return {"access_token": access_token, "refresh_token": refresh_token}
    return {"error": "Login gagal"}, 401

@app.route("/refresh", methods=["POST"])
def refresh():
    data = request.json
    refresh_token = data.get("refresh_token")

    try:
        decoded = jwt.decode(refresh_token, SECRET_KEY, algorithms=["HS256"])
        username = decoded["user"]

        if refresh_token not in refresh_tokens:
            return {"error": "Refresh token tidak valid"}, 401

        new_access_payload = {
            "user": username,
            "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=1)
        }
        new_access_token = jwt.encode(new_access_payload, SECRET_KEY, algorithm="HS256")

        return {"access_token": new_access_token}
    except jwt.ExpiredSignatureError:
        return {"error": "Refresh token kadaluarsa"}, 401
    except jwt.InvalidTokenError:
        return {"error": "Refresh token tidak valid"}, 401
