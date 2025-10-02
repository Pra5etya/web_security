import jwt
import datetime

SECRET_KEY = "rahasia_super_sulit"

@app.route("/login-jwt", methods=["POST"])
def login_jwt():
    data = request.json
    username = data.get("username")
    password = data.get("password")

    if users.get(username) == password:
        payload = {
            "user": username,
            "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=5)  # expired 5 menit
        }
        token = jwt.encode(payload, SECRET_KEY, algorithm="HS256")
        return {"jwt": token}
    return {"error": "Login gagal"}, 401

@app.route("/jwt-protected", methods=["GET"])
def jwt_protected():
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        return {"error": "JWT tidak ada"}, 401

    token = auth_header.split(" ")[1]

    try:
        decoded = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        return {"message": f"Halo {decoded['user']}, JWT valid!"}
    except jwt.ExpiredSignatureError:
        return {"error": "JWT kadaluarsa"}, 401
    except jwt.InvalidTokenError:
        return {"error": "JWT tidak valid"}, 401
