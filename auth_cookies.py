from flask import Flask, request, jsonify, make_response

app = Flask(__name__)

users = {"raka": "1234"}  # fake database

@app.route("/login", methods=["POST"])
def login():
    data = request.json
    
    username = data.get("username")
    password = data.get("password")

    if users.get(username) == password:
        resp = make_response({"message": "Login sukses"})
        resp.set_cookie("session_id", "user-" + username)  # set cookie
        return resp
    
    return {"error": "Login gagal"}, 401

@app.route("/profile", methods=["GET"])
def profile():
    session_id = request.cookies.get("session_id")
    if not session_id:
        return {"error": "Belum login"}, 401
    return {"message": f"Ini profil untuk {session_id}"}


if __name__ == "__main__":
    app.run(debug=True)
