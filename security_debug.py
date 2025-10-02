from flask import Flask, request, make_response

app = Flask(__name__)

# Route GET biasa
@app.route("/", methods=["GET"])
def home():
    return "Halo! Coba akses /info /set_cookie ~ /get_cookie"


# Contoh set cookie ke client
@app.route("/set_cookie", methods=["GET"])
def set_cookie():
    response = make_response("Cookie sudah diset!")
    response.set_cookie("user_id", "12345")     # Membuat request ke cookies
    return response


# Contoh baca cookie dari request
@app.route("/get_cookie", methods=["GET"])
def get_cookie():
    user_id = request.cookies.get("user_id", "Belum ada cookie")
    return f"Cookie user_id: {user_id}"


if __name__ == "__main__":
    app.run(debug=True)
