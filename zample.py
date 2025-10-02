from flask import Flask, request, jsonify, render_template_string

app = Flask(__name__)

# 1. Args (Query String)
@app.route("/args", methods=["GET"])
def test_args():
    # Ambil parameter dari URL query string (?name=...&age=...)
    # misal -> http://localhost:5000/args?name=raka&age=25
    name = request.args.get("name", "Anonim")
    age = request.args.get("age", "Tidak diketahui")

    return jsonify({
        "type": "args",
        "message": f"Halo {name}, umur kamu {age} tahun!",
        "name": name,
        "age": age
    })


# 2.

# ==============================
# FORM DATA (x-www-form-urlencoded atau multipart/form-data)
# ==============================
@app.route("/form", methods=["GET", "POST"])
def test_form():
    if request.method == "POST":
        username = request.form.get("username", "guest")
        password = request.form.get("password", "kosong")
        return jsonify({
            "type": "form",
            "message": f"Login sebagai {username} dengan password {password}",
            "username": username,
            "password": password
        })
    # Kalau GET, tampilkan HTML form sederhana
    return render_template_string('''
        <h2>Form Login</h2>
        <form method="post">
            <input type="text" name="username" placeholder="Username"><br>
            <input type="password" name="password" placeholder="Password"><br>
            <button type="submit">Login</button>
        </form>
    ''')


# ==============================
# JSON DATA (application/json)
# ==============================
@app.route("/json", methods=["POST"])
def test_json():
    # Coba ambil data JSON dari body
    data = request.get_json(silent=True)

    if not data:
        return jsonify({
            "error": "Request harus berisi JSON dengan Content-Type application/json"
        }), 400

    username = data.get("username", "guest")
    password = data.get("password", "kosong")

    return jsonify({
        "type": "json",
        "message": f"Login JSON sebagai {username} dengan password {password}",
        "username": username,
        "password": password
    })


# 3. Method (GET, POST, PUT, DELETE)
@app.route("/method", methods=["GET", "POST", "PUT", "DELETE"])
def test_method():
    return jsonify({
        "type": "method",
        "message": f"Request diterima dengan method {request.method}",
        "method": request.method
    })


# 4. Remote Address (IP Client)
@app.route("/remote", methods=["GET"])
def test_remote():
    ip_client = request.remote_addr
    return jsonify({
        "type": "remote_addr",
        "message": f"Request datang dari IP {ip_client}",
        "ip": ip_client
    })


if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0')
