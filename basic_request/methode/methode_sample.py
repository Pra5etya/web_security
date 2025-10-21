from flask import Flask, request, jsonify, render_template_string
import uuid

app = Flask(__name__)

# fake database, key = username (unik)
users = {
    "raka": {"id": str(uuid.uuid4()), "username": "raka", "password": "1234"},
    "budi": {"id": str(uuid.uuid4()), "username": "budi", "password": "abcd"}
}


@app.route("/")
def index():
    return render_template_string("""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Flask Method Demo</title>
    </head>
    <body>
        <h1>Demo Request Method di Flask</h1>

        <h2>GET (ambil semua user)</h2>
        <button onclick="getUsers()">GET Users</button>
        <pre id="getResult"></pre>

        <h2>POST (tambah user)</h2>
        <form id="postForm">
            <input type="text" name="username" placeholder="username" required>
            <input type="password" name="password" placeholder="password" required>
            <button type="submit">Tambah User</button>
        </form>
        <pre id="postResult"></pre>

        <h2>PUT (update user)</h2>
        <form id="putForm">
            <input type="text" name="username" placeholder="username (unik)" required>
            <input type="text" name="new_username" placeholder="username baru">
            <input type="password" name="password" placeholder="password baru">
            <button type="submit">Update User</button>
        </form>
        <pre id="putResult"></pre>

        <h2>DELETE (hapus user)</h2>
        <form id="deleteForm">
            <input type="text" name="username" placeholder="username" required>
            <button type="submit">Hapus User</button>
        </form>
        <pre id="deleteResult"></pre>

        <script>
            // GET
            function getUsers() {
                fetch('/method')
                .then(res => res.json())
                .then(data => {
                    document.getElementById('getResult').textContent = JSON.stringify(data, null, 2);
                });
            }

            // POST
            document.getElementById("postForm").addEventListener("submit", function(e) {
                e.preventDefault();
                const formData = new FormData(e.target);
                fetch('/method', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(Object.fromEntries(formData))
                })
                .then(res => res.json())
                .then(data => {
                    document.getElementById('postResult').textContent = JSON.stringify(data, null, 2);
                });
            });

            // PUT
            document.getElementById("putForm").addEventListener("submit", function(e) {
                e.preventDefault();
                const formData = new FormData(e.target);
                fetch('/method', {
                    method: 'PUT',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(Object.fromEntries(formData))
                })
                .then(res => res.json())
                .then(data => {
                    document.getElementById('putResult').textContent = JSON.stringify(data, null, 2);
                });
            });

            // DELETE
            document.getElementById("deleteForm").addEventListener("submit", function(e) {
                e.preventDefault();
                const formData = new FormData(e.target);
                fetch('/method', {
                    method: 'DELETE',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(Object.fromEntries(formData))
                })
                .then(res => res.json())
                .then(data => {
                    document.getElementById('deleteResult').textContent = JSON.stringify(data, null, 2);
                });
            });
        </script>
    </body>
    </html>
    """)


@app.route("/method", methods=["GET", "POST", "PUT", "DELETE"])
def test_method():
    if request.method == "GET":
        return jsonify({
            "type": "method",
            "message": "GET: ambil semua data user",
            "data": list(users.values())  # list karena dict keyed by username
        })

    elif request.method == "POST":
        data = request.get_json()
        username = data.get("username")
        password = data.get("password", "kosong")

        if username in users:
            return jsonify({"error": "Username sudah ada"}), 409

        new_user = {
            "id": str(uuid.uuid4()),
            "username": username,
            "password": password
        }
        users[username] = new_user
        return jsonify({
            "type": "method",
            "message": "POST: user baru ditambahkan",
            "new_user": new_user
        }), 201

    elif request.method == "PUT":
        data = request.get_json()
        username = data.get("username")

        if username not in users:
            return jsonify({"error": "User tidak ditemukan"}), 404

        # update user
        if data.get("new_username"):
            new_username = data.get("new_username")
            if new_username in users:
                return jsonify({"error": "Username baru sudah digunakan"}), 409
            users[new_username] = users.pop(username)
            users[new_username]["username"] = new_username
            username = new_username

        if data.get("password"):
            users[username]["password"] = data.get("password")

        return jsonify({
            "type": "method",
            "message": f"PUT: user {username} diperbarui",
            "updated_user": users[username]
        })

    elif request.method == "DELETE":
        data = request.get_json()
        username = data.get("username")

        if username not in users:
            return jsonify({"error": "User tidak ditemukan"}), 404

        deleted = users.pop(username)
        return jsonify({
            "type": "method",
            "message": f"DELETE: user {username} dihapus",
            "deleted_user": deleted
        })


if __name__ == "__main__":
    app.run(debug=True)
