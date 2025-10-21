from flask import Flask, request, jsonify, render_template_string
import re, os

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = "uploads"

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

@app.route("/", methods=["GET", "POST"])
def test_form():
    if request.method == "POST":
        errors = []

        # --- Ambil data dasar ---
        username = request.form.get("username", "guest")
        password = request.form.get("password", "kosong")
        email = request.form.get("email", "")
        role = request.form.get("role", "user")
        hobbies = request.form.getlist("hobbies")

        # --- Nested data (alamat) ---
        alamat = {
            "jalan": request.form.get("alamat_jalan", ""),
            "kota": request.form.get("alamat_kota", ""),
            "kodepos": request.form.get("alamat_kodepos", "")
        }

        # --- Multiple select (skills) ---
        skills = request.form.getlist("skills")

        # --- Validasi sederhana ---
        if len(password) < 6:
            errors.append("Password minimal 6 karakter")
        if email and not re.match(r"[^@]+@[^@]+\.[^@]+", email):
            errors.append("Format email tidak valid")

        # --- File upload (bisa banyak) ---
        uploaded_files = request.files.getlist("documents")
        files_info = []
        for f in uploaded_files:
            if f and f.filename:
                path = os.path.join(app.config['UPLOAD_FOLDER'], f.filename)
                f.save(path)
                files_info.append({
                    "filename": f.filename,
                    "content_type": f.content_type,
                    "size": os.path.getsize(path)
                })

        if errors:
            return jsonify({"status": "error", "errors": errors}), 400

        return jsonify({
            "status": "success",
            "message": f"User {username} terdaftar dengan role {role}",
            "data": {
                "username": username,
                "email": email,
                "role": role,
                "hobbies": hobbies,
                "alamat": alamat,
                "skills": skills,
                "uploaded_files": files_info
            }
        })

    # --- HTML Form dengan AJAX (fetch) ---
    return render_template_string('''
        <h2>Form Registrasi Lengkap</h2>
        <form id="regForm" enctype="multipart/form-data">
            <label>Username:</label><br>
            <input type="text" name="username" placeholder="Username"><br><br>
            
            <label>Password:</label><br>
            <input type="password" name="password" placeholder="Password"><br><br>

            <label>Email:</label><br>
            <input type="email" name="email" placeholder="Email"><br><br>

            <label>Role:</label><br>
            <select name="role">
                <option value="user">User</option>
                <option value="admin">Admin</option>
                <option value="moderator">Moderator</option>
            </select><br><br>

            <label>Hobi:</label><br>
            <input type="checkbox" name="hobbies" value="coding"> Coding<br>
            <input type="checkbox" name="hobbies" value="gaming"> Gaming<br>
            <input type="checkbox" name="hobbies" value="reading"> Reading<br><br>

            <label>Alamat:</label><br>
            Jalan: <input type="text" name="alamat_jalan"><br>
            Kota: <input type="text" name="alamat_kota"><br>
            Kode Pos: <input type="text" name="alamat_kodepos"><br><br>

            <label>Skills (CTRL+Click untuk multi):</label><br>
            <select name="skills" multiple size="4">
                <option value="python">Python</option>
                <option value="flask">Flask</option>
                <option value="js">JavaScript</option>
                <option value="sql">SQL</option>
            </select><br><br>

            <label>Upload Dokumen (boleh banyak):</label><br>
            <input type="file" name="documents" multiple><br><br>

            <!-- Hidden field simulasi CSRF token -->
            <input type="hidden" name="csrf_token" value="dummy_token_12345">

            <button type="submit">Daftar</button>
        </form>

        <h3>Hasil Response:</h3>
        <pre id="result"></pre>

        <script>
        document.getElementById("regForm").addEventListener("submit", async function(e) {
            e.preventDefault(); // cegah reload

            let formData = new FormData(this);

            try {
                let response = await fetch("/", {
                    method: "POST",
                    body: formData
                });

                let data = await response.json();
                document.getElementById("result").textContent = JSON.stringify(data, null, 2);
            } catch (err) {
                document.getElementById("result").textContent = "Error: " + err;
            }
        });
        </script>
    ''')


if __name__ == "__main__":
    app.run(debug=True)
