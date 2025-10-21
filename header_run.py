from flask import Flask
from front_secure.header import (
    generate_nonce,
    apply_secure_headers
)

app = Flask(__name__)

# sebelum request — buat nonce unik per request
app.before_request(generate_nonce)

# setelah request — terapkan semua header keamanan
app.after_request(apply_secure_headers)

@app.route("/")
def index():
    return "<h1>✅ Semua Security Header aktif!</h1>"

if __name__ == "__main__":
    app.run(debug=True)
