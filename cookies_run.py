from flask import Flask

from front_secure.cookies import apply_secure_cookies

app = Flask(__name__)
app.secret_key = "super-secret-key-change-me"

# Aktifkan semua lapisan keamanan
apply_secure_cookies(app, excluded_routes=["login", "public_endpoint"])

@app.route('/')
def home():
    return 'Hello, Flask with HTTPS!'

@app.route("/login")
def login():
    return {"message": "Login berhasil"}

@app.route("/public")
def public_endpoint():
    return {"message": "Endpoint publik"}

@app.route("/update-profile", methods=["POST"])
def update_profile():
    return {"message": "Profil berhasil diperbarui"}

if __name__ == "__main__":
    app.run(debug=True, 
            ssl_context = "adhoc")  # testing HTTPS Local untuk menguji Secure cookie, SameSite, atau CSP
