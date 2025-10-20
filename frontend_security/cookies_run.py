from flask import Flask, request, jsonify
from cookies import register_security_middleware, verify_csrf_request, verify_secure_session_cookie

app = Flask(__name__)
app.secret_key = "super-secret-key-change-me"

register_security_middleware(app, excluded_routes=["login", "public_endpoint"])

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
    if not verify_csrf_request(request):
        return {"error": "CSRF verification failed"}, 403
    
    if not verify_secure_session_cookie(request):
        return {"error": "Invalid session"}, 401
    
    return {"message": "Profil berhasil diperbarui"}

if __name__ == "__main__":
    app.run(debug=True, 
            ssl_context = "adhoc")  # testing HTTPS Local untuk menguji Secure cookie, SameSite, atau CSP
