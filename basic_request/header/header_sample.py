from flask import Flask, request, make_response, jsonify, redirect

app = Flask(__name__)

# Route GET biasa
@app.route("/", methods=["GET"])
def home():
    return "Halo! Coba akses /info, /play, atau /set-cookie"


# Menampilkan semua info dari request
@app.route("/info", methods=["GET", "POST"])
def info():
    header = {
        # semua header dalam bentuk dict
        "all_headers": dict(request.headers),

        # shortcut terkait Content-Type
        "content_type": request.content_type,
        "mimetype": request.mimetype,
        "mimetype_params": dict(request.mimetype_params),

        # Accept headers
        # ==============

        # MIMEAccept object, iterable (mirip list of tuple).
        "accept_mimetypes": list(request.accept_mimetypes),     # contoh: [('text/html', 1), ('application/json', 0.9)]

        # LanguageAccept object, iterable (mirip list of tuple).
        "accept_languages": list(request.accept_languages),     # contoh: [('en-US', 1), ('id', 0.8)]
        "accept_charsets": list(request.accept_charsets),
        "accept_encodings": list(request.accept_encodings),

        # User-Agent detail
        "user_agent": {
            "string": request.user_agent.string,
            "platform": request.user_agent.platform,
            "browser": request.user_agent.browser,
            "version": request.user_agent.version,
            "language": request.user_agent.language
        },

        # Cookies (ubah ke dict biar JSON valid)
        "cookies": dict(request.cookies),

        # Authorization (di-cast ke string supaya aman)
        "authorization": str(request.authorization),

        # Informasi client & host
        "remote_addr": request.remote_addr,
        "host": request.host,
        "url_root": request.url_root
        }

    data = {
        "method": request.method,                       # Method (GET/POST/...)
        "url": request.url,                             # URL lengkap
        "path": request.path,                           # Path (tanpa query string)
        "query_params": request.args.to_dict(),         # Query string (?key=value)
        "all_header": header,                           # Semua headers
        "json_body": request.get_json(silent = True),   # JSON body jika ada
        "form_data": request.form.to_dict(),            # Form data (POST form)
    }
    return jsonify(data)  # Otomatis jadi response JSON


@app.route("/play")
def playground():
    # Ambil header custom (kalau ada)
    custom1 = request.headers.get("X-My-Header", "Tidak ada")   # membuat request ke header
    custom2 = request.headers.get("X-Api-Key", "Tidak ada")     # membuat request ke header

    return jsonify({
        "message": "Playground: uji coba header",
        "custom_headers": {
            "X-My-Header": custom1,
            "X-Api-Key": custom2
        }
    })


if __name__ == "__main__":
    app.run(debug=True)