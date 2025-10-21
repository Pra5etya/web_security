from flask import Flask, request, jsonify, render_template_string

app = Flask(__name__)

@app.route("/")
def home():
    return render_template_string("""
        <h2>Halo!</h2>
        <p>
            Coba akses:
            <ul>
                <li><a href="/args">/args</a></li>
                <li><a href="/args/multiple">/args/multiple</a></li>
                <li><a href="/args/list">/args/list</a></li>
                <li><a href="/args/filter">/args/filter</a></li>
                <li><a href="/args/pagination">/args/pagination</a></li>
            </ul>
        </p>
        <p>
            <b>Note:</b> Jangan lupa tambahkan query string 
            (<code>?nama_param=param_value</code>) agar bisa mengakses query-nya.
            <b>Misal:</b> http://localhost:5000/args?name=raka&age=25
        </p>
    """)

# 1. Args sederhana (query string biasa)
@app.route("/args", methods=["GET"])
def test_args():
    # Ambil parameter dari URL query string (?name=...&age=...)
    # misal -> /args?name=raka&age=25
    name = request.args.get("name", "Anonim")
    age = request.args.get("age", "Tidak diketahui")

    return jsonify({
        "type": "args",
        "message": f"Halo {name}, umur kamu {age} tahun!",
        "name": name,
        "age": age
    })


# 2. Args multiple parameter
@app.route("/args/multiple", methods=["GET"])
def args_multiple():
    # misal -> /args/multiple?username=raka&role=admin&active=true
    username = request.args.get("username", "guest")
    role = request.args.get("role", "user")
    active = request.args.get("active", "false")

    return jsonify({
        "username": username,
        "role": role,
        "messages": "misal -> /args/multiple?username=x&role=x&active=x", 
        "active": active
    })


# 3. Args dengan list parameter
@app.route("/args/list", methods=["GET"])
def args_list():
    # misal -> /args/list?hobi=ngoding&hobi=makan&hobi=tidur
    hobi = request.args.getlist("hobi")  # ambil semua nilai dari query "hobi"

    return jsonify({
        "type": "args-list",
        "total_hobi": len(hobi),
        "messages": "/args/list?hobi=x&hobi=x&hobi=x",
        "hobi": hobi
    })


# 4. Args filtering (misal untuk pencarian)
@app.route("/args/filter", methods=["GET"])
def args_filter():
    # Data dummy
    users = [
        {"id": 1, "name": "Raka", "age": 25},
        {"id": 2, "name": "Budi", "age": 30},
        {"id": 3, "name": "Siti", "age": 22},
        {"id": 4, "name": "Raka", "age": 28},
    ]

    # query string: /args/filter?name=Raka&min_age=26
    name = request.args.get("name")
    min_age = request.args.get("min_age", type=int)
    list_data = request.args.getlist("list_data")

    result = users

    if name:
        result = [u for u in result if u["name"].lower() == name.lower()]

    if min_age:
        result = [u for u in result if u["age"] >= min_age]

    return jsonify({
        "query": {"name": name, "min_age": min_age},
        "result": result, 
        "messages": "misal -> /args/filter?name=x&min_age=x", 
        "list_data": list_data
    })


# 5. Args dengan pagination
@app.route("/args/pagination", methods=["GET"])
def args_pagination():
    # Data dummy
    items = list(range(1, 51))  # angka 1 sampai 50
    # contoh: /args/pagination?page=2&limit=10
    page = request.args.get("page", 1, type=int)
    limit = request.args.get("limit", 5, type=int)

    start = (page - 1) * limit
    end = start + limit
    paged_items = items[start:end]

    return jsonify({
        "page": page,
        "limit": limit,
        "items": paged_items,
        "total": len(items), 
        "messages": "contoh: /args/pagination?page=2&limit=10"
    })


if __name__ == "__main__":
    app.run(debug=True)
