# =====================================================
# TEMPLATE HALAMAN GENERATE (REGISTRASI)
# =====================================================
GENERATE_TEMPLATE = """
<!doctype html>
<html lang="id">
<head>
  <meta charset="utf-8">
  <title>Generate JWT (Session-Safe)</title>
  <style>
    body { font-family: Arial, sans-serif; margin: 40px; background: #fafafa; }
    form { background: #fff; padding: 20px; border-radius: 10px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); max-width: 480px; }
    input { width: 100%; padding: 8px; margin: 8px 0; box-sizing: border-box; }
    label { font-weight: bold; display:block; margin-top: 8px; }
    button { background: #007bff; color: white; border: none; padding: 10px 15px; border-radius: 6px; cursor: pointer; }
    button:hover { background: #0056b3; }
    pre { background: #f5f5f5; padding: 10px; border-radius: 6px; overflow-x: auto; }
    .section { margin-top: 30px; }
    .error { color: red; }
  </style>
</head>
<body>
  <h2>🔐 Registrasi User (Token disimpan di Session)</h2>
  <form method="POST">
    <label>Username:</label>
    <input type="text" name="username" required>

    <label>Email:</label>
    <input type="email" name="email" required>

    <label>Password:</label>
    <input type="password" name="password" required>

    <button type="submit">Generate Token</button>
  </form>

  {% if result %}
    {% if result.error %}
      <p class="error">Error: {{ result.error }}</p>
    {% else %}
      <hr>
      <div class="section">
        <h3>Header (decoded)</h3>
        <pre>{{ result.header | tojson(indent=2) }}</pre>

        <h3>Payload (decoded)</h3>
        <pre>{{ result.payload | tojson(indent=2) }}</pre>

        <h3>Signature</h3>
        <pre>{{ result.signature_b64 }}</pre>
      </div>

      {% if display_time %}
        <div class="section">
          <h3>Waktu Token</h3>
          <p><strong>Dibuat:</strong> {{ display_time.created_at }}</p>
          <p><strong>Expired:</strong> {{ display_time.exp }}</p>
        </div>
      {% endif %}

      <div class="section">
        <h3>JWT disimpan di session</h3>
        <p>Token tersimpan di sisi server sampai masa berlakunya habis.</p>
        <form action="/decode" method="GET">
          <button type="submit">🔍 Decode Token dari Session</button>
        </form>
      </div>
    {% endif %}
  {% endif %}
</body>
</html>
"""

# =====================================================
# TEMPLATE HALAMAN DECODE
# =====================================================
DECODE_TEMPLATE = """
<!doctype html>
<html lang="id">
<head>
  <meta charset="utf-8">
  <title>Decode JWT (Session-Aware)</title>
  <style>
    body { font-family: Arial, sans-serif; margin: 40px; background: #fafafa; }
    textarea { width: 100%; height: 100px; }
    pre { background: #f5f5f5; padding: 10px; border-radius: 6px; overflow-x: auto; }
    .error { color: red; }
    .btn {
      display: inline-block;
      padding: 8px 14px;
      margin: 5px 0;
      border-radius: 5px;
      text-decoration: none;
      background-color: #007BFF;
      color: white;
      border: none;
      cursor: pointer;
    }
    .btn:hover { background-color: #0056b3; }
    .btn-logout { background-color: #dc3545; }
    .btn-logout:hover { background-color: #a71d2a; }
  </style>
</head>
<body>
  <h2>🔍 Decode JWT Token</h2>

  <form method="POST">
    <label><strong>Masukkan Token (opsional):</strong></label><br>
    <textarea name="token" placeholder="Decode manual dari JWT"></textarea><br><br>
    <button type="submit" class="btn">Decode</button>
  </form>

  {% if decoded %}
    <hr>
    <h3>Header</h3>
    <pre>{{ decoded.header | tojson(indent=2) }}</pre>

    <h3>Payload</h3>
    <pre>{{ decoded.payload | tojson(indent=2) }}</pre>

    <h3>Signature</h3>
    <pre>{{ decoded.signature }}</pre>

    {% if decoded.token_source %}
      <p><em>Token berasal dari: {{ decoded.token_source }}</em></p>
    {% endif %}

    {% if display_exp_local %}
      <p><strong>Expired (lokal):</strong> {{ display_exp_local }}</p>
    {% endif %}
  {% endif %}

  {% if error %}
    <hr>
    <p class="error">Error: {{ error }}</p>
  {% endif %}

  <hr>
  <a href="/" class="btn">⬅️ Kembali ke halaman Generate</a>
  <a href="/logout" class="btn btn-logout">🚪 Logout (hapus session)</a>
</body>
</html>
"""
