import jwt
from datetime import datetime, timedelta
from flask import current_app
from .jwt_manager import generate_access_token

_refresh_store = {}  # Simulasi penyimpanan refresh token

def generate_refresh_token(user_id):
    payload = {
        "sub": user_id,
        "type": "refresh",
        "exp": datetime.utcnow() + timedelta(seconds=current_app.config["REFRESH_TOKEN_EXPIRE"])
    }
    token = jwt.encode(payload, current_app.config["SECRET_KEY"], algorithm="HS256")
    _refresh_store[user_id] = token
    return token

def refresh_access_token(refresh_token):
    try:
        payload = jwt.decode(refresh_token, current_app.config["SECRET_KEY"], algorithms=["HS256"])
        if payload.get("type") != "refresh":
            return {"error": "invalid refresh token type"}

        stored = _refresh_store.get(payload["sub"])
        if not stored or stored != refresh_token:
            return {"error": "refresh token revoked or invalid"}

        new_access = generate_access_token({"sub": payload["sub"]})
        return {"access_token": new_access}

    except jwt.ExpiredSignatureError:
        return {"error": "refresh token expired"}
    except jwt.InvalidTokenError:
        return {"error": "invalid refresh token"}
