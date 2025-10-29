# tokens/services.py
# Business logic functions for login, refresh, and logout.
# Each function receives 'app' or minimal inputs to avoid tight coupling to Flask in tests.

from flask import jsonify, make_response
from .utils import gen_random_string, hash_token_hmac

def handle_login(app, username, password):
    """
    Business logic for login:
    - Validate credentials (demo check here).
    - Generate token pair using app.token_manager.
    - Store hashed refresh token in app.token_store.
    - Create CSRF token and map it to refresh jti.
    - Return Flask response with cookies set.
    """
    # simple demo validation; in production use password hash verify
    if not username or username != password:
        return jsonify({"msg": "invalid credentials"}), 401

    # create tokens
    access_token, refresh_token, refresh_jti = app.token_manager.create_token_pair(username)

    # store hashed refresh token to storage
    refresh_hash = hash_token_hmac(refresh_token, app.config['REFRESH_TOKEN_SALT'])
    app.token_store.insert_refresh(refresh_jti, username, refresh_hash, app.token_manager.refresh_exp_ts())

    # create CSRF token and map to jti
    csrf_val = gen_random_string(24)
    app.token_store.store_csrf_for_jti(refresh_jti, csrf_val)

    # build response and set cookies
    resp = make_response(jsonify({"msg": "logged in"}))
    resp.set_cookie(app.config['ACCESS_COOKIE'], access_token, httponly=True, secure=app.config['COOKIE_SECURE'], samesite=app.config['COOKIE_SAMESITE'])
    resp.set_cookie(app.config['REFRESH_COOKIE'], refresh_token, httponly=True, secure=app.config['COOKIE_SECURE'], samesite=app.config['COOKIE_SAMESITE'])
    resp.set_cookie(app.config['CSRF_COOKIE'], csrf_val, httponly=False, secure=app.config['COOKIE_SECURE'], samesite=app.config['COOKIE_SAMESITE'])
    return resp

def handle_refresh(app, refresh_cookie):
    """
    Business logic for refreshing:
    - Rotate refresh token safely using TokenManager.rotate_refresh.
    - On success, store new CSRF and set new cookies.
    """
    result = app.token_manager.rotate_refresh(refresh_cookie, app.token_store)
    if not result["ok"]:
        return jsonify({"msg": result["msg"]}), 401

    new_access, new_refresh, new_jti = result["tokens"]
    csrf_val = gen_random_string(24)
    app.token_store.store_csrf_for_jti(new_jti, csrf_val)

    resp = make_response(jsonify({"msg": "token refreshed"}))
    resp.set_cookie(app.config['ACCESS_COOKIE'], new_access, httponly=True, secure=app.config['COOKIE_SECURE'], samesite=app.config['COOKIE_SAMESITE'])
    resp.set_cookie(app.config['REFRESH_COOKIE'], new_refresh, httponly=True, secure=app.config['COOKIE_SECURE'], samesite=app.config['COOKIE_SAMESITE'])
    resp.set_cookie(app.config['CSRF_COOKIE'], csrf_val, httponly=False, secure=app.config['COOKIE_SECURE'], samesite=app.config['COOKIE_SAMESITE'])
    return resp

def handle_logout(app, refresh_cookie):
    """
    Business logic for logout:
    - If refresh token present, mark it revoked in storage.
    - Return response that clears cookies.
    """
    if refresh_cookie:
        decoded = app.token_manager.decode(refresh_cookie, expect_type="refresh")
        if decoded:
            app.token_store.mark_revoked(decoded['jti'])

    resp = make_response(jsonify({"msg": "logged out"}))
    # delete cookies to remove session from client
    resp.delete_cookie(app.config['ACCESS_COOKIE'])
    resp.delete_cookie(app.config['REFRESH_COOKIE'])
    resp.delete_cookie(app.config['CSRF_COOKIE'])
    return resp
