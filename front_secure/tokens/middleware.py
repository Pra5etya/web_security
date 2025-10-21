# tokens/middleware.py
# Lightweight Flask decorators for verifying access tokens and CSRF double-submit.
# Keep decorators minimal: they should call TokenManager on app object.

from functools import wraps
from flask import request, jsonify, g, current_app

def token_required(f):
    """
    Decorator to assert that a valid access token (from cookie) exists.
    - Reads access token from configured cookie name.
    - Decodes via app.token_manager.decode.
    - On success, stores current user identifier in flask.g for downstream use.
    """
    @wraps(f)
    def wrapper(*args, **kwargs):
        # read access token from cookie configured in app
        token = request.cookies.get(current_app.config['ACCESS_COOKIE'])
        if not token:
            # no token provided
            return jsonify({"msg": "missing access token"}), 401

        # decode & validate token
        payload = current_app.token_manager.decode(token, expect_type="access")
        if not payload:
            # invalid or expired
            return jsonify({"msg": "invalid or expired access token"}), 401

        # attach current user to flask.g for usage in view
        g.current_user = payload.get("sub")
        return f(*args, **kwargs)
    return wrapper

def validate_csrf(f):
    """
    Decorator to enforce CSRF validation for state-changing requests.
    - Expects a non-HttpOnly cookie containing CSRF token and a header with the same value.
    - Skips validation for safe HTTP methods (GET, HEAD, OPTIONS).
    """
    @wraps(f)
    def wrapper(*args, **kwargs):
        # Only enforce for unsafe methods
        if request.method not in ("GET", "HEAD", "OPTIONS"):
            # get cookie and header
            cookie_val = request.cookies.get(current_app.config['CSRF_COOKIE'])
            header_val = request.headers.get(current_app.config['CSRF_HEADER'])
            # missing or mismatch -> forbidden
            if not cookie_val or not header_val or cookie_val != header_val:
                return jsonify({"msg": "CSRF validation failed"}), 403
        return f(*args, **kwargs)
    return wrapper
