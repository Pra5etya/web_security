# tokens/routes.py
# Blueprint that defines API endpoints and delegates real work to services.
# Routes are small and readable.

from flask import Blueprint, request, jsonify, g
from .middleware import token_required, validate_csrf
from .services import handle_login, handle_refresh, handle_logout

# create Blueprint instance
bp = Blueprint("tokens", __name__)

@bp.route("/api/login", methods=["POST"])
def login():
    """
    Route that handles login requests.
    Delegates to handle_login service (keeps route thin).
    """
    data = request.get_json() or {}
    username = data.get("username")
    password = data.get("password")
    # call service with bp.app (app injected in token_run)
    return handle_login(bp.app, username, password)

@bp.route("/api/protected", methods=["GET", "POST"])
@token_required
@validate_csrf
def protected():
    """
    Protected endpoint example.
    token_required ensures valid access token and sets g.current_user.
    validate_csrf ensures CSRF header matches cookie for non-GET methods.
    """
    return jsonify({"msg": f"Hello, {g.current_user}! Access granted."})

@bp.route("/api/refresh", methods=["POST"])
def refresh():
    """
    Route to refresh tokens.
    Delegates to handle_refresh service.
    """
    refresh_cookie = request.cookies.get(bp.app.config['REFRESH_COOKIE'])
    return handle_refresh(bp.app, refresh_cookie)

@bp.route("/api/logout", methods=["POST"])
def logout():
    """
    Route to logout.
    Delegates to handle_logout service.
    """
    refresh_cookie = request.cookies.get(bp.app.config['REFRESH_COOKIE'])
    return handle_logout(bp.app, refresh_cookie)
