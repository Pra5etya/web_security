from flask import request, g
from .cookies_xss import mitigate_cookie_theft_via_xss
from .csrf_protection import set_csrf_cookie, verify_csrf_request
from .session_protection import create_secure_session_cookie, verify_secure_session_cookie
from .headers import set_security_headers
import logging

logger = logging.getLogger("security")

def register_security_middleware(app, excluded_routes=None):
    """
    Middleware entry+exit
    """
    if excluded_routes is None:
        excluded_routes = []

    @app.before_request
    def before_request():
        g.fingerprint = f"{request.headers.get('X-Forwarded-For', request.remote_addr)}|{request.headers.get('User-Agent','')[:100]}"
        endpoint = request.endpoint
        if endpoint in excluded_routes:
            return None

        if not verify_secure_session_cookie(request):
            logger.warning(f"Invalid session for {endpoint} from {request.remote_addr}")
            return {"error": "Invalid session"}, 401

        if request.method in ["POST", "PUT", "DELETE"]:
            if not verify_csrf_request(request):
                logger.warning(f"CSRF verification failed for {endpoint} from {request.remote_addr}")
                return {"error": "CSRF verification failed"}, 403

        return None

    @app.after_request
    def after_request(response):
        endpoint = request.endpoint
        if endpoint in excluded_routes:
            return response

        response = set_security_headers(response)
        response = mitigate_cookie_theft_via_xss(response)
        response = create_secure_session_cookie(response)
        response, _ = set_csrf_cookie(response)

        return response
