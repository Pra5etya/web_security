from flask import request, Response
import hmac
from .utils import generate_token

def set_csrf_cookie(
    response: Response,
    cookie_name: str = "csrf_token",
    header_name: str = "X-CSRF-Token",
    token: str | None = None,
    token_length: int = 32,
    max_age: int = 1800,
    path: str = "/",
    domain: str | None = None,
    secure: bool = True,
    http_only: bool = False,
    same_site: str = "Lax",
    ensure_domain_from_request: bool = True
):
    """
    Set CSRF cookie (double-submit)
    """
    if domain is None and ensure_domain_from_request:
        domain = request.host

    if same_site not in {"Strict", "Lax", "None"}:
        raise ValueError("same_site harus 'Strict', 'Lax', atau 'None'")

    if token is None:
        token = generate_token(token_length)

    response.set_cookie(
        key=cookie_name,
        value=token,
        max_age=max_age,
        path=path,
        domain=domain,
        secure=secure,
        httponly=http_only,
        samesite=same_site
    )
    return response, token


def verify_csrf_request(request, cookie_name="csrf_token", header_name="X-CSRF-Token") -> bool:
    """
    Verifikasi token CSRF
    """
    cookie_token = request.cookies.get(cookie_name)
    header_token = request.headers.get(header_name)
    if not cookie_token or not header_token:
        return False
    return hmac.compare_digest(cookie_token, header_token)
