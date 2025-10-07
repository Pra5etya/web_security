from flask import Response, request
from .utils import generate_token

def mitigate_cookie_theft_via_xss(
    response: Response,
    cookie_name: str = "session_id",
    session_value: str | None = None,
    max_age: int = 1800,
    expires: str | None = None,
    path: str = "/",
    domain: str | None = None,
    secure: bool = True,
    http_only: bool = True,
    same_site: str = "Strict",
    priority: str | None = "High",
    partitioned: bool = False,
    same_party: bool = False,
    ensure_domain_from_request: bool = True
):
    """
    Set cookie untuk mencegah pencurian via XSS
    """
    if domain is None and ensure_domain_from_request:
        domain = request.host  # default domain = request host

    if session_value is None:
        session_value = generate_token(32)  # buat token acak

    if same_site not in {"Strict", "Lax", "None"}:
        raise ValueError("same_site harus 'Strict', 'Lax', atau 'None'")
    if same_site == "None" and not secure:
        raise ValueError("Jika same_site='None', maka secure must be True")

    response.set_cookie(
        key=cookie_name,
        value=session_value,
        max_age=max_age,
        expires=expires,
        path=path,
        domain=domain,
        secure=secure,
        httponly=http_only,
        samesite=same_site
    )

    cookie_headers = response.headers.getlist("Set-Cookie")
    if cookie_headers:
        updated = []
        for h in cookie_headers:
            if h.startswith(f"{cookie_name}="):
                extras = ""
                if priority:
                    extras += f"; Priority={priority}"
                if partitioned:
                    extras += "; Partitioned"
                if same_party:
                    extras += "; SameParty"
                h = h + extras
            updated.append(h)
        response.headers.set("Set-Cookie", ", ".join(updated))

    return response
