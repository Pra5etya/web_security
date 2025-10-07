from flask import Response, request, current_app
from .utils import generate_token, generate_fingerprint, sign_data, verify_signature
import time
from typing import Callable, Optional

def create_secure_session_cookie(
    response: Response,
    cookie_name: str = "session_id",
    session_id: str | None = None,
    max_age: int = 1800,
    path: str = "/",
    domain: str | None = None,
    secure: bool = True,
    http_only: bool = True,
    same_site: str = "Strict",
    sign: bool = True,
    secret_key: str | None = None,
    bind_fingerprint: bool = True,
    fingerprint_func: Callable[[], str] | None = None,
    rotate: bool = True,
    renew_on_activity: bool = True,
    idle_timeout: Optional[int] = None,
    absolute_timeout: Optional[int] = None,
    server_side_store: Optional[Callable[[str, dict], None]] = None,
    ensure_domain_from_request: bool = True
):
    """
    Buat session cookie aman
    """
    if domain is None and ensure_domain_from_request:
        domain = request.host

    if not session_id:
        session_id = generate_token(24)

    if bind_fingerprint:
        fingerprint = fingerprint_func() if fingerprint_func else generate_fingerprint()
    else:
        fingerprint = ""

    session_data = f"{session_id}|{fingerprint}" if fingerprint else session_id

    used_secret = secret_key or getattr(current_app, "secret_key", None)
    if sign:
        if not used_secret:
            raise ValueError("secret_key diperlukan untuk sign=True")
        signature = sign_data(session_data)
        cookie_value = f"{session_data}|{signature}"
    else:
        cookie_value = session_data

    if server_side_store:
        meta = {
            "created_at": int(time.time()),
            "last_activity": int(time.time()),
            "max_age": max_age,
            "idle_timeout": idle_timeout,
            "absolute_timeout": absolute_timeout
        }
        try:
            server_side_store(session_id, meta)
        except Exception:
            pass

    response.set_cookie(
        key=cookie_name,
        value=cookie_value,
        max_age=max_age,
        path=path,
        domain=domain,
        secure=secure,
        httponly=http_only,
        samesite=same_site
    )

    return response


def verify_secure_session_cookie(
    request,
    cookie_name: str = "session_id",
    secret_key: str | None = None,
    verify_signature_flag: bool = True,
    bind_fingerprint: bool = True,
    fingerprint_func: Callable[[], str] | None = None,
    server_side_lookup: Optional[Callable[[str], dict]] = None
) -> bool:
    """
    Verifikasi session cookie
    """
    raw = request.cookies.get(cookie_name)
    if not raw:
        return False

    parts = raw.split("|")
    if len(parts) == 1:
        session_id = parts[0]
        fingerprint = ""
        signature = ""
    elif len(parts) == 2:
        session_id, signature = parts
        fingerprint = ""
    else:
        session_id, fingerprint, signature = parts[0], parts[1], parts[2]

    if verify_signature_flag:
        original = f"{session_id}|{fingerprint}" if fingerprint else session_id
        if not verify_signature(original, signature):
            return False

    if bind_fingerprint and fingerprint:
        current_fp = fingerprint_func() if fingerprint_func else generate_fingerprint()
        if not hmac.compare_digest(current_fp, fingerprint):
            return False

    if server_side_lookup:
        try:
            meta = server_side_lookup(session_id)
            if not meta:
                return False
            now = int(time.time())
            if meta.get("absolute_timeout") and meta.get("created_at"):
                if now > meta["created_at"] + meta["absolute_timeout"]:
                    return False
            if meta.get("idle_timeout") and meta.get("last_activity"):
                if now > meta["last_activity"] + meta["idle_timeout"]:
                    return False
            if meta.get("revoked"):
                return False
        except Exception:
            return False

    return True
