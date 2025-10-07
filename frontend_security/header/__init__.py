from .csp import generate_nonce, apply_csp
from .hsts import apply_hsts
from .frame_protection import apply_x_frame_options
from .referrer_policy import apply_referrer_policy
from .permissions_policy import apply_permissions_policy
from .legacy_modern import apply_legacy_modern_headers


def apply_all_headers(response):
    """Gabungkan semua header keamanan menjadi satu fungsi."""
    response = apply_csp(response)
    response = apply_hsts(response)
    response = apply_x_frame_options(response)
    response = apply_referrer_policy(response)
    response = apply_permissions_policy(response)
    response = apply_legacy_modern_headers(response)
    return response
