# tokens/utils.py
# Small helper functions used across the package.
# Keep these focused and minimal.

import hmac
import hashlib
import secrets

def gen_random_string(length=32):
    """
    Generate a cryptographically secure random URL-safe string
    and trim to desired length.
    """
    # secrets.token_urlsafe generates base64-like URL-safe string
    return secrets.token_urlsafe(length)[:length]

def hash_token_hmac(token, salt):
    """
    Hash token using HMAC-SHA256 with a server-side salt.
    Purpose: avoid storing raw refresh tokens in DB.
    Returns hex digest string.
    """
    # use HMAC with salt to bind token to server secret/salt
    return hmac.new(salt.encode(), token.encode(), hashlib.sha256).hexdigest()
