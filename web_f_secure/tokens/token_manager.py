# tokens/token_manager.py
# Core JWT handling: create token pairs, decode/verify, rotate refresh tokens.
# Uses PyJWT (pip install PyJWT). Designed to be single-responsibility.

import jwt                        # PyJWT library
from datetime import datetime
from .utils import gen_random_string, hash_token_hmac
from .config import Config        # fallback config if needed

class TokenManager:
    """
    TokenManager handles creation and verification of access and refresh tokens.
    - Tokens are signed with HS256 by default (HMAC). Can be extended to RS256.
    - Refresh rotation logic provided via rotate_refresh(store).
    """

    def __init__(self, secret_key=None, issuer=None, salt=None):
        # secret key for signing tokens; fallback to Config.SECRET_KEY if not provided
        self.secret = secret_key or Config.SECRET_KEY
        # issuer claim for tokens
        self.issuer = issuer or Config.JWT_ISSUER
        # salt used for hashing refresh tokens in storage
        self.salt = salt or Config.REFRESH_TOKEN_SALT
        # algorithm choice; change to 'RS256' if using asymmetric keys
        self.alg = "HS256"
        # lifetime deltas from Config
        self.access_delta = Config.ACCESS_EXPIRES
        self.refresh_delta = Config.REFRESH_EXPIRES

    def _base_claims(self, sub, token_type="access", delta=None, jti=None):
        """
        Build base JWT claims used for access/refresh tokens.
        - sub: subject (user identifier)
        - token_type: "access" or "refresh"
        - delta: override expiration delta
        - jti: optional provided JWT ID
        """
        now = datetime.utcnow()
        exp = now + (delta or self.access_delta)
        return {
            "iss": self.issuer,                    # issuer
            "sub": sub,                            # subject (user id/username)
            "type": token_type,                    # custom claim to identify token type
            "iat": int(now.timestamp()),           # issued-at (epoch seconds)
            "exp": int(exp.timestamp()),           # expiration (epoch seconds)
            "jti": jti or gen_random_string(24)    # JWT ID unique identifier
        }

    def create_token_pair(self, username):
        """
        Create an access token (short-lived) and a refresh token (longer-lived).
        Returns: (access_token_str, refresh_token_str, refresh_jti)
        """
        # prepare payloads
        access_payload = self._base_claims(username, token_type="access", delta=self.access_delta)
        refresh_payload = self._base_claims(username, token_type="refresh", delta=self.refresh_delta)
        # encode payloads into JWT strings
        access_token = jwt.encode(access_payload, self.secret, algorithm=self.alg)
        refresh_token = jwt.encode(refresh_payload, self.secret, algorithm=self.alg)
        # return tokens and jti of refresh for storage mapping
        return access_token, refresh_token, refresh_payload["jti"]

    def decode(self, token, expect_type=None):
        """
        Decode and validate JWT token.
        - If expect_type provided ('access'/'refresh'), ensure 'type' claim matches.
        - Returns decoded payload dict if valid, else None.
        """
        try:
            # jwt.decode verifies signature & expiration by default (PyJWT)
            data = jwt.decode(token, self.secret, algorithms=[self.alg])
            # validate issuer
            if data.get("iss") != self.issuer:
                return None
            # validate token type if expected
            if expect_type and data.get("type") != expect_type:
                return None
            return data
        except jwt.ExpiredSignatureError:
            # token expired
            return None
        except jwt.InvalidTokenError:
            # signature invalid or tampered
            return None

    def refresh_exp_ts(self):
        """
        Helper returning epoch timestamp when a new refresh token will expire.
        Used when inserting new refresh record into storage.
        """
        return int((datetime.utcnow() + self.refresh_delta).timestamp())

    def rotate_refresh(self, refresh_token, store):
        """
        Perform refresh token rotation with misuse detection:
        Steps:
        1) decode token and ensure type == 'refresh'
        2) lookup record in store by jti
        3) compare stored hash with hash(refresh_token)
        4) if mismatch or revoked -> revoke all tokens for user (suspected theft)
        5) if OK -> revoke old jti, create new token pair, store new hashed refresh
        Returns dict: {"ok": bool, "msg": str, "tokens": (access, refresh, jti)|None}
        """
        # basic presence check
        if not refresh_token:
            return {"ok": False, "msg": "no refresh token", "tokens": None}

        # decode and expect refresh type
        decoded = self.decode(refresh_token, expect_type="refresh")
        if not decoded:
            return {"ok": False, "msg": "invalid or expired refresh token", "tokens": None}

        # extract identifiers
        jti = decoded.get("jti")
        username = decoded.get("sub")

        # lookup in storage by jti
        rec = store.get_refresh_by_jti(jti)
        # compute hash (must use same salt)
        token_hash = hash_token_hmac(refresh_token, self.salt)

        # if no record -> possible reuse/forgery: revoke all sessions for user
        if not rec:
            if username:
                store.revoke_all_for_user(username)
            return {"ok": False, "msg": "refresh token not recognized - possible theft", "tokens": None}

        # if record revoked or hash mismatch -> reuse or theft -> revoke all
        if rec["revoked"] or rec["token_hash"] != token_hash:
            store.revoke_all_for_user(rec["username"])
            return {"ok": False, "msg": "refresh token reuse detected", "tokens": None}

        # valid: rotate token
        # mark old token revoked
        store.mark_revoked(jti)

        # create new tokens
        access, new_refresh, new_jti = self.create_token_pair(username)

        # store hashed new refresh in storage with expiry
        store.insert_refresh(new_jti, username, hash_token_hmac(new_refresh, self.salt), self.refresh_exp_ts())

        # return new tokens to caller
        return {"ok": True, "msg": "rotated", "tokens": (access, new_refresh, new_jti)}
