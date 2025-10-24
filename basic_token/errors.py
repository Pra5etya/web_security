class TokenError(Exception):
    """Base class untuk error JWT"""

class InvalidTokenFormat(TokenError):
    pass

class InvalidSignature(TokenError):
    pass

class ExpiredToken(TokenError):
    pass

class NotYetValid(TokenError):
    pass
