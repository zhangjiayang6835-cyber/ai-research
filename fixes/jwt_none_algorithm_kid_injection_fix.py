"""Fix for Issue #210: JWT None Algorithm + Weak Secret + Kid Injection"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import secrets
import time
from dataclasses import dataclass
from typing import Any, Callable, Dict, FrozenSet, Mapping, Optional, Set

# Optional dependencies for RSA/ECDSA (if not installed, those algorithms are unavailable)
try:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
    from cryptography.hazmat.backends import default_backend
    from cryptography.exceptions import InvalidSignature as CryptoInvalidSignature
    _ASYMMETRIC_AVAILABLE = True
except ImportError:
    _ASYMMETRIC_AVAILABLE = False

# ---------------------------------------------------------------------------
# Constants (RFC 7519 / OWASP / NIST)
# ---------------------------------------------------------------------------

# Minimum secret entropy for HMAC algorithms (NIST SP 800-107r1 / OWASP)
_MIN_SECRET_BYTES = 32  # 256 bits

# Kid validation: only alphanumeric, hyphen, underscore (no path components)
_KID_ALLOWED_CHARS = re.compile(r"^[A-Za-z0-9_-]{1,64}$")

# Algorithms that are ALWAYS rejected
_FORBIDDEN_ALGORITHMS: FrozenSet[str] = frozenset({
    "none", "None", "NONE", "", "null", "NULL"
})

# HMAC algorithm -> hashlib hash function
_HMAC_HASH_MAP: Dict[str, Callable] = {
    "HS256": hashlib.sha256,
    "HS384": hashlib.sha384,
    "HS512": hashlib.sha512,
}

# RSA algorithm -> cryptography hash algorithm + padding
_RSA_HASH_MAP: Dict[str, Any] = {
    "RS256": hashes.SHA256(),
    "RS384": hashes.SHA384(),
    "RS512": hashes.SHA512(),
} if _ASYMMETRIC_AVAILABLE else {}

# ECDSA algorithm -> cryptography hash algorithm
_ECDSA_HASH_MAP: Dict[str, Any] = {
    "ES256": hashes.SHA256(),
    "ES384": hashes.SHA384(),
    "ES512": hashes.SHA512(),
} if _ASYMMETRIC_AVAILABLE else {}

# All supported algorithms (for documentation only)
_ALL_SUPPORTED_ALGORITHMS: FrozenSet[str] = frozenset(
    set(_HMAC_HASH_MAP.keys())
    | set(_RSA_HASH_MAP.keys())
    | set(_ECDSA_HASH_MAP.keys())
)


# ---------------------------------------------------------------------------
# Errors — single generic error class so no oracle leaks failure mode
# ---------------------------------------------------------------------------

class InvalidToken(Exception):
    """Single generic error for every JWT validation failure.

    Callers MUST NOT branch on the message or introduce subclasses.
    All validation errors (signature, algorithm, expiry, kid, etc.)
    return this same exception.
    """
    pass


# ---------------------------------------------------------------------------
# Helper functions (base64url, constant-time comparison)
# ---------------------------------------------------------------------------

def _base64url_decode(data: str) -> bytes:
    """Decode base64url (RFC 7515 §2) with padding normalization."""
    # JWT uses unpadded base64url; add padding if needed
    padding = 4 - (len(data) % 4)
    if padding != 4:
        data += "=" * padding
    try:
        return base64.urlsafe_b64decode(data)
    except Exception:
        raise InvalidToken("malformed base64url encoding")


def _base64url_encode(data: bytes) -> str:
    """Encode to base64url without padding (RFC 7515 §2)."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _constant_time_compare(a: str, b: str) -> bool:
    """Constant-time string comparison to prevent timing attacks."""
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))


# ---------------------------------------------------------------------------
# Kid (Key ID) sanitization
# ---------------------------------------------------------------------------

def _validate_kid(kid: Optional[str], allowed_kids: Optional[FrozenSet[str]]) -> str:
    """Validate and sanitize the kid (key ID) header parameter.

    Defends against:
      - Path traversal (../../dev/null)
      - SQL injection (key' OR '1'='1)
      - Command injection (key; cat /etc/passwd)
      - Null byte injection (key\x00.txt)
      - Overly long values (DoS / buffer overflow)

    Returns the validated kid or raises InvalidToken.
    """
    if kid is None:
        if allowed_kids is None or len(allowed_kids) == 0:
            # No kid header, no allow-list -> use a default sentinel
            return "default"
        else:
            # No kid header but an allow-list exists -> require explicit kid
            raise InvalidToken("missing required kid header")

    if not isinstance(kid, str):
        raise InvalidToken("kid header must be a string")

    # 1. Length check (prevent DoS)
    if len(kid) > 64:
        raise InvalidToken("kid header too long")

    # 2. Character allow-list (alphanumeric + hyphen + underscore only)
    if not _KID_ALLOWED_CHARS.match(kid):
        raise InvalidToken("kid header contains forbidden characters")

    # 3. Allow-list check (if provided)
    if allowed_kids is not None and len(allowed_kids) > 0:
        # Use constant-time comparison to prevent timing oracle on kid values
        match_found = any(_constant_time_compare(kid, allowed) for allowed in allowed_kids)
        if not match_found:
            raise InvalidToken("kid header not in allow-list")

    return kid


# ---------------------------------------------------------------------------
# Algorithm validation (defense against "none" and algorithm confusion)
# ---------------------------------------------------------------------------

def _validate_algorithm(
    alg: Optional[str],
    allowed_algorithms: FrozenSet[str],
) -> str:
    """Validate the JWT "alg" header against the server's allow-list.

    Defends against:
      - None algorithm bypass (alg: "none")
      - Algorithm confusion (RS256 -> HS256)
      - Unsupported/unknown algorithms

    Returns the validated algorithm or raises InvalidToken.
    """
    if alg is None or not isinstance(alg, str):
        raise InvalidToken("missing or invalid alg header")

    # 1. Explicit rejection of forbidden algorithms (none, None, NONE, etc.)
    if alg in _FORBIDDEN_ALGORITHMS or alg.lower() in {"none", "null"}:
        raise InvalidToken("forbidden algorithm")

    # 2. Check against server's allow-list
    if alg not in allowed_algorithms:
        raise InvalidToken("algorithm not allowed")

    # 3. Ensure the algorithm is supported by this module
    if alg not in _ALL_SUPPORTED_ALGORITHMS:
        raise InvalidToken("unsupported algorithm")

    # 4. If asymmetric algorithm, ensure cryptography is available
    if alg in _RSA_HASH_MAP or alg in _ECDSA_HASH_MAP:
        if not _ASYMMETRIC_AVAILABLE:
            raise InvalidToken("asymmetric algorithms require cryptography package")

    return alg


# ---------------------------------------------------------------------------
# Signature verification (HMAC, RSA, ECDSA)
# ---------------------------------------------------------------------------

def _verify_hmac_signature(
    message: bytes,
    signature: bytes,
    secret: bytes,
    alg: str,
) -> None:
    """Verify HMAC signature (HS256, HS384, HS512) in constant time."""
    hash_fn = _HMAC_HASH_MAP[alg]
    expected = hmac.new(secret, message, hash_fn).digest()

    # Constant-time comparison (critical!)
    if not hmac.compare_digest(signature, expected):
        raise InvalidToken("signature verification failed")


def _verify_rsa_signature(
    message: bytes,
    signature: bytes,
    public_key: rsa.RSAPublicKey,
    alg: str,
) -> None:
    """Verify RSA signature (RS256, RS384, RS512)."""
    hash_alg = _RSA_HASH_MAP[alg]
    try:
        public_key.verify(
            signature,
            message,
            padding.PKCS1v15(),
            hash_alg,
        )
    except CryptoInvalidSignature:
        raise InvalidToken("signature verification failed")
    except Exception:
        raise InvalidToken("signature verification failed")


def _verify_ecdsa_signature(
    message: bytes,
    signature: bytes,
    public_key: ec.EllipticCurvePublicKey,
    alg: str,
) -> None:
    """Verify ECDSA signature (ES256, ES384, ES512)."""
    hash_alg = _ECDSA_HASH_MAP[alg]
    try:
        public_key.verify(signature, message, ec.ECDSA(hash_alg))
    except CryptoInvalidSignature:
        raise InvalidToken("signature verification failed")
    except Exception:
        raise InvalidToken("signature verification failed")


# ---------------------------------------------------------------------------
# Main validator class
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class SecureJWTValidator:
    """Secure JWT validator with defense against none/weak-secret/kid attacks.

    Usage (HMAC with single secret):
        validator = SecureJWTValidator(
            allowed_algorithms=frozenset({"HS256"}),
            hmac_secrets={"default": b"<32+ bytes of random data>"},
        )
        payload = validator.verify(token)

    Usage (RSA with key rotation):
        validator = SecureJWTValidator(
            allowed_algorithms=frozenset({"RS256"}),
            rsa_public_keys={"key-2024": rsa_public_key_obj},
            allowed_kids=frozenset({"key-2024", "key-2023"}),
        )
        payload = validator.verify(token)

    Usage (with expiry and issuer checks):
        validator = SecureJWTValidator(
            allowed_algorithms=frozenset({"HS256"}),
            hmac_secrets={"default": secret},
            verify_expiry=True,
            required_claims={"iss": "https://auth.example.com"},
        )
        payload = validator.verify(token)
    """

    # Algorithm configuration (REQUIRED)
    allowed_algorithms: FrozenSet[str]

    # Key stores (provide at least one matching the allowed_algorithms)
    hmac_secrets: Optional[Dict[str, bytes]] = None
    rsa_public_keys: Optional[Dict[str, Any]] = None
    ecdsa_public_keys: Optional[Dict[str, Any]] = None

    # Kid allow-list (if None, any syntactically-valid kid is accepted after sanitization)
    allowed_kids: Optional[FrozenSet[str]] = None

    # Claim validation
    verify_expiry: bool = True
    clock_skew_seconds: int = 60  # Allow 60s clock skew for exp/nbf
    required_claims: Optional[Dict[str, Any]] = None  # e.g. {"iss": "..."}

    def __post_init__(self) -> None:
        """Validate configuration at construction time."""
        if not self.allowed_algorithms or len(self.allowed_algorithms) == 0:
            raise ValueError("allowed_algorithms must be a non-empty frozenset")

        # Ensure at least one key store is provided
        has_hmac = self.hmac_secrets is not None and len(self.hmac_secrets) > 0
        has_rsa = self.rsa_public_keys is not None and len(self.rsa_public_keys) > 0
        has_ecdsa = self.ecdsa_public_keys is not None and len(self.ecdsa_public_keys) > 0

        if not (has_hmac or has_rsa or has_ecdsa):
            raise ValueError("at least one key store must be provided")

        # Validate HMAC secrets (must be >= 256 bits)
        if self.hmac_secrets:
            for kid, secret in self.hmac_secrets.items():
                if not isinstance(secret, bytes):
                    raise ValueError(f"HMAC secret for kid={kid} must be bytes")
                if len(secret) < _MIN_SECRET_BYTES:
                    raise ValueError(
                        f"HMAC secret for kid={kid} is too short "
                        f"({len(secret)} bytes, minimum {_MIN_SECRET_BYTES})"
                    )

    def verify(self, token: str) -> Dict[str, Any]:
        """Verify a JWT and return the payload.

        Raises InvalidToken on any validation failure (signature, algorithm,
        expiry, kid, missing claims, etc.). The error message is intentionally
        generic to prevent oracle attacks.

        Returns the decoded payload dict on success.
        """
        # 1. Parse token structure (header.payload.signature)
        parts = token.split(".")
        if len(parts) != 3:
            raise InvalidToken("malformed token structure")

        header_b64, payload_b64, signature_b64 = parts

        # 2. Decode header and payload (JSON)
        try:
            header_bytes = _base64url_decode(header_b64)
            header = json.loads(header_bytes)
        except (json.JSONDecodeError, Exception):
            raise InvalidToken("malformed token header")

        try:
            payload_bytes = _base64url_decode(payload_b64)
            payload = json.loads(payload_bytes)
        except (json.JSONDecodeError, Exception):
            raise InvalidToken("malformed token payload")

        # 3. Decode signature
        try:
            signature = _base64url_decode(signature_b64)
        except Exception:
            raise InvalidToken("malformed token signature")

        # 4. Validate algorithm (defense against "none" and algorithm confusion)
        alg = _validate_algorithm(header.get("alg"), self.allowed_algorithms)

        # 5. Validate kid (defense against injection attacks)
        kid = _validate_kid(header.get("kid"), self.allowed_kids)

        # 6. Verify signature (algorithm-specific)
        message = f"{header_b64}.{payload_b64}".encode("utf-8")

        if alg in _HMAC_HASH_MAP:
            # HMAC (HS256, HS384, HS512)
            if self.hmac_secrets is None or kid not in self.hmac_secrets:
                raise InvalidToken("key not found")
            secret = self.hmac_secrets[kid]
            _verify_hmac_signature(message, signature, secret, alg)

        elif alg in _RSA_HASH_MAP:
            # RSA (RS256, RS384, RS512)
            if self.rsa_public_keys is None or kid not in self.rsa_public_keys:
                raise InvalidToken("key not found")
            public_key = self.rsa_public_keys[kid]
            _verify_rsa_signature(message, signature, public_key, alg)

        elif alg in _ECDSA_HASH_MAP:
            # ECDSA (ES256, ES384, ES512)
            if self.ecdsa_public_keys is None or kid not in self.ecdsa_public_keys:
                raise InvalidToken("key not found")
            public_key = self.ecdsa_public_keys[kid]
            _verify_ecdsa_signature(message, signature, public_key, alg)

        else:
            # Should never reach here (caught by _validate_algorithm)
            raise InvalidToken("unsupported algorithm")

        # 7. Validate claims
        if not isinstance(payload, dict):
            raise InvalidToken("payload must be a JSON object")

        # 7a. Expiry check (exp claim)
        if self.verify_expiry:
            exp = payload.get("exp")
            if exp is None:
                raise InvalidToken("missing exp claim")
            if not isinstance(exp, (int, float)):
                raise InvalidToken("invalid exp claim")
            now = time.time()
            if exp < now - self.clock_skew_seconds:
                raise InvalidToken("token expired")

        # 7b. Not-before check (nbf claim, optional)
        nbf = payload.get("nbf")
        if nbf is not None:
            if not isinstance(nbf, (int, float)):
                raise InvalidToken("invalid nbf claim")
            now = time.time()
            if nbf > now + self.clock_skew_seconds:
                raise InvalidToken("token not yet valid")

        # 7c. Required claims check (iss, aud, custom claims)
        if self.required_claims:
            for claim_key, expected_value in self.required_claims.items():
                actual_value = payload.get(claim_key)
                if actual_value != expected_value:
                    raise InvalidToken(f"claim validation failed")

        # 8. All checks passed
        return payload


# ---------------------------------------------------------------------------
# Convenience helpers
# ---------------------------------------------------------------------------

def generate_strong_secret(nbytes: int = _MIN_SECRET_BYTES) -> bytes:
    """Generate a cryptographically strong secret for HMAC algorithms.

    Uses secrets.token_bytes (backed by os.urandom). The default is 32 bytes
    (256 bits), which exceeds NIST/OWASP minimums and is suitable for HS256.

    Usage:
        secret = generate_strong_secret()
        # Store in environment variable or secret manager, never in code
        # os.environ["JWT_SECRET"] = base64.b64encode(secret).decode()
    """
    if nbytes < _MIN_SECRET_BYTES:
        raise ValueError(f"secret must be >= {_MIN_SECRET_BYTES} bytes")
    return secrets.token_bytes(nbytes)


def create_token(payload: Dict[str, Any], secret: bytes, alg: str = "HS256", kid: str = "default") -> str:
    """Create a JWT token with the given payload (for testing / demo only).

    In production, use a well-vetted library like PyJWT or python-jose with
    proper key management, expiry, and claim validation.

    This helper is provided for self-tests and demonstrations.
    """
    if alg not in _HMAC_HASH_MAP:
        raise ValueError("Only HMAC algorithms supported by this helper")

    header = {"alg": alg, "typ": "JWT", "kid": kid}
    header_b64 = _base64url_encode(json.dumps(header, separators=(",", ":")).encode())
    payload_b64 = _base64url_encode(json.dumps(payload, separators=(",", ":")).encode())

    message = f"{header_b64}.{payload_b64}".encode("utf-8")
    hash_fn = _HMAC_HASH_MAP[alg]
    signature = hmac.new(secret, message, hash_fn).digest()
    signature_b64 = _base64url_encode(signature)

    return f"{header_b64}.{payload_b64}.{signature_b64}"


# ---------------------------------------------------------------------------
# Self-tests (comprehensive attack vector coverage)
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    strong_secret = generate_strong_secret()
    validator = SecureJWTValidator(
        allowed_algorithms=frozenset({"HS256"}),
        hmac_secrets={"default": strong_secret, "key-2024": strong_secret},
        allowed_kids=frozenset({"default", "key-2024"}),
        verify_expiry=True,
        required_claims={"iss": "https://auth.example.com"},
    )
    now = int(time.time())
    
    payload_valid = {"sub": "user-123", "iss": "https://auth.example.com", "exp": now + 3600, "iat": now}
    token_valid = create_token(payload_valid, strong_secret, "HS256", "default")
    assert validator.verify(token_valid)["sub"] == "user-123"
    
    header_none_b64 = _base64url_encode(json.dumps({"alg": "none", "typ": "JWT"}).encode())
    payload_b64 = _base64url_encode(json.dumps(payload_valid).encode())
    try:
        validator.verify(f"{header_none_b64}.{payload_b64}.")
        assert False
    except InvalidToken:
        pass
    
    header_trav_b64 = _base64url_encode(json.dumps({"alg": "HS256", "kid": "../../dev/null"}).encode())
    try:
        validator.verify(f"{header_trav_b64}.{payload_b64}.fake")
        assert False
    except InvalidToken:
        pass
    
    weak_secret = b"password"
    try:
        SecureJWTValidator(allowed_algorithms=frozenset({"HS256"}), hmac_secrets={"default": weak_secret})
        assert False
    except ValueError:
        pass
    
    payload_exp = {"sub": "user-123", "iss": "https://auth.example.com", "exp": now - 3600, "iat": now - 7200}
    try:
        validator.verify(create_token(payload_exp, strong_secret, "HS256", "default"))
        assert False
    except InvalidToken:
        pass
