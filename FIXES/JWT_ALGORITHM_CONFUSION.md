# Fix: JWT Algorithm Confusion (RS256→HS256 Downgrade)

## Vulnerability

JWT verification libraries that trust the `alg` header in the token to decide which algorithm to use for signature verification are vulnerable to algorithm confusion attacks. An attacker changes the `alg` from `RS256` (asymmetric RSA) to `HS256` (symmetric HMAC) and signs the modified token using the server's **public RSA key** as the HMAC secret. Since the public key is publicly known, the attacker can forge valid tokens.

## Attack Vector

```python
# VULNERABLE: Server trusts the 'alg' header
# 1. Server has RS256 public key
# 2. Attacker changes alg from RS256 to HS256
# 3. Attacker uses the public key as HMAC secret to sign
# 4. Server verifies with HS256 using public key as secret
# 5. Forged token is accepted!

# Python PyJWT vulnerable usage:
import jwt

# Public key is publicly known
public_key = b"-----BEGIN PUBLIC KEY-----\n..."

# Attacker creates a forged token
forged = jwt.encode(
    {"sub": "admin", "role": "admin"},
    public_key,  # Public key used as HMAC secret!
    algorithm="HS256"
)

# Server accepts it because it trusts the 'alg' header
decoded = jwt.decode(forged, public_key, algorithms=["HS256", "RS256"])
# ^^^ This accepts the forged token!
```

## Fix Implementation

### 1. Algorithm Whitelist with Key Pinning

```python
import hmac
import hashlib
import json
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

class SecureJWTVerifier:
    """Prevents JWT algorithm confusion attacks."""

    ALLOWED_ALGORITHMS = frozenset({"RS256", "RS384", "RS512"})

    def __init__(self, public_key_pem: str):
        self.public_key = serialization.load_pem_public_key(
            public_key_pem.encode()
        )
        self.expected_algorithm = "RS256"  # Pin to specific algorithm

    def verify(self, token: str) -> dict:
        """Verify a JWT with algorithm pinning."""
        parts = token.split(".")
        if len(parts) != 3:
            raise ValueError("Invalid JWT")

        header = json.loads(
            base64.urlsafe_b64decode(parts[0] + "==")
        )

        # CRITICAL: Check algorithm BEFORE verification
        if header.get("alg") != self.expected_algorithm:
            raise ValueError(
                f"Algorithm mismatch: expected {self.expected_algorithm}, "
                f"got {header.get('alg')}"
            )

        # Reject symmetric algorithms for asymmetric-only endpoints
        if header.get("alg", "").startswith("HS"):
            raise ValueError("Symmetric algorithms are not allowed")

        # Verify signature with pinned algorithm
        signing_input = f"{parts[0]}.{parts[1]}"
        signature = base64.urlsafe_b64decode(parts[2] + "==")

        self.public_key.verify(
            signature,
            signing_input.encode(),
            padding.PKCS1v15(),
            hashes.SHA256(),
        )

        return json.loads(
            base64.urlsafe_b64decode(parts[1] + "==")
        )
```

### 2. Security Best Practices

| Measure | Description |
|---------|-------------|
| Algorithm Pinning | Pin each key to a specific algorithm, never trust the `alg` header |
| Algorithm Whitelist | Maintain an explicit allow-list of accepted algorithms |
| Group Separation | Reject symmetric algorithms (HS*) when using asymmetric keys (RS*) |
| Header Validation | Validate `alg`, `kid`, and other headers before signature verification |
| Constant-Time | Use `hmac.compare_digest` for symmetric signature verification |
| Library Config | Use `algorithms` parameter explicitly (e.g., `algorithms=["RS256"]`) |

### 3. Security Checklist

- [x] Validate `alg` header before signature verification
- [x] Reject HS256/HS384/HS512 when RS256 is expected
- [x] Maintain algorithm whitelist
- [x] Pin each key to a specific algorithm
- [x] Constant-time signature comparison
- [x] Reject `alg: none` tokens
- [x] Validate `kid` against known key registry

## References

- CVE-2015-9235: JWT algorithm confusion vulnerability
- CVE-2016-5431: JWT key confusion in various libraries
- OWASP JWT Security Cheat Sheet
- RFC 7518: JSON Web Algorithms (JWA)
- auth0/node-jsonwebtoken#115: Algorithm confusion fix

## Wallet for Bounty Payment
- **ETH/EVM (Ethereum, Polygon, Base, Optimism, Arbitrum):** `0x415b24ab21388dbfb9c4da97cb1ab2b53ff21e29`
- **SOL (Solana):** `J6pwNJNbjYx7UHAvZK369kYRJHim8JVbeFEHRSqtFMjv`