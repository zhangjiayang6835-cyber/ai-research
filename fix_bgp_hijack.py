import requests
import hashlib
import ssl
from urllib.parse import urlparse

# Expected TLS certificate fingerprints (SHA-256) for the legitimate server
EXPECTED_FINGERPRINTS = {
    "example.com": "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
}

def get_cert_fingerprint(cert_der):
    """Compute SHA-256 fingerprint of DER-encoded certificate."""
    return hashlib.sha256(cert_der).hexdigest()

def secure_request(url):
    """
    Perform an HTTPS request with strict TLS certificate validation to prevent
    BGP hijacking attacks that attempt to bypass certificate verification.
    """
    parsed = urlparse(url)
    hostname = parsed.hostname
    if hostname not in EXPECTED_FINGERPRINTS:
        raise ValueError(f"No expected fingerprint configured for {hostname}")

    # Create a custom SSL context that validates certificates
    ctx = ssl.create_default_context()
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED

    # Additional: verify certificate fingerprint (public key pinning)
    original_verify = ctx.verify_flags
    ctx.verify_flags = ssl.VERIFY_X509_TRUSTED_FIRST

    # Use requests with the custom SSL context
    session = requests.Session()
    session.verify = ctx  # Use the SSL context for verification

    # We need to intercept the connection to check the fingerprint
    # Since requests doesn't directly expose the certificate, we use a custom adapter
    class FingerprintAdapter(requests.adapters.HTTPAdapter):
        def send(self, request, **kwargs):
            response = super().send(request, **kwargs)
            # Retrieve the peer certificate from the underlying socket
            sock = response.raw._connection.sock
            if sock:
                cert_der = sock.getpeercert(binary_form=True)
                if not cert_der:
                    raise requests.exceptions.SSLError("No peer certificate received")
                fingerprint = get_cert_fingerprint(cert_der)
                if fingerprint != EXPECTED_FINGERPRINTS[hostname]:
                    raise requests.exceptions.SSLError(
                        f"Certificate fingerprint mismatch for {hostname}: "
                        f"expected {EXPECTED_FINGERPRINTS[hostname]}, got {fingerprint}"
                    )
            return response

    session.mount("https://", FingerprintAdapter())

    try:
        response = session.get(url, timeout=10)
        response.raise_for_status()
        return response.text
    except requests.exceptions.SSLError as e:
        # Log and handle the error appropriately (e.g., alert security team)
        raise RuntimeError(f"TLS validation failed: {e}") from e
    except requests.exceptions.RequestException as e:
        raise RuntimeError(f"Request failed: {e}") from e

# Example usage (commented out):
# if __name__ == "__main__":
#     try:
#         content = secure_request("https://example.com/api/data")
#         print("Secure connection established")
#     except RuntimeError as e:
#         print(f"Connection blocked: {e}")
