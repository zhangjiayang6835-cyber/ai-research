import requests
import hashlib
import ssl

# Expected certificate fingerprint (SHA-256) for the legitimate server
EXPECTED_FINGERPRINT = "sha256$xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"

def verify_certificate(host, port=443):
    """
    Verifies the TLS certificate of the given host by pinning the SHA-256 fingerprint.
    Raises an exception if the fingerprint does not match.
    """
    # Create a custom SSL context that checks the certificate fingerprint
    context = ssl.create_default_context()
    
    def check_fingerprint(conn, cert, errno, depth, is_critical):
        if depth == 0:
            # Extract the DER-encoded certificate and compute SHA-256 hash
            cert_der = ssl.DER_cert_to_PEM_cert(cert).encode()
            cert_hash = hashlib.sha256(cert_der).hexdigest()
            expected_hash = EXPECTED_FINGERPRINT.split('$')[1]
            if cert_hash != expected_hash:
                raise ssl.CertificateError("Certificate fingerprint mismatch")
        return True
    
    context.verify_callback = check_fingerprint
    # Disable certificate verification from CA since we use pinning
    context.verify_mode = ssl.CERT_REQUIRED
    context.check_hostname = False  # We rely on fingerprint
    
    # Perform HTTPS request using the custom context
    try:
        response = requests.get(f"https://{host}:{port}", verify=context)
        return response
    except requests.exceptions.SSLError as e:
        print(f"TLS verification failed: {e}")
        raise

# Example usage (replace with actual host and fingerprint)
# verify_certificate('example.com')
