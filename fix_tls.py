import ssl
import socket
import certifi

def secure_connect(hostname: str, port: int = 443) -> ssl.SSLSocket:
    """
    Establish a secure TLS connection with proper certificate validation.
    This prevents BGP hijacking attacks that could bypass TLS verification.
    The function enforces hostname matching and certificate chain validation.
    """
    # Create an SSL context using certifi's CA bundle (or system default)
    context = ssl.create_default_context(cafile=certifi.where())
    
    # Require certificate and validate hostname
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    
    # Optional: Certificate Pinning (HPKP) – uncomment and set the actual public key hash
    # pinned_hashes = ["sha256//..."]
    # def verify_callback(conn, cert, errnum, depth, ok):
    #     if depth == 0:  # leaf certificate
    #         # Compute SHA-256 hash of the certificate's public key
    #         from cryptography.hazmat.primitives import hashes
    #         from cryptography.x509 import load_der_x509_certificate
    #         pubkey = cert.get_pubkey()
    #         pubkey_bytes = pubkey.to_cryptography_key().public_bytes(
    #             encoding=serialization.Encoding.DER,
    #             format=serialization.PublicFormat.SubjectPublicKeyInfo
    #         )
    #         digest = hashes.Hash(hashes.SHA256())
    #         digest.update(pubkey_bytes)
    #         pubkey_hash = digest.finalize().hex()
    #         if pubkey_hash not in pinned_hashes:
    #             raise ssl.CertificateError("Certificate pinning mismatch")
    #     return ok
    # context.verify_callback = verify_callback

    try:
        with socket.create_connection((hostname, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                print(f"TLS connection established: {hostname}:{port}, version={ssock.version()}")
                return ssock
    except ssl.SSLError as e:
        raise ConnectionError(f"TLS verification failed for {hostname}: {e}")
    except socket.timeout:
        raise ConnectionError(f"Connection timed out for {hostname}:{port}")
    except Exception as e:
        raise ConnectionError(f"Failed to connect to {hostname}:{port}: {e}")

# Example usage:
if __name__ == "__main__":
    try:
        sock = secure_connect("example.com")
        sock.close()
    except Exception as e:
        print(f"Error: {e}")
