import ssl
import socket
import hashlib
import hmac

# Certificate pinning hash (SHA-256 of the DER-encoded certificate)
EXPECTED_PIN = "sha256//YOUR_EXPECTED_PIN_BASE64="

def verify_certificate(host, port):
    """
    Establish a TLS connection with certificate pinning to prevent BGP hijacking
    and certificate bypass attacks.
    """
    context = ssl.create_default_context()
    # Ensure strict certificate validation
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5)
    try:
        wrapped_socket = context.wrap_socket(sock, server_hostname=host)
        wrapped_socket.connect((host, port))
        
        # Get the certificate in DER format
        der_cert = wrapped_socket.getpeercert(binary_form=True)
        # Compute SHA-256 hash and base64 encode (simplified; use proper base64 encoding)
        import base64
        cert_hash = hashlib.sha256(der_cert).digest()
        pin = "sha256//" + base64.b64encode(cert_hash).decode()
        
        if pin != EXPECTED_PIN:
            raise Exception("Certificate pin mismatch - possible hijack")
        
        print("TLS connection established securely with pinning.")
        return wrapped_socket
    except Exception as e:
        print(f"Connection failed: {e}")
        return None
    finally:
        sock.close()

# Example usage
if __name__ == "__main__":
    # Replace with actual host and port
    verify_certificate("example.com", 443)
