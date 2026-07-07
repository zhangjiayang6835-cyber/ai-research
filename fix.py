# Auto fix for zhangjiayang6835-cyber/ai-research#194
# 1782921258

#!/usr/bin/env python3
"""
BGP Hijacking Simulation → TLS Certificate Bypass Fix

This module provides secure TLS certificate verification that prevents
BGP hijacking attacks by properly validating certificates and using
certificate pinning where appropriate.
"""

import ssl
import socket
import hashlib
import base64
from urllib.parse import urlparse


# Certificate pinning for known services (example: pin SHA-256 of known good certs)
# In production, these would be loaded from a secure configuration
CERTIFICATE_PINS = {
    # Example: 'api.example.com': 'sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA='
}


class TLSSecurityError(Exception):
    """Raised when TLS security validation fails."""
    pass


class SecureTLSContext:
    """
    A secure TLS context that prevents certificate bypass attacks.
    
    Features:
    - Disables insecure SSL/TLS versions
    - Enforces certificate verification
    - Supports certificate pinning
    - Validates hostname against certificate
    """
    
    def __init__(self, verify_mode=ssl.CERT_REQUIRED, check_hostname=True):
        self.context = ssl.create_default_context()
        self.context.minimum_version = ssl.TLSVersion.TLSv1_2
        self.context.verify_mode = verify_mode
        self.context.check_hostname = check_hostname
        
        # Disable insecure cipher suites
        self.context.set_ciphers('ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!MD5:!SHA1')
    
    def create_connection(self, hostname, port=443, timeout=10):
        """
        Create a secure connection with full certificate validation.
        
        Args:
            hostname: The target hostname
            port: The target port (default 443)
            timeout: Connection timeout in seconds
            
        Returns:
            ssl.SSLSocket: A verified SSL socket
            
        Raises:
            TLSSecurityError: If certificate validation fails
        """
        try:
            with socket.create_connection((hostname, port), timeout=timeout) as sock:
                with self.context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    # Get certificate for additional validation
                    cert = ssock.getpeercert(binary_form=True)
                    
                    if not cert:
                        raise TLSSecurityError("No certificate presented by server")
                    
                    # Check certificate pinning if configured
                    if hostname in CERTIFICATE_PINS:
                        cert_hash = hashlib.sha256(cert).digest()
                        expected_pin = base64.b64decode(CERTIFICATE_PINS[hostname].split('/')[1])
                        if cert_hash != expected_pin:
                            raise TLSSecurityError(f"Certificate pin mismatch for {hostname}")
                    
                    return ssock
                    
        except ssl.SSLError as e:
            raise TLSSecurityError(f"SSL/TLS error: {str(e)}")
        except socket.error as e:
            raise TLSSecurityError(f"Connection error: {str(e)}")
print("fix #194")
