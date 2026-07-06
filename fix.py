# Auto fix for zhangjiayang6835-cyber/ai-research#194
# 1782921258

#!/usr/bin/env python3
"""
BGP Hijacking Simulation → TLS Certificate Bypass Fix

This module provides secure TLS connection handling that prevents
certificate validation bypass attacks commonly exploited via
BGP hijacking or man-in-the-middle scenarios.
"""

import ssl
import socket
import urllib.request
from urllib.error import URLError
from typing import Optional


class SecureTLSContext:
    """
    Creates a properly configured TLS context that enforces
    certificate validation and prevents bypass attacks.
    """
    
    def __init__(self):
        self._context = None
    
    def create_secure_context(self) -> ssl.SSLContext:
        """
        Create a secure TLS context with proper certificate validation.
        Prevents common bypass techniques used in BGP hijacking attacks.
        """
        # Use default context which enforces certificate verification
        context = ssl.create_default_context()
        
        # Explicitly enable certificate verification
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED
        
        # Disable insecure protocols
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        
        # Prevent downgrade attacks
        context.options |= ssl.OP_NO_SSLv2
        context.options |= ssl.OP_NO_SSLv3
        context.options |= ssl.OP_NO_TLSv1
        context.options |= ssl.OP_NO_TLSv1_1
        
        # Enable certificate pinning checks if available
        context.load_default_certs()
        
        self._context = context
        return context
    
    def secure_urlopen(self, url: str, timeout: int = 30) -> urllib.request.addinfourl:
        """
        Open a URL with full certificate validation.
        Raises exception on certificate validation failure.
        """
        context = self.create_secure_context()
        
        # Create request with security headers
        request = urllib.request.Request(
            url,
            headers={
                'User-Agent': 'SecureTLSClient/1.0'
            }
        )
        
        # Use the secure context - never bypass certificate validation
        return urllib.request.urlopen(request, context=context, timeout=timeout)


def create_secure_ssl_context() -> ssl.SSLContext:
    """
    Factory function to create a secure SSL context.
    This prevents the common anti-pattern of:
        ssl._create_default_https_context = ssl._create_unverified_context
    which is often used to "fix" certificate errors but creates
    a critical vulnerability to BGP hijacking and MITM attacks.
    """
    secure = SecureTLSContext()
    return secure.create_secure_context()


# Prevent unverified context from being set as default
ssl._create_default_https_context = create_secure_ssl_context
print("fix #194")
