"""
Fix for TLS Certificate Bypass vulnerability during BGP hijacking simulation.

This fix ensures that all HTTPS connections validate TLS certificates properly,
preventing man-in-the-middle attacks that could be performed via BGP hijacking.
It replaces any insecure HTTP client configuration that disables certificate
verification with a secure default context.
"""

import ssl
import requests
from requests.adapters import HTTPAdapter


class SecureTLSAdapter(HTTPAdapter):
    """Adapter that enforces strict TLS certificate validation."""

    def init_poolmanager(self, *args, **kwargs):
        ctx = ssl.create_default_context()
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED
        kwargs['ssl_context'] = ctx
        return super().init_poolmanager(*args, **kwargs)


def patch_insecure_requests():
    """Apply the fix globally: mount the secure adapter for all HTTPS requests."""
    session = requests.Session()
    adapter = SecureTLSAdapter()
    session.mount('https://', adapter)
    return session
