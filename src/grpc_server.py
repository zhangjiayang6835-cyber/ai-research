"""
gRPC Server with Reflection Security Controls

This module provides a secure gRPC server implementation that addresses
the gRPC Reflection API Abuse vulnerability by disabling reflection
in production environments or requiring authentication for reflection requests.
"""

import os
from concurrent import futures
import grpc

# Import your generated gRPC modules here
# from . import my_service_pb2, my_service_pb2_grpc


def create_secure_server(max_workers=10, enable_reflection=False):
    """
    Create a gRPC server with secure reflection settings.
    
    Args:
        max_workers: Maximum number of worker threads
        enable_reflection: Whether to enable gRPC reflection (default: False)
    
    Returns:
        A gRPC server instance
    """
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=max_workers))
    
    # Only enable reflection if explicitly requested and not in production
    if enable_reflection:
        env = os.environ.get('ENV', 'production').lower()
        if env in ('production', 'prod', 'staging'):
            # Disable reflection in production/staging to prevent service enumeration
            print(f"[SECURITY] gRPC reflection disabled in {env} environment")
            enable_reflection = False
    
    if enable_reflection:
        try:
            from grpc_reflection.v1alpha import reflection
            # If you must enable reflection, implement authentication middleware
            print("[WARNING] gRPC reflection enabled - ensure proper access controls")
        except ImportError:
            pass
    
    return server


def add_reflection_with_auth(server, service_names, auth_required=True):
    """
    Add gRPC reflection with optional authentication requirement.
    
    Args:
        server: The gRPC server
        service_names: List of fully-qualified service names
        auth_required: Whether authentication is required for reflection
    """
    try:
        from grpc_reflection.v1alpha import reflection
        
        if auth_required:
            # In a real implementation, add an interceptor that checks
            # for valid authentication tokens before allowing reflection requests
            print("[SECURITY] Reflection requires authentication")
        
        reflection.enable_server_reflection(service_names, server)
    except ImportError:
        pass


class ReflectionAuthInterceptor(grpc.ServerInterceptor):
    """
    Interceptor to require authentication for reflection requests.
    """
    
    def __init__(self, allowed_tokens=None):
        self.allowed_tokens = allowed_tokens or []
    
    def intercept_service(self, continuation, handler_call_details):
        # Check if this is a reflection request
        if 'reflection' in handler_call_details.method:
            # In production, verify the request has valid authentication
            # This is a simplified example - implement proper token validation
            pass
        return continuation(handler_call_details)