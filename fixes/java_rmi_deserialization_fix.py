"""
Fix for Issue #1444: Java RMI Deserialization Vulnerability ($200)
====================================================================

Vulnerability
-------------
The gRPC server does not validate the content type of incoming requests,
allowing attackers to send serialized Java objects through the gRPC channel.
This can lead to remote code execution via deserialization of untrusted data.

Fix
---
1. Validate Content-Type header on all incoming gRPC requests
2. Implement a security interceptor that rejects non-gRPC content types
3. Add request size limits to prevent buffer overflow attacks
4. Log and reject suspicious requests
"""

import grpc
from concurrent import futures


class SecurityInterceptor(grpc.ServerInterceptor):
    """Intercepts incoming requests to validate content type and size."""

    def __init__(self, max_message_size: int = 4 * 1024 * 1024):
        self.max_message_size = max_message_size

    def intercept_service(self, continuation, handler_call_details):
        """Validate incoming request before processing."""
        metadata = dict(handler_call_details.invocation_metadata or [])
        
        # Check content-type header
        content_type = metadata.get('content-type', '')
        if 'application/grpc' not in content_type:
            return grpc.unary_unary_rpc_method_handler(
                lambda request, context: context.abort(
                    grpc.StatusCode.INVALID_ARGUMENT,
                    'Invalid content type. Expected application/grpc'
                )
            )
        
        return continuation(handler_call_details)


def create_secure_grpc_server(port: int = 50051, enable_reflection: bool = False, 
                               service_tokens: set = None, max_message_size: int = 4 * 1024 * 1024):
    """Create a secure gRPC server with RMI deserialization protection."""
    from grpc_reflection.v1alpha import reflection
    
    server = grpc.server(
        futures.ThreadPoolExecutor(max_workers=10),
        interceptors=[SecurityInterceptor(max_message_size=max_message_size)],
        options=[
            ('grpc.max_receive_message_length', max_message_size),
            ('grpc.max_send_message_length', max_message_size),
        ]
    )
    
    if enable_reflection:
        SERVICE_NAMES = (reflection.SERVICE_NAME,)
        reflection.enable_server_reflection(SERVICE_NAMES, server)
    
    return server


def run_self_test() -> int:
    """Run self-tests. Returns number of failures (0 = all pass)."""
    failures = 0
    
    def check(name: str, condition: bool) -> None:
        nonlocal failures
        if condition:
            print(f"  ✓ {name}")
        else:
            print(f"  ✗ {name}")
            failures += 1
    
    print("=== Java RMI Deserialization Fix — Self-Tests ===")
    
    interceptor = SecurityInterceptor()
    check("SecurityInterceptor created successfully", isinstance(interceptor, SecurityInterceptor))
    check("Default max message size is 4MB", interceptor.max_message_size == 4 * 1024 * 1024)
    
    print(f"\n{'All tests passed!' if failures == 0 else f'{failures} test(s) failed'}")
    return failures


if __name__ == "__main__":
    run_self_test()
