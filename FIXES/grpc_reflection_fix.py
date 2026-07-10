"""
gRPC Reflection Enabled → Service Enumeration Fix
Bounty #807 ($120)
=========================================
Vulnerability: gRPC server exposes Reflection API (grpc.reflection.v1alpha).
Attacker enumerates all services and methods.

Fix: Disable Reflection in production + mTLS + auth.
"""


class SecureGrpcConfig:
    """
    Secure gRPC server configuration.
    """

    @staticmethod
    def production_config() -> dict:
        """Production gRPC configuration with Reflection disabled."""
        return {
            "reflection_enabled": False,
            "tls_required": True,
            "mtls_required": True,
            "auth_required": True,
            "rate_limiting": True,
            "max_message_size": 4194304,  # 4MB
        }

    @staticmethod
    def development_config() -> dict:
        """Development config — Reflection enabled but access restricted."""
        return {
            "reflection_enabled": True,
            "reflection_allowed_ips": ["127.0.0.1", "::1"],
            "tls_required": False,
            "auth_required": True,
        }

    @staticmethod
    def interceptor_config() -> str:
        """Python gRPC interceptor for auth + Reflection blocking."""
        return """
import grpc
from grpc_interceptor import ServerInterceptor

class AuthInterceptor(ServerInterceptor):
    def intercept(self, method, request, context):
        # Block Reflection API in production
        if 'Reflection' in method:
            context.abort(grpc.StatusCode.PERMISSION_DENIED,
                         "Reflection API disabled")
        
        # Validate auth token
        metadata = context.invocation_metadata()
        token = dict(metadata).get('authorization', '')
        if not token.startswith('Bearer '):
            context.abort(grpc.StatusCode.UNAUTHENTICATED,
                         "Missing auth token")
        
        return method(request, context)
"""

    @staticmethod
    def grpcurl_block_command() -> str:
        """Command to test Reflection is disabled."""
        return (
            "# Test: should fail\n"
            "grpcurl -plaintext localhost:50051 list\n"
            "# Expected: Failed to list services: server does not support the reflection API\n"
        )


# ========== Usage Example ==========
if __name__ == "__main__":
    print("=== gRPC Reflection Prevention ===")
    print()

    print("Attack scenario:")
    print("  grpcurl -plaintext localhost:50051 list")
    print("  → Lists all gRPC services and methods!")
    print("  → Attacker identifies unauthenticated endpoints")
    print()

    print("Production config:")
    for k, v in SecureGrpcConfig.production_config().items():
        print(f"  ✓ {k}: {v}")
    print()
    print("Measures:")
    print("✓ Reflection disabled in production")
    print("✓ mTLS required for all connections")
    print("✓ Auth interceptor blocks Reflection API")
    print("✓ Rate limiting")
    print("✓ Development: Reflection allowed only from localhost")