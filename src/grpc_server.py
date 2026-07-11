"""Secure gRPC server with mTLS, token auth, and conditional reflection."""

import os
import grpc
from grpc_reflection.v1alpha import reflection
from concurrent import futures
import logging

logger = logging.getLogger(__name__)


class TokenAuthInterceptor(grpc.ServerInterceptor):
    """Interceptor that validates service tokens for internal API calls."""

    def __init__(self, valid_tokens: set):
        self._valid_tokens = valid_tokens

    def intercept_service(self, continuation, handler_call_details):
        """Validate Authorization header before processing request."""
        metadata = dict(handler_call_details.invocation_metadata or [])
        auth_header = metadata.get('authorization', '')

        if auth_header.startswith('Bearer '):
            token = auth_header[7:]
            if token in self._valid_tokens:
                return continuation(handler_call_details)

        # Reject unauthenticated requests
        return grpc.unary_unary_rpc_method_handler(
            lambda request, context: context.abort(
                grpc.StatusCode.UNAUTHENTICATED,
                'Invalid or missing service token'
            )
        )


def create_secure_grpc_server(
    port: int = 50051,
    enable_reflection: bool = False,
    service_tokens: set = None,
    cert_path: str = None,
    key_path: str = None,
    ca_cert_path: str = None,
):
    """Create a production-ready gRPC server with security controls.

    Args:
        port: Server port
        enable_reflection: Only enable in dev/staging (default: False)
        service_tokens: Set of valid Bearer tokens for internal API auth
        cert_path: Server certificate for mTLS
        key_path: Server private key for mTLS
        ca_cert_path: CA certificate for client verification (mTLS)

    Returns:
        grpc.Server configured with security features
    """
    server = grpc.server(
        futures.ThreadPoolExecutor(max_workers=10),
        interceptors=[
            TokenAuthInterceptor(service_tokens or set())
        ] if service_tokens else None
    )

    # Configure mTLS if certificates provided
    if cert_path and key_path and ca_cert_path:
        with open(key_path, 'rb') as f:
            private_key = f.read()
        with open(cert_path, 'rb') as f:
            certificate_chain = f.read()
        with open(ca_cert_path, 'rb') as f:
            root_certificates = f.read()

        server_credentials = grpc.ssl_server_credentials(
            [(private_key, certificate_chain)],
            root_certificates=root_certificates,
            require_client_auth=True  # Enforce mTLS
        )
        server.add_secure_port(f'[::]:{port}', server_credentials)
        logger.info(f"gRPC server with mTLS listening on port {port}")
    else:
        server.add_insecure_port(f'[::]:{port}')
        logger.warning(f"gRPC server WITHOUT TLS on port {port}")

    # Reflection: DISABLED in production by default
    if enable_reflection:
        SERVICE_NAMES = (
            reflection.SERVICE_NAME,
            # Add your service names here
        )
        reflection.enable_server_reflection(SERVICE_NAMES, server)
        logger.warning("gRPC reflection ENABLED (should only be used in dev/staging)")
    else:
        logger.info("gRPC reflection DISABLED (production mode)")

    return server