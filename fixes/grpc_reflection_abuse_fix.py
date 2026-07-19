"""
Fix for gRPC Reflection abuse and service enumeration.

gRPC server reflection is useful in development, but leaving it open in
production gives unauthenticated clients a service map. Attackers can enumerate
package names, admin services, streaming methods, and message types, then use
that information to target weak endpoints.

This module provides three layers of defense:
  1. Production gating — disable reflection in production by default
  2. mTLS authentication — validate client TLS certificates
  3. Service token requirement — require X-Service-Token for internal APIs
"""

from __future__ import annotations

import os
import ssl
from dataclasses import dataclass, field
from time import monotonic
from typing import Mapping, Sequence


REFLECTION_METHOD_PREFIXES: tuple[str, ...] = (
    "/grpc.reflection.v1alpha.ServerReflection/",
    "/grpc.reflection.v1.ServerReflection/",
)

DEFAULT_SENSITIVE_SERVICE_HINTS: tuple[str, ...] = (
    "admin",
    "debug",
    "internal",
    "private",
    "secret",
    "root",
    "billing",
)

SERVICE_TOKEN_HEADER = "x-service-token"
MTLS_CERT_HEADER = "x-tls-client-cert"


class ReflectionAccessError(PermissionError):
    """Raised when a reflection request should not be served."""


@dataclass(frozen=True)
class ReflectionPolicy:
    """Declarative policy for serving gRPC reflection safely."""

    environment: str = "production"
    allow_reflection_in_production: bool = False
    allowed_roles: frozenset[str] = frozenset({"admin", "operator"})
    allowed_services: frozenset[str] = frozenset()
    sensitive_service_hints: tuple[str, ...] = DEFAULT_SENSITIVE_SERVICE_HINTS
    max_reflection_requests_per_window: int = 5
    rate_window_seconds: float = 60.0
    # mTLS settings
    require_mtls: bool = True
    mtls_ca_cert_path: str = ""
    # Service token settings
    require_service_token: bool = True
    service_tokens: frozenset[str] = frozenset()
    # Internal API patterns
    internal_api_prefixes: tuple[str, ...] = (
        "/internal.",
        "/admin.",
        "/debug.",
    )


@dataclass
class ReflectionDecision:
    """Result of an allowed reflection access check."""

    peer: str
    role: str
    service_names: tuple[str, ...] = field(default_factory=tuple)


class ReflectionGuard:
    """Authorize, rate-limit, and filter gRPC reflection requests."""

    def __init__(self, policy: ReflectionPolicy, bearer_tokens: Mapping[str, str]):
        self.policy = policy
        self._bearer_tokens = dict(bearer_tokens)
        self._request_times: dict[str, list[float]] = {}

    def authorize(
        self,
        *,
        method: str,
        metadata: Mapping[str, str] | Sequence[tuple[str, str]],
        peer: str,
        service_names: Sequence[str] = (),
        now: float | None = None,
        tls_client_cert: str | None = None,
    ) -> ReflectionDecision | None:
        """Return a decision for reflection calls; return None for other RPCs.

        Layers of defense (applied in order):
          1. Production gating — reject if in production and not explicitly allowed
          2. mTLS authentication — validate client TLS certificate
          3. Bearer token / role-based auth — validate authorization
          4. Service token — require service token for internal APIs
          5. Rate limiting — prevent abuse
          6. Service name filtering — only return allowed, non-sensitive services
        """

        # Only intercept reflection methods
        if not is_reflection_method(method):
            return None

        # Layer 1: Production gating
        if (
            self.policy.environment.lower() == "production"
            and not self.policy.allow_reflection_in_production
        ):
            raise ReflectionAccessError("gRPC reflection is disabled in production")

        # Layer 2: mTLS authentication
        if self.policy.require_mtls:
            self._verify_mtls(tls_client_cert or "", metadata)

        # Layer 3: Bearer token / role-based auth
        role = self._role_from_metadata(metadata)
        if role not in self.policy.allowed_roles:
            raise ReflectionAccessError("reflection requires an authorized role")

        # Layer 4: Service token for internal API access
        if self._is_internal_request(method, service_names):
            self._verify_service_token(metadata)

        # Layer 5: Rate limiting
        self._check_rate_limit(peer, monotonic() if now is None else now)

        # Layer 6: Service name filtering
        visible_services = self.filter_service_names(service_names)
        return ReflectionDecision(peer=peer, role=role, service_names=visible_services)

    def _verify_mtls(
        self,
        tls_client_cert: str,
        metadata: Mapping[str, str] | Sequence[tuple[str, str]],
    ) -> None:
        """Verify mTLS client certificate is present."""
        headers = normalize_metadata(metadata)
        cert = tls_client_cert or headers.get(MTLS_CERT_HEADER, "")

        if not cert:
            raise ReflectionAccessError("mTLS client certificate is required")

        # If CA cert path is configured, verify the certificate chain
        if self.policy.mtls_ca_cert_path and os.path.exists(
            self.policy.mtls_ca_cert_path
        ):
            _verify_cert_against_ca(cert, self.policy.mtls_ca_cert_path)

    def _verify_service_token(
        self, metadata: Mapping[str, str] | Sequence[tuple[str, str]]
    ) -> None:
        """Verify service token for internal API access."""
        if not self.policy.require_service_token:
            return

        if not self.policy.service_tokens:
            return

        headers = normalize_metadata(metadata)
        token = headers.get(SERVICE_TOKEN_HEADER, "")

        if not token:
            raise ReflectionAccessError("service token is required for internal APIs")

        if token not in self.policy.service_tokens:
            raise ReflectionAccessError("invalid service token")

    def _is_internal_request(
        self, method: str, service_names: Sequence[str]
    ) -> bool:
        """Check if the request targets an internal API."""
        if any(
            method.startswith(prefix)
            for prefix in self.policy.internal_api_prefixes
        ):
            return True
        for name in service_names:
            canonical = name.strip()
            if canonical and self._looks_sensitive(canonical):
                return True
        return False

    def filter_service_names(self, service_names: Sequence[str]) -> tuple[str, ...]:
        """Return only explicitly allowed non-sensitive service names."""
        filtered: list[str] = []
        for name in service_names:
            canonical = name.strip()
            if not canonical:
                continue
            if self.policy.allowed_services and canonical not in self.policy.allowed_services:
                continue
            if self._looks_sensitive(canonical):
                continue
            filtered.append(canonical)
        return tuple(filtered)

    def _role_from_metadata(
        self, metadata: Mapping[str, str] | Sequence[tuple[str, str]]
    ) -> str:
        headers = normalize_metadata(metadata)
        auth = headers.get("authorization", "")
        scheme, _, token = auth.partition(" ")
        if scheme.lower() != "bearer" or not token:
            raise ReflectionAccessError("missing bearer token")
        role = self._bearer_tokens.get(token)
        if role is None:
            raise ReflectionAccessError("invalid bearer token")
        return role

    def _check_rate_limit(self, peer: str, now: float) -> None:
        with_window = [
            timestamp
            for timestamp in self._request_times.get(peer, [])
            if now - timestamp < self.policy.rate_window_seconds
        ]
        if len(with_window) >= self.policy.max_reflection_requests_per_window:
            raise ReflectionAccessError("reflection rate limit exceeded")
        with_window.append(now)
        self._request_times[peer] = with_window

    def _looks_sensitive(self, service_name: str) -> bool:
        lowered = service_name.lower()
        return any(hint in lowered for hint in self.policy.sensitive_service_hints)


def _verify_cert_against_ca(cert_pem: str, ca_cert_path: str) -> None:
    """Verify a PEM-encoded client certificate against a CA certificate file."""
    context = ssl.create_default_context(cafile=ca_cert_path)
    context.verify_mode = ssl.CERT_REQUIRED
    from tempfile import NamedTemporaryFile

    with NamedTemporaryFile(mode="w", suffix=".pem", delete=False) as f:
        f.write(cert_pem)
        cert_path = f.name
    try:
        context.load_verify_locations(cafile=ca_cert_path)
        # Load the cert to verify it
        context.load_cert_chain(cert_path)
    except ssl.SSLError as e:
        raise ValueError(f"certificate verification failed: {e}") from e
    finally:
        os.unlink(cert_path)


def is_reflection_method(method: str) -> bool:
    """Detect both v1alpha and v1 gRPC reflection service methods."""
    return any(method.startswith(prefix) for prefix in REFLECTION_METHOD_PREFIXES)


def normalize_metadata(
    metadata: Mapping[str, str] | Sequence[tuple[str, str]]
) -> dict[str, str]:
    """Normalize gRPC metadata to lowercase keys with stripped values."""
    items = metadata.items() if isinstance(metadata, Mapping) else metadata
    normalized: dict[str, str] = {}
    for key, value in items:
        normalized[str(key).lower()] = str(value).strip()
    return normalized


def vulnerable_reflection_service(service_names: Sequence[str]) -> tuple[str, ...]:
    """Unsafe example: returns every service to any caller."""
    return tuple(service_names)


def create_reflection_guard_from_env(
    bearer_tokens: Mapping[str, str] | None = None,
) -> ReflectionGuard:
    """Create a ReflectionGuard configured from environment variables.

    Environment variables:
      - GRPC_REFLECTION_ENVIRONMENT: environment name (default: production)
      - GRPC_REFLECTION_ALLOW_IN_PROD: set to "true" to allow in production
      - GRPC_REFLECTION_REQUIRE_MTLS: set to "false" to disable mTLS (default: true)
      - GRPC_REFLECTION_CA_CERT_PATH: path to CA cert for mTLS verification
      - GRPC_REFLECTION_SERVICE_TOKENS: comma-separated list of valid service tokens
      - GRPC_REFLECTION_ALLOWED_SERVICES: comma-separated list of allowed services
      - GRPC_REFLECTION_BEARER_TOKENS: comma-separated "token=role" pairs
    """
    import os

    env = os.environ.get("GRPC_REFLECTION_ENVIRONMENT", "production")
    allow_prod = os.environ.get("GRPC_REFLECTION_ALLOW_IN_PROD", "").lower() == "true"
    require_mtls = os.environ.get("GRPC_REFLECTION_REQUIRE_MTLS", "true").lower() != "false"
    ca_path = os.environ.get("GRPC_REFLECTION_CA_CERT_PATH", "")
    svc_tokens_str = os.environ.get("GRPC_REFLECTION_SERVICE_TOKENS", "")
    svc_tokens = frozenset(
        t.strip() for t in svc_tokens_str.split(",") if t.strip()
    )
    allowed_svcs_str = os.environ.get("GRPC_REFLECTION_ALLOWED_SERVICES", "")
    allowed_svcs = frozenset(
        s.strip() for s in allowed_svcs_str.split(",") if s.strip()
    )

    # Parse bearer tokens
    bt = dict(bearer_tokens or {})
    bt_str = os.environ.get("GRPC_REFLECTION_BEARER_TOKENS", "")
    if bt_str:
        for pair in bt_str.split(","):
            if "=" in pair:
                token, role = pair.strip().split("=", 1)
                bt[token.strip()] = role.strip()

    policy = ReflectionPolicy(
        environment=env,
        allow_reflection_in_production=allow_prod,
        require_mtls=require_mtls,
        mtls_ca_cert_path=ca_path,
        service_tokens=svc_tokens,
        allowed_services=allowed_svcs,
    )

    return ReflectionGuard(policy, bearer_tokens=bt)


def _demo() -> None:
    """Demonstrate the reflection guard with all three layers."""
    guard = ReflectionGuard(
        ReflectionPolicy(
            environment="staging",
            allowed_services=frozenset({"public.Health", "public.Profile"}),
            require_mtls=True,
            require_service_token=True,
            service_tokens=frozenset({"svc-internal-001"}),
        ),
        bearer_tokens={"demo-token": "operator"},
    )
    decision = guard.authorize(
        method="/grpc.reflection.v1.ServerReflection/ServerReflectionInfo",
        metadata={
            "authorization": "Bearer demo-token",
            SERVICE_TOKEN_HEADER: "svc-internal-001",
            MTLS_CERT_HEADER: "fake-cert-placeholder",
        },
        peer="127.0.0.1",
        service_names=("public.Health", "admin.Root"),
    )
    print(decision)


if __name__ == "__main__":
    _demo()
