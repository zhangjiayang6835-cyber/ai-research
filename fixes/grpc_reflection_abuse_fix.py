"""Fix for issue #196: gRPC reflection abuse and service enumeration.

gRPC server reflection is useful in development, but leaving it open in
production gives unauthenticated clients a service map. Attackers can enumerate
package names, admin services, streaming methods, and message types, then use
that information to target weak endpoints.

This module is framework-neutral: it models the policy checks a real gRPC
interceptor should apply before dispatching reflection requests.
"""

from __future__ import annotations

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
    ) -> ReflectionDecision | None:
        """Return a decision for reflection calls; return None for other RPCs."""

        if not is_reflection_method(method):
            return None

        if (
            self.policy.environment.lower() == "production"
            and not self.policy.allow_reflection_in_production
        ):
            raise ReflectionAccessError("gRPC reflection is disabled in production")

        role = self._role_from_metadata(metadata)
        if role not in self.policy.allowed_roles:
            raise ReflectionAccessError("reflection requires an authorized role")

        self._check_rate_limit(peer, monotonic() if now is None else now)
        visible_services = self.filter_service_names(service_names)
        return ReflectionDecision(peer=peer, role=role, service_names=visible_services)

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


def _demo() -> None:
    guard = ReflectionGuard(
        ReflectionPolicy(
            environment="staging",
            allowed_services=frozenset({"public.Health", "public.Profile"}),
        ),
        bearer_tokens={"demo-token": "operator"},
    )
    decision = guard.authorize(
        method="/grpc.reflection.v1.ServerReflection/ServerReflectionInfo",
        metadata={"authorization": "Bearer demo-token"},
        peer="127.0.0.1",
        service_names=("public.Health", "admin.Root"),
    )
    print(decision)


if __name__ == "__main__":
    _demo()
