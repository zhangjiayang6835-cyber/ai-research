"""Tests for issue #807 gRPC Reflection abuse prevention.

Covers all three defense layers:
  1. Production gating (disable reflection in production)
  2. mTLS authentication
  3. Service token requirement for internal APIs
"""

from __future__ import annotations

import unittest

from fixes.grpc_reflection_abuse_fix import (
    ReflectionAccessError,
    ReflectionGuard,
    ReflectionPolicy,
    SERVICE_TOKEN_HEADER,
    MTLS_CERT_HEADER,
    is_reflection_method,
    normalize_metadata,
    vulnerable_reflection_service,
)


REFLECTION_METHOD = "/grpc.reflection.v1.ServerReflection/ServerReflectionInfo"


class GrpcReflectionAbuseFixTests(unittest.TestCase):
    """Tests for gRPC Reflection abuse fix (issue #807)."""

    # --- Layer 1: Production gating ---

    def test_vulnerable_service_exposes_everything(self) -> None:
        """Unfixed reflection returns all services to any caller."""
        services = (
            "public.Health",
            "public.Profile",
            "internal.Admin",
            "billing.SecretLedger",
        )
        self.assertEqual(vulnerable_reflection_service(services), services)

    def test_production_reflection_is_disabled_by_default(self) -> None:
        """Layer 1: Reflection is disabled in production by default."""
        guard = ReflectionGuard(ReflectionPolicy(), bearer_tokens={"token": "admin"})
        with self.assertRaisesRegex(ReflectionAccessError, "disabled in production"):
            guard.authorize(
                method=REFLECTION_METHOD,
                metadata={"authorization": "Bearer token"},
                peer="203.0.113.10",
                service_names=("public.Health",),
            )

    def test_production_reflection_can_be_allowed_explicitly(self) -> None:
        """Production reflection allowed when policy permits."""
        guard = ReflectionGuard(
            ReflectionPolicy(
                environment="production",
                allow_reflection_in_production=True,
                require_mtls=False,
                require_service_token=False,
            ),
            bearer_tokens={"token": "admin"},
        )
        decision = guard.authorize(
            method=REFLECTION_METHOD,
            metadata={"authorization": "Bearer token"},
            peer="127.0.0.1",
            service_names=("public.Health",),
        )
        self.assertIsNotNone(decision)
        self.assertEqual(decision.role, "admin")

    def test_non_reflection_rpc_is_not_blocked_by_guard(self) -> None:
        """Non-reflection RPCs pass through without being blocked."""
        guard = ReflectionGuard(ReflectionPolicy(), bearer_tokens={})
        self.assertIsNone(
            guard.authorize(
                method="/shop.CartService/GetCart",
                metadata={},
                peer="203.0.113.10",
            )
        )

    def test_staging_environment_allows_reflection_with_auth(self) -> None:
        """Staging env allows reflection when properly authenticated."""
        guard = ReflectionGuard(
            ReflectionPolicy(
                environment="staging",
                require_mtls=False,
                require_service_token=False,
                allowed_services=frozenset({"public.Health", "public.Profile"}),
            ),
            bearer_tokens={"operator-token": "operator"},
        )
        decision = guard.authorize(
            method=REFLECTION_METHOD,
            metadata={"authorization": "Bearer operator-token"},
            peer="203.0.113.10",
            service_names=("public.Health", "public.Profile"),
        )
        self.assertIsNotNone(decision)
        self.assertEqual(decision.role, "operator")

    # --- Layer 2: mTLS authentication ---

    def test_mtls_is_required_by_default(self) -> None:
        """Layer 2: mTLS cert is required for reflection access."""
        guard = ReflectionGuard(
            ReflectionPolicy(
                environment="development",
                require_mtls=True,
                require_service_token=False,
            ),
            bearer_tokens={"admin-token": "admin"},
        )

        with self.assertRaisesRegex(ReflectionAccessError, "mTLS"):
            guard.authorize(
                method=REFLECTION_METHOD,
                metadata={"authorization": "Bearer admin-token"},
                peer="127.0.0.1",
                service_names=("public.Health",),
            )

    def test_mtls_passes_with_cert_header(self) -> None:
        """mTLS check passes when cert is provided via metadata header."""
        guard = ReflectionGuard(
            ReflectionPolicy(
                environment="development",
                require_mtls=True,
                require_service_token=False,
            ),
            bearer_tokens={"admin-token": "admin"},
        )

        decision = guard.authorize(
            method=REFLECTION_METHOD,
            metadata={
                "authorization": "Bearer admin-token",
                MTLS_CERT_HEADER: "-----BEGIN CERTIFICATE-----\nMIID\n-----END CERTIFICATE-----",
            },
            peer="127.0.0.1",
            service_names=("public.Health",),
        )
        self.assertIsNotNone(decision)

    def test_mtls_passes_with_tls_client_cert_param(self) -> None:
        """mTLS check passes when cert is provided via tls_client_cert param."""
        guard = ReflectionGuard(
            ReflectionPolicy(
                environment="development",
                require_mtls=True,
                require_service_token=False,
            ),
            bearer_tokens={"admin-token": "admin"},
        )

        decision = guard.authorize(
            method=REFLECTION_METHOD,
            metadata={"authorization": "Bearer admin-token"},
            peer="127.0.0.1",
            service_names=("public.Health",),
            tls_client_cert="-----BEGIN CERTIFICATE-----\nMIID\n-----END CERTIFICATE-----",
        )
        self.assertIsNotNone(decision)

    def test_mtls_optional_when_disabled_in_policy(self) -> None:
        """mTLS is not required when policy disables it."""
        guard = ReflectionGuard(
            ReflectionPolicy(
                environment="development",
                require_mtls=False,
                require_service_token=False,
            ),
            bearer_tokens={"admin-token": "admin"},
        )

        decision = guard.authorize(
            method=REFLECTION_METHOD,
            metadata={"authorization": "Bearer admin-token"},
            peer="127.0.0.1",
            service_names=("public.Health",),
        )
        self.assertIsNotNone(decision)

    # --- Layer 3: Service token for internal APIs ---

    def test_service_token_required_for_internal_api(self) -> None:
        """Layer 3: Service token is required for internal/sensitive APIs."""
        guard = ReflectionGuard(
            ReflectionPolicy(
                environment="development",
                require_mtls=False,
                require_service_token=True,
                service_tokens=frozenset({"svc-token-123"}),
            ),
            bearer_tokens={"admin-token": "admin"},
        )

        with self.assertRaisesRegex(ReflectionAccessError, "service token"):
            guard.authorize(
                method=REFLECTION_METHOD,
                metadata={"authorization": "Bearer admin-token"},
                peer="127.0.0.1",
                service_names=("internal.Admin", "billing.SecretLedger"),
            )

    def test_service_token_passes_with_valid_token(self) -> None:
        """Valid service token allows internal API access."""
        guard = ReflectionGuard(
            ReflectionPolicy(
                environment="development",
                require_mtls=False,
                require_service_token=True,
                service_tokens=frozenset({"svc-token-123"}),
            ),
            bearer_tokens={"admin-token": "admin"},
        )

        decision = guard.authorize(
            method=REFLECTION_METHOD,
            metadata={
                "authorization": "Bearer admin-token",
                SERVICE_TOKEN_HEADER: "svc-token-123",
            },
            peer="127.0.0.1",
            service_names=("internal.Admin",),
        )
        self.assertIsNotNone(decision)

    def test_service_token_rejected_for_invalid_token(self) -> None:
        """Invalid service token is rejected."""
        guard = ReflectionGuard(
            ReflectionPolicy(
                environment="development",
                require_mtls=False,
                require_service_token=True,
                service_tokens=frozenset({"svc-token-123"}),
            ),
            bearer_tokens={"admin-token": "admin"},
        )

        with self.assertRaisesRegex(ReflectionAccessError, "invalid service token"):
            guard.authorize(
                method=REFLECTION_METHOD,
                metadata={
                    "authorization": "Bearer admin-token",
                    SERVICE_TOKEN_HEADER: "wrong-token",
                },
                peer="127.0.0.1",
                service_names=("internal.Admin",),
            )

    def test_service_token_not_required_for_public_services(self) -> None:
        """Service token is not required for public (non-sensitive) services."""
        guard = ReflectionGuard(
            ReflectionPolicy(
                environment="development",
                require_mtls=False,
                require_service_token=True,
                service_tokens=frozenset({"svc-token-123"}),
            ),
            bearer_tokens={"admin-token": "admin"},
        )

        decision = guard.authorize(
            method=REFLECTION_METHOD,
            metadata={"authorization": "Bearer admin-token"},
            peer="127.0.0.1",
            service_names=("public.Health", "public.Profile"),
        )
        self.assertIsNotNone(decision)
        # Should NOT raise about service token since these are public services

    # --- Combined: All three layers ---

    def test_all_three_layers_staging(self) -> None:
        """All three layers work together in staging."""
        guard = ReflectionGuard(
            ReflectionPolicy(
                environment="staging",
                require_mtls=True,
                require_service_token=True,
                service_tokens=frozenset({"svc-internal-001"}),
                allowed_services=frozenset(
                    {"public.Health", "public.Profile"}
                ),
            ),
            bearer_tokens={"admin-token": "admin"},
        )

        # With all requirements satisfied
        decision = guard.authorize(
            method=REFLECTION_METHOD,
            metadata={
                "authorization": "Bearer admin-token",
                MTLS_CERT_HEADER: "-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----",
                SERVICE_TOKEN_HEADER: "svc-internal-001",
            },
            peer="127.0.0.1",
            service_names=("public.Health", "internal.Admin"),
        )
        self.assertIsNotNone(decision)
        self.assertEqual(decision.role, "admin")
        # Sensitive service should be filtered out
        self.assertNotIn("internal.Admin", decision.service_names)
        self.assertIn("public.Health", decision.service_names)

    # --- Existing tests (migrated) ---

    def test_authorized_operator_gets_only_allowlisted_public_services(self) -> None:
        """Authorized operators only see allowed services; sensitive ones filtered."""
        guard = ReflectionGuard(
            ReflectionPolicy(
                environment="staging",
                require_mtls=False,
                require_service_token=False,
                allowed_services=frozenset(
                    {
                        "public.Health",
                        "public.Profile",
                        "internal.Admin",
                        "billing.SecretLedger",
                    }
                ),
            ),
            bearer_tokens={"operator-token": "operator"},
        )

        decision = guard.authorize(
            method=REFLECTION_METHOD,
            metadata={"authorization": "Bearer operator-token"},
            peer="203.0.113.10",
            service_names=(
                "public.Health",
                "public.Profile",
                "internal.Admin",
                "billing.SecretLedger",
                "unknown.Debug",
            ),
        )

        self.assertIsNotNone(decision)
        self.assertEqual(decision.role, "operator")
        self.assertEqual(decision.service_names, ("public.Health", "public.Profile"))

    def test_missing_or_invalid_token_is_rejected(self) -> None:
        """Missing or invalid bearer token is rejected."""
        guard = ReflectionGuard(
            ReflectionPolicy(
                environment="development",
                require_mtls=False,
                require_service_token=False,
            ),
            bearer_tokens={"admin-token": "admin"},
        )

        with self.assertRaisesRegex(ReflectionAccessError, "missing bearer"):
            guard.authorize(
                method=REFLECTION_METHOD,
                metadata={},
                peer="127.0.0.1",
            )

        with self.assertRaisesRegex(ReflectionAccessError, "invalid bearer"):
            guard.authorize(
                method=REFLECTION_METHOD,
                metadata={"authorization": "Bearer wrong"},
                peer="127.0.0.1",
            )

    def test_disallowed_role_is_rejected(self) -> None:
        """Roles not in the allowed roles set are rejected."""
        guard = ReflectionGuard(
            ReflectionPolicy(
                environment="development",
                require_mtls=False,
                require_service_token=False,
                allowed_roles=frozenset({"admin"}),
            ),
            bearer_tokens={"viewer-token": "viewer"},
        )

        with self.assertRaisesRegex(ReflectionAccessError, "authorized role"):
            guard.authorize(
                method=REFLECTION_METHOD,
                metadata={"authorization": "Bearer viewer-token"},
                peer="127.0.0.1",
            )

    def test_reflection_rate_limit_is_per_peer(self) -> None:
        """Rate limiting is applied per client peer."""
        guard = ReflectionGuard(
            ReflectionPolicy(
                environment="development",
                require_mtls=False,
                require_service_token=False,
                max_reflection_requests_per_window=2,
                rate_window_seconds=10,
            ),
            bearer_tokens={"admin-token": "admin"},
        )
        metadata = {"authorization": "Bearer admin-token"}

        guard.authorize(method=REFLECTION_METHOD, metadata=metadata, peer="client-a", now=100.0)
        guard.authorize(method=REFLECTION_METHOD, metadata=metadata, peer="client-a", now=101.0)
        guard.authorize(method=REFLECTION_METHOD, metadata=metadata, peer="client-b", now=101.0)

        with self.assertRaisesRegex(ReflectionAccessError, "rate limit"):
            guard.authorize(
                method=REFLECTION_METHOD,
                metadata=metadata,
                peer="client-a",
                now=102.0,
            )

        guard.authorize(
            method=REFLECTION_METHOD,
            metadata=metadata,
            peer="client-a",
            now=111.5,
        )

    def test_reflection_method_detection_and_metadata_normalization(self) -> None:
        """Reflection method prefix detection and metadata normalization work."""
        self.assertTrue(is_reflection_method(REFLECTION_METHOD))
        self.assertTrue(
            is_reflection_method(
                "/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo"
            )
        )
        self.assertFalse(is_reflection_method("/public.Health/Check"))

        self.assertEqual(
            normalize_metadata(
                [("Authorization", " Bearer token "), ("X-Trace", "abc")]
            ),
            {"authorization": "Bearer token", "x-trace": "abc"},
        )

    def test_env_var_based_configuration(self) -> None:
        """Environment variable based configuration works."""
        import os

        os.environ["GRPC_REFLECTION_ENVIRONMENT"] = "development"
        os.environ["GRPC_REFLECTION_REQUIRE_MTLS"] = "false"
        os.environ["GRPC_REFLECTION_REQUIRE_SERVICE_TOKEN"] = "false"

        from fixes.grpc_reflection_abuse_fix import create_reflection_guard_from_env

        guard = create_reflection_guard_from_env(
            bearer_tokens={"admin-token": "admin"}
        )
        self.assertEqual(guard.policy.environment, "development")
        self.assertFalse(guard.policy.require_mtls)

        # Clean up
        del os.environ["GRPC_REFLECTION_ENVIRONMENT"]
        del os.environ["GRPC_REFLECTION_REQUIRE_MTLS"]


if __name__ == "__main__":
    unittest.main()
