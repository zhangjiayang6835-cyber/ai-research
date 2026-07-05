"""Tests for issue #196 gRPC reflection abuse prevention."""

from __future__ import annotations

import unittest

from fixes.grpc_reflection_abuse_fix import (
    ReflectionAccessError,
    ReflectionGuard,
    ReflectionPolicy,
    is_reflection_method,
    normalize_metadata,
    vulnerable_reflection_service,
)


REFLECTION_METHOD = "/grpc.reflection.v1.ServerReflection/ServerReflectionInfo"


class GrpcReflectionAbuseFixTests(unittest.TestCase):
    def test_vulnerable_service_exposes_everything(self) -> None:
        services = (
            "public.Health",
            "public.Profile",
            "internal.Admin",
            "billing.SecretLedger",
        )

        self.assertEqual(vulnerable_reflection_service(services), services)

    def test_production_reflection_is_disabled_by_default(self) -> None:
        guard = ReflectionGuard(ReflectionPolicy(), bearer_tokens={"token": "admin"})

        with self.assertRaisesRegex(ReflectionAccessError, "disabled in production"):
            guard.authorize(
                method=REFLECTION_METHOD,
                metadata={"authorization": "Bearer token"},
                peer="203.0.113.10",
                service_names=("public.Health",),
            )

    def test_non_reflection_rpc_is_not_blocked_by_guard(self) -> None:
        guard = ReflectionGuard(ReflectionPolicy(), bearer_tokens={})

        self.assertIsNone(
            guard.authorize(
                method="/shop.CartService/GetCart",
                metadata={},
                peer="203.0.113.10",
            )
        )

    def test_authorized_operator_gets_only_allowlisted_public_services(self) -> None:
        guard = ReflectionGuard(
            ReflectionPolicy(
                environment="staging",
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
        guard = ReflectionGuard(
            ReflectionPolicy(environment="development"),
            bearer_tokens={"admin-token": "admin"},
        )

        with self.assertRaisesRegex(ReflectionAccessError, "missing bearer"):
            guard.authorize(method=REFLECTION_METHOD, metadata={}, peer="127.0.0.1")

        with self.assertRaisesRegex(ReflectionAccessError, "invalid bearer"):
            guard.authorize(
                method=REFLECTION_METHOD,
                metadata={"authorization": "Bearer wrong"},
                peer="127.0.0.1",
            )

    def test_disallowed_role_is_rejected(self) -> None:
        guard = ReflectionGuard(
            ReflectionPolicy(environment="development", allowed_roles=frozenset({"admin"})),
            bearer_tokens={"viewer-token": "viewer"},
        )

        with self.assertRaisesRegex(ReflectionAccessError, "authorized role"):
            guard.authorize(
                method=REFLECTION_METHOD,
                metadata={"authorization": "Bearer viewer-token"},
                peer="127.0.0.1",
            )

    def test_reflection_rate_limit_is_per_peer(self) -> None:
        guard = ReflectionGuard(
            ReflectionPolicy(
                environment="development",
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

        guard.authorize(method=REFLECTION_METHOD, metadata=metadata, peer="client-a", now=111.5)

    def test_reflection_method_detection_and_metadata_normalization(self) -> None:
        self.assertTrue(is_reflection_method(REFLECTION_METHOD))
        self.assertTrue(
            is_reflection_method(
                "/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo"
            )
        )
        self.assertFalse(is_reflection_method("/public.Health/Check"))

        self.assertEqual(
            normalize_metadata([("Authorization", " Bearer token "), ("X-Trace", "abc")]),
            {"authorization": "Bearer token", "x-trace": "abc"},
        )


if __name__ == "__main__":
    unittest.main()
