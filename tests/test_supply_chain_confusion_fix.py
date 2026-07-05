"""Tests for issue #336 dependency confusion and typosquatting hardening."""

from __future__ import annotations

import unittest

from fixes.supply_chain_confusion_fix import (
    DependencyPolicy,
    DependencySpec,
    SupplyChainSecurityError,
    looks_like_typosquat,
    parse_pip_requirement,
    validate_dependencies,
    validate_pip_requirements,
)


VALID_HASH = "sha256:0123456789abcdef0123456789abcdef"


def test_policy() -> DependencyPolicy:
    return DependencyPolicy(
        allowed_public_registries=frozenset({"https://pypi.org/simple", "https://registry.npmjs.org"}),
        private_registry="https://packages.example.internal",
        internal_prefixes=frozenset({"company-", "@company/"}),
        protected_names=frozenset({"requests", "flask", "lodash"}),
    )


class SupplyChainConfusionFixTests(unittest.TestCase):
    def test_accepts_pinned_public_dependency_with_hash(self) -> None:
        validate_dependencies(
            [
                DependencySpec(
                    name="requests",
                    version="2.32.4",
                    registry="https://pypi.org/simple",
                    hashes=frozenset({VALID_HASH}),
                )
            ],
            policy=test_policy(),
        )

    def test_rejects_unpinned_dependency_version(self) -> None:
        with self.assertRaises(SupplyChainSecurityError):
            validate_dependencies(
                [
                    DependencySpec(
                        name="flask",
                        version=">=3.0",
                        registry="https://pypi.org/simple",
                        hashes=frozenset({VALID_HASH}),
                    )
                ],
                policy=test_policy(),
            )

    def test_rejects_missing_hash_or_lock_entry(self) -> None:
        with self.assertRaises(SupplyChainSecurityError):
            validate_dependencies(
                [
                    DependencySpec(
                        name="flask",
                        version="3.0.0",
                        registry="https://pypi.org/simple",
                    )
                ],
                policy=test_policy(),
            )

    def test_rejects_internal_package_from_public_registry(self) -> None:
        with self.assertRaises(SupplyChainSecurityError):
            validate_dependencies(
                [
                    DependencySpec(
                        name="company-auth",
                        version="1.4.1",
                        registry="https://pypi.org/simple",
                        hashes=frozenset({VALID_HASH}),
                    )
                ],
                policy=test_policy(),
            )

    def test_accepts_internal_package_from_private_registry(self) -> None:
        validate_dependencies(
            [
                DependencySpec(
                    name="company-auth",
                    version="1.4.1",
                    registry="https://packages.example.internal",
                    hashes=frozenset({VALID_HASH}),
                )
            ],
            policy=test_policy(),
        )

    def test_rejects_typosquat_with_adjacent_transposition(self) -> None:
        self.assertEqual(looks_like_typosquat("requsets", {"requests"}), "requests")

        with self.assertRaises(SupplyChainSecurityError):
            validate_dependencies(
                [
                    DependencySpec(
                        name="requsets",
                        version="2.32.4",
                        registry="https://pypi.org/simple",
                        hashes=frozenset({VALID_HASH}),
                    )
                ],
                policy=test_policy(),
            )

    def test_rejects_untrusted_registry_for_public_package(self) -> None:
        with self.assertRaises(SupplyChainSecurityError):
            validate_dependencies(
                [
                    DependencySpec(
                        name="lodash",
                        version="4.17.21",
                        registry="https://mirror.example.invalid/npm",
                        hashes=frozenset({VALID_HASH}),
                    )
                ],
                policy=test_policy(),
            )

    def test_parses_and_validates_pip_requirement_line(self) -> None:
        dependency = parse_pip_requirement(
            "flask==3.0.0 --hash=sha256:0123456789abcdef0123456789abcdef"
        )

        self.assertIsNotNone(dependency)
        self.assertEqual(dependency.name, "flask")
        self.assertEqual(dependency.version, "3.0.0")
        validate_pip_requirements(
            ["flask==3.0.0 --hash=sha256:0123456789abcdef0123456789abcdef"],
            policy=test_policy(),
        )


if __name__ == "__main__":
    unittest.main()
