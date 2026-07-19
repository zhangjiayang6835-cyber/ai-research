"""Tests for the Issue #1347 Docker capability-escape hardening fix."""

from __future__ import annotations

import os
import sys
import unittest

try:
    from fixes.fix_1347 import (
        CapabilityEscapeError,
        assert_safe_capabilities,
        find_capability_escape_risks,
        harden_service,
        normalize_cap,
    )
except ModuleNotFoundError:
    sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(__file__)), "FIXES"))
    from fix_1347 import (
        CapabilityEscapeError,
        assert_safe_capabilities,
        find_capability_escape_risks,
        harden_service,
        normalize_cap,
    )


class CapabilityEscapeTests(unittest.TestCase):
    def test_normalize_cap_strips_prefix_and_case(self) -> None:
        self.assertEqual(normalize_cap("CAP_SYS_ADMIN"), "SYS_ADMIN")
        self.assertEqual(normalize_cap("sys_admin"), "SYS_ADMIN")
        self.assertEqual(normalize_cap("  cap_sys_module "), "SYS_MODULE")

    def test_privileged_container_is_flagged(self) -> None:
        compose = {"services": {"worker": {"image": "x", "privileged": True}}}
        with self.assertRaises(CapabilityEscapeError):
            assert_safe_capabilities(compose)

    def test_escape_capabilities_flagged_various_forms(self) -> None:
        for cap in ("SYS_ADMIN", "CAP_SYS_MODULE", "dac_read_search", "ALL"):
            compose = {"services": {"api": {"image": "x", "cap_add": [cap]}}}
            with self.subTest(cap=cap):
                findings = find_capability_escape_risks(compose)
                caps = {f.capability for f in findings}
                self.assertTrue(
                    normalize_cap(cap) in caps or "ALL" in caps,
                    f"{cap} not flagged: {caps}",
                )

    def test_unconfined_seccomp_and_apparmor_flagged(self) -> None:
        compose = {
            "services": {
                "api": {
                    "image": "x",
                    "cap_add": ["SYS_ADMIN"],
                    "security_opt": ["seccomp=unconfined", "apparmor=unconfined"],
                }
            }
        }
        findings = find_capability_escape_risks(compose)
        locations = {f.capability for f in findings}
        self.assertIn("seccomp=unconfined", locations)
        self.assertIn("apparmor=unconfined", locations)

    def test_missing_no_new_privileges_flagged_when_risky(self) -> None:
        compose = {"services": {"api": {"image": "x", "cap_add": ["SYS_ADMIN"]}}}
        findings = find_capability_escape_risks(compose)
        self.assertTrue(any("no-new-privileges" in f.capability for f in findings))

    def test_safe_service_passes(self) -> None:
        compose = {
            "services": {
                "api": {
                    "image": "x",
                    "cap_drop": ["ALL"],
                    "security_opt": ["no-new-privileges:true", "seccomp=default"],
                }
            }
        }
        self.assertEqual(find_capability_escape_risks(compose), [])
        assert_safe_capabilities(compose)  # should not raise

    def test_non_escape_capability_is_allowed(self) -> None:
        # NET_BIND_SERVICE is not an escape primitive.
        compose = {
            "services": {
                "api": {
                    "image": "x",
                    "cap_drop": ["ALL"],
                    "cap_add": ["NET_BIND_SERVICE"],
                    "security_opt": ["no-new-privileges:true"],
                }
            }
        }
        self.assertEqual(find_capability_escape_risks(compose), [])

    def test_harden_service_produces_passing_config(self) -> None:
        unsafe = {
            "image": "x",
            "privileged": True,
            "cap_add": ["SYS_ADMIN", "SYS_MODULE"],
            "security_opt": ["seccomp=unconfined"],
        }
        hardened = harden_service(unsafe)
        self.assertEqual(hardened["privileged"], False)
        self.assertEqual(hardened["cap_drop"], ["ALL"])
        self.assertNotIn("cap_add", hardened)
        self.assertTrue(any("no-new-privileges" in t for t in hardened["security_opt"]))
        self.assertFalse(any("unconfined" in t for t in hardened["security_opt"]))
        # And it now passes validation.
        assert_safe_capabilities({"services": {"api": hardened}})

    def test_harden_service_refuses_to_readd_escape_caps(self) -> None:
        with self.assertRaises(ValueError):
            harden_service({"image": "x"}, cap_add=["SYS_ADMIN"])

    def test_harden_service_can_readd_safe_cap(self) -> None:
        hardened = harden_service({"image": "x"}, cap_add=["NET_BIND_SERVICE"])
        self.assertEqual(hardened["cap_add"], ["NET_BIND_SERVICE"])
        assert_safe_capabilities({"services": {"api": hardened}})

    def test_accepts_single_service_mapping(self) -> None:
        with self.assertRaises(CapabilityEscapeError):
            assert_safe_capabilities({"image": "x", "privileged": True})


if __name__ == "__main__":
    unittest.main()
