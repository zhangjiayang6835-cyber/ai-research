"""Tests for Host Header Injection → Password Reset Poisoning fix (#1343)."""

from __future__ import annotations

import unittest

from fixes.host_header_injection_password_reset_1343_fix import (
    HostHeaderValidationError,
    PasswordResetPoisoningError,
    build_password_reset_url,
    sanitize_password_reset_link,
    validate_host_header,
)


class HostHeaderInjectionPasswordReset1343Tests(unittest.TestCase):
    """Test suite for issue #1343 fix."""

    ALLOWED_HOSTS = {
        "localhost:5000",
        "app.example.com",
    }

    # ── Host Header Validation ─────────────────────────────────────

    def test_valid_host_is_accepted(self) -> None:
        """Valid host in allow-list passes validation."""
        host = validate_host_header(
            "app.example.com",
            self.ALLOWED_HOSTS,
        )
        self.assertEqual(host, "app.example.com")

    def test_valid_localhost_is_accepted(self) -> None:
        host = validate_host_header(
            "localhost:5000",
            self.ALLOWED_HOSTS,
        )
        self.assertEqual(host, "localhost:5000")

    def test_malicious_host_is_rejected(self) -> None:
        """Host not in allow-list is rejected."""
        with self.assertRaises(HostHeaderValidationError):
            validate_host_header(
                "evil.com",
                self.ALLOWED_HOSTS,
            )

    def test_empty_host_is_rejected(self) -> None:
        with self.assertRaises(HostHeaderValidationError):
            validate_host_header("", self.ALLOWED_HOSTS)

    def test_crlf_injection_host_is_rejected(self) -> None:
        """Host with CR/LF characters is rejected."""
        with self.assertRaises(HostHeaderValidationError):
            validate_host_header(
                "good.com\r\nX-Injected: true",
                self.ALLOWED_HOSTS,
            )

    def test_multiple_host_header_is_rejected(self) -> None:
        """Comma-separated multiple Host headers are rejected."""
        with self.assertRaises(HostHeaderValidationError):
            validate_host_header(
                "app.example.com,evil.com",
                self.ALLOWED_HOSTS,
            )

    def test_host_with_control_chars_is_rejected(self) -> None:
        with self.assertRaises(HostHeaderValidationError):
            validate_host_header(
                "app\x00example.com",
                self.ALLOWED_HOSTS,
            )

    # ── Password Reset URL Building ─────────────────────────────────

    def test_password_reset_url_uses_validated_host(self) -> None:
        """Reset URL uses the validated hostname."""
        url = sanitize_password_reset_link(
            "app.example.com",
            "abc123",
            self.ALLOWED_HOSTS,
        )
        self.assertTrue(url.startswith("https://app.example.com/reset"))
        self.assertIn("token=abc123", url)

    def test_password_reset_url_rejects_poisoned_host(self) -> None:
        """Reset URL with malicious host raises error."""
        with self.assertRaises(HostHeaderValidationError):
            sanitize_password_reset_link(
                "evil.com",
                "abc123",
                self.ALLOWED_HOSTS,
            )

    def test_build_reset_url_without_host_defaults(self) -> None:
        """build_password_reset_url with no host uses first allowed."""
        url = build_password_reset_url(
            "tok123",
            allowed_hosts={"localhost:5000"},
        )
        self.assertIn("localhost:5000", url)
        self.assertIn("token=tok123", url)

    def test_build_reset_url_rejects_nonexistent_host(self) -> None:
        with self.assertRaises(PasswordResetPoisoningError):
            build_password_reset_url(
                "tok123",
                host="nonexistent.com",
                allowed_hosts={"valid.com"},
            )


if __name__ == "__main__":
    unittest.main()
