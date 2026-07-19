"""Tests for the Issue #1353 TOTP-secret-in-logs fix.

Verifies the raw base32 secret never survives into emitted log output and that
`redact()` fully removes it (no partial-prefix leak).
"""

from __future__ import annotations

import io
import logging
import os
import sys
import unittest

try:
    from fixes.fix_1353 import (
        SecureTOTPProvisioner,
        SensitiveDataRedactor,
        install_redaction,
        redact,
    )
except ModuleNotFoundError:
    sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(__file__)), "FIXES"))
    from fix_1353 import (
        SecureTOTPProvisioner,
        SensitiveDataRedactor,
        install_redaction,
        redact,
    )

SECRET = "JBSWY3DPEHPK3PXP"
URI = f"otpauth://totp/Example:user@example.com?secret={SECRET}&issuer=Example"


class RedactTests(unittest.TestCase):
    def test_otpauth_uri_is_fully_removed(self) -> None:
        out = redact(f"QR generated: {URI} done")
        self.assertNotIn(SECRET, out)
        self.assertNotIn("otpauth://", out)

    def test_secret_field_is_fully_removed_no_prefix_leak(self) -> None:
        out = redact(f"totp secret={SECRET} stored")
        self.assertNotIn(SECRET, out)
        # Even the first characters of the secret must not survive.
        self.assertNotIn(SECRET[:3], out)
        self.assertIn("secret=[REDACTED]", out)

    def test_non_sensitive_text_is_preserved(self) -> None:
        self.assertEqual(redact("user=alice action=login"), "user=alice action=login")


class LoggingFilterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.stream = io.StringIO()
        self.handler = logging.StreamHandler(self.stream)
        self.handler.addFilter(SensitiveDataRedactor())
        self.logger = logging.getLogger("test.totp.1353")
        self.logger.handlers.clear()
        self.logger.addHandler(self.handler)
        self.logger.setLevel(logging.DEBUG)
        self.logger.propagate = False

    def _output(self) -> str:
        self.handler.flush()
        return self.stream.getvalue()

    def test_secret_in_message_is_redacted(self) -> None:
        self.logger.info("Provisioning QR: %s", URI)
        out = self._output()
        self.assertNotIn(SECRET, out)

    def test_secret_in_format_args_is_redacted(self) -> None:
        self.logger.warning("failed with secret=%s", SECRET)
        out = self._output()
        self.assertNotIn(SECRET, out)

    def test_dict_args_are_redacted(self) -> None:
        self.logger.info("setup %(secret)s", {"secret": SECRET})
        self.assertNotIn(SECRET, self._output())


class ProvisionerTests(unittest.TestCase):
    def test_uri_contains_secret_but_logs_do_not(self) -> None:
        stream = io.StringIO()
        handler = logging.StreamHandler(stream)
        # Bind to the exact logger the provisioner uses (module __name__).
        logger = logging.getLogger(SecureTOTPProvisioner.__module__)
        logger.handlers.clear()
        logger.addHandler(handler)
        logger.setLevel(logging.DEBUG)
        logger.propagate = False

        provisioner = SecureTOTPProvisioner("Example", "user@example.com")
        uri = provisioner.provisioning_uri(SECRET)

        handler.flush()
        logs = stream.getvalue()
        # The QR needs the secret...
        self.assertIn(SECRET, uri)
        # ...but the logs must not contain it.
        self.assertNotIn(SECRET, logs)
        self.assertIn("issuer=Example", logs)

    def test_install_redaction_covers_accidental_logging(self) -> None:
        stream = io.StringIO()
        handler = logging.StreamHandler(stream)
        logger = logging.getLogger("test.totp.1353.install")
        logger.handlers.clear()
        logger.addHandler(handler)
        logger.setLevel(logging.DEBUG)
        logger.propagate = False

        install_redaction(logger)
        logger.info("oops leaked the whole uri %s", URI)

        handler.flush()
        self.assertNotIn(SECRET, stream.getvalue())


if __name__ == "__main__":
    unittest.main()
