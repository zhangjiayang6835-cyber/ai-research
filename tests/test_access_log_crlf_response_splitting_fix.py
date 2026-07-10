import unittest

from FIXES.access_log_crlf_response_splitting_fix import (
    AccessLogHeaderPolicy,
    HeaderInjectionError,
    access_log_header_value,
    contains_crlf,
    set_access_log_header,
    validate_header_name,
)


class AccessLogCRLFFixTests(unittest.TestCase):
    def test_detects_literal_and_encoded_crlf_payloads(self):
        self.assertTrue(contains_crlf("Mozilla\r\nX-Hacked: true"))
        self.assertTrue(contains_crlf("Mozilla%0d%0aX-Hacked:%20true"))
        self.assertTrue(contains_crlf("Mozilla%250d%250aX-Hacked:%2520true"))
        self.assertFalse(contains_crlf("Mozilla/5.0 (Windows NT 10.0)"))

    def test_rejects_response_splitting_user_agent_by_default(self):
        with self.assertRaises(HeaderInjectionError):
            access_log_header_value("Mozilla\r\nX-Hacked: true")

        with self.assertRaises(HeaderInjectionError):
            access_log_header_value("Mozilla%0d%0aSet-Cookie:%20sid=attacker")

    def test_encodes_safe_user_agent_without_json_or_raw_header_copy(self):
        value = access_log_header_value("Mozilla/5.0 test bot")

        self.assertEqual(value, "Mozilla%2F5.0%20test%20bot")
        self.assertNotIn("\r", value)
        self.assertNotIn("\n", value)

    def test_sanitize_mode_removes_crlf_before_encoding(self):
        policy = AccessLogHeaderPolicy(reject_on_crlf=False)

        value = access_log_header_value("Mozilla%0d%0aX-Hacked: true", policy=policy)

        self.assertEqual(value, "Mozilla%20X-Hacked%3A%20true")
        self.assertNotIn("\r", value)
        self.assertNotIn("\n", value)

    def test_set_access_log_header_writes_only_encoded_value(self):
        response = {}

        written = set_access_log_header(response, "curl/8.0; test")

        self.assertEqual(response, {"X-Log": "curl%2F8.0%3B%20test"})
        self.assertEqual(written, response["X-Log"])

    def test_set_header_protocol_response_is_supported(self):
        class Response:
            def __init__(self):
                self.headers = {}

            def set_header(self, name, value):
                self.headers[name] = value

        response = Response()

        set_access_log_header(response, "Agent ok")

        self.assertEqual(response.headers, {"X-Log": "Agent%20ok"})

    def test_header_names_are_validated(self):
        self.assertEqual(validate_header_name("X-Log"), "X-Log")

        with self.assertRaises(HeaderInjectionError):
            validate_header_name("X-Log\r\nInjected")

        with self.assertRaises(HeaderInjectionError):
            set_access_log_header({}, "safe", policy=AccessLogHeaderPolicy(header_name="Set-Cookie"))


if __name__ == "__main__":
    unittest.main()
