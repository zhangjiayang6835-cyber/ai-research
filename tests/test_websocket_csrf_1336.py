"""Tests for WebSocket CSRF → Cross-Origin Data Exfiltration fix (#1336)."""

from __future__ import annotations

import unittest

from fixes.websocket_csrf_1336_fix import (
    AuthenticatedWebSocketProcessor,
    MessageAuthenticationError,
    OriginValidationError,
    WebSocketCSRFError,
    authorize_data_access,
    generate_message_token,
    generate_ws_csrf_token,
    validate_origin,
    validate_ws_csrf_token,
    verify_message_token,
)


class WebSocketCSRF1336Tests(unittest.TestCase):
    """Test suite for issue #1336 fix."""

    def setUp(self):
        self.processor = AuthenticatedWebSocketProcessor()
        self.session_id = "sess_test123"
        self.csrf_token = generate_ws_csrf_token(self.session_id)

    # ── Origin Validation ───────────────────────────────────────────

    def test_allowed_origin_passes_validation(self) -> None:
        validate_origin("http://localhost:3000")
        validate_origin("https://app.example.com")

    def test_missing_origin_is_rejected(self) -> None:
        with self.assertRaises(OriginValidationError):
            validate_origin(None)

    def test_malicious_origin_is_rejected(self) -> None:
        with self.assertRaises(OriginValidationError):
            validate_origin("https://evil.com")

    def test_origin_with_trailing_slash_is_normalized(self) -> None:
        validate_origin("https://app.example.com/")

    def test_empty_origin_is_rejected(self) -> None:
        with self.assertRaises(OriginValidationError):
            validate_origin("")

    # ── CSRF Token ──────────────────────────────────────────────────

    def test_valid_csrf_token_passes_validation(self) -> None:
        self.assertTrue(
            validate_ws_csrf_token(self.session_id, self.csrf_token)
        )

    def test_invalid_csrf_token_fails_validation(self) -> None:
        self.assertFalse(
            validate_ws_csrf_token(self.session_id, "invalid_token")
        )

    def test_csrf_token_for_different_session_fails(self) -> None:
        other_token = generate_ws_csrf_token("sess_other456")
        self.assertFalse(
            validate_ws_csrf_token(self.session_id, other_token)
        )

    def test_empty_csrf_token_fails(self) -> None:
        self.assertFalse(
            validate_ws_csrf_token(self.session_id, "")
        )

    # ── Message Token ───────────────────────────────────────────────

    def test_valid_message_token_passes(self) -> None:
        token = generate_message_token(self.session_id, "get_data")
        self.assertTrue(
            verify_message_token(self.session_id, "get_data", token)
        )

    def test_message_token_for_different_action_fails(self) -> None:
        token = generate_message_token(self.session_id, "ping")
        self.assertFalse(
            verify_message_token(self.session_id, "get_data", token)
        )

    def test_invalid_message_token_fails(self) -> None:
        self.assertFalse(
            verify_message_token(self.session_id, "get_data", "bad")
        )

    # ── Data Access Control ─────────────────────────────────────────

    def test_public_data_accessible_without_session(self) -> None:
        self.assertTrue(
            authorize_data_access(None, "public_info")
        )

    def test_sensitive_data_denied_without_session(self) -> None:
        self.assertFalse(
            authorize_data_access(None, "sensitive")
        )

    def test_sensitive_data_accessible_with_admin_role(self) -> None:
        self.assertTrue(
            authorize_data_access("sess_1", "sensitive", role="admin")
        )

    def test_sensitive_data_denied_for_user_role(self) -> None:
        self.assertFalse(
            authorize_data_access("sess_1", "sensitive", role="user")
        )

    def test_unknown_data_type_denied_by_default(self) -> None:
        self.assertFalse(
            authorize_data_access("sess_1", "unknown_type")
        )

    # ── Full WebSocket Upgrade Validation ───────────────────────────

    def test_valid_upgrade_passes(self) -> None:
        """Valid origin + CSRF token passes upgrade validation."""
        self.processor.validate_upgrade(
            "http://localhost:3000",
            self.session_id,
            self.csrf_token,
        )

    def test_upgrade_with_invalid_origin_fails(self) -> None:
        with self.assertRaises(OriginValidationError):
            self.processor.validate_upgrade(
                "https://evil.com",
                self.session_id,
                self.csrf_token,
            )

    def test_upgrade_without_csrf_token_fails(self) -> None:
        with self.assertRaises(WebSocketCSRFError):
            self.processor.validate_upgrade(
                "http://localhost:3000",
                self.session_id,
                None,
            )

    def test_upgrade_without_session_fails(self) -> None:
        with self.assertRaises(WebSocketCSRFError):
            self.processor.validate_upgrade(
                "http://localhost:3000",
                None,
                "some_token",
            )

    def test_upgrade_with_invalid_csrf_token_fails(self) -> None:
        with self.assertRaises(WebSocketCSRFError):
            self.processor.validate_upgrade(
                "http://localhost:3000",
                self.session_id,
                "bad_token",
            )

    # ── Message Processing ──────────────────────────────────────────

    def test_ping_message_returns_pong(self) -> None:
        token = generate_message_token(self.session_id, "ping")
        result = self.processor.process_message(
            self.session_id,
            {"action": "ping", "_token": token},
        )
        self.assertEqual(result.get("type"), "pong")

    def test_message_without_token_is_rejected(self) -> None:
        with self.assertRaises(MessageAuthenticationError):
            self.processor.process_message(
                self.session_id,
                {"action": "get_data", "_token": ""},
            )

    def test_get_data_with_valid_token_succeeds(self) -> None:
        token = generate_message_token(self.session_id, "get_data")
        result = self.processor.process_message(
            self.session_id,
            {
                "action": "get_data",
                "_token": token,
                "_role": "admin",
                "type": "public_info",
            },
        )
        self.assertEqual(result.get("status"), "ok")

    def test_get_sensitive_data_denied_for_user(self) -> None:
        token = generate_message_token(self.session_id, "get_data")
        result = self.processor.process_message(
            self.session_id,
            {
                "action": "get_data",
                "_token": token,
                "_role": "user",
                "type": "sensitive",
            },
        )
        self.assertEqual(result.get("status"), "denied")


if __name__ == "__main__":
    unittest.main()
