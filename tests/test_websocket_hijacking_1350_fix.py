"""Tests for the Issue #1350 WebSocket hijacking (missing cookie validation) fix.

Covers the three acceptance criteria: Bearer token on connect, token on every
message, and token bound to the user session.
"""

from __future__ import annotations

import os
import sys
import unittest

try:
    from fixes.fix_1350 import (
        Principal,
        SecureWebSocketServer,
        SessionTokenAuthenticator,
        WebSocketAuthError,
    )
except ModuleNotFoundError:
    sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(__file__)), "FIXES"))
    from fix_1350 import (
        Principal,
        SecureWebSocketServer,
        SessionTokenAuthenticator,
        WebSocketAuthError,
    )

ORIGINS = ["https://app.example.com"]


class WebSocketHijackingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.clock = [1000.0]
        self.auth = SessionTokenAuthenticator(b"server-secret", ttl_seconds=100, now=lambda: self.clock[0])
        self.server = SecureWebSocketServer(self.auth, ORIGINS)
        self.alice_token = self.auth.start_session("alice", "sess-alice")
        self.bob_token = self.auth.start_session("bob", "sess-bob")

    def _connect_alice(self) -> Principal:
        return self.server.authenticate_connection(
            origin="https://app.example.com",
            authorization=f"Bearer {self.alice_token}",
        )

    # -- Criterion 1: Bearer token on connection --------------------------

    def test_connection_requires_valid_bearer_token(self) -> None:
        principal = self._connect_alice()
        self.assertEqual(principal, Principal("alice", "sess-alice"))

    def test_connection_rejected_without_token_even_if_origin_ok(self) -> None:
        # The CSWSH core: passing Origin must NOT be enough.
        with self.assertRaisesRegex(WebSocketAuthError, "Authorization"):
            self.server.authenticate_connection(
                origin="https://app.example.com", authorization=None
            )

    def test_connection_rejected_for_bad_origin(self) -> None:
        with self.assertRaisesRegex(WebSocketAuthError, "origin"):
            self.server.authenticate_connection(
                origin="https://evil.example.com",
                authorization=f"Bearer {self.alice_token}",
            )

    def test_connection_rejected_for_forged_token(self) -> None:
        forged = self.alice_token[:-4] + ("0000" if self.alice_token[-4:] != "0000" else "1111")
        with self.assertRaisesRegex(WebSocketAuthError, "signature|encoding"):
            self.server.authenticate_connection(
                origin="https://app.example.com", authorization=f"Bearer {forged}"
            )

    # -- Criterion 2: token verified on every message ---------------------

    def test_valid_message_passes(self) -> None:
        conn = self._connect_alice()
        data = self.server.authenticate_message(conn, {"token": self.alice_token, "data": "hi"})
        self.assertEqual(data, "hi")

    def test_message_without_token_is_rejected(self) -> None:
        conn = self._connect_alice()
        with self.assertRaisesRegex(WebSocketAuthError, "missing authentication token"):
            self.server.authenticate_message(conn, {"data": "hi"})

    def test_expired_token_rejected_mid_stream(self) -> None:
        conn = self._connect_alice()
        self.clock[0] += 1000  # push past ttl
        with self.assertRaisesRegex(WebSocketAuthError, "expired"):
            self.server.authenticate_message(conn, {"token": self.alice_token, "data": "hi"})

    def test_revoked_session_rejected_mid_stream(self) -> None:
        conn = self._connect_alice()
        self.auth.revoke_session("sess-alice")
        with self.assertRaisesRegex(WebSocketAuthError, "active session"):
            self.server.authenticate_message(conn, {"token": self.alice_token, "data": "hi"})

    # -- Criterion 3: token bound to user session -------------------------

    def test_cannot_impersonate_another_user_with_their_token(self) -> None:
        # Alice's connection cannot send messages authenticated as Bob.
        conn = self._connect_alice()
        with self.assertRaisesRegex(WebSocketAuthError, "does not match"):
            self.server.authenticate_message(conn, {"token": self.bob_token, "data": "steal"})

    def test_token_bound_to_session_not_just_user(self) -> None:
        # A second session for alice yields a token that does not match the
        # connection bound to the first session.
        other_alice = self.auth.start_session("alice", "sess-alice-2")
        conn = self._connect_alice()
        with self.assertRaisesRegex(WebSocketAuthError, "does not match"):
            self.server.authenticate_message(conn, {"token": other_alice, "data": "x"})


if __name__ == "__main__":
    unittest.main()
