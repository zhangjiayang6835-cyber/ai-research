"""Clickjacking protection helpers for issue #61.

The fix adds frame-busting headers to every HTTP response:
- X-Frame-Options: DENY
- Content-Security-Policy: frame-ancestors 'none'

It is intentionally framework-light so the same behavior can be used from
Flask, plain WSGI, or tests without adding dependencies.

In addition to the frame-busting headers, this module also hardens the
crypto withdrawal confirmation flow (issue: "Clickjacking via X-Frame-Options
Missing -> Crypto Withdraw") by requiring an explicit, server-issued,
single-use confirmation token before a withdrawal request can be finalized.
This provides defense-in-depth: even if a clickjacking attempt somehow got a
user to interact with a framed page, the withdrawal still cannot complete
without a second, out-of-band confirmation step.
"""

from __future__ import annotations

import secrets
import unittest
from typing import Callable, Dict, Iterable, MutableMapping, Optional, Tuple


X_FRAME_OPTIONS = "DENY"
CSP_FRAME_ANCESTORS = "frame-ancestors 'none'"


def _merge_csp(existing: str | None) -> str:
    """Return a CSP value that always includes frame-ancestors 'none'."""
    if not existing:
        return CSP_FRAME_ANCESTORS

    directives = [part.strip() for part in existing.split(";") if part.strip()]
    filtered = [
        directive
        for directive in directives
        if not directive.lower().startswith("frame-ancestors")
    ]
    filtered.append(CSP_FRAME_ANCESTORS)
    return "; ".join(filtered)


def apply_clickjacking_headers(
    headers: MutableMapping[str, str],
) -> MutableMapping[str, str]:
    """Apply clickjacking protections to a mutable headers mapping."""
    headers["X-Frame-Options"] = X_FRAME_OPTIONS
    headers["Content-Security-Policy"] = _merge_csp(
        headers.get("Content-Security-Policy")
    )
    return headers


def install_flask_clickjacking_protection(app):
    """Install response headers on all Flask responses.

    Usage:
        app = Flask(__name__)
        install_flask_clickjacking_protection(app)
    """

    @app.after_request
    def add_clickjacking_headers(response):
        response.headers["X-Frame-Options"] = X_FRAME_OPTIONS
        response.headers["Content-Security-Policy"] = _merge_csp(
            response.headers.get("Content-Security-Policy")
        )
        return response

    return app


class ClickjackingProtectionMiddleware:
    """WSGI middleware that adds frame-busting headers to every response."""

    def __init__(self, app: Callable):
        self.app = app

    def __call__(self, environ, start_response):
        def protected_start_response(
            status: str,
            headers: list[Tuple[str, str]],
            exc_info=None,
        ):
            normalized = {}
            output_headers = []
            for name, value in headers:
                lower = name.lower()
                normalized[lower] = value
                if lower not in {"x-frame-options", "content-security-policy"}:
                    output_headers.append((name, value))

            output_headers.append(("X-Frame-Options", X_FRAME_OPTIONS))
            output_headers.append(
                (
                    "Content-Security-Policy",
                    _merge_csp(normalized.get("content-security-policy")),
                )
            )
            return start_response(status, output_headers, exc_info)

        return self.app(environ, protected_start_response)


# ============================================================================
# Withdrawal two-step confirmation
# ----------------------------------------------------------------------------
# Mitigates clickjacking-driven unauthorized crypto withdrawals by requiring
# a second, explicit confirmation step tied to a server-issued single-use
# token. Step 1 (initiate) records the pending withdrawal and returns a
# token the legitimate client must present back. Step 2 (confirm) requires
# both that exact token AND an explicit confirm=True flag.
# ============================================================================

class WithdrawalConfirmationError(Exception):
    """Raised when a withdrawal confirmation cannot be completed."""


class WithdrawalConfirmationManager:
    """Tracks pending withdrawals and enforces two-step confirmation."""

    def __init__(self):
        self._pending: Dict[str, dict] = {}

    def initiate_withdrawal(self, user_id: str, amount: float) -> str:
        """Step 1: record a pending withdrawal and issue a one-time token."""
        if amount <= 0:
            raise WithdrawalConfirmationError("Invalid withdrawal amount")

        token = secrets.token_urlsafe(32)
        self._pending[token] = {
            "user_id": user_id,
            "amount": amount,
            "confirmed": False,
        }
        return token

    def confirm_withdrawal(
        self,
        user_id: str,
        token: str,
        confirm: bool = False,
    ) -> dict:
        """Step 2: finalize a withdrawal.

        Requires the exact token issued during ``initiate_withdrawal`` AND an
        explicit ``confirm=True`` flag. Tokens are single-use: once consumed
        (successfully or not matching) they are removed to prevent replay.
        """
        record = self._pending.get(token)
        if record is None:
            raise WithdrawalConfirmationError("Invalid or expired confirmation token")

        if record["user_id"] != user_id:
            # Do not leak which part failed; remove token to prevent probing.
            del self._pending[token]
            raise WithdrawalConfirmationError("Invalid or expired confirmation token")

        if not confirm:
            raise WithdrawalConfirmationError(
                "Explicit second confirmation (confirm=True) is required"
            )

        # Token is single-use regardless of outcome beyond this point.
        del self._pending[token]

        return {
            "user_id": record["user_id"],
            "amount": record["amount"],
            "status": "confirmed",
        }


def register_withdrawal_routes(app, manager: Optional[WithdrawalConfirmationManager] = None):
    """Register a hardened two-step withdrawal flow on a Flask app.

    Ensures both withdrawal endpoints inherit the clickjacking protections
    installed by :func:`install_flask_clickjacking_protection` and enforces
    the two-step confirmation requirement at the application layer.

    Usage:
        app = Flask(__name__)
        install_flask_clickjacking_protection(app)
        register_withdrawal_routes(app)
    """
    from flask import jsonify, request  # local import: optional Flask dependency

    manager = manager or WithdrawalConfirmationManager()

    @app.route("/withdraw/initiate", methods=["POST"])
    def withdraw_initiate():
        data = request.get_json(silent=True) or {}
        user_id = data.get("user_id")
        amount = data.get("amount")
        try:
            token = manager.initiate_withdrawal(user_id, amount)
        except WithdrawalConfirmationError as exc:
            return jsonify({"error": str(exc)}), 400
        return jsonify({"confirmation_token": token, "requires_confirmation": True})

    @app.route("/withdraw/confirm", methods=["POST"])
    def withdraw_confirm():
        data = request.get_json(silent=True) or {}
        user_id = data.get("user_id")
        token = data.get("confirmation_token")
        confirm = bool(data.get("confirm", False))
        try:
            result = manager.confirm_withdrawal(user_id, token, confirm=confirm)
        except WithdrawalConfirmationError as exc:
            return jsonify({"error": str(exc)}), 400
        return jsonify(result)

    return app


class ClickjackingHeaderTests(unittest.TestCase):
    def test_apply_headers_sets_required_values(self):
        headers: dict[str, str] = {}

        apply_clickjacking_headers(headers)

        self.assertEqual(headers["X-Frame-Options"], "DENY")
        self.assertEqual(
            headers["Content-Security-Policy"], "frame-ancestors 'none'"
        )

    def test_existing_csp_is_preserved_and_frame_ancestors_replaced(self):
        headers = {
            "Content-Security-Policy": (
                "default-src 'self'; frame-ancestors https://example.com"
            )
        }

        apply_clickjacking_headers(headers)

        self.assertEqual(
            headers["Content-Security-Policy"],
            "default-src 'self'; frame-ancestors 'none'",
        )

    def test_wsgi_middleware_adds_headers_to_all_responses(self):
        def app(_environ, start_response):
            start_response("200 OK", [("Content-Type", "text/plain")])
            return [b"ok"]

        observed = {}

        def start_response(status, headers, exc_info=None):
            observed["status"] = status
            observed["headers"] = dict(headers)

        response: Iterable[bytes] = ClickjackingProtectionMiddleware(app)(
            {}, start_response
        )

        self.assertEqual(list(response), [b"ok"])
        self.assertEqual(observed["status"], "200 OK")
        self.assertEqual(observed["headers"]["X-Frame-Options"], "DENY")
        self.assertEqual(
            observed["headers"]["Content-Security-Policy"],
            "frame-ancestors 'none'",
        )


class WithdrawalConfirmationTests(unittest.TestCase):
    def test_confirm_requires_valid_token(self):
        manager = WithdrawalConfirmationManager()

        with self.assertRaises(WithdrawalConfirmationError):
            manager.confirm_withdrawal("user-1", "bogus-token", confirm=True)

    def test_confirm_requires_explicit_confirm_flag(self):
        manager = WithdrawalConfirmationManager()
        token = manager.initiate_withdrawal("user-1", 100.0)

        with self.assertRaises(WithdrawalConfirmationError):
            manager.confirm_withdrawal("user-1", token, confirm=False)

    def test_token_is_single_use(self):
        manager = WithdrawalConfirmationManager()
        token = manager.initiate_withdrawal("user-1", 50.0)

        result = manager.confirm_withdrawal("user-1", token, confirm=True)
        self.assertEqual(result["status"], "confirmed")
        self.assertEqual(result["amount"], 50.0)

        with self.assertRaises(WithdrawalConfirmationError):
            manager.confirm_withdrawal("user-1", token, confirm=True)

    def test_confirm_rejects_mismatched_user(self):
        manager = WithdrawalConfirmationManager()
        token = manager.initiate_withdrawal("user-1", 25.0)

        with self.assertRaises(WithdrawalConfirmationError):
            manager.confirm_withdrawal("attacker", token, confirm=True)

    def test_successful_two_step_flow(self):
        manager = WithdrawalConfirmationManager()
        token = manager.initiate_withdrawal("user-2", 12.5)
        result = manager.confirm_withdrawal("user-2", token, confirm=True)

        self.assertEqual(result["user_id"], "user-2")
        self.assertEqual(result["amount"], 12.5)
        self.assertEqual(result["status"], "confirmed")


if __name__ == "__main__":
    unittest.main()
