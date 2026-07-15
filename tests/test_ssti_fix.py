"""
Tests for SSTI fix (Issue #1184).
Verifies that user input containing Jinja2 syntax is escaped and not executed.
"""
from __future__ import annotations

import pytest
from flask import Flask
from markupsafe import Markup

from src.email_service import (
    send_reset_email,
    send_welcome_email,
    render_notification,
    preview_email,
    render_profile_bio,
)


@pytest.fixture
def app():
    """Minimal Flask app context for rendering."""
    return Flask(__name__)


def test_reset_email_escapes_ssti(app):
    """Reset email: user input with Jinja2 syntax is rendered as text, not executed."""
    with app.app_context():
        malicious = "{{ 7*7 }}"
        result = send_reset_email(malicious, "token123")
        assert "{{ 7*7 }}" in result
        assert "49" not in result  # 7*7 should NOT be evaluated


def test_reset_email_contains_token(app):
    """Reset email: the actual reset token is rendered."""
    with app.app_context():
        result = send_reset_email("user@example.com", "real-token-xyz")
        assert "real-token-xyz" in result


def test_reset_email_contains_email(app):
    """Reset email: the email address is rendered."""
    with app.app_context():
        result = send_reset_email("user@example.com", "tok")
        assert "user@example.com" in result


def test_welcome_email_escapes_ssti(app):
    """Welcome email: Jinja2 payload is escaped, not executed."""
    with app.app_context():
        malicious = "{{ config }}"
        result = send_welcome_email(malicious)
        assert "{{ config }}" in result
        assert "SECRET_KEY" not in result


def test_welcome_email_normal_name(app):
    """Welcome email: normal username is rendered correctly."""
    with app.app_context():
        result = send_welcome_email("Alice")
        assert "Alice" in result


def test_notification_escapes_ssti(app):
    """Notification: dangerous SSTI payload is not executed."""
    with app.app_context():
        malicious = '{{ "".__class__.__bases__[0].__subclasses__() }}'
        result = render_notification(malicious)
        assert malicious in result
        assert "os" not in result


def test_notification_escapes_html(app):
    """Notification: HTML tags in input are escaped."""
    with app.app_context():
        result = render_notification("<script>alert(1)</script>")
        assert "&lt;script&gt;" in result or "<script>" not in result


def test_preview_email_escapes_ssti(app):
    """Preview: SSTI payload is rendered as plain text."""
    with app.app_context():
        malicious = "{{ 7*7 }}"
        result = preview_email(malicious)
        assert "{{ 7*7 }}" in result
        assert "49" not in result


def test_profile_bio_escapes_ssti(app):
    """Profile bio: SSTI payload is rendered as plain text."""
    with app.app_context():
        malicious = "{{ self._TemplateReference__context }}"
        result = render_profile_bio(malicious)
        assert malicious in result


def test_reset_email_special_chars_escaped(app):
    """Reset email: HTML special characters in email are escaped."""
    with app.app_context():
        malicious_email = '<script>alert("xss")</script>@x.com'
        result = send_reset_email(malicious_email, "tok")
        assert "<script>" not in result


def test_welcome_email_special_chars_escaped(app):
    """Welcome email: HTML special chars in username are escaped."""
    with app.app_context():
        result = send_welcome_email('<b>Admin</b>')
        assert "<b>" not in result
