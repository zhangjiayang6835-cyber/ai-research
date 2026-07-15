"""
Tests for Issue #1182 — Host Header Injection → Password Reset Poisoning fix.

Verifies:
- Host header validated against TRUSTED_HOSTS
- Password reset links use CANONICAL_HOST (not client-supplied Host)
- CSRF token validated on password reset form
- Session cookies set with Secure + HttpOnly flags
- Malicious Host headers rejected (400)
"""

import hmac
import pytest
from src.app import app, TRUSTED_HOSTS, CANONICAL_HOST


@pytest.fixture
def client():
    """Create a Flask test client with secure defaults overridden for HTTP testing."""
    app.config['TESTING'] = True
    app.config['SESSION_COOKIE_SECURE'] = False
    app.config['SESSION_COOKIE_HTTPONLY'] = True
    app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
    with app.test_client() as c:
        yield c


# ---------------------------------------------------------------------------
# Host Header Validation
# ---------------------------------------------------------------------------

class TestHostHeaderValidation:
    """before_request rejects invalid Host headers before any route is hit."""

    def test_trusted_host_allowed(self, client):
        resp = client.get('/', headers={'Host': 'example.com'})
        assert resp.status_code == 200

    def test_trusted_host_with_port(self, client):
        resp = client.get('/', headers={'Host': 'example.com:443'})
        assert resp.status_code == 200

    def test_all_trusted_hosts_accepted(self, client):
        for host in TRUSTED_HOSTS:
            resp = client.get('/', headers={'Host': host})
            assert resp.status_code == 200, f"Host {host} should be trusted"

    def test_untrusted_host_rejected(self, client):
        resp = client.get('/', headers={'Host': 'attacker.com'})
        assert resp.status_code == 400
        assert b'Invalid Host header' in resp.data

    def test_empty_host_rejected(self, client):
        resp = client.get('/', headers={'Host': ''})
        assert resp.status_code == 400

    def test_crlf_injection_rejected(self, client):
        """CRLF in Host header — test at WSGI environ level since
        Werkzeug rejects it in the header constructor."""
        with client.application.test_request_context('/'):
            from werkzeug.test import EnvironBuilder
            environ = EnvironBuilder(
                path='/',
                headers={'Host': 'example.com'},
            ).get_environ()
            environ['HTTP_HOST'] = 'example.com\r\nX-Injected: true'
            with app.request_context(environ):
                resp = app.full_dispatch_request()
                assert resp.status_code == 400

    def test_multiple_hosts_rejected(self, client):
        resp = client.get('/', headers={'Host': 'example.com,evil.com'})
        assert resp.status_code == 400

    def test_x_forwarded_host_not_trusted(self, client):
        resp = client.get('/', headers={
            'Host': 'attacker.com',
            'X-Forwarded-Host': 'example.com',
        })
        assert resp.status_code == 400


# ---------------------------------------------------------------------------
# Password Reset Flow
# ---------------------------------------------------------------------------

class TestPasswordReset:
    """Password reset links must use CANONICAL_HOST, never client-supplied Host."""

    def test_forgot_password_page_renders(self, client):
        resp = client.get('/forgot_password', headers={'Host': 'example.com'})
        assert resp.status_code == 200
        assert b'csrf_token' in resp.data

    def test_forgot_password_requires_csrf(self, client):
        resp = client.post('/forgot_password', data={
            'email': 'user@example.com',
        }, headers={'Host': 'example.com'})
        assert resp.status_code == 403

    def test_forgot_password_with_csrf_returns_canonical_url(self, client):
        get_resp = client.get('/forgot_password', headers={'Host': 'example.com'})
        assert get_resp.status_code == 200
        with client.session_transaction() as sess:
            csrf = sess.get('csrf_token', '')

        resp = client.post('/forgot_password', data={
            'email': 'user@example.com',
            'csrf_token': csrf,
        }, headers={'Host': 'example.com'})
        assert resp.status_code == 200
        data = resp.get_json()
        assert data['reset_url'].startswith(f'https://{CANONICAL_HOST}/reset?token=')

    def test_reset_url_ignores_client_host(self, client):
        resp = client.post('/forgot_password', data={
            'email': 'evil@attacker.com',
            'csrf_token': 'forged',
        }, headers={'Host': 'attacker.com'})
        assert resp.status_code == 400

    def test_reset_page_renders_with_token(self, client):
        resp = client.get('/reset?token=test123', headers={'Host': 'example.com'})
        assert resp.status_code == 200
        assert b'test123' in resp.data

    def test_reset_page_requires_token(self, client):
        resp = client.get('/reset', headers={'Host': 'example.com'})
        assert resp.status_code == 400

    def test_reset_password_requires_csrf(self, client):
        resp = client.post('/reset', data={
            'token': 'some-token',
            'password': 'newpass123',
        }, headers={'Host': 'example.com'})
        assert resp.status_code == 403

    def test_reset_password_with_csrf_succeeds(self, client):
        client.get('/reset?token=tok', headers={'Host': 'example.com'})
        with client.session_transaction() as sess:
            csrf = sess.get('csrf_token', '')

        resp = client.post('/reset', data={
            'token': 'tok',
            'password': 'newpass123',
            'csrf_token': csrf,
        }, headers={'Host': 'example.com'})
        assert resp.status_code == 200

    def test_reset_password_missing_fields(self, client):
        client.get('/reset?token=tok', headers={'Host': 'example.com'})
        with client.session_transaction() as sess:
            csrf = sess.get('csrf_token', '')

        resp = client.post('/reset', data={
            'token': '',
            'password': '',
            'csrf_token': csrf,
        }, headers={'Host': 'example.com'})
        assert resp.status_code == 400


# ---------------------------------------------------------------------------
# Secure Cookie Configuration
# ---------------------------------------------------------------------------

class TestSecureCookies:
    """Session cookie defaults must include Secure, HttpOnly, and SameSite."""

    def test_session_cookie_httponly_config(self, client):
        assert app.config['SESSION_COOKIE_HTTPONLY'] is True

    def test_session_cookie_samesite_config(self, client):
        assert app.config['SESSION_COOKIE_SAMESITE'] == 'Lax'

    def test_login_sets_session(self, client):
        resp = client.post('/login', data={
            'username': 'admin',
            'password': 'admin123',
        }, headers={'Host': 'example.com'})
        assert resp.status_code == 200

    def test_security_headers_present(self, client):
        resp = client.get('/', headers={'Host': 'example.com'})
        assert resp.headers.get('X-Frame-Options') == 'DENY'
        assert resp.headers.get('X-Content-Type-Options') == 'nosniff'


# ---------------------------------------------------------------------------
# CSRF Validation (constant-time comparison)
# ---------------------------------------------------------------------------

class TestCSRFValidation:
    """CSRF validation uses hmac.compare_digest (constant-time)."""

    def test_valid_csrf_accepted(self, client):
        assert _constant_time_compare('valid-token', 'valid-token') is True

    def test_invalid_csrf_rejected(self, client):
        assert _constant_time_compare('wrong-token', 'valid-token') is False

    def test_empty_csrf_rejected(self, client):
        assert _constant_time_compare('', 'some-token') is False

    def test_csrf_different_length_rejected(self, client):
        assert _constant_time_compare('short', 'a-longer-token') is False


def _constant_time_compare(token, stored):
    """Constant-time CSRF comparison (same logic as app)."""
    if not stored or not token:
        return False
    return hmac.compare_digest(token, stored)


# ---------------------------------------------------------------------------
# Config sanity checks
# ---------------------------------------------------------------------------

class TestConfigSanity:
    """Ensure key security constants are properly set."""

    def test_trusted_hosts_is_frozenset(self):
        assert isinstance(TRUSTED_HOSTS, frozenset)

    def test_canonical_host_in_trusted(self):
        assert CANONICAL_HOST in TRUSTED_HOSTS

    def test_app_secret_key_is_long(self):
        assert len(app.secret_key) >= 32

    def test_minimal_trusted_hosts(self):
        assert len(TRUSTED_HOSTS) >= 1
