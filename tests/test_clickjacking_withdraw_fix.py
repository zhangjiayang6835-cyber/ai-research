"""Tests for issue #1176: Clickjacking via X-Frame-Options Missing on crypto withdrawal.

Validates:
1. X-Frame-Options: DENY header on all responses
2. Content-Security-Policy: frame-ancestors 'none' header on all responses
3. Crypto withdrawal endpoint requires explicit confirmation checkbox
"""
import unittest
from src.app import app


class ClickjackingProtectionTests(unittest.TestCase):
    """Verify frame-busting headers are set on every response."""

    def setUp(self):
        self.client = app.test_client()

    def test_x_frame_options_header_present(self):
        resp = self.client.get('/')
        self.assertIn('X-Frame-Options', resp.headers)
        self.assertEqual(resp.headers['X-Frame-Options'], 'DENY')

    def test_csp_frame_ancestors_header_present(self):
        resp = self.client.get('/')
        csp = resp.headers.get('Content-Security-Policy', '')
        self.assertIn("frame-ancestors 'none'", csp)

    def test_x_frame_options_on_withdraw_route(self):
        resp = self.client.get('/withdraw/crypto')
        self.assertEqual(resp.status_code, 401)
        self.assertIn('X-Frame-Options', resp.headers)
        self.assertEqual(resp.headers['X-Frame-Options'], 'DENY')
        self.assertIn("frame-ancestors 'none'",
                      resp.headers.get('Content-Security-Policy', ''))


class CryptoWithdrawConfirmationTests(unittest.TestCase):
    """Verify withdrawal requires explicit user confirmation."""

    def setUp(self):
        self.app = app
        self.app.config['TESTING'] = True
        self.client = self.app.test_client()

    def test_withdraw_get_returns_form_with_confirmation(self):
        with self.client.session_transaction() as sess:
            sess['username'] = 'user1'
        resp = self.client.get('/withdraw/crypto')
        self.assertEqual(resp.status_code, 200)
        body = resp.get_data(as_text=True).lower()
        self.assertIn('confirm', body)
        self.assertIn('irreversible', body)

    def test_withdraw_post_requires_confirmation_checkbox(self):
        with self.client.session_transaction() as sess:
            sess['username'] = 'user1'
        resp = self.client.post('/withdraw/crypto', data={
            'address': '0x1234',
            'amount': '1.5',
        })
        self.assertEqual(resp.status_code, 200)
        body = resp.get_data(as_text=True).lower()
        # Should show error about confirmation
        self.assertIn('confirm', body)

    def test_withdraw_post_with_confirmation_succeeds(self):
        with self.client.session_transaction() as sess:
            sess['username'] = 'user1'
        resp = self.client.post('/withdraw/crypto', data={
            'address': '0x1234abcd',
            'amount': '1.5',
            'confirm_withdraw': 'yes',
        })
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b'Withdrawal Initiated', resp.get_data())

    def test_withdraw_post_missing_fields_rejected(self):
        with self.client.session_transaction() as sess:
            sess['username'] = 'user1'
        resp = self.client.post('/withdraw/crypto', data={
            'confirm_withdraw': 'yes',
        })
        self.assertEqual(resp.status_code, 200)
        body = resp.get_data(as_text=True).lower()
        self.assertIn('required', body)


if __name__ == '__main__':
    unittest.main()
