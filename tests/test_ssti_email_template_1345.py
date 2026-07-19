"""Tests for SSTI in Email Template Engine → Sandbox Escape fix (#1345)."""

from __future__ import annotations

import unittest

from fixes.ssti_email_template_1345_fix import (
    SandboxEscapeError,
    SSTISecurityError,
    contains_template_syntax,
    create_sandboxed_env,
    escape_template_input,
    is_probable_ssti_probe,
    render_email_template,
)


class SSTIEmailTemplate1345Tests(unittest.TestCase):
    """Test suite for issue #1345 fix."""

    # ── Template Syntax Detection ───────────────────────────────────

    def test_detects_jinja2_expression(self) -> None:
        self.assertTrue(
            contains_template_syntax("Hello {{ name }}!")
        )

    def test_detects_jinja2_block(self) -> None:
        self.assertTrue(
            contains_template_syntax("{% if x %}yes{% endif %}")
        )

    def test_detects_jinja2_comment(self) -> None:
        self.assertTrue(
            contains_template_syntax("{# comment #}")
        )

    def test_plain_text_returns_false(self) -> None:
        self.assertFalse(
            contains_template_syntax("Hello World!")
        )

    # ── Email Template Rendering (Safe) ─────────────────────────────

    def test_simple_template_renders_correctly(self) -> None:
        result = render_email_template(
            "Hello {{ name }}!",
            {"name": "Alice"},
        )
        self.assertEqual(result, "Hello Alice!")

    def test_template_without_variables(self) -> None:
        result = render_email_template("Welcome to our service!")
        self.assertEqual(result, "Welcome to our service!")

    def test_template_with_multiple_variables(self) -> None:
        result = render_email_template(
            "Hi {{ name }}, your code is {{ code }}",
            {"name": "Bob", "code": "ABC123"},
        )
        self.assertEqual(result, "Hi Bob, your code is ABC123")

    def test_safe_filter_upper_works(self) -> None:
        """Safe filters like |upper are available."""
        result = render_email_template(
            "Hello {{ name | upper }}!",
            {"name": "alice"},
        )
        self.assertEqual(result, "Hello ALICE!")

    def test_safe_filter_lower_works(self) -> None:
        result = render_email_template(
            "Hello {{ name | lower }}!",
            {"name": "ALICE"},
        )
        self.assertEqual(result, "Hello alice!")

    # ── SSTI Protection ─────────────────────────────────────────────

    def test_config_access_is_blocked(self) -> None:
        """Template accessing 'config' raises SSTISecurityError."""
        with self.assertRaises((SSTISecurityError, SandboxEscapeError)):
            render_email_template("{{ config }}")

    def test_class_chain_is_blocked(self) -> None:
        """__class__ access is detected and blocked."""
        with self.assertRaises(SandboxEscapeError):
            render_email_template(
                "{{ ''.__class__ }}"
            )

    def test_mro_chain_is_blocked(self) -> None:
        with self.assertRaises(SandboxEscapeError):
            render_email_template(
                "{{ ''.__class__.__mro__ }}"
            )

    def test_subclasses_is_blocked(self) -> None:
        with self.assertRaises(SandboxEscapeError):
            render_email_template(
                "{{ ''.__class__.__subclasses__() }}"
            )

    def test_os_popen_is_blocked(self) -> None:
        with self.assertRaises(SandboxEscapeError):
            render_email_template(
                "{{ config.__class__.__init__.__globals__['os'].popen('id').read() }}"
            )

    def test_eval_is_blocked(self) -> None:
        with self.assertRaises(SandboxEscapeError):
            render_email_template(
                "{{ ''.__class__.__bases__[0].__subclasses__() }}"
            )

    def test_builtins_access_is_blocked(self) -> None:
        with self.assertRaises((SSTISecurityError, SandboxEscapeError)):
            render_email_template("{{ __builtins__ }}")

    def test_import_is_blocked(self) -> None:
        with self.assertRaises(SandboxEscapeError):
            render_email_template("{{ import('os').popen('id') }}")

    def test_open_is_blocked(self) -> None:
        with self.assertRaises((SSTISecurityError, SandboxEscapeError)):
            render_email_template("{{ open('/etc/passwd').read() }}")

    # ── Template Syntax Escaping in User Input ──────────────────────

    def test_escape_template_input(self) -> None:
        """User input with Jinja2 syntax is escaped."""
        payload = "Hello {{ 7*7 }}"
        escaped = escape_template_input(payload)
        self.assertNotIn("{{", escaped)
        self.assertIn("&#123;", escaped)

    def test_escaped_input_renders_as_literal(self) -> None:
        """Escaped user input in template renders as literal text."""
        user_input = "{{ 7*7 }}"
        safe_input = escape_template_input(user_input)
        result = render_email_template(
            "User said: {{ text }}",
            {"text": safe_input},
        )
        self.assertIn("7*7", result)
        self.assertNotIn("49", result)  # Not evaluated

    def test_escaped_block_syntax(self) -> None:
        payload = "{% if True %}malicious{% endif %}"
        escaped = escape_template_input(payload)
        self.assertIn("&#123;", escaped)

    # ── SSTI Probe Detection ────────────────────────────────────────

    def test_ssti_probe_detection_config(self) -> None:
        self.assertTrue(is_probable_ssti_probe("{{ config }}"))

    def test_ssti_probe_detection_class(self) -> None:
        self.assertTrue(
            is_probable_ssti_probe("{{ obj.__class__ }}")
        )

    def test_ssti_probe_detection_popen(self) -> None:
        self.assertTrue(
            is_probable_ssti_probe("{{ os.popen('id') }}")
        )

    def test_normal_text_not_detected_as_probe(self) -> None:
        self.assertFalse(is_probable_ssti_probe("Hello World"))

    # ── Sandboxed Environment Features ──────────────────────────────

    def test_sandboxed_env_has_no_dangerous_builtins(self) -> None:
        env = create_sandboxed_env()
        self.assertNotIn("__builtins__", env.globals)
        self.assertNotIn("eval", env.globals)
        self.assertNotIn("exec", env.globals)
        self.assertNotIn("open", env.globals)

    def test_sandboxed_env_has_safe_builtins(self) -> None:
        env = create_sandboxed_env()
        self.assertIn("range", env.globals)
        self.assertIn("dict", env.globals)
        self.assertIn("list", env.globals)
        self.assertIn("true", env.globals)
        self.assertIn("false", env.globals)
        self.assertIn("none", env.globals)

    def test_sandbox_renders_without_sandbox_check(self) -> None:
        """With sandbox_check=False, safe templates still render."""
        result = render_email_template(
            "Hello {{ name }}!",
            {"name": "Test"},
            sandbox_check=False,
        )
        self.assertEqual(result, "Hello Test!")


if __name__ == "__main__":
    unittest.main()
