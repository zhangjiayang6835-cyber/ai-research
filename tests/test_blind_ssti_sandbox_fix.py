import unittest

from fixes.blind_ssti_sandbox_fix import (
    RenderPolicy,
    SSTISecurityError,
    is_probable_ssti_probe,
    render_untrusted_template,
    render_with_allowed_names,
)


class BlindSSTISandboxFixTests(unittest.TestCase):
    def setUp(self):
        self.policy = RenderPolicy.from_names(["name", "plan"])

    def test_renders_allowlisted_placeholders_and_escapes_values(self):
        rendered = render_untrusted_template(
            "Hello {{ name }}, {{ plan }} is ready.",
            {"name": "<script>alert(1)</script>", "plan": "starter"},
            self.policy,
        )

        self.assertEqual(
            rendered,
            "Hello &lt;script&gt;alert(1)&lt;/script&gt;, starter is ready.",
        )

    def test_rejects_blind_rce_attribute_walk_payload(self):
        payload = "{{ ''.__class__.__mro__[1].__subclasses__()[40]('/tmp/pwn','w').write('x') }}"

        with self.assertRaises(SSTISecurityError):
            render_untrusted_template(payload, {"name": "Ada", "plan": "pro"}, self.policy)

        self.assertTrue(is_probable_ssti_probe(payload))

    def test_rejects_attr_filter_obfuscation(self):
        payload = "{{ request|attr('__class__')|attr('__mro__') }}"

        with self.assertRaises(SSTISecurityError):
            render_untrusted_template(payload, {"name": "Ada", "plan": "pro"}, self.policy)

    def test_rejects_unicode_escape_dunder_obfuscation(self):
        payload = "{{ ''.\\x5f\\x5fclass\\x5f\\x5f }}"

        with self.assertRaises(SSTISecurityError):
            render_untrusted_template(payload, {"name": "Ada", "plan": "pro"}, self.policy)

        self.assertTrue(is_probable_ssti_probe(payload))

    def test_rejects_jinja_blocks_and_includes(self):
        payload = "{% include '/etc/passwd' %}{{ name }}"

        with self.assertRaises(SSTISecurityError):
            render_untrusted_template(payload, {"name": "Ada", "plan": "pro"}, self.policy)

    def test_rejects_unknown_placeholders(self):
        with self.assertRaises(SSTISecurityError):
            render_untrusted_template(
                "Hello {{ admin_secret }}",
                {"name": "Ada", "plan": "pro"},
                self.policy,
            )

    def test_rejects_callable_and_object_context_values(self):
        with self.assertRaises(SSTISecurityError):
            render_untrusted_template(
                "Hello {{ name }}, {{ plan }}",
                {"name": lambda: "Ada", "plan": "pro"},
                self.policy,
            )

        with self.assertRaises(SSTISecurityError):
            render_untrusted_template(
                "Hello {{ name }}, {{ plan }}",
                {"name": object(), "plan": "pro"},
                self.policy,
            )

    def test_rejects_extra_context_values(self):
        with self.assertRaises(SSTISecurityError):
            render_untrusted_template(
                "Hello {{ name }}, {{ plan }}",
                {"name": "Ada", "plan": "pro", "request": object()},
                self.policy,
            )

    def test_convenience_wrapper_uses_same_policy(self):
        rendered = render_with_allowed_names(
            "{{ name }} selected {{ position }}",
            {"name": "Ada", "position": "host"},
            ["name", "position"],
        )

        self.assertEqual(rendered, "Ada selected host")


if __name__ == "__main__":
    unittest.main()
