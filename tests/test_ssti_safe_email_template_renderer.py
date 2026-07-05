import unittest

from fixes.ssti_safe_email_template_renderer import (
    SafeEmailTemplateRenderer,
    TemplateRenderError,
    UnknownTemplateError,
    UnsafeContextError,
    UnsafeTemplateError,
    render_email,
)


class SafeEmailTemplateRendererTests(unittest.TestCase):
    def test_renders_trusted_template_with_escaped_context(self) -> None:
        body = render_email(
            "welcome",
            {"first_name": "<Ada>", "product_name": "Example & Co"},
        )

        self.assertEqual(
            body,
            "<p>Hello &lt;Ada&gt;, welcome to Example &amp; Co.</p>",
        )

    def test_ssti_payload_is_not_evaluated_as_template_code(self) -> None:
        payload = "{{ config.__class__.__init__.__globals__['os'].system('id') }}"
        body = render_email(
            "welcome",
            {"first_name": payload, "product_name": "Portal"},
        )

        self.assertIn("{{ config.__class__", body)
        self.assertIn("__globals__", body)
        self.assertNotIn("<script>", body)

    def test_template_id_is_an_allowlist_not_a_path_or_source(self) -> None:
        with self.assertRaises(UnknownTemplateError):
            render_email("../templates/welcome.html", {"first_name": "Ada"})

        with self.assertRaises(UnknownTemplateError):
            render_email(
                "{{ cycler.__init__.__globals__ }}",
                {"first_name": "Ada"},
            )

    def test_rejects_attribute_and_item_lookup_placeholders(self) -> None:
        bad_templates = (
            "{user.__class__}",
            "{user[password]}",
            "{__import__('os').system('id')}",
            "{name!r}",
            "{amount:.2f}",
        )

        for source in bad_templates:
            with self.subTest(source=source):
                with self.assertRaises(UnsafeTemplateError):
                    SafeEmailTemplateRenderer({"welcome": source})

    def test_rejects_non_scalar_context_objects(self) -> None:
        renderer = SafeEmailTemplateRenderer({"welcome": "Hello {user}"})

        with self.assertRaises(UnsafeContextError):
            renderer.render("welcome", {"user": object()})

        with self.assertRaises(UnsafeContextError):
            renderer.render("welcome", {"user": {"name": "Ada"}})

    def test_rejects_unsafe_context_keys_and_missing_values(self) -> None:
        renderer = SafeEmailTemplateRenderer({"welcome": "Hello {first_name}"})

        with self.assertRaises(UnsafeContextError):
            renderer.render("welcome", {"first-name": "Ada", "first_name": "Ada"})

        with self.assertRaises(UnsafeContextError):
            renderer.render("welcome", {})

    def test_literal_braces_remain_available_for_static_copy(self) -> None:
        renderer = SafeEmailTemplateRenderer(
            {"debug": "<code>{{literal}}</code> {value}"}
        )

        self.assertEqual(
            renderer.render("debug", {"value": "<safe>"}),
            "<code>{literal}</code> &lt;safe&gt;",
        )

    def test_unknown_template_fails_closed(self) -> None:
        renderer = SafeEmailTemplateRenderer({"welcome": "Hello {first_name}"})

        with self.assertRaises(UnknownTemplateError):
            renderer.render("receipt", {"first_name": "Ada"})

    def test_policy_errors_share_base_type(self) -> None:
        renderer = SafeEmailTemplateRenderer({"welcome": "Hello {first_name}"})

        with self.assertRaises(TemplateRenderError):
            renderer.render("welcome", {})


if __name__ == "__main__":
    unittest.main()
