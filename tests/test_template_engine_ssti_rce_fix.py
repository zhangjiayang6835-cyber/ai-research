from __future__ import annotations

import unittest

from fixes.template_engine_ssti_rce_fix import SafeTemplateRenderer, TemplatePolicyError


class SafeTemplateRendererTests(unittest.TestCase):
    def test_renders_trusted_template_with_escaped_user_data(self) -> None:
        renderer = SafeTemplateRenderer({"welcome": "<h1>Hello {name}</h1><p>{bio}</p>"})

        html = renderer.render("welcome", {"name": "Ada", "bio": "<script>alert(1)</script>"})

        self.assertEqual(html, "<h1>Hello Ada</h1><p>&lt;script&gt;alert(1)&lt;/script&gt;</p>")

    def test_template_payload_in_user_data_is_not_executed(self) -> None:
        renderer = SafeTemplateRenderer({"profile": "About: {description}"})
        payload = "{{ config.__class__.__init__.__globals__['os'].system('id') }}"

        html = renderer.render("profile", {"description": payload})

        self.assertIn("config.__class__", html)
        self.assertNotIn("uid=", html)

    def test_unknown_or_path_like_template_id_is_rejected(self) -> None:
        renderer = SafeTemplateRenderer({"invoice": "Total: {total}"})

        for template_id in ("../invoice", "https://evil.example/tpl", "invoice.html", "missing"):
            with self.subTest(template_id=template_id):
                with self.assertRaises(TemplatePolicyError):
                    renderer.render(template_id, {"total": 10})

    def test_dynamic_template_source_is_not_accepted_as_template_id(self) -> None:
        renderer = SafeTemplateRenderer({"safe": "Hello {name}"})

        with self.assertRaises(TemplatePolicyError):
            renderer.render("{{7*7}}", {"name": "Ada"})

    def test_attribute_item_and_call_fields_are_rejected(self) -> None:
        unsafe_templates = (
            "{user.__class__}",
            "{user[__class__]}",
            "{user()}",
            "{__import__}",
            "{}",
        )

        for source in unsafe_templates:
            with self.subTest(source=source):
                with self.assertRaises(TemplatePolicyError):
                    SafeTemplateRenderer({"unsafe": source})

    def test_conversions_and_format_specs_are_rejected(self) -> None:
        for source in ("{name!r}", "{amount:.2f}", "{name:{width}}"):
            with self.subTest(source=source):
                with self.assertRaises(TemplatePolicyError):
                    SafeTemplateRenderer({"unsafe": source})

    def test_missing_extra_or_unsafe_context_keys_are_rejected(self) -> None:
        renderer = SafeTemplateRenderer({"safe": "Hello {name}"})

        for context in ({}, {"name": "Ada", "extra": "x"}, {"name.__class__": "Ada"}):
            with self.subTest(context=context):
                with self.assertRaises(TemplatePolicyError):
                    renderer.render("safe", context)

    def test_object_callable_and_large_values_are_rejected(self) -> None:
        renderer = SafeTemplateRenderer({"safe": "Hello {name}"})

        for value in (object(), lambda: "Ada", "x" * 10_001):
            with self.subTest(value_type=type(value).__name__):
                with self.assertRaises(TemplatePolicyError):
                    renderer.render("safe", {"name": value})

    def test_scalar_values_are_normalized(self) -> None:
        renderer = SafeTemplateRenderer({"safe": "{name}:{count}:{active}:{note}"})

        html = renderer.render("safe", {"name": "Ada", "count": 3, "active": True, "note": None})

        self.assertEqual(html, "Ada:3:true:")


if __name__ == "__main__":
    unittest.main()
