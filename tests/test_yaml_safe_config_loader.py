import tempfile
import unittest
from pathlib import Path

from fixes.yaml_safe_config_loader import YamlConfigError, load_yaml_config, load_yaml_config_file


class TestYamlSafeConfigLoader(unittest.TestCase):
    def test_loads_normal_mapping_config(self):
        parsed = load_yaml_config(
            """
            service:
              host: 127.0.0.1
              port: 8080
            features:
              audit: true
            """
        )

        self.assertEqual(parsed["service"]["port"], 8080)
        self.assertIs(parsed["features"]["audit"], True)

    def test_empty_config_returns_empty_mapping(self):
        self.assertEqual(load_yaml_config(""), {})

    def test_rejects_python_object_apply_tag(self):
        payload = '!!python/object/apply:os.system ["echo should-not-run"]'

        with self.assertRaises(YamlConfigError):
            load_yaml_config(payload, require_mapping=False)

    def test_rejects_python_name_tag(self):
        payload = "dangerous: !!python/name:os.system"

        with self.assertRaises(YamlConfigError):
            load_yaml_config(payload)

    def test_rejects_alias_expansion(self):
        payload = """
        base: &base
          enabled: true
        copy: *base
        """

        with self.assertRaisesRegex(YamlConfigError, "aliases"):
            load_yaml_config(payload)

    def test_rejects_top_level_sequence_for_config(self):
        with self.assertRaisesRegex(YamlConfigError, "top level"):
            load_yaml_config("- one\n- two\n")

    def test_allows_non_mapping_when_explicitly_requested(self):
        self.assertEqual(
            load_yaml_config("- one\n- two\n", require_mapping=False),
            ["one", "two"],
        )

    def test_rejects_oversized_input(self):
        with self.assertRaisesRegex(YamlConfigError, "byte limit"):
            load_yaml_config("x: " + ("a" * 20), max_bytes=8)

    def test_rejects_document_that_exceeds_node_budget(self):
        payload = "\n".join(f"k{i}: {i}" for i in range(20))

        with self.assertRaisesRegex(YamlConfigError, "node limit"):
            load_yaml_config(payload, max_nodes=5)

    def test_loads_from_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "config.yaml"
            path.write_text("mode: safe\n", encoding="utf-8")

            self.assertEqual(load_yaml_config_file(path), {"mode": "safe"})


if __name__ == "__main__":
    unittest.main()
