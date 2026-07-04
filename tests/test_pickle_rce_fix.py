"""
Regression tests for Issue #325: Remote Code Execution via Unsafe Pickle Deserialization.

These tests verify that:
  - The SafeUnpickler blocks untrusted class instantiation (RCE payloads).
  - Allow-listed types round-trip correctly.
  - Oversized payloads are rejected before deserialization begins.
  - JSON is parsed safely via safe_json_roundtrip.
  - YAML is loaded via safe_load (not the unsafe bare yaml.load).
  - SafeModelLoader refuses checkpoints that exceed the size limit.
"""

from __future__ import annotations

import io
import json
import os
import pickle
import tempfile
from pathlib import Path

import pytest

from fixes.pickle_rce_fix import (
    PICKLE_ALLOWLIST,
    PickleSecurityError,
    SafeModelLoader,
    SafeUnpickler,
    safe_dumps,
    safe_json_roundtrip,
    safe_loads,
    to_json_bytes,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_evil_pickle() -> bytes:
    """Craft a pickle payload that would execute os.system('id') if loaded."""

    class _Exploit:
        def __reduce__(self):
            return (os.system, ("id",))

    return pickle.dumps(_Exploit())


def _make_evil_yaml() -> str:
    """Craft a YAML document that would invoke os.system via yaml.load."""
    return "!!python/object/apply:os.system ['id']"


# ---------------------------------------------------------------------------
# SafeUnpickler / safe_loads — RCE prevention
# ---------------------------------------------------------------------------


class TestSafeLoadsBlocksRCE:
    """Untrusted pickle payloads must raise PickleSecurityError, never execute."""

    def test_blocks_os_system_payload(self):
        evil = _make_evil_pickle()
        with pytest.raises(PickleSecurityError, match="not permitted"):
            safe_loads(evil)

    def test_blocks_subprocess_payload(self):
        import subprocess

        class _SubExploit:
            def __reduce__(self):
                return (subprocess.check_output, (["id"],))

        evil = pickle.dumps(_SubExploit())
        with pytest.raises(PickleSecurityError):
            safe_loads(evil)

    def test_blocks_eval_payload(self):
        """Payloads that try to reach builtins.eval must be blocked."""

        class _EvalExploit:
            def __reduce__(self):
                return (eval, ("1+1",))

        evil = pickle.dumps(_EvalExploit())
        with pytest.raises(PickleSecurityError):
            safe_loads(evil)

    def test_blocks_exec_payload(self):
        class _ExecExploit:
            def __reduce__(self):
                return (exec, ("import os; os.system('id')",))

        evil = pickle.dumps(_ExecExploit())
        with pytest.raises(PickleSecurityError):
            safe_loads(evil)

    def test_blocks_open_payload(self):
        class _OpenExploit:
            def __reduce__(self):
                return (open, ("/etc/passwd",))

        evil = pickle.dumps(_OpenExploit())
        with pytest.raises(PickleSecurityError):
            safe_loads(evil)

    def test_blocks_arbitrary_class(self):
        """A module-level class not in the allow-list must be rejected."""
        import collections

        # OrderedDict *is* in the default allow-list; use a stripped
        # allow-list to prove find_class is exercised and rejection works.
        obj = collections.Counter({"a": 1, "b": 2})
        data = pickle.dumps(obj)
        # Counter is NOT in PICKLE_ALLOWLIST — must be rejected by default
        with pytest.raises(PickleSecurityError):
            safe_loads(data)

    def test_error_message_names_blocked_module(self):
        evil = _make_evil_pickle()
        with pytest.raises(PickleSecurityError) as exc_info:
            safe_loads(evil)
        assert "posix" in str(exc_info.value) or "os" in str(exc_info.value) or "not permitted" in str(exc_info.value)


# ---------------------------------------------------------------------------
# SafeUnpickler — allow-listed types
# ---------------------------------------------------------------------------


class TestSafeLoadsAllowList:
    """Allow-listed types must round-trip without errors."""

    @pytest.mark.parametrize(
        "obj",
        [
            {"a": 1, "b": [True, None, 3.14]},
            [1, "two", 3, {"nested": "dict"}],
            (1, 2, 3),
            frozenset({1, 2, 3}),
            b"raw bytes",
            bytearray(b"mutable bytes"),
            42,
            3.14,
            True,
            None,
        ],
    )
    def test_primitive_roundtrip(self, obj):
        assert safe_loads(safe_dumps(obj)) == obj

    def test_nested_dict_roundtrip(self):
        obj = {"level1": {"level2": {"level3": [1, 2, 3]}}}
        assert safe_loads(safe_dumps(obj)) == obj

    def test_empty_structures(self):
        for empty in [{}, [], (), set(), frozenset()]:
            assert safe_loads(safe_dumps(empty)) == empty


# ---------------------------------------------------------------------------
# Size limit enforcement
# ---------------------------------------------------------------------------


class TestSizeLimit:
    """Oversized payloads must be rejected before deserialization."""

    def test_rejects_oversized_payload(self):
        data = pickle.dumps(b"x" * 1000)
        with pytest.raises(PickleSecurityError, match="exceeds"):
            safe_loads(data, max_bytes=10)

    def test_accepts_within_size_limit(self):
        data = safe_dumps({"key": "value"})
        result = safe_loads(data, max_bytes=10 * 1024)
        assert result == {"key": "value"}

    def test_wrong_input_type_raises_type_error(self):
        with pytest.raises(TypeError):
            safe_loads("not bytes")  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Custom allow-list
# ---------------------------------------------------------------------------


class TestCustomAllowList:
    """Users can supply a narrower or wider allow-list."""

    def test_empty_allowlist_blocks_everything(self):
        import datetime

        # Use datetime.date which requires find_class; empty allowlist must block it
        data = safe_dumps(datetime.date(2025, 1, 1))
        with pytest.raises(PickleSecurityError):
            safe_loads(data, allowlist=frozenset())

    def test_custom_allowlist_permits_specific_type(self):
        import datetime

        obj = datetime.date(2025, 1, 1)
        data = safe_dumps(obj)
        custom = frozenset({("datetime", "date")})
        result = safe_loads(data, allowlist=custom)
        assert result == obj


# ---------------------------------------------------------------------------
# JSON helpers
# ---------------------------------------------------------------------------


class TestSafeJsonRoundtrip:
    """JSON parsing must never execute code."""

    def test_parses_dict(self):
        raw = b'{"hello": "world"}'
        assert safe_json_roundtrip(raw) == {"hello": "world"}

    def test_parses_list(self):
        assert safe_json_roundtrip(b"[1, 2, 3]") == [1, 2, 3]

    def test_parses_string_input(self):
        assert safe_json_roundtrip('{"x": 1}') == {"x": 1}

    def test_rejects_oversized_json(self):
        big = json.dumps({"a": "b" * 1000}).encode()
        with pytest.raises(PickleSecurityError, match="exceeds"):
            safe_json_roundtrip(big, max_bytes=100)

    def test_raises_on_invalid_json(self):
        with pytest.raises((json.JSONDecodeError, ValueError)):
            safe_json_roundtrip(b"not valid json }{")

    def test_to_json_bytes_roundtrip(self):
        obj = {"nums": [1, 2, 3], "flag": True}
        assert json.loads(to_json_bytes(obj)) == obj


# ---------------------------------------------------------------------------
# YAML helper
# ---------------------------------------------------------------------------


class TestSafeYamlLoad:
    """yaml.safe_load must be used; !!python/* tags must raise, not execute."""

    @pytest.fixture(autouse=True)
    def skip_if_no_yaml(self):
        pytest.importorskip("yaml")

    def test_safe_load_parses_plain_yaml(self):
        from fixes.pickle_rce_fix import safe_yaml_load

        doc = "key: value\nnested:\n  - 1\n  - 2\n"
        result = safe_yaml_load(doc)
        assert result == {"key": "value", "nested": [1, 2]}

    def test_safe_load_rejects_python_object_tag(self):
        from yaml import YAMLError

        from fixes.pickle_rce_fix import safe_yaml_load

        evil = _make_evil_yaml()
        # yaml.safe_load raises ConstructorError for !!python/* tags
        with pytest.raises((YAMLError, Exception)):
            safe_yaml_load(evil)

    def test_safe_load_parses_bytes(self):
        from fixes.pickle_rce_fix import safe_yaml_load

        result = safe_yaml_load(b"answer: 42")
        assert result == {"answer": 42}

    def test_safe_load_accepts_file_like(self):
        from fixes.pickle_rce_fix import safe_yaml_load

        stream = io.StringIO("hello: world")
        assert safe_yaml_load(stream) == {"hello": "world"}


# ---------------------------------------------------------------------------
# SafeModelLoader
# ---------------------------------------------------------------------------


class TestSafeModelLoader:
    """Model checkpoints must never be loaded via unsafe pickle."""

    def test_loads_json_checkpoint(self):
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as f:
            json.dump({"weights": [0.1, 0.2, 0.3]}, f)
            path = f.name
        try:
            loader = SafeModelLoader()
            result = loader.load_checkpoint(path)
            assert result == {"weights": [0.1, 0.2, 0.3]}
        finally:
            os.unlink(path)

    def test_rejects_oversized_file(self):
        with tempfile.NamedTemporaryFile(suffix=".pkl", delete=False) as f:
            f.write(safe_dumps({"ok": True}))
            path = f.name
        try:
            loader = SafeModelLoader(max_bytes=5)  # tiny limit
            with pytest.raises(PickleSecurityError, match="exceeds"):
                loader.load_checkpoint(path)
        finally:
            os.unlink(path)

    def test_raises_file_not_found(self):
        loader = SafeModelLoader()
        with pytest.raises(FileNotFoundError):
            loader.load_checkpoint("/tmp/nonexistent_claw_test_325.pkl")

    def test_loads_safe_pickle_checkpoint(self):
        data = {"layer1": [1.0, 2.0], "layer2": [3.0, 4.0]}
        with tempfile.NamedTemporaryFile(suffix=".pkl", delete=False) as f:
            f.write(safe_dumps(data))
            path = f.name
        try:
            loader = SafeModelLoader()
            result = loader.load_checkpoint(path)
            assert result == data
        finally:
            os.unlink(path)

    def test_blocks_rce_pickle_checkpoint(self):
        """A malicious .pkl file must be rejected by the loader."""
        evil = _make_evil_pickle()
        with tempfile.NamedTemporaryFile(suffix=".pkl", delete=False) as f:
            f.write(evil)
            path = f.name
        try:
            loader = SafeModelLoader()
            with pytest.raises(PickleSecurityError):
                loader.load_checkpoint(path)
        finally:
            os.unlink(path)


# ---------------------------------------------------------------------------
# SafeUnpickler direct usage
# ---------------------------------------------------------------------------


class TestSafeUnpicklerDirect:
    """Direct SafeUnpickler usage mirrors safe_loads behaviour."""

    def test_direct_usage(self):
        data = pickle.dumps({"direct": True})
        unpickler = SafeUnpickler(io.BytesIO(data))
        result = unpickler.load()
        assert result == {"direct": True}

    def test_direct_blocks_os_module(self):
        evil = _make_evil_pickle()
        unpickler = SafeUnpickler(io.BytesIO(evil))
        with pytest.raises(PickleSecurityError):
            unpickler.load()
