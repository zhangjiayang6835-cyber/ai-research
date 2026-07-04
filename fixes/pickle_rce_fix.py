"""
Fix for Issue #325: Remote Code Execution via Unsafe Pickle Deserialization.

Python's ``pickle`` module is a powerful serialization format, but it
executes arbitrary Python code during deserialization.  Loading untrusted
pickle data is therefore equivalent to remote code execution:

    import pickle, os
    class Exploit:
        def __reduce__(self):
            return (os.system, ('id',))
    pickle.loads(pickle.dumps(Exploit()))   # executes: id

This module provides safe alternatives that cover the common use-cases
where pickle is misapplied to untrusted data:

1. **JSON** (``safe_json_roundtrip``) — for plain Python primitives
   (str, int, float, bool, None, list, dict).  Zero deserialization risk.

2. **SafeUnpickler** — a strict allow-list unpickler for trusted formats
   that *must* remain in pickle (e.g. legacy model checkpoints).
   Only modules/classes explicitly listed in ``PICKLE_ALLOWLIST`` can be
   instantiated.  Everything else raises ``PickleSecurityError``.

3. **SafeModelLoader** — wraps common ML checkpoint helpers and routes
   to JSON or an allow-listed unpickler so that ``torch.load()`` /
   ``numpy.load()`` paths are never called on untrusted data without a
   safety layer.

4. **safe_yaml_load** — replaces the dangerous bare ``yaml.load()`` call
   (which also allows arbitrary object construction) with
   ``yaml.safe_load()``.

Usage::

    from fixes.pickle_rce_fix import (
        safe_loads,
        safe_json_roundtrip,
        safe_yaml_load,
        SafeModelLoader,
    )

    # Instead of: pickle.loads(user_data)
    obj = safe_loads(user_data)            # raises on untrusted types

    # Instead of: json.loads(data) with mixed pickle fall-back:
    obj = safe_json_roundtrip(data)

    # Instead of: yaml.load(stream)
    cfg = safe_yaml_load(stream)           # uses yaml.safe_load internally

    # For ML checkpoints:
    loader = SafeModelLoader()
    weights = loader.load_checkpoint(path)
"""

from __future__ import annotations

import io
import json
import pickle
import pickletools
import struct
from pathlib import Path
from typing import Any, FrozenSet, Mapping, Type, Union

try:
    import yaml as _yaml
except ImportError:  # pragma: no cover
    _yaml = None  # type: ignore[assignment]

__all__ = [
    "PickleSecurityError",
    "PICKLE_ALLOWLIST",
    "SafeUnpickler",
    "safe_loads",
    "safe_dumps",
    "safe_json_roundtrip",
    "safe_yaml_load",
    "SafeModelLoader",
]


# ---------------------------------------------------------------------------
# Exception
# ---------------------------------------------------------------------------


class PickleSecurityError(Exception):
    """Raised when a pickle payload attempts to instantiate a disallowed type."""


# ---------------------------------------------------------------------------
# Allow-list: (module, qualname) pairs that are safe to deserialize
# ---------------------------------------------------------------------------

#: Extend this set in your application code when adding new safe types.
PICKLE_ALLOWLIST: FrozenSet[tuple[str, str]] = frozenset(
    {
        # Pure Python builtins that carry no execution side-effects
        ("builtins", "dict"),
        ("builtins", "list"),
        ("builtins", "tuple"),
        ("builtins", "set"),
        ("builtins", "frozenset"),
        ("builtins", "str"),
        ("builtins", "bytes"),
        ("builtins", "bytearray"),
        ("builtins", "int"),
        ("builtins", "float"),
        ("builtins", "complex"),
        ("builtins", "bool"),
        ("builtins", "type"),
        # datetime (safe, no __reduce__ execution side-effects)
        ("datetime", "datetime"),
        ("datetime", "date"),
        ("datetime", "time"),
        ("datetime", "timedelta"),
        ("datetime", "timezone"),
        # collections
        ("collections", "OrderedDict"),
        ("collections", "defaultdict"),
        ("collections", "namedtuple"),
        # numpy arrays (safe data container only — no code in __reduce__)
        ("numpy", "ndarray"),
        ("numpy.core.multiarray", "_reconstruct"),
        ("numpy", "dtype"),
        ("numpy.core.multiarray", "scalar"),
    }
)


# ---------------------------------------------------------------------------
# SafeUnpickler
# ---------------------------------------------------------------------------


class SafeUnpickler(pickle.Unpickler):
    """An Unpickler that refuses to instantiate any class not in the allow-list.

    This is a defence-in-depth measure for legacy data that *must* remain
    in pickle format.  For new data, prefer JSON.

    Parameters
    ----------
    file:
        A binary-mode file-like object (same as ``pickle.Unpickler``).
    allowlist:
        Set of ``(module, qualname)`` pairs that may be constructed.
        Defaults to :data:`PICKLE_ALLOWLIST`.
    max_bytes:
        Reject payloads larger than this threshold to prevent DoS.
        Defaults to 100 MB.
    """

    def __init__(
        self,
        file: io.RawIOBase,
        *,
        allowlist: FrozenSet[tuple[str, str]] = PICKLE_ALLOWLIST,
        max_bytes: int = 100 * 1024 * 1024,
    ) -> None:
        super().__init__(file)
        self._allowlist = allowlist
        self._max_bytes = max_bytes

    def find_class(self, module: str, name: str) -> Any:
        """Block every class not in the allow-list."""
        if (module, name) not in self._allowlist:
            raise PickleSecurityError(
                f"Deserialization of {module}.{name} is not permitted. "
                "Only explicitly allow-listed types may be loaded from pickle."
            )
        return super().find_class(module, name)


def _check_size(data: bytes, max_bytes: int) -> None:
    if len(data) > max_bytes:
        raise PickleSecurityError(
            f"Pickle payload size {len(data):,} bytes exceeds the "
            f"safety limit of {max_bytes:,} bytes."
        )


def safe_loads(
    data: bytes,
    *,
    allowlist: FrozenSet[tuple[str, str]] = PICKLE_ALLOWLIST,
    max_bytes: int = 100 * 1024 * 1024,
) -> Any:
    """Safely deserialize a pickle payload using the allow-list unpickler.

    Raises :class:`PickleSecurityError` if the payload references any
    module/class outside ``allowlist`` or exceeds ``max_bytes``.

    This is the **drop-in replacement** for ``pickle.loads(untrusted_data)``.

    >>> import pickle
    >>> safe_loads(pickle.dumps({"key": [1, 2, 3]}))
    {'key': [1, 2, 3]}
    """
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError(f"safe_loads expects bytes, got {type(data).__name__}")
    _check_size(data, max_bytes)
    return SafeUnpickler(io.BytesIO(data), allowlist=allowlist, max_bytes=max_bytes).load()


def safe_dumps(obj: Any) -> bytes:
    """Serialize *obj* to pickle bytes.

    This is a thin wrapper around ``pickle.dumps`` provided for symmetry.
    Serialization itself is always safe; only *deserialization* is dangerous.
    """
    return pickle.dumps(obj, protocol=pickle.HIGHEST_PROTOCOL)


# ---------------------------------------------------------------------------
# JSON helpers (preferred over pickle for untrusted data)
# ---------------------------------------------------------------------------


def safe_json_roundtrip(
    data: Union[str, bytes],
    *,
    max_bytes: int = 10 * 1024 * 1024,
) -> Any:
    """Parse *data* as JSON and return the Python object.

    Use this instead of ``pickle.loads`` whenever the payload is expected
    to contain only plain data (dicts, lists, strings, numbers, booleans,
    None).  JSON deserialization never executes arbitrary code.

    Parameters
    ----------
    data:
        UTF-8-encoded JSON string or bytes.
    max_bytes:
        Reject inputs larger than this to prevent DoS.

    Raises
    ------
    ValueError
        If *data* is not valid JSON.
    PickleSecurityError
        If *data* exceeds *max_bytes*.
    """
    raw = data.encode("utf-8") if isinstance(data, str) else data
    if len(raw) > max_bytes:
        raise PickleSecurityError(
            f"JSON payload {len(raw):,} bytes exceeds safety limit of "
            f"{max_bytes:,} bytes."
        )
    return json.loads(raw)


def to_json_bytes(obj: Any, *, indent: int | None = None) -> bytes:
    """Serialize *obj* to compact JSON bytes (UTF-8).

    Raises ``TypeError`` for non-serialisable objects.
    """
    return json.dumps(obj, indent=indent, ensure_ascii=False).encode("utf-8")


# ---------------------------------------------------------------------------
# YAML helper (replaces yaml.load with yaml.safe_load)
# ---------------------------------------------------------------------------


def safe_yaml_load(stream: Union[str, bytes, io.IOBase]) -> Any:
    """Parse YAML from *stream* using the safe loader.

    ``yaml.load(stream)`` without an explicit ``Loader`` argument (or with
    ``Loader=yaml.Loader`` / ``yaml.FullLoader``) allows arbitrary Python
    object construction via the ``!!python/object`` tag family, equivalent
    to pickle deserialization.

    This function always uses ``yaml.safe_load``, which only allows standard
    YAML types and raises ``yaml.constructor.ConstructorError`` on any
    Python-specific tag.

    Parameters
    ----------
    stream:
        A YAML document as a string, bytes, or file-like object.

    Raises
    ------
    RuntimeError
        If the ``yaml`` package is not installed.
    """
    if _yaml is None:
        raise RuntimeError(
            "PyYAML is not installed. Install it with: pip install pyyaml"
        )
    # Always use safe_load — never yaml.load(stream, Loader=yaml.FullLoader)
    return _yaml.safe_load(stream)


# ---------------------------------------------------------------------------
# ML model checkpoint loader
# ---------------------------------------------------------------------------


class SafeModelLoader:
    """Safe wrapper for loading ML model checkpoints.

    Prevents RCE that arises when ``torch.load()`` or ``pickle.load()``
    is called on a user-supplied checkpoint without ``weights_only=True``
    or an allow-list filter.

    Usage::

        loader = SafeModelLoader()
        state_dict = loader.load_checkpoint("model.pt")
    """

    def __init__(
        self,
        *,
        allowlist: FrozenSet[tuple[str, str]] = PICKLE_ALLOWLIST,
        max_bytes: int = 2 * 1024 * 1024 * 1024,  # 2 GB
    ) -> None:
        self._allowlist = allowlist
        self._max_bytes = max_bytes

    def load_checkpoint(self, path: Union[str, Path]) -> Any:
        """Load a model checkpoint from *path*.

        Strategy:
        1. If the file has a ``.json`` extension, parse as JSON.
        2. If ``torch`` is available, use ``torch.load(..., weights_only=True)``
           which is safe against RCE (PyTorch ≥ 2.0).
        3. Otherwise fall back to :func:`safe_loads` with the allow-list
           unpickler.

        In all cases the file size is checked against *max_bytes* before
        loading.

        Raises
        ------
        PickleSecurityError
            If any deserialization policy is violated.
        FileNotFoundError
            If *path* does not exist.
        """
        path = Path(path)
        if not path.exists():
            raise FileNotFoundError(f"Checkpoint not found: {path}")

        size = path.stat().st_size
        if size > self._max_bytes:
            raise PickleSecurityError(
                f"Checkpoint {path} ({size:,} bytes) exceeds the safety "
                f"limit of {self._max_bytes:,} bytes."
            )

        # 1. JSON checkpoint
        if path.suffix.lower() == ".json":
            return json.loads(path.read_text(encoding="utf-8"))

        # 2. PyTorch — use weights_only=True (safe mode, PyTorch ≥ 2.0)
        try:
            import torch  # type: ignore[import]
            # weights_only=True restricts unpickling to tensor types only
            return torch.load(str(path), map_location="cpu", weights_only=True)
        except ImportError:
            pass

        # 3. NumPy .npy / .npz — never uses pickle for data arrays
        try:
            import numpy as np  # type: ignore[import]
            if path.suffix.lower() in (".npy", ".npz"):
                return np.load(str(path), allow_pickle=False)
        except ImportError:
            pass

        # 4. Fall back to allow-list pickle
        raw = path.read_bytes()
        return safe_loads(raw, allowlist=self._allowlist, max_bytes=self._max_bytes)


# ---------------------------------------------------------------------------
# Self-tests
# ---------------------------------------------------------------------------


def _selftest() -> None:  # pragma: no cover
    import os
    import sys

    # -----------------------------------------------------------------------
    # 1. Benign data round-trips correctly
    # -----------------------------------------------------------------------
    payload = {"key": [1, 2, 3], "nested": {"a": True, "b": None}}
    assert safe_loads(safe_dumps(payload)) == payload

    # -----------------------------------------------------------------------
    # 2. Malicious pickle is blocked
    # -----------------------------------------------------------------------
    class _RCEPayload:
        """Simulate an attacker payload that would run os.system."""
        def __reduce__(self):
            return (os.system, ("echo pwned",))

    evil_bytes = pickle.dumps(_RCEPayload())
    try:
        safe_loads(evil_bytes)
        raise AssertionError("RCE payload was NOT blocked!")
    except PickleSecurityError:
        pass

    # -----------------------------------------------------------------------
    # 3. Oversized payload is rejected before deserialization
    # -----------------------------------------------------------------------
    big = pickle.dumps(b"x" * 1000)
    try:
        safe_loads(big, max_bytes=10)
        raise AssertionError("Oversized payload was NOT rejected!")
    except PickleSecurityError:
        pass

    # -----------------------------------------------------------------------
    # 4. JSON round-trip
    # -----------------------------------------------------------------------
    raw = b'{"hello": "world", "nums": [1, 2, 3]}'
    obj = safe_json_roundtrip(raw)
    assert obj == {"hello": "world", "nums": [1, 2, 3]}

    # -----------------------------------------------------------------------
    # 5. YAML safe_load rejects object construction
    # -----------------------------------------------------------------------
    if _yaml is not None:
        try:
            safe_yaml_load("!!python/object/apply:os.system ['id']")
            # safe_load should either raise or return a string, never execute
        except Exception:
            pass  # Expected: constructor error

    print("pickle_rce_fix: all self-tests passed", file=sys.stderr)


if __name__ == "__main__":  # pragma: no cover
    _selftest()
