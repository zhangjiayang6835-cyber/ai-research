"""Safe YAML configuration loading for issue #341.

Unsafe PyYAML loaders such as ``yaml.Loader`` and ``yaml.UnsafeLoader`` can
construct arbitrary Python objects from tags like ``!!python/object/apply``.
If a configuration endpoint accepts untrusted YAML and uses one of those
loaders, a payload can execute code during parsing.

This module provides a small, framework-agnostic replacement for config
parsers:

* parse with ``yaml.SafeLoader`` semantics only;
* reject aliases/anchors so YAML expansion cannot create parser bombs;
* enforce a byte limit and node limit before returning data;
* optionally require the top-level value to be a mapping, as config files
  normally should be.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, TextIO

import yaml
from yaml.events import AliasEvent


DEFAULT_MAX_BYTES = 128 * 1024
DEFAULT_MAX_NODES = 10_000


class YamlConfigError(ValueError):
    """Raised when a YAML config is unsafe or has an invalid shape."""


class _BoundedSafeLoader(yaml.SafeLoader):
    """SafeLoader with alias rejection and a simple node budget."""

    def __init__(self, stream: str, *, max_nodes: int) -> None:
        super().__init__(stream)
        self._max_nodes = max_nodes
        self._node_count = 0

    def compose_node(self, parent: Any, index: Any) -> yaml.Node:
        if self.check_event(AliasEvent):
            raise YamlConfigError("YAML aliases and anchors are not allowed")

        self._node_count += 1
        if self._node_count > self._max_nodes:
            raise YamlConfigError("YAML document exceeds the node limit")

        return super().compose_node(parent, index)


def _read_yaml_text(source: str | bytes | TextIO) -> str:
    if hasattr(source, "read"):
        source = source.read()  # type: ignore[assignment]

    if isinstance(source, bytes):
        try:
            return source.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise YamlConfigError("YAML config must be valid UTF-8") from exc

    if not isinstance(source, str):
        raise YamlConfigError("YAML config must be text, bytes, or a text stream")

    return source


def load_yaml_config(
    source: str | bytes | TextIO,
    *,
    require_mapping: bool = True,
    max_bytes: int = DEFAULT_MAX_BYTES,
    max_nodes: int = DEFAULT_MAX_NODES,
) -> dict[str, Any] | list[Any] | str | int | float | bool | None:
    """Parse YAML configuration without executing Python object tags.

    ``yaml.load`` is used only with a ``yaml.SafeLoader`` subclass so the
    parser never constructs arbitrary Python objects. Unknown or Python-specific
    tags raise ``YamlConfigError`` instead of being evaluated.
    """

    text = _read_yaml_text(source)
    if len(text.encode("utf-8")) > max_bytes:
        raise YamlConfigError("YAML config exceeds the byte limit")

    class Loader(_BoundedSafeLoader):
        def __init__(self, stream: str) -> None:
            super().__init__(stream, max_nodes=max_nodes)

    try:
        parsed = yaml.load(text, Loader=Loader)
    except YamlConfigError:
        raise
    except yaml.YAMLError as exc:
        raise YamlConfigError("YAML config is invalid or contains unsafe tags") from exc

    if parsed is None:
        parsed = {}

    if require_mapping and not isinstance(parsed, dict):
        raise YamlConfigError("YAML config must be a mapping at the top level")

    return parsed


def load_yaml_config_file(
    path: str | Path,
    *,
    require_mapping: bool = True,
    max_bytes: int = DEFAULT_MAX_BYTES,
    max_nodes: int = DEFAULT_MAX_NODES,
) -> dict[str, Any] | list[Any] | str | int | float | bool | None:
    """Read and safely parse a YAML config file."""

    config_path = Path(path)
    if config_path.stat().st_size > max_bytes:
        raise YamlConfigError("YAML config exceeds the byte limit")

    return load_yaml_config(
        config_path.read_bytes(),
        require_mapping=require_mapping,
        max_bytes=max_bytes,
        max_nodes=max_nodes,
    )


__all__ = [
    "DEFAULT_MAX_BYTES",
    "DEFAULT_MAX_NODES",
    "YamlConfigError",
    "load_yaml_config",
    "load_yaml_config_file",
]
