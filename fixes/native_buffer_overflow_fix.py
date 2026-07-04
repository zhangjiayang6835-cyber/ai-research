"""Safe input handling helpers for native-module boundaries.

Native addons often copy Python/JS strings into fixed-size C buffers. This
module keeps that boundary boring: reject oversized or malformed data before it
ever reaches a native copy routine.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Union

BytesLike = Union[bytes, bytearray, memoryview, str]


class NativeBufferValidationError(ValueError):
    """Raised when data would be unsafe to pass into a fixed native buffer."""


@dataclass(frozen=True)
class NativeBufferPolicy:
    """The little contract we enforce before touching native memory."""

    max_bytes: int = 4096
    encoding: str = "utf-8"
    allow_nul: bool = False

    def __post_init__(self) -> None:
        if self.max_bytes <= 0:
            raise ValueError("max_bytes must be positive")


def _to_bytes(value: BytesLike, encoding: str) -> bytes:
    if isinstance(value, str):
        return value.encode(encoding)
    if isinstance(value, memoryview):
        return value.tobytes()
    if isinstance(value, bytearray):
        return bytes(value)
    if isinstance(value, bytes):
        return value
    raise TypeError("value must be str, bytes, bytearray, or memoryview")


def validate_native_buffer(value: BytesLike, policy: NativeBufferPolicy | None = None) -> bytes:
    """Return bytes only if they are safe for a fixed-size native buffer.

    The check is length-aware after encoding, so multibyte text cannot sneak past
    a character-count guard. It also rejects NUL bytes by default because C APIs
    commonly treat them as terminators and accidentally truncate validation.
    """

    active_policy = policy or NativeBufferPolicy()
    data = _to_bytes(value, active_policy.encoding)

    if len(data) > active_policy.max_bytes:
        raise NativeBufferValidationError(
            f"native buffer input is {len(data)} bytes; limit is {active_policy.max_bytes} bytes"
        )

    if not active_policy.allow_nul and b"\x00" in data:
        raise NativeBufferValidationError("native buffer input contains a NUL byte")

    return data


def copy_to_fixed_buffer(value: BytesLike, size: int, *, allow_nul: bool = False) -> bytes:
    """Build a NUL-padded fixed buffer without truncating attacker input.

    This mirrors the safe side of a C extension boundary: payload bytes must fit
    with room for a terminator, otherwise we reject them instead of slicing.
    """

    if size <= 0:
        raise ValueError("size must be positive")

    payload = validate_native_buffer(value, NativeBufferPolicy(max_bytes=size - 1, allow_nul=allow_nul))
    return payload + (b"\x00" * (size - len(payload)))


__all__ = [
    "NativeBufferPolicy",
    "NativeBufferValidationError",
    "copy_to_fixed_buffer",
    "validate_native_buffer",
]
