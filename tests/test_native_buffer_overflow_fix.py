import pytest

from fixes.native_buffer_overflow_fix import (
    NativeBufferPolicy,
    NativeBufferValidationError,
    copy_to_fixed_buffer,
    validate_native_buffer,
)


def test_accepts_payload_that_fits_after_encoding():
    assert validate_native_buffer("neo", NativeBufferPolicy(max_bytes=3)) == b"neo"


def test_rejects_payload_larger_than_native_buffer():
    with pytest.raises(NativeBufferValidationError, match="limit is 4 bytes"):
        validate_native_buffer(b"A" * 5, NativeBufferPolicy(max_bytes=4))


def test_counts_utf8_bytes_not_characters():
    with pytest.raises(NativeBufferValidationError):
        validate_native_buffer("你好", NativeBufferPolicy(max_bytes=5))


def test_rejects_nul_byte_by_default():
    with pytest.raises(NativeBufferValidationError, match="NUL byte"):
        validate_native_buffer(b"safe\x00hidden", NativeBufferPolicy(max_bytes=32))


def test_fixed_buffer_never_truncates_to_fit():
    with pytest.raises(NativeBufferValidationError):
        copy_to_fixed_buffer(b"12345678", 8)


def test_fixed_buffer_pads_when_input_is_safe():
    assert copy_to_fixed_buffer(b"abc", 8) == b"abc\x00\x00\x00\x00\x00"
