"""Submission entrypoint for issue #95: Buffer Overflow in Native Module."""

from fixes.native_buffer_overflow_fix import copy_to_fixed_buffer, validate_native_buffer


__all__ = ["copy_to_fixed_buffer", "validate_native_buffer"]


if __name__ == "__main__":
    print("fix #95: native buffer inputs are length-checked before fixed-buffer copies")
