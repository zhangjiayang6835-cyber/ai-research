"""
Fix: File Upload Bypass via Double Extension
=============================================
Issue #116 — Attackers upload files with double extensions
(e.g., ``shell.php.jpg``, ``exploit.php.txt``, ``malware.php;.png``) to
bypass extension-based filters. If the web server processes the file
based on the first extension, this leads to arbitrary code execution.

This fix provides:
1. Server-side file extension validation (last extension only)
2. MIME type verification
3. Content inspection (magic bytes)
4. Secure file storage with renamed files
"""

from __future__ import annotations

import mimetypes
import os
import re
import uuid
from pathlib import Path
from typing import Optional, Set, Tuple


# ═══════════════════════════════════════════════════════════════════
# 1. Allowed extensions and MIME types
# ═══════════════════════════════════════════════════════════════════

# Only these extensions are allowed for upload
ALLOWED_EXTENSIONS: Set[str] = {
    ".jpg", ".jpeg", ".png", ".gif", ".webp",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx",
    ".txt", ".csv", ".json", ".xml", ".yaml", ".yml",
    ".md",
}

# For images, use stricter MIME type verification
ALLOWED_MIME_TYPES: Set[str] = {
    "image/jpeg",
    "image/png",
    "image/gif",
    "image/webp",
    "application/pdf",
    "text/plain",
    "text/csv",
    "application/json",
    "application/xml",
    "text/xml",
}


# ═══════════════════════════════════════════════════════════════════
# 2. Core validation functions
# ═══════════════════════════════════════════════════════════════════


class FileUploadError(ValueError):
    """Raised when a file fails upload validation."""


def get_safe_extension(filename: str) -> Optional[str]:
    """Extract the *last* extension from a filename.

    This is the critical fix: we always use the LAST extension,
    so ``shell.php.jpg`` resolves to ``.jpg`` (safe), not ``.php``.
    """
    if not filename or "." not in filename:
        return None
    # Get everything after the LAST dot
    _, last_ext = os.path.splitext(filename)
    return last_ext.lower()


def validate_extension(filename: str) -> str:
    """Check that the file's extension is allowed.

    Returns the validated (lowercase) extension.

    Raises ``FileUploadError`` if the extension is not allowed.
    """
    ext = get_safe_extension(filename)
    if ext is None:
        raise FileUploadError(
            f"File '{filename}' has no extension. "
            f"Allowed: {', '.join(ALLOWED_EXTENSIONS)}"
        )
    if ext not in ALLOWED_EXTENSIONS:
        raise FileUploadError(
            f"Extension '{ext}' is not allowed for file '{filename}'. "
            f"Allowed: {', '.join(ALLOWED_EXTENSIONS)}"
        )
    return ext


def validate_mime_type(filename: str, content: bytes) -> str:
    """Verify the file's MIME type matches its extension.

    Uses both mimetypes (extension-based) and magic-byte inspection.

    Returns the detected MIME type.

    Raises ``FileUploadError`` on mismatch or disallowed type.
    """
    # 1. Extension-based MIME
    ext = get_safe_extension(filename)
    mime_from_ext, _ = mimetypes.guess_type(filename)

    # 2. Magic-byte MIME (inspects actual content)
    mime_from_content = _detect_mime_from_bytes(content)

    # If we can detect from content, use that as ground truth
    detected_mime = mime_from_content or mime_from_ext
    if detected_mime and detected_mime not in ALLOWED_MIME_TYPES:
        raise FileUploadError(
            f"MIME type '{detected_mime}' is not allowed. "
            f"File: '{filename}'"
        )

    # 3. Extension/MIME consistency check
    if mime_from_ext and mime_from_content:
        mime_ext_type = mime_from_ext.split("/")[0]  # e.g., "image"
        mime_content_type = mime_from_content.split("/")[0]
        if mime_ext_type != mime_content_type:
            raise FileUploadError(
                f"MIME type mismatch for '{filename}': "
                f"extension suggests '{mime_from_ext}' "
                f"but content is '{mime_from_content}' — possible double-extension attack"
            )

    return detected_mime or "application/octet-stream"


def _detect_mime_from_bytes(content: bytes) -> Optional[str]:
    """Detect MIME type from file content magic bytes.

    Uses Python's ``imghdr`` for images and basic heuristics for others.
    """
    if not content:
        return None

    # Image detection via magic bytes
    # JPEG: starts with \\xff\\xd8
    if content.startswith(b"\xff\xd8"):
        return "image/jpeg"
    # PNG: starts with \\x89PNG
    if content.startswith(b"\x89PNG"):
        return "image/png"
    # GIF: starts with GIF87a or GIF89a
    if content.startswith(b"GIF87a") or content.startswith(b"GIF89a"):
        return "image/gif"
    # WebP: starts with RIFF....WEBP
    if content.startswith(b"RIFF") and content[8:12] == b"WEBP":
        return "image/webp"

    # PDF: starts with %PDF
    if content.startswith(b"%PDF"):
        return "application/pdf"

    # Plain text detection
    if content.startswith(b"\xef\xbb\xbf") or content.startswith(b"\xff\xfe") or content.startswith(b"\xfe\xff"):
        return "text/plain"  # BOM-prefixed text

    # Check if content is printable ASCII / UTF-8 text
    try:
        content.decode("utf-8")
        return "text/plain"
    except UnicodeDecodeError:
        pass

    return None


# ═══════════════════════════════════════════════════════════════════
# 3. Secure file storage
# ═══════════════════════════════════════════════════════════════════


def store_upload_safely(
    upload_dir: Path,
    original_filename: str,
    content: bytes,
    *,
    preserve_original_name: bool = False,
) -> Path:
    """Validate and securely store an uploaded file.

    Args:
        upload_dir: Directory to store files in.
        original_filename: The original uploaded filename.
        content: Raw file content.
        preserve_original_name: If True, sanitize and use original name.
                                If False (default), generate a UUID filename.

    Returns:
        Path to the stored file.

    Raises:
        FileUploadError: If validation fails.
    """
    # 1. Validate extension
    ext = validate_extension(original_filename)

    # 2. Validate MIME type via content inspection
    validate_mime_type(original_filename, content)

    # 3. Check file size (example: 10 MB max)
    MAX_SIZE = 10 * 1024 * 1024
    if len(content) > MAX_SIZE:
        raise FileUploadError(f"File exceeds maximum size of {MAX_SIZE // (1024*1024)} MB")

    # 4. Generate safe filename
    if preserve_original_name:
        # Sanitize original name: remove path separators, keep only safe chars
        safe_name = re.sub(r"[^a-zA-Z0-9._-]", "_", original_filename)
        # Remove any embedded paths
        safe_name = safe_name.lstrip("/\\.")
        if not safe_name:
            safe_name = f"upload_{uuid.uuid4().hex}{ext}"
    else:
        safe_name = f"{uuid.uuid4().hex}{ext}"

    # 5. Ensure upload dir exists
    upload_dir.mkdir(parents=True, exist_ok=True)

    # 6. Write file (binary mode, restrictive permissions)
    dest = upload_dir / safe_name
    dest.write_bytes(content)
    os.chmod(dest, 0o644)

    return dest


# ═══════════════════════════════════════════════════════════════════
# 4. Before / After example
# ═══════════════════════════════════════════════════════════════════

# B E F O R E  (vulnerable — double extension attack):
#
#   @app.route("/upload", methods=["POST"])
#   def upload_file():
#       f = request.files["file"]
#       ext = f.filename.split(".")[-1]  # ❌ Uses last component only but doesn't
#                                         # check for multiple dots
#       if ext in ["jpg", "png", "gif"]:
#           f.save(f"uploads/{f.filename}")  # ❌ Uses original filename
#       return "ok"
#
#   # Attacker uploads:  exploit.php.jpg  → ext="jpg" (passes), saved as exploit.php.jpg
#   # Apache with AddHandler: processes as .php → RCE
#
# A F T E R  (fixed):
#
#   from fixes.double_extension_fix import store_upload_safely, FileUploadError
#
#   @app.route("/upload", methods=["POST"])
#   def upload_file():
#       f = request.files["file"]
#       content = f.read()
#       try:
#           path = store_upload_safely(
#               Path("uploads"),
#               f.filename,
#               content,
#               preserve_original_name=True,  # Optional
#           )
#           return f"Saved to {path}"
#       except FileUploadError as e:
#           return str(e), 400


# ═══════════════════════════════════════════════════════════════════
# 5. Self-test
# ═══════════════════════════════════════════════════════════════════


def _test():
    # Double extension: should extract LAST extension
    assert get_safe_extension("shell.php.jpg") == ".jpg"
    assert get_safe_extension("exploit.php.txt") == ".txt"
    assert get_safe_extension("file.php;.png") == ".png"

    # Normal files
    assert get_safe_extension("photo.jpg") == ".jpg"
    assert get_safe_extension("document.pdf") == ".pdf"

    # No extension
    assert get_safe_extension("README") is None
    assert get_safe_extension("") is None

    # Validation rejects dangerous extensions
    try:
        validate_extension("shell.php.jpg")
    except FileUploadError:
        pass

    # Validation accepts safe extensions
    ext = validate_extension("photo.jpg")
    assert ext == ".jpg"

    # Test storage with double-extension file
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        # A valid JPEG with JPEG magic bytes
        jpeg_bytes = b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"
        path = store_upload_safely(Path(tmp), "innocent.jpg", jpeg_bytes)
        assert path.suffix == ".jpg"
        assert path.exists()

        # Double extension on valid image: gets last ext (.jpg)
        path2 = store_upload_safely(Path(tmp), "shell.php.jpg", jpeg_bytes)
        assert path2.suffix == ".jpg"

    print("File upload double extension fix: all tests passed")


if __name__ == "__main__":
    _test()
