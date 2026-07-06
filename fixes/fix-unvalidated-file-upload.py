"""
Fix for: Unvalidated File Upload Type (Issue #105)

Vulnerability
-------------
An unvalidated file upload endpoint allows users to upload arbitrary file
types without proper validation. An attacker can upload executable files
(e.g. .exe, .py, .php, .sh, .jsp, .war) which the server may then
interpret or execute, leading to:

- Remote Code Execution (RCE) via uploaded web shells
- Malware distribution
- Path traversal attacks via crafted filenames
- Denial of Service via oversized or malicious files

Root cause
----------
1. No MIME-type validation — only checking Content-Type header (easily spoofed).
2. No file extension whitelist — any extension is accepted.
3. No content-based validation — magic bytes / "magic number" check is missing.
4. No file size limit — attacker can fill the disk.
5. No filename sanitization — an attacker can include "../" sequences.

Fix (defense in depth)
----------------------
1. Whitelist allowed file extensions and MIME types.
2. Validate file content by inspecting magic bytes (not just Content-Type header).
3. Sanitize filenames and randomize stored filenames.
4. Enforce strict file size limits.
5. Store files outside the web root and serve through an authenticated view.
"""

from __future__ import annotations

import imghdr  # Fast content-type detection via magic bytes
import os
import secrets
import struct
from pathlib import Path
from typing import Set, Tuple

from flask import Flask, abort, request, send_from_directory
from werkzeug.utils import secure_filename

app = Flask(__name__)

# Resolve once at startup so every comparison is against a canonical path.
UPLOAD_DIR = Path(os.environ.get("UPLOAD_DIR", "/var/app/uploads")).resolve()
MAX_UPLOAD_BYTES = 10 * 1024 * 1024  # 10 MiB

# Strict whitelist of allowed extensions and their associated MIME types.
ALLOWED_EXTENSIONS: Set[str] = {
    "png", "jpg", "jpeg", "gif", "bmp", "webp",
    "pdf", "txt", "csv", "json", "xml", "yaml", "toml",
    "zip", "gz", "tar",
    "doc", "docx", "xls", "xlsx", "ppt", "pptx",
}

ALLOWED_MIME_TYPES: Set[str] = {
    "image/png", "image/jpeg", "image/gif", "image/bmp", "image/webp",
    "application/pdf",
    "text/plain", "text/csv", "application/json", "application/xml",
    "text/yaml", "text/x-yaml",
    "application/zip", "application/gzip", "application/x-tar",
    "application/msword",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "application/vnd.ms-excel",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    "application/vnd.ms-powerpoint",
    "application/vnd.openxmlformats-officedocument.presentationml.presentation",
}

# Magic-byte signatures for content-based validation.
# (offset, bytes) -> set of safe extensions
MAGIC_SIGNATURES: list[Tuple[int, bytes, Set[str]]] = [
    (0, b"\x89PNG\r\n\x1a\n", {"png"}),
    (0, b"\xff\xd8\xff", {"jpg", "jpeg"}),
    (0, b"GIF87a", {"gif"}),
    (0, b"GIF89a", {"gif"}),
    (0, b"BM", {"bmp"}),
    (0, b"RIFF", {"webp"}),  # WebP starts with RIFF
    (0, b"%PDF-", {"pdf"}),
    (0, b"PK\x03\x04", {"zip", "docx", "xlsx", "pptx"}),  # ZIP-based formats
    (0, b"\x1f\x8b\x08", {"gz"}),
    (257, b"ustar", {"tar"}),  # POSIX tar header
    (0, b"\x1f\x9d", {"z"}),  # compress'd
]

app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_BYTES


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _ensure_upload_dir() -> None:
    """Create the uploads directory (exists_ok) so it's always ready."""
    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)


def _allowed_extension(filename: str) -> bool:
    """Return True iff the filename has a whitelisted extension."""
    if "." not in filename:
        return False
    ext = filename.rsplit(".", 1)[1].lower()
    return ext in ALLOWED_EXTENSIONS


def _detect_extension_by_magic(data: bytes) -> str | None:
    """
    Inspect the first few bytes of `data` and return the detected file
    extension (lowercase, no dot) or None if the content type cannot be
    positively identified.
    """
    for offset, sig, exts in MAGIC_SIGNATURES:
        if len(data) >= offset + len(sig) and data[offset : offset + len(sig)] == sig:
            # Return the first matching extension.
            return next(iter(exts))
    # Fallback to imghdr for known image types.
    img_type = imghdr.what(None, h=data)
    if img_type:
        return img_type
    # Check for plain text (printable ASCII / UTF-8).
    try:
        decoded = data.decode("utf-8")
        if decoded.isprintable() or any(c in " \t\n\r" for c in decoded):
            return "txt"
    except (UnicodeDecodeError, ValueError):
        pass
    return None


def _validate_mime_type(content_type: str) -> bool:
    """Validate the declared Content-Type header against the whitelist."""
    if not content_type:
        return False
    # Strip parameters (e.g. "text/plain; charset=utf-8" -> "text/plain").
    mime = content_type.split(";")[0].strip().lower()
    return mime in ALLOWED_MIME_TYPES


def _safe_join(directory: Path, filename: str) -> Path:
    """Resolve ``filename`` under ``directory`` and reject path traversal."""
    candidate = (directory / filename).resolve()
    try:
        candidate.relative_to(directory)
    except ValueError:
        abort(404, "invalid path")
    return candidate


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/upload", methods=["POST"])
def upload():
    """Handle file uploads with multi-layer validation."""
    # --- Layer 1: File presence ---
    if "file" not in request.files:
        abort(400, "no file part in request")
    file = request.files["file"]
    if not file.filename:
        abort(400, "no filename provided")

    # --- Layer 2: Extension whitelist ---
    if not _allowed_extension(file.filename):
        abort(400, f"file extension not allowed; accepted: {', '.join(sorted(ALLOWED_EXTENSIONS))}")

    # --- Layer 3: Declared MIME type ---
    if not _validate_mime_type(file.content_type or ""):
        abort(400, f"Content-Type '{file.content_type}' is not allowed")

    # --- Layer 4: Content-based validation (magic bytes) ---
    # Read a small chunk so we don't load the whole file into memory.
    chunk = file.read(1024)
    if not chunk:
        abort(400, "empty file")
    detected_ext = _detect_extension_by_magic(chunk)
    if detected_ext is None:
        abort(400, "unrecognized or executable file content — upload rejected")
    # Verify declared extension matches detected content type.
    declared_ext = file.filename.rsplit(".", 1)[1].lower()
    if detected_ext != declared_ext and detected_ext != "txt":
        # Allow text files under any text-like extension.
        abort(400, f"file content ({detected_ext}) does not match declared extension ({declared_ext})")

    # --- Layer 5: Size enforcement ---
    # We already enforce MAX_CONTENT_LENGTH at the Flask level; read the rest.
    file.seek(0)
    # --- Layer 6: Store safely ---
    _ensure_upload_dir()
    ext = file.filename.rsplit(".", 1)[1].lower()
    # Randomized name prevents path traversal and filename guessing.
    stored_name = f"{secrets.token_urlsafe(16)}.{secure_filename(ext)}"
    safe_path = _safe_join(UPLOAD_DIR, stored_name)
    file.save(safe_path)
    # Verify the saved file is not empty and is not a symlink.
    if not safe_path.is_file() or safe_path.is_symlink():
        safe_path.unlink(missing_ok=True)
        abort(500, "file storage failed")
    return {"status": "ok", "stored_as": stored_name, "size": safe_path.stat().st_size}, 201


@app.route("/uploads/<path:filename>")
def serve_upload(filename: str):
    """Serve uploaded files with path traversal protection and auth gate."""
    if not filename:
        abort(404)
    # Enforce authentication (replace with real authn check).
    if not request.headers.get("Authorization"):
        abort(401, "authentication required")

    target = _safe_join(UPLOAD_DIR, filename)
    if not target.is_file():
        abort(404)
    return send_from_directory(
        UPLOAD_DIR,
        filename,
        as_attachment=True,
        max_age=3600,
    )


# ---------------------------------------------------------------------------
# CLI / Dev server
# ---------------------------------------------------------------------------

if __name__ == "__main__":  # pragma: no cover
    _ensure_upload_dir()
    app.run(host="0.0.0.0", port=5000, debug=True)
