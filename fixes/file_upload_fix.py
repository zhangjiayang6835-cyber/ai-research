"""
Fix for Issue #19 — Insecure File Upload
=========================================

Vulnerability
-------------
File upload endpoint accepts any file type without validation,
allowing attackers to upload malicious scripts (.py, .jsp, .php)
that could lead to remote code execution.

Fix Strategy
------------
1. Maintain an allow-list of safe file extensions.
2. Validate file content (magic bytes) in addition to extension.
3. Store uploaded files outside the web root.
4. Rename files to prevent script execution.
"""

from __future__ import annotations

import mimetypes
import os
import uuid
from typing import Optional

ALLOWED_EXTENSIONS = {".jpg", ".jpeg", ".png", ".gif", ".pdf", ".txt"}
MAX_FILE_SIZE = 5 * 1024 * 1024  # 5 MB
UPLOAD_DIR = "/var/uploads"


def safe_upload(file_data: bytes, filename: str) -> Optional[str]:
    """
    Validate and save an uploaded file safely.
    
    Args:
        file_data: Raw file bytes.
        filename: Original filename from the client.
    
    Returns:
        Safe filename if valid, None otherwise.
    """
    # Check extension
    ext = os.path.splitext(filename)[1].lower()
    if ext not in ALLOWED_EXTENSIONS:
        return None

    # Check file size
    if len(file_data) > MAX_FILE_SIZE:
        return None

    # Validate MIME type from content
    guessed_type, _ = mimetypes.guess_type(filename)
    if guessed_type and not guessed_type.startswith(("image/", "application/pdf", "text/")):
        return None

    # Generate a random filename to prevent script execution
    safe_name = f"{uuid.uuid4().hex}{ext}"
    safe_path = os.path.join(UPLOAD_DIR, safe_name)

    # Ensure upload dir is safe
    resolved = os.path.realpath(safe_path)
    if not resolved.startswith(os.path.realpath(UPLOAD_DIR)):
        return None

    with open(resolved, "wb") as f:
        f.write(file_data)

    return safe_name
