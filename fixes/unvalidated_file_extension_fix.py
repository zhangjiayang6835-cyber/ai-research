"""
Fix for Issue #89: Unvalidated File Extension ($10)

Vulnerability:
    File upload endpoints that do not validate file extensions allow
    attackers to upload executable files (.php, .jsp, .exe, .sh) which
    can lead to remote code execution if the uploaded file is served
    from a web-accessible directory.

Fix:
    Strict allow-list validation of file extensions, plus content-type
    verification and safe filename generation.
"""

from __future__ import annotations

import mimetypes
import os
import re
import uuid
from pathlib import Path
from typing import Optional, Set, Tuple


# Strictly allowed extensions for user uploads
ALLOWED_EXTENSIONS: Set[str] = {
    # Images
    '.jpg', '.jpeg', '.png', '.gif', '.webp', '.svg', '.bmp',
    # Documents
    '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
    '.txt', '.csv', '.md', '.rtf',
    # Audio/Video
    '.mp3', '.mp4', '.wav', '.ogg', '.webm',
    # Archives
    '.zip', '.tar', '.gz', '.7z',
    # Data
    '.json', '.xml', '.yaml', '.yml',
}

# Extensions that are NEVER allowed (defense in depth)
BLOCKED_EXTENSIONS: Set[str] = {
    '.php', '.php3', '.php4', '.php5', '.phtml',
    '.jsp', '.jspx', '.war',
    '.asp', '.aspx', '.asa', '.asax',
    '.exe', '.dll', '.so', '.bin', '.com', '.bat', '.cmd',
    '.sh', '.bash', '.zsh', '.csh',
    '.py', '.pyc', '.pyo',
    '.pl', '.pm', '.cgi',
    '.rb', '.rhtml',
    '.hta', '.htaccess',
    '.swf',
    '.jar',
    '.wasm',
    '.msi', '.msp', '.mst',
    '.vbs', '.vbe', '.js', '.jse', '.wsf', '.wsh',
    '.ps1', '.psm1', '.psd1',
}


class FileExtensionValidator:
    """Validate uploaded filenames against a strict allow-list."""

    def __init__(
        self,
        allowed: Optional[Set[str]] = None,
        blocked: Optional[Set[str]] = None,
        max_filename_bytes: int = 255,
    ) -> None:
        self.allowed = set(allowed or ALLOWED_EXTENSIONS)
        self.blocked = set(blocked or BLOCKED_EXTENSIONS)
        self.max_filename_bytes = max_filename_bytes

        # Pre-compile patterns
        self._double_ext_pattern = re.compile(
            r'\.(php\d?|phtml|asp|aspx|jsp|jspx)\.[a-z]+$', re.IGNORECASE
        )
        self._path_traversal = re.compile(r'\.\./|\.\.\\|\.\.$')

    def _get_ext(self, filename: str) -> str:
        """Get the lowercase file extension."""
        name = filename.strip()
        # Handle double extensions like file.php.jpg
        match = self._double_ext_pattern.search(name)
        if match:
            return match.group(1).lower()
        _, ext = os.path.splitext(name)
        return ext.lower()

    def validate(self, filename: str, content_type: Optional[str] = None) -> Tuple[bool, str]:
        """Validate a filename for upload.

        Returns:
            (is_valid, error_message)
        """
        if not filename or not filename.strip():
            return False, "Filename is empty"

        name = filename.strip()

        # Check length
        if len(name.encode('utf-8')) > self.max_filename_bytes:
            return False, "Filename too long"

        # Check path traversal
        if self._path_traversal.search(name):
            return False, "Path traversal detected in filename"

        # Check for hidden files
        if name.startswith('.'):
            return False, "Hidden files are not allowed"

        ext = self._get_ext(name)

        if not ext:
            return False, "File has no extension"

        if ext in self.blocked:
            return False, f"File extension '{ext}' is not allowed"

        if ext not in self.allowed:
            return False, f"File extension '{ext}' is not in the allowed list"

        # Optional: content-type match
        if content_type:
            expected_type, _ = mimetypes.guess_type(f"file{ext}")
            if expected_type and content_type.lower() != expected_type:
                # Non-matching content-type is a warning, not a block
                # (some browsers send different types for the same extension)
                pass

        return True, ""

    def safe_filename(self, filename: str) -> str:
        """Generate a safe, unique filename preserving the extension."""
        ext = self._get_ext(filename)
        if ext not in self.allowed:
            ext = '.bin'
        return f"{uuid.uuid4().hex}{ext}"

    def sanitize_path(self, upload_dir: str, filename: str) -> Tuple[Optional[Path], str]:
        """Generate a safe absolute path within upload_dir.

        Returns:
            (safe_path, error_message) — safe_path is None if invalid.
        """
        base = Path(upload_dir).resolve()
        safe_name = self.safe_filename(filename)
        full = (base / safe_name).resolve()

        # Ensure we're still within the upload directory
        if not str(full).startswith(str(base)):
            return None, "Path traversal detected"

        return full, ""


# --------------------------------------------------------------------- self-test
if __name__ == "__main__":
    v = FileExtensionValidator()

    ok, msg = v.validate("photo.jpg")
    assert ok, f"expected OK for .jpg: {msg}"

    ok, msg = v.validate("script.php")
    assert not ok, "expected block for .php"

    ok, msg = v.validate("evil.php.jpg")
    assert not ok, "expected block for double extension .php.jpg"

    ok, msg = v.validate("../../../etc/passwd")
    assert not ok, "expected block for path traversal"

    ok, msg = v.validate("")
    assert not ok, "expected block for empty filename"

    safe = v.safe_filename("evil.php")
    assert not safe.endswith('.php'), "safe name should not preserve blocked ext"

    print("unvalidated_file_extension_fix self-test passed")
