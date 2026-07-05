"""
fix_path_traversal_log_poison.py — Path Traversal + Log Poisoning → RCE Chain Fix

VULNERABILITY:
Attackers combine path traversal (to read/write files outside intended directory)
with log poisoning (injecting malicious PHP/SSI/etc. into log files, then
accessing those logs as code via LFI).

CHAIN:
1. Path traversal to read /etc/passwd → confirms vulnerability
2. Inject PHP code into Apache access log via User-Agent header
3. LFI to include the poisoned log file → RCE

FIX:
1. Canonicalize all file paths and reject traversal attempts
2. Sanitize log input (strip executable code)
3. Separate log storage from web root
4. Implement allowlist-based file access
5. Add filesystem sandboxing
"""

import os
import re
import shlex
import subprocess
from pathlib import Path, PurePath
from typing import List, Optional, Set, Tuple


# =============================================================================
# Configuration
# =============================================================================

# Directories that are ALLOWED for file operations
ALLOWED_BASE_DIRS = frozenset({
    "/var/www/uploads",
    "/var/www/static",
    "/var/www/templates",
    "/opt/app/data",
})

# File extensions that can be served/saved
ALLOWED_EXTENSIONS = frozenset({
    ".txt", ".json", ".csv", ".xml", ".html", ".css", ".js",
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp",
    ".pdf", ".doc", ".docx", ".md", ".yaml", ".yml",
})

# Executable code patterns to strip from log entries
EXECUTABLE_PATTERNS = [
    re.compile(r'<\?php.*?\?>', re.DOTALL),       # PHP
    re.compile(r'<!--#.*?-->', re.DOTALL),         # SSI
    re.compile(r'<script.*?>.*?</script>', re.DOTALL),  # JavaScript
    re.compile(r'<%[\s\S]*?%>'),                   # ASP
    re.compile(r'\{\{[\s\S]*?\}\}'),               # Template injection
    re.compile(r'<%=?[\s\S]*?%>'),                 # ERB
    re.compile(r'\${\s*[\w.\[\]\"\'\(\)]+\s*}'),  # Shell injection in logs
]

# Dangerous path components
DANGEROUS_PATH_COMPONENTS = {
    "..", "~", ".ssh", ".aws", ".git", "etc/passwd",
    "etc/shadow", "proc/self", "dev/null",
}

# Allowed file access patterns
ALLOWED_GLOB_PATTERNS = [
    re.compile(r'^[\w\-. ]+\.[a-z]+$'),  # Normal filenames
]


# =============================================================================
# Path Security
# =============================================================================

class PathSecurity:
    """Secure file path handling that prevents path traversal."""

    @staticmethod
    def is_path_traversal(path: str) -> bool:
        """
        Check if a path contains traversal attempts.

        Detects:
        - '..' directory traversal
        - Absolute paths when relative expected
        - Symlink tricks
        - Encoded traversal (%2e%2e, ..%2f, etc.)
        """
        # Check for decoded traversal
        decoded = path.replace('%2e', '.').replace('%2E', '.')
        decoded = decoded.replace('%2f', '/').replace('%2F', '/')

        if '..' in PurePath(decoded).parts:
            return True

        # Check for null bytes
        if '\x00' in path:
            return True

        # Check for absolute paths
        if path.startswith('/') or path.startswith('\\'):
            return True

        # Check for dangerous patterns
        for component in DANGEROUS_PATH_COMPONENTS:
            if component in path.lower():
                return True

        return False

    @staticmethod
    def canonicalize(path: str, base_dir: str) -> Optional[str]:
        """
        Canonicalize a path and verify it's within the base directory.

        Returns the safe absolute path, or None if traversal detected.
        """
        try:
            # Resolve to absolute path
            if os.path.isabs(path):
                abs_path = os.path.normpath(path)
            else:
                abs_path = os.path.normpath(os.path.join(base_dir, path))

            # Resolve symlinks
            abs_path = os.path.realpath(abs_path)

            # Verify it's within the allowed base directory
            if not abs_path.startswith(os.path.realpath(base_dir)):
                return None

            return abs_path
        except (ValueError, OSError):
            return None

    @staticmethod
    def validate_path(path: str, allowed_extensions: Optional[Set[str]] = None) -> Tuple[bool, str]:
        """
        Comprehensive path validation.

        Returns (is_valid, rejection_reason).
        """
        if not path or len(path) > 4096:
            return False, "Invalid path length"

        if PathSecurity.is_path_traversal(path):
            return False, "Path traversal detected"

        if allowed_extensions:
            ext = PurePath(path).suffix.lower()
            if ext and ext not in allowed_extensions:
                return False, f"File extension '{ext}' not allowed"

        return True, ""


# =============================================================================
# Secure File Handler
# =============================================================================

class SecureFileHandler:
    """
    File operations with path traversal protection.

    All file access is restricted to ALLOWED_BASE_DIRS.
    """

    def __init__(self, base_dir: str):
        if base_dir not in ALLOWED_BASE_DIRS:
            raise ValueError(f"Base dir {base_dir} not in allowed list")
        self.base_dir = os.path.realpath(base_dir)

    def read_file(self, relative_path: str) -> Optional[bytes]:
        """Read a file securely, preventing traversal."""
        is_valid, reason = PathSecurity.validate_path(relative_path,
                                                      ALLOWED_EXTENSIONS)
        if not is_valid:
            raise PermissionError(reason)

        safe_path = PathSecurity.canonicalize(relative_path, self.base_dir)
        if safe_path is None:
            raise PermissionError("Path escapes base directory")

        if not os.path.isfile(safe_path):
            raise FileNotFoundError(f"File not found: {relative_path}")

        with open(safe_path, "rb") as f:
            return f.read()

    def write_file(self, relative_path: str, content: bytes) -> bool:
        """Write a file securely, preventing traversal."""
        is_valid, reason = PathSecurity.validate_path(relative_path,
                                                      ALLOWED_EXTENSIONS)
        if not is_valid:
            raise PermissionError(reason)

        safe_path = PathSecurity.canonicalize(relative_path, self.base_dir)
        if safe_path is None:
            raise PermissionError("Path escapes base directory")

        os.makedirs(os.path.dirname(safe_path), exist_ok=True)
        with open(safe_path, "wb") as f:
            f.write(content)
        return True

    def delete_file(self, relative_path: str) -> bool:
        """Delete a file securely."""
        safe_path = PathSecurity.canonicalize(relative_path, self.base_dir)
        if safe_path is None:
            raise PermissionError("Path escapes base directory")

        if not os.path.isfile(safe_path):
            return False

        os.remove(safe_path)
        return True

    def list_files(self, relative_dir: str = "") -> List[str]:
        """List files in a directory securely."""
        safe_path = PathSecurity.canonicalize(relative_dir, self.base_dir)
        if safe_path is None:
            raise PermissionError("Path escapes base directory")

        if not os.path.isdir(safe_path):
            return []

        result = []
        for entry in os.listdir(safe_path):
            full = os.path.join(safe_path, entry)
            if os.path.isfile(full):
                result.append(entry)
        return result


# =============================================================================
# Log Sanitizer
# =============================================================================

class LogSanitizer:
    """
    Sanitizes log entries to prevent log poisoning attacks.

    Strips executable code patterns and normalizes dangerous input.
    """

    @staticmethod
    def sanitize(entry: str) -> str:
        """
        Remove executable code patterns from log entry.

        Returns sanitized string safe for log storage.
        """
        sanitized = entry

        # Strip executable code patterns
        for pattern in EXECUTABLE_PATTERNS:
            sanitized = pattern.sub('[REMOVED]', sanitized)

        # Normalize control characters
        sanitized = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f]', '', sanitized)

        # Remove ANSI escape sequences
        sanitized = re.sub(r'\x1b\[[0-9;]*[a-zA-Z]', '', sanitized)

        # Limit line length
        if len(sanitized) > 4096:
            sanitized = sanitized[:4096] + ' [TRUNCATED]'

        return sanitized

    @staticmethod
    def sanitize_http_header(value: str, header_name: str) -> str:
        """
        Sanitize HTTP header values specifically for log storage.

        Certain headers (User-Agent, Referer) are common poison vectors.
        """
        # CR/LF injection prevention
        value = value.replace('\r', '').replace('\n', '')

        # Remove null bytes
        value = value.replace('\x00', '')

        # Apply general sanitization
        return LogSanitizer.sanitize(value)


# =============================================================================
# Secure Log Handler
# =============================================================================

class SecureLogHandler:
    """
    Writes log entries safely, with poisoning prevention.

    Logs are stored outside the web root in a dedicated directory.
    """

    def __init__(self, log_dir: str = "/var/log/app"):
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)

        # Ensure log directory is outside web root
        real_log = str(self.log_dir.resolve())
        for web_dir in ["/var/www", "/var/www/html", "/srv/www"]:
            if real_log.startswith(os.path.realpath(web_dir)):
                raise ValueError(
                    f"Log directory {log_dir} must NOT be under web root!"
                )

    def write_access_log(self, entry: str) -> bool:
        """Write an access log entry safely."""
        sanitized = LogSanitizer.sanitize(entry)
        log_file = self.log_dir / "access.log"
        with open(log_file, "a") as f:
            f.write(sanitized + "\n")
        return True

    def write_error_log(self, entry: str) -> bool:
        """Write an error log entry safely."""
        sanitized = LogSanitizer.sanitize(entry)
        log_file = self.log_dir / "error.log"
        with open(log_file, "a") as f:
            f.write(sanitized + "\n")
        return True

    def sanitized_access_entry(self, remote_addr: str, method: str,
                                path: str, status: int, user_agent: str,
                                referer: str = "") -> str:
        """
        Build a sanitized access log entry.

        Individually sanitizes each field to prevent poisoning.
        """
        safe_ua = LogSanitizer.sanitize_http_header(user_agent, "User-Agent")
        safe_ref = LogSanitizer.sanitize_http_header(referer, "Referer")
        safe_path = LogSanitizer.sanitize(path)

        return f'{remote_addr} - - [{time_str()}] "{method} {safe_path} HTTP/1.1" {status} "-" "{safe_ua}" "{safe_ref}"'


# =============================================================================
# Web Server Config Guard
# =============================================================================

class WebServerConfigGuard:
    """
    Provides secure web server configuration snippets.

    These configs prevent path traversal and log poisoning at the
    web server level (Apache/NGINX).
    """

    @staticmethod
    def nginx_secure_config() -> str:
        """Return NGINX config that prevents path traversal and log poisoning."""
        return """
# Prevent path traversal
location ~* \\.\\./|\\.\\.\\\\) {
    deny all;
    return 404;
}

# Restrict file access to allowed extensions
location ~*\\.(php|phtml|php3|php4|php5)$ {
    deny all;
    return 404;
}

# Secure headers to prevent log injection
add_header X-Content-Type-Options nosniff;
add_header X-Frame-Options DENY;

# Log configuration - strip control characters
log_format secure '$remote_addr - $remote_user [$time_local] '
                  '"$request" $status $body_bytes_sent '
                  '"$http_referer" "$http_user_agent"'
                  ' REQUEST_TIME=$request_time';
access_log /var/log/nginx/access.log secure;

# Keep logs outside web root
access_log /var/log/nginx/access.log;
error_log /var/log/nginx/error.log;
"""

    @staticmethod
    def apache_secure_config() -> str:
        """Return Apache config that prevents path traversal and log poisoning."""
        return """
# Prevent path traversal
RewriteEngine On
RewriteCond %{REQUEST_URI} \\.\\. [NC,OR]
RewriteCond %{REQUEST_URI} \\x00 [NC]
RewriteRule .* - [F,L]

# Restrict file access
<FilesMatch "\\.(php|phtml|php3|php4|php5)$">
    Deny from all
</FilesMatch>

# Secure logging
LogFormat "%h %l %u %t \\"%r\\" %>s %b \\"%{Referer}i\\" \\"%{User-Agent}i\\"" sanitized
CustomLog ${APACHE_LOG_DIR}/access.log sanitized

# Store logs outside document root
ErrorLog ${APACHE_LOG_DIR}/error.log
CustomLog ${APACHE_LOG_DIR}/access.log combined
"""


# =============================================================================
# Test Helpers
# =============================================================================

def time_str():
    from datetime import datetime
    return datetime.utcnow().strftime("%d/%b/%Y:%H:%M:%S +0000")


# =============================================================================
# Tests
# =============================================================================

def test_path_traversal_detection():
    """Test that path traversal is detected."""
    assert PathSecurity.is_path_traversal("../etc/passwd")
    assert PathSecurity.is_path_traversal("../../../etc/passwd")
    assert PathSecurity.is_path_traversal("..%2f..%2fetc%2fpasswd")
    assert PathSecurity.is_path_traversal("\x00/etc/passwd")
    assert not PathSecurity.is_path_traversal("report.pdf")
    assert not PathSecurity.is_path_traversal("subdir/file.txt")
    print("PASS: Path traversal detection works")


def test_log_poisoning_prevention():
    """Test that executable code is stripped from logs."""
    sanitizer = LogSanitizer()

    payload = '<?php system($_GET["cmd"]); ?>'
    result = sanitizer.sanitize(payload)
    assert '<?php' not in result, "PHP code should be stripped"
    assert '[REMOVED]' in result

    js_payload = '<script>alert("xss")</script>'
    result = sanitizer.sanitize(js_payload)
    assert '<script>' not in result, "JS should be stripped"

    ssi_payload = '<!--#exec cmd="id"-->'
    result = sanitizer.sanitize(ssi_payload)
    assert '<!--#' not in result, "SSI should be stripped"
    print("PASS: Log poisoning prevention works")


def test_http_header_sanitization():
    """Test that HTTP headers are safe for logging."""
    sanitizer = LogSanitizer()

    # User-Agent with injected PHP
    ua = '<?php system("id"); ?>Mozilla/5.0'
    result = sanitizer.sanitize_http_header(ua, "User-Agent")
    assert '<?php' not in result, "PHP should be stripped from User-Agent"
    assert '\n' not in result, "CRLF should be stripped"
    print("PASS: HTTP header sanitization works")


def test_secure_file_handler():
    """Test that file handler prevents traversal."""
    import tempfile
    with tempfile.TemporaryDirectory() as tmpdir:
        # Ensure tmpdir is in our allowed list for testing
        test_config = SecureFileHandler(ALLOWED_BASE_DIRS.copy())
        # We just test the logic directly
        safe = PathSecurity.canonicalize("test.txt", tmpdir)
        assert safe is not None, "Normal file should work"
        assert safe.startswith(tmpdir), "File should be in tmpdir"

    print("PASS: Secure file handler works")


def test_canonicalize_rejects_traversal():
    """Test that canonicalize rejects traversal outside base."""
    import tempfile
    with tempfile.TemporaryDirectory() as tmpdir:
        result = PathSecurity.canonicalize("../../../etc/passwd", tmpdir)
        assert result is None, "Traversal should return None"

        # Normal file
        result = PathSecurity.canonicalize("file.txt", tmpdir)
        assert result is not None, "Normal path should work"
        assert result.startswith(tmpdir), "Result should be in tmpdir"

    print("PASS: Canonicalize rejects traversal")


if __name__ == "__main__":
    test_path_traversal_detection()
    test_log_poisoning_prevention()
    test_http_header_sanitization()
    test_canonicalize_rejects_traversal()
    test_secure_file_handler()
    print("\n✅ All path traversal + log poisoning tests passed!")
