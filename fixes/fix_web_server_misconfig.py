"""
fix_web_server_misconfig.py — Apache/NGINX Misconfiguration → Source Code Disclosure + RCE Fix

VULNERABILITY:
Misconfigured web servers expose source code (.git, .env, backup files) or allow
path traversal to sensitive files. Attackers can read source code to find
vulnerabilities, or execute arbitrary code via misconfigured handlers.

FIX:
1. Block access to sensitive files and directories
2. Implement proper MIME type handling
3. Disable directory listing
4. Set secure headers
5. Restrict file access patterns
6. Provide secure server configuration templates
"""

import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple


# =============================================================================
# Configuration
# =============================================================================

# Files and patterns that should never be served
BLOCKED_FILES = frozenset({
    ".env", ".git", ".gitignore", ".gitmodules", ".gitattributes",
    ".htaccess", ".htpasswd",
    "composer.json", "composer.lock",
    "package.json", "package-lock.json", "yarn.lock",
    "Dockerfile", "docker-compose.yml", "docker-compose.yaml",
    "Makefile", "Gemfile", "Gemfile.lock",
    "config.php", "config.py", "config.json", "config.yaml",
    "credentials", "secrets", "secret",
    "wp-config.php", "wp-config",
    ".aws", ".azure", ".gcp",
    "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519",
    ".npmrc", ".pypirc", ".gemrc",
    ".DS_Store", "Thumbs.db",
    "*.sql", "*.sqlite", "*.db",
    "*.bak", "*.old", "*.orig", "*.swp", "*.swo",
    "*.log", "*.tar", "*.gz", "*.zip", "*.rar",
    "*.pem", "*.key", "*.crt", "*.cert",
    "*.pyc", "*.pyo", "__pycache__",
    ".vscode", ".idea", ".sublime-*",
})

# File extensions that should be served as static files
STATIC_EXTENSIONS = frozenset({
    ".html", ".htm", ".css", ".js", ".json", ".xml",
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp",
    ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".pdf", ".txt", ".md",
    ".map", ".wasm",
})

# File extensions that indicate source code (should NOT be served)
SOURCE_EXTENSIONS = frozenset({
    ".py", ".php", ".rb", ".pl", ".go", ".rs", ".java",
    ".c", ".cpp", ".h", ".hpp", ".cs", ".swift", ".kt",
    ".ts", ".jsx", ".tsx", ".vue", ".svelte",
    ".env", ".cfg", ".conf", ".ini",
    ".yml", ".yaml", ".toml",
    ".sh", ".bash", ".zsh", ".bat", ".ps1",
})


@dataclass
class WebServerConfig:
    """Security configuration for web server."""
    # Document root
    document_root: str = "/var/www/html"
    # Block directory listing
    disable_directory_listing: bool = True
    # Block sensitive files
    block_sensitive_files: bool = True
    # Block source code serving
    block_source_code: bool = True
    # Enable security headers
    enable_security_headers: bool = True
    # Custom blocked paths
    custom_blocked_paths: Set[str] = frozenset()


# =============================================================================
# Request Validator
# =============================================================================

class RequestValidator:
    """
    Validates incoming HTTP requests before they reach the application.

    Checks:
    - Path traversal attempts
    - Access to blocked files
    - Access to source code
    - Directory listing attempts
    - Malicious file extensions
    """

    def __init__(self, config: Optional[WebServerConfig] = None):
        self.config = config or WebServerConfig()

    def validate_path(self, request_path: str) -> Tuple[bool, str]:
        """
        Validate a request path against security rules.

        Returns (is_allowed, rejection_reason).
        """
        if not request_path or len(request_path) > 4096:
            return False, "Invalid request path"

        # Decode URL encoding
        from urllib.parse import unquote
        decoded = unquote(request_path)

        # Check for path traversal
        if self._is_path_traversal(decoded):
            return False, "Path traversal detected"

        # Check for null bytes
        if '\x00' in decoded:
            return False, "Null byte injection detected"

        # Check for blocked files
        if self.config.block_sensitive_files:
            if self._is_blocked_file(decoded):
                return False, "Access to sensitive file blocked"

        # Check for source code exposure
        if self.config.block_source_code:
            if self._is_source_code(decoded):
                return False, "Source code files are not served"

        # Check for directory listing
        if self.config.disable_directory_listing:
            if self._is_directory_listing_attempt(decoded):
                return False, "Directory listing is disabled"

        return True, ""

    def _is_path_traversal(self, path: str) -> bool:
        """Check for path traversal attempts."""
        # Direct traversal
        if re.search(r'(\.\.|%2e%2e|%252e%252e)', path, re.IGNORECASE):
            return True
        # Absolute path access
        if path.startswith('/') and not path.startswith(self.config.document_root):
            return True
        # Encoded variants
        if re.search(r'\.\\/', path):
            return True
        return False

    def _is_blocked_file(self, path: str) -> bool:
        """Check if path targets a blocked file."""
        path_lower = path.lower()
        filename = Path(path_lower).name

        # Check exact blocked files
        for blocked in BLOCKED_FILES:
            if blocked.startswith('*'):
                if filename.endswith(blocked[1:]):
                    return True
            elif blocked == filename:
                return True

        # Check hidden files (.env, .git, etc.)
        if filename.startswith('.') and filename not in {'.well-known'}:
            return True

        # Check for .git path access
        if '/.git' in path_lower:
            return True

        return False

    def _is_source_code(self, path: str) -> bool:
        """Check if path targets a source code file."""
        ext = Path(path).suffix.lower()
        if ext in SOURCE_EXTENSIONS:
            return True
        return False

    def _is_directory_listing_attempt(self, path: str) -> bool:
        """Check for directory listing attempts."""
        if not path or path.endswith('/'):
            return True  # Directory requests should go through index handler
        return False

    def get_security_headers(self) -> Dict[str, str]:
        """Get security headers to add to all responses."""
        if not self.config.enable_security_headers:
            return {}
        return {
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "X-XSS-Protection": "1; mode=block",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
            "Content-Security-Policy": "default-src 'self'",
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
            "Cache-Control": "no-store, max-age=0",
        }


# =============================================================================
# Secure Static File Server
# =============================================================================

class SecureStaticFileServer:
    """
    Serves static files while preventing source code disclosure.

    Only serves files with allowed static extensions.
    All other requests are rejected or passed to the application handler.
    """

    def __init__(self, document_root: str,
                 config: Optional[WebServerConfig] = None):
        self.document_root = Path(document_root).resolve()
        self.config = config or WebServerConfig(
            document_root=str(self.document_root)
        )
        self.validator = RequestValidator(self.config)

    def serve_file(self, request_path: str) -> Tuple[Optional[bytes], str, Dict[str, str]]:
        """
        Serve a static file securely.

        Returns (content, content_type, headers) or (None, error_code, headers).
        """
        # Validate the path
        allowed, reason = self.validator.validate_path(request_path)
        if not allowed:
            return None, "403", self.validator.get_security_headers()

        # Resolve the file path
        safe_path = self._resolve_safe_path(request_path)
        if safe_path is None:
            return None, "404", self.validator.get_security_headers()

        # Check if it's a valid static file
        ext = safe_path.suffix.lower()
        if ext not in STATIC_EXTENSIONS:
            return None, "404", self.validator.get_security_headers()

        # Check that the resolved path is within document root
        try:
            safe_path.resolve().relative_to(self.document_root)
        except ValueError:
            return None, "403", self.validator.get_security_headers()

        # Read and serve the file
        if not safe_path.is_file():
            return None, "404", self.validator.get_security_headers()

        content = safe_path.read_bytes()
        content_type = self._get_mime_type(ext)
        headers = self.validator.get_security_headers()
        headers["Content-Type"] = content_type
        headers["Content-Length"] = str(len(content))

        return content, "200", headers

    def _resolve_safe_path(self, request_path: str) -> Optional[Path]:
        """Resolve a request path to a filesystem path safely."""
        # Remove query string
        request_path = request_path.split('?')[0]

        # Remove leading slash
        clean_path = request_path.lstrip('/')

        # Resolve
        full_path = (self.document_root / clean_path).resolve()

        # Verify it's within document root
        try:
            full_path.relative_to(self.document_root)
        except ValueError:
            return None

        return full_path

    def _get_mime_type(self, ext: str) -> str:
        """Get MIME type for a file extension."""
        mime_types = {
            ".html": "text/html; charset=utf-8",
            ".css": "text/css; charset=utf-8",
            ".js": "application/javascript",
            ".json": "application/json",
            ".xml": "application/xml",
            ".png": "image/png",
            ".jpg": "image/jpeg",
            ".jpeg": "image/jpeg",
            ".gif": "image/gif",
            ".svg": "image/svg+xml",
            ".ico": "image/x-icon",
            ".webp": "image/webp",
            ".pdf": "application/pdf",
            ".txt": "text/plain; charset=utf-8",
            ".md": "text/markdown; charset=utf-8",
            ".woff": "font/woff",
            ".woff2": "font/woff2",
            ".ttf": "font/ttf",
        }
        return mime_types.get(ext, "application/octet-stream")


# =============================================================================
# Server Configuration Generator
# =============================================================================

def generate_nginx_config(document_root: str = "/var/www/html",
                          server_name: str = "_") -> str:
    """Generate secure NGINX configuration."""
    return f"""
server {{
    listen 80;
    server_name {server_name};
    root {document_root};
    index index.html;

    # Security headers
    add_header X-Content-Type-Options nosniff always;
    add_header X-Frame-Options DENY always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always;
    add_header Content-Security-Policy "default-src 'self'" always;
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header Cache-Control "no-store, max-age=0" always;

    # Disable directory listing
    autoindex off;

    # Block access to sensitive files
    location ~* (\\.git|\\.env|\\.svn|\\.hg|composer\\.json|package-lock\\.json|Dockerfile) {{
        deny all;
        return 404;
    }}

    # Block access to hidden files
    location ~* /\\. {{
        deny all;
        return 404;
    }}

    # Block access to backup/config files
    location ~* \\.(bak|old|orig|swp|swo|log|sql|db|pem|key|crt|cert)$ {{
        deny all;
        return 404;
    }}

    # Block access to source code files
    location ~* \\.(py|php|rb|pl|go|rs|java|c|cpp|h|hpp|cs|swift|kt)$ {{
        deny all;
        return 404;
    }}

    # Only serve static files with allowed extensions
    location ~* \\.(html|css|js|json|xml|png|jpg|jpeg|gif|svg|ico|webp|woff2?|ttf|eot|otf|pdf|txt|md|wasm)$ {{
        expires 1h;
        add_header Cache-Control "public, immutable";
        try_files $uri =404;
    }}

    # Prevent path traversal
    if ($uri ~* '\\.\\.') {{
        return 404;
    }}

    # Deny all other requests (pass to application)
    location / {{
        try_files $uri $uri/ /index.html;
    }}
}}
"""


def generate_apache_config(document_root: str = "/var/www/html") -> str:
    """Generate secure Apache configuration."""
    return f"""
<VirtualHost *:80>
    DocumentRoot {document_root}

    # Security headers
    Header always set X-Content-Type-Options "nosniff"
    Header always set X-Frame-Options "DENY"
    Header always set X-XSS-Protection "1; mode=block"
    Header always set Referrer-Policy "strict-origin-when-cross-origin"
    Header always set Permissions-Policy "camera=(), microphone=(), geolocation=()"
    Header always set Content-Security-Policy "default-src 'self'"
    Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"
    Header always set Cache-Control "no-store, max-age=0"

    # Disable directory listing
    Options -Indexes

    # Block access to sensitive files
    <FilesMatch "\\.(git|env|svn|hg|bak|old|orig|swp|swo|log|sql|db|pem|key|crt|cert)$">
        Require all denied
    </FilesMatch>

    <FilesMatch "^(composer\\.json|package-lock\\.json|Dockerfile|Makefile|Gemfile)$">
        Require all denied
    </FilesMatch>

    # Block access to hidden files
    <FilesMatch "^\.">
        Require all denied
    </FilesMatch>

    # Block access to source code
    <FilesMatch "\\.(py|php|rb|pl|go|rs|java|c|cpp|h|hpp|cs|swift|kt)$">
        Require all denied
    </FilesMatch>

    # Prevent path traversal
    RewriteEngine On
    RewriteCond %{{REQUEST_URI}} \.\. [NC]
    RewriteRule .* - [F,L]
</VirtualHost>
"""


# =============================================================================
# Tests
# =============================================================================

def test_block_sensitive_files():
    """Test that sensitive files are blocked."""
    validator = RequestValidator()

    # .git access
    allowed, _ = validator.validate_path("/.git/config")
    assert not allowed, ".git access should be blocked"

    # .env access
    allowed, _ = validator.validate_path("/.env")
    assert not allowed, ".env access should be blocked"

    # Normal file
    allowed, _ = validator.validate_path("/index.html")
    assert allowed, "Normal file access should be allowed"

    print("PASS: Sensitive files are blocked")


def test_block_source_code():
    """Test that source code files are blocked."""
    validator = RequestValidator()

    allowed, _ = validator.validate_path("/app.py")
    assert not allowed, ".py files should be blocked"

    allowed, _ = validator.validate_path("/config.php")
    assert not allowed, ".php files should be blocked"

    print("PASS: Source code files are blocked")


def test_path_traversal_detection():
    """Test that path traversal is detected."""
    validator = RequestValidator()

    allowed, _ = validator.validate_path("/../../../etc/passwd")
    assert not allowed, "Path traversal should be blocked"

    allowed, _ = validator.validate_path("/static/../../config.json")
    assert not allowed, "Encoded path traversal should be blocked"

    print("PASS: Path traversal is detected")


def test_static_file_server():
    """Test that static file server works correctly."""
    import tempfile
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create a test file
        test_file = Path(tmpdir) / "test.html"
        test_file.write_text("<html>test</html>")

        server = SecureStaticFileServer(str(tmpdir))

        # Serve valid file
        content, status, _ = server.serve_file("/test.html")
        assert status == "200", "Valid file should be served"
        assert content == b"<html>test</html>"

        # Block .env access
        _, status, _ = server.serve_file("/.env")
        assert status == "403", ".env should be blocked"

        # Block traversal
        _, status, _ = server.serve_file("/../../../etc/passwd")
        assert status in ("403", "404")

    print("PASS: Static file server works correctly")


def test_security_headers():
    """Test that security headers are generated."""
    validator = RequestValidator()
    headers = validator.get_security_headers()

    assert "X-Content-Type-Options" in headers
    assert headers["X-Content-Type-Options"] == "nosniff"
    assert "X-Frame-Options" in headers
    assert headers["X-Frame-Options"] == "DENY"

    print("PASS: Security headers are generated")


if __name__ == "__main__":
    test_block_sensitive_files()
    test_block_source_code()
    test_path_traversal_detection()
    test_static_file_server()
    test_security_headers()
    print("\n✅ All web server misconfiguration tests passed!")
