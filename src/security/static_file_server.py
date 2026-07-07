"""Secure static file serving helpers.

The stdlib SimpleHTTPRequestHandler is convenient for small apps and local
tools, but its default directory behavior is unsafe for public endpoints: when
no index file exists it renders a browsable file listing.  This handler keeps
normal file serving while refusing every directory request with HTTP 403.
"""

from __future__ import annotations

import os
from http import HTTPStatus
from http.server import SimpleHTTPRequestHandler


class SecureStaticFileHandler(SimpleHTTPRequestHandler):
    """A SimpleHTTPRequestHandler variant with directory listing disabled."""

    server_version = "SecureStaticHTTP/1.0"

    def send_head(self):  # noqa: D401 - signature matches stdlib override.
        """Send response headers, denying directories before stdlib redirects."""
        path = self.translate_path(self.path)
        if os.path.isdir(path):
            self.send_error(HTTPStatus.FORBIDDEN, "Directory listing disabled")
            return None
        return super().send_head()

    def list_directory(self, path):  # noqa: D401 - signature matches stdlib override.
        """Refuse fallback directory listings if stdlib reaches this hook."""
        self.send_error(HTTPStatus.FORBIDDEN, "Directory listing disabled")
        return None
