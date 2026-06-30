"""
Fix for: Directory Listing Enabled on Uploads (Issue #114)

Vulnerability
-------------
When a web server serves an uploads directory with autoindex / directory
listing enabled, anonymous visitors can enumerate every uploaded file by
requesting the directory URL (e.g. /uploads/). That lets attackers harvest
private documents, brute-force filenames, and map out user activity.

Root cause
----------
1. The framework (Flask/Django/etc.) or the fronting web server (nginx,
   Apache) is configured to list directory contents when no index file is
   present.
2. The upload handler stores files under predictable names without any
   per-request access control.

Fix (defense in depth)
----------------------
1. Explicitly disable directory listing in the application.
2. Serve uploaded files through an authenticated view that validates the
   request and the resolved path (also prevents path traversal).
3. Drop an empty ``index.html`` into the uploads directory so any
   misconfigured upstream server returns an empty page instead of a
   listing.
4. Randomize stored filenames so even if a listing leaks, names are not
   guessable.
"""

from __future__ import annotations

import os
import secrets
from pathlib import Path

from flask import Flask, abort, request, send_from_directory
from werkzeug.utils import secure_filename

app = Flask(__name__)

# Resolve once at startup so every comparison is against a canonical path.
UPLOAD_DIR = Path(os.environ.get("UPLOAD_DIR", "/var/app/uploads")).resolve()
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "pdf", "txt"}
MAX_UPLOAD_BYTES = 5 * 1024 * 1024  # 5 MiB

app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_BYTES


def _ensure_upload_dir() -> None:
    """Create the uploads dir and a blank index.html that suppresses any
    accidental autoindex from an upstream web server."""
    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    index = UPLOAD_DIR / "index.html"
    if not index.exists():
        index.write_text("")  # empty page — never a directory listing


def _allowed(filename: str) -> bool:
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def _safe_join(directory: Path, filename: str) -> Path:
    """Resolve ``filename`` under ``directory`` and reject any escape."""
    candidate = (directory / filename).resolve()
    if directory != candidate and directory not in candidate.parents:
        abort(404)
    return candidate


@app.route("/upload", methods=["POST"])
def upload():
    if "file" not in request.files:
        abort(400, "no file part")
    file = request.files["file"]
    if not file.filename or not _allowed(file.filename):
        abort(400, "invalid file")

    _ensure_upload_dir()
    ext = file.filename.rsplit(".", 1)[1].lower()
    # Randomized name → unguessable even if a listing ever leaks.
    stored_name = f"{secrets.token_urlsafe(16)}.{secure_filename(ext)}"
    file.save(_safe_join(UPLOAD_DIR, stored_name))
    return {"stored_as": stored_name}, 201


@app.route("/uploads/", defaults={"filename": ""})
@app.route("/uploads/<path:filename>")
def serve_upload(filename: str):
    """Explicitly refuse directory listings; only serve known files."""
    if not filename or filename.endswith("/"):
        abort(404)  # no listing, ever

    # TODO: replace with your real authn/authz check.
    if not request.headers.get("Authorization"):
        abort(401)

    target = _safe_join(UPLOAD_DIR, filename)
    if not target.is_file():
        abort(404)

    return send_from_directory(
        UPLOAD_DIR,
        filename,
        as_attachment=True,
        max_age=0,
    )


# --- Recommended upstream config (nginx) -------------------------------------
# location /uploads/ {
#     autoindex off;            # disable directory listing
#     try_files $uri =404;      # never fall through to a listing
#     internal;                 # only reachable via X-Accel-Redirect
# }
# -----------------------------------------------------------------------------


if __name__ == "__main__":  # pragma: no cover
    _ensure_upload_dir()
    app.run()
