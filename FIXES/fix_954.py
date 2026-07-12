"""
Fix for Issue #954 — Blind XXE via SVG Upload → SSRF + Data Exfil
====================================================================

Vulnerability
-------------
SVG file upload functionality does not disable external entity resolution.
Attackers can craft SVGs containing external entities to exfiltrate server
files via OOB techniques.

Fix Strategy
------------
1. Disable DOCTYPE declarations to prevent entity definitions.
2. Disable external entity resolution in the XML parser.
3. Whitelist allowed SVG tags and attributes.
"""

from __future__ import annotations

import io
import re
from typing import Final

# Allowlist of safe SVG tags
SAFE_SVG_TAGS: Final[set[str]] = {
    "svg", "g", "path", "circle", "rect", "line", "polyline", "polygon",
    "text", "tspan", "defs", "use", "image", "clipPath", "mask",
    "linearGradient", "radialGradient", "stop", "filter", "feBlend",
    "feColorMatrix", "feComponentTransfer", "feComposite", "feGaussianBlur",
    "feMerge", "feOffset", "feFlood", "feTile", "feDropShadow",
    "animate", "animateTransform", "set", "style", "desc",
}

# XML/DOCTYPE detection patterns
DOCTYPE_PATTERN: Final[re.Pattern] = re.compile(r"<!DOCTYPE", re.IGNORECASE)
ENTITY_PATTERN: Final[re.Pattern] = re.compile(r"<!ENTITY", re.IGNORECASE)
EXTERNAL_ENTITY_PATTERN: Final[re.Pattern] = re.compile(
    r"<!ENTITY\s+\S+\s+(SYSTEM|PUBLIC)\s+", re.IGNORECASE
)

# Known XXE payload patterns
XXE_PATTERNS: Final[list[re.Pattern]] = [
    re.compile(r"<!ENTITY\s+\S+\s+SYSTEM\s+['\"]file://", re.IGNORECASE),
    re.compile(r"<!ENTITY\s+\S+\s+SYSTEM\s+['\"]http://", re.IGNORECASE),
    re.compile(r"<!ENTITY\s+\S+\s+SYSTEM\s+['\"]https://", re.IGNORECASE),
    re.compile(r"<!ENTITY\s+\S+\s+SYSTEM\s+['\"]ftp://", re.IGNORECASE),
    re.compile(r"<!ENTITY\s+\S+\s+SYSTEM\s+['\"]php://", re.IGNORECASE),
    re.compile(r"<!ENTITY\s+\S+\s+SYSTEM\s+['\"]expect://", re.IGNORECASE),
    re.compile(r"<!ENTITY\s+\S+\s+SYSTEM\s+['\"]data://", re.IGNORECASE),
]


def has_xxe_payload(svg_content: str) -> bool:
    """Check if SVG content contains XXE-related declarations."""
    if DOCTYPE_PATTERN.search(svg_content):
        return True
    if ENTITY_PATTERN.search(svg_content):
        return True
    for pattern in XXE_PATTERNS:
        if pattern.search(svg_content):
            return True
    return False


def validate_svg_tags(svg_content: str) -> tuple[bool, str]:
    """Validate that SVG only contains allowed tags."""
    tags = re.findall(r"<(\w+)", svg_content)
    for tag in tags:
        if tag.lower() not in SAFE_SVG_TAGS:
            return False, f"Tag '{tag}' is not in the allowed SVG whitelist"
    return True, ""


def safe_svg_parse(svg_content: str) -> bytes | None:
    """
    Parse SVG content safely, rejecting XXE payloads and disallowed tags.

    Returns the content as bytes if safe, None if rejected.
    """
    if has_xxe_payload(svg_content):
        return None
    valid, reason = validate_svg_tags(svg_content)
    if not valid:
        return None
    return svg_content.encode("utf-8")


def safe_svg_parse_with_lxml(svg_content: str) -> bytes | None:
    """
    Parse SVG using lxml with all XXE protections enabled.

    Requires lxml to be installed.
    """
    try:
        from lxml import etree
    except ImportError:
        return safe_svg_parse(svg_content)

    if has_xxe_payload(svg_content):
        return None

    parser = etree.XMLParser(
        no_network=True,           # Disable network access
        dtd_validation=False,      # Disable DTD validation
        load_dtd_constant=False,   # Disable DTD constant loading
        huge_tree=False,           # Disable huge tree parsing
        resolve_entities=False,    # Disable entity resolution
        remove_blank_text=True,
    )
    try:
        tree = etree.parse(io.BytesIO(svg_content.encode()), parser)
        root_tag = tree.getroot().tag
        if isinstance(root_tag, str) and root_tag.lower() != "svg":
            return None
        return etree.tostring(tree, pretty_print=True, encoding="unicode").encode()
    except Exception:
        return None
