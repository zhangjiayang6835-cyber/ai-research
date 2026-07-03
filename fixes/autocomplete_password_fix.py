"""
Fix for Issue #90: Autocomplete Enabled on Password Field ($10)

Vulnerability:
    Password fields with autocomplete enabled allow browsers to store
    and auto-fill credentials, making them accessible to anyone with
    access to the user's machine or browser password manager.

Fix:
    Ensure autocomplete="off" is set on password fields and provide
    a middleware helper to audit and fix HTML responses.
"""

from __future__ import annotations

import re
from html.parser import HTMLParser
from typing import List, Tuple


class PasswordAuditParser(HTMLParser):
    """Parse HTML and find password fields without autocomplete=off."""

    def __init__(self) -> None:
        super().__init__()
        self.vulnerable_fields: List[Tuple[int, str]] = []
        self._current_tag: str = ""
        self._current_attrs: dict = {}
        self._tag_stack: List[Tuple[str, dict]] = []

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, str | None]]) -> None:
        attr_dict = {k.lower(): v or "" for k, v in attrs}
        if tag == "input" and attr_dict.get("type", "").lower() == "password":
            autocomplete = attr_dict.get("autocomplete", "").lower()
            if autocomplete != "off":
                self.vulnerable_fields.append((self.getpos()[0], "password"))
        self._tag_stack.append((tag, attr_dict))

    def get_report(self) -> str:
        if not self.vulnerable_fields:
            return "No vulnerable password fields found."
        lines = [f"Found {len(self.vulnerable_fields)} vulnerable password field(s):"]
        for lineno, field_type in self.vulnerable_fields:
            lines.append(f"  Line {lineno}: <input type=\"{field_type}\"> missing autocomplete=off")
        return "\n".join(lines)


def fix_autocomplete(html: str) -> str:
    """Add autocomplete='off' to all password fields in HTML."""
    # Pattern: <input ... type="password" ...>
    # Insert autocomplete="off" if not present
    def _fix_password_field(match: re.Match) -> str:
        tag = match.group(0)
        if 'autocomplete' in tag.lower():
            return tag
        # Insert before the closing >
        if tag.endswith('/>'):
            return tag[:-2] + ' autocomplete="off" />'
        return tag[:-1] + ' autocomplete="off">'

    pattern = re.compile(
        r'<input\s[^>]*?\btype\s*=\s*["\']password["\'][^>]*?>',
        re.IGNORECASE,
    )
    return pattern.sub(_fix_password_field, html)


def audit_response(html: str) -> Tuple[str, bool]:
    """Audit and optionally fix password fields.

    Returns:
        (report_or_fixed_html, was_modified)
    """
    parser = PasswordAuditParser()
    parser.feed(html)
    if parser.vulnerable_fields:
        fixed = fix_autocomplete(html)
        return fixed, True
    return html, False


# --------------------------------------------------------------------- self-test
if __name__ == "__main__":
    safe_html = '<input type="password" autocomplete="off" name="pwd">'
    fixed, changed = audit_response(safe_html)
    assert not changed, "safe HTML should not be modified"

    vuln_html = '<input type="password" name="pwd">'
    fixed, changed = audit_response(vuln_html)
    assert changed, "vulnerable HTML should be modified"
    assert 'autocomplete="off"' in fixed, "autocomplete=off should be added"
    print("autocomplete_password_fix self-test passed")
