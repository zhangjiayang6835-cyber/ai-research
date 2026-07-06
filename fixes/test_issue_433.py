"""Tests for fixes/issue_433_subdomain_takeover.py"""
from issue_433_subdomain_takeover import (
    audit_dns_records,
    build_safe_cookie,
    make_host_allowlist_middleware,
)


def test_audit_flags_nonresolving_github_pages():
    records = [("blog.example.com", "unclaimed-nonexistent-repo-xyz.github.io")]
    findings = audit_dns_records(records, resolver=lambda h: False)
    assert findings, "should flag dangling github.io CNAME"
    assert findings[0].provider == "github.io"


def test_audit_ignores_unknown_providers():
    assert audit_dns_records([("x.example.com", "example.net")]) == []


def test_audit_uses_http_fingerprint():
    records = [("api.example.com", "myapp.herokuapp.com")]
    findings = audit_dns_records(
        records, http_get=lambda url: "No such app", resolver=lambda h: True
    )
    # Either resolution failure or fingerprint should trigger a finding.
    assert findings and findings[0].provider == "herokuapp.com"


def test_safe_cookie_has_hardening_attrs_and_no_domain():
    header = build_safe_cookie("sid", "abc123")
    assert "Secure" in header
    assert "HttpOnly" in header
    assert "SameSite=Strict" in header
    assert "Domain=" not in header  # host-only!


def test_safe_cookie_rejects_bad_name():
    try:
        build_safe_cookie("evil name;", "x")
    except ValueError:
        return
    raise AssertionError("should reject unsafe cookie name")


def test_host_allowlist_blocks_unknown_host():
    def app(environ, start_response):
        start_response("200 OK", [("Content-Type", "text/plain")])
        return [b"ok"]

    mw = make_host_allowlist_middleware(app, ["app.example.com"])
    seen = {}

    def start_response(status, headers):
        seen["status"] = status

    body = mw({"HTTP_HOST": "evil.example.com"}, start_response)
    assert seen["status"].startswith("421")
    assert b"not allowed" in b"".join(body)

    body = mw({"HTTP_HOST": "app.example.com"}, start_response)
    assert seen["status"].startswith("200")


if __name__ == "__main__":
    for name, fn in list(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"ok {name}")
