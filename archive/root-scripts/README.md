# Archived root-level scripts

These files used to sit in the repository root. They were moved here in a single
cleanup so the root shows the project itself rather than 30 loose one-off scripts.

Nothing in `.github/`, `tests/`, `docs/` or any module imported them — each was
verified unreferenced before being moved. Nothing was deleted: every file is here
at its original content.

## Broken — did not compile before being moved

These raise `SyntaxError` / `IndentationError` and could never have run. They are
kept only as a record of work that was attempted.

| File | Error |
|---|---|
| `check_issue29.py` | `IndentationError` — orphaned statement at module level, no `urllib` import |
| `check_new.py` | `SyntaxError` — nested double quotes inside `"token os.environ["GH_TOKEN"]"` |
| `fix-oauth2-pkce-interception.py` | `SyntaxError` — unterminated string, a `=== ... ===` banner was pasted inside a `print("` |
| `fix_issue_341.py` | `SyntaxError` — raw newline inside `re.sub(r'[<>&"'\n\r]', ...)` |
| `fix_issue_342.py` | same as `fix_issue_341.py` |
| `fix_issue_343.py` | same as `fix_issue_341.py` |
| `fix_issue_344.py` | same as `fix_issue_341.py` |
| `fix_issue_345.py` | same as `fix_issue_341.py` |
| `security_fix.py` | `SyntaxError` — same broken `re.sub` character class, with an escaped `\\` |

## Compiles, but cannot work

These parse cleanly, which is why a syntax check alone would not have caught them.

| File | Problem |
|---|---|
| `check_issues.py` | uses `os.environ["GH_TOKEN"]` but never imports `os` → `NameError` on run |
| `check_new2.py` | the token expression sits *inside* the string literal: `"token os.environ['GH_TOKEN']"` — it sends that text literally, so every request is unauthenticated |
| `fix_344.py` | `SecurityFix.apply()` takes no `self`, and only `return True`; no fix logic |
| `fix_345.py` | identical shell to `fix_344.py` |
| `solution.python` | not a `.py` file; a fragment using `websockets`, `ALLOWED_ORIGINS` and `sessions` that are never defined |

## Superseded by a maintained implementation

The root copies are early drafts; a maintained implementation of the same issue
lives in `fixes/`. Prefer those.

| Archived file | Maintained replacement |
|---|---|
| `fix.py` | `fixes/native_buffer_overflow_fix.py` |
| `fix-host-header-injection.py` | `fixes/host_header_injection_fix.py` |
| `fix_issue_677.py` | `fixes/jwt_kid_injection_fix.py` |
| `fix-ssrf-aws-metadata.py` | `fixes/fix_dns_rebinding_ssrf.py` |
| `k8s_rbac_validator.py`, `k8s_rbac_fix_submission.md` | `fixes/fix_k8s_rbac_bypass.py` |
| `fix-integer-overflow-solidity.sol` | `fixes/solidity_integer_overflow_fix.py` |
| `fix-sidecar-injection.py` | no replacement in `fixes/` |

## Still usable, kept for reference

| File | What it is | In `fixes/` |
|---|---|---|
| `event_policy.py` | `PRIVILEGED_EVENT_FIELDS` set for privilege-escalation checks | — |
| `rate_limit.py` | `rate_limit(max_attempts, window)` decorator for login endpoints | — |
| `fix_957.py` | LDAP filter escaping via `ldap3` (needs the `ldap3` package) | — |
| `fix_issue_680.py` | OAuth token leaked via `Referer` header | `oauth_referer_leak_fix.py` |
| `fix_issue_684.py` | SSRF via the gopher protocol → Redis RCE | `gopher_ssrf_fix.py` |
| `fix_issue_685.py` | WebSocket hijacking from missing cookie validation | `websocket_origin_hijack_fix.py` |
| `fix_issue_721.py` | HTTP/2 downgrade → request smuggling | `request_smuggling_fix.py` |
| `fix_issue_733.py` | AWS IAM privilege escalation via `PassRole` + EC2 | — |
| `jwt_poc.py` | Proof of concept; imports the root `sso_federation` module | — |
| `shanaboo_solution.md` | Write-up | — |

Note that `fixes/` holds 121 modules but only 29 are imported by `tests/`. The
column above records where an implementation of the same issue exists, not that
it is test-covered.

`jwt_poc.py` is the one file here with a live dependency: it does
`from sso_federation import _create_jwt, _verify_jwt`. `sso_federation.py` stayed in
the root because `tests/test_sso_federation.py` imports it, so this PoC still runs
if you copy it back beside that module.
