# Fix: Docker Container Escape via Capability Abuse — Issue #1347

**Difficulty:** Expert · **Bounty:** $200 · **Labels:** security, bug, expert

## Vulnerability

The container is started with dangerous Linux capabilities (or `privileged`),
letting an attacker with in-container code execution break out to the host:

| Capability | Escape technique |
|------------|------------------|
| `CAP_SYS_ADMIN` | mount + cgroup-v1 `release_agent` runs a host command |
| `CAP_SYS_MODULE` | `init_module` loads a kernel module → full host compromise |
| `CAP_DAC_READ_SEARCH` | `open_by_handle_at` ("Shocker") reads arbitrary host files |
| `CAP_SYS_PTRACE` | trace/inject host processes when PID ns is shared |
| `CAP_SYS_RAWIO` | raw device / `/dev/mem` access |
| `CAP_BPF`, `CAP_SYS_BOOT`, `CAP_SYS_TIME`, ... | assorted host-level abuse |

`privileged: true` implicitly grants **all** capabilities plus device access —
the strongest escape primitive. `seccomp=unconfined` / `apparmor=unconfined`
remove the syscall/MAC backstop that would otherwise blunt these abuses.
(CWE-250 Execution with Unnecessary Privileges, CWE-269 Improper Privilege
Management.)

## Fix

Implemented in [`fix_1347.py`](./fix_1347.py) as a config validator:

- `find_capability_escape_risks(compose)` — flags `privileged`, escape-capable
  `cap_add` entries (normalising `CAP_` prefix / case / `ALL`), and
  `seccomp`/`apparmor` `unconfined`; also flags missing `no-new-privileges`
  when the service is otherwise risky. Accepts a full compose mapping or a
  single service.
- `assert_safe_capabilities(compose)` — raises `CapabilityEscapeError` (fail
  closed in CI).
- `harden_service(service)` — returns a least-privilege config: `cap_drop:
  [ALL]`, `privileged: false`, `no-new-privileges:true`, `seccomp=default`, and
  refuses to re-add any escape-capable capability.

Non-escape capabilities (e.g. `NET_BIND_SERVICE`) are intentionally allowed so
the validator doesn't produce false positives on legitimate configs.

## Verification

`tests/test_docker_capability_escape_1347_fix.py` (11 tests, all pass):
privileged flagged; `SYS_ADMIN`/`SYS_MODULE`/`DAC_READ_SEARCH`/`ALL` flagged in
`CAP_`-prefixed and lower-case forms; unconfined seccomp/apparmor flagged;
missing `no-new-privileges` flagged; safe and hardened configs pass;
`harden_service` refuses to re-add escape caps.

## References

- CWE-250, CWE-269
- Docker: `--cap-drop=ALL`, `--security-opt=no-new-privileges`, seccomp/AppArmor
- Trail of Bits / "Understanding Docker container escapes"
