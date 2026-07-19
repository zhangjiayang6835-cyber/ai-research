"""
Fix for Issue #1347 — Docker Container Escape via Capability Abuse
=================================================================

Vulnerability
-------------
The container is started with dangerous Linux capabilities (or ``privileged``),
which lets an attacker with code execution inside the container break out to the
host. Well-known capability-based escapes include:

- ``CAP_SYS_ADMIN``        — mount filesystems; the classic cgroup-v1
  ``release_agent`` escape runs an arbitrary command on the host.
- ``CAP_SYS_MODULE``       — ``init_module``: load a kernel module → full host
  compromise.
- ``CAP_DAC_READ_SEARCH``  — ``open_by_handle_at`` ("Shocker"): read arbitrary
  host files, e.g. ``/etc/shadow``.
- ``CAP_SYS_PTRACE``       — trace/inject into host processes when the host PID
  namespace is shared.
- ``CAP_SYS_RAWIO``        — raw device / ``/dev/mem`` access.
- ``CAP_SYS_BOOT`` / ``CAP_SYS_CHROOT`` / ``CAP_SYS_TIME`` / ``CAP_BPF`` ...

``privileged: true`` implicitly grants *all* capabilities plus device access and
is the strongest escape primitive of all. Running with
``seccomp=unconfined`` or ``apparmor=unconfined`` removes the syscall/MAC
backstop that would otherwise blunt these abuses.

Fix
---
Validate the container/compose configuration and refuse escape-enabling
settings. This module:

1. Flags ``privileged: true`` and ``cap_add`` entries that grant escape-capable
   capabilities (normalising ``CAP_`` prefix / case / ``ALL``).
2. Flags ``seccomp=unconfined`` and ``apparmor=unconfined``.
3. Flags missing ``no-new-privileges`` when the config is otherwise risky.
4. Provides ``harden_service()`` to produce a least-privilege config
   (``cap_drop: [ALL]``, ``privileged: false``, ``no-new-privileges``, seccomp
   default) and ``assert_safe_capabilities()`` to fail closed in CI.

Acceptance Criteria
-------------------
- [x] ``privileged`` containers rejected
- [x] Escape-capable ``cap_add`` values rejected (CAP_ prefix / case / ALL)
- [x] ``seccomp``/``apparmor`` ``unconfined`` rejected
- [x] Hardened config passes validation

References: CWE-250 (Execution with Unnecessary Privileges),
CWE-269 (Improper Privilege Management).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping

# Capabilities that (alone or combined) enable a container->host escape.
# Value = short reason shown in findings.
ESCAPE_CAPABILITIES: dict[str, str] = {
    "SYS_ADMIN": "mount + cgroup release_agent escape; extremely powerful",
    "SYS_MODULE": "load kernel modules → full host compromise",
    "DAC_READ_SEARCH": "open_by_handle_at (Shocker) reads arbitrary host files",
    "DAC_OVERRIDE": "bypass file permission checks on host-shared paths",
    "SYS_PTRACE": "trace/inject into host processes if PID ns is shared",
    "SYS_RAWIO": "raw device / /dev/mem access",
    "SYS_BOOT": "reboot the host",
    "SYS_CHROOT": "chroot-based escape primitives",
    "SYS_TIME": "set host clock",
    "BPF": "load eBPF programs",
    "PERFMON": "perf/eBPF observability of the host",
    "NET_ADMIN": "reconfigure host networking",
    "MKNOD": "create device nodes (dangerous with device cgroup access)",
    "AUDIT_CONTROL": "manipulate host kernel audit subsystem",
}

# A conservative least-privilege set most app containers can run with (or none).
SAFE_DEFAULT_CAP_ADD: tuple[str, ...] = ()

_UNCONFINED_PROFILES = ("seccomp=unconfined", "apparmor=unconfined")


class CapabilityEscapeError(PermissionError):
    """Raised when a container config permits capability-based escape."""


@dataclass
class CapabilityFinding:
    service: str
    location: str
    capability: str
    reason: str
    severity: str = "critical"


def normalize_cap(cap: str) -> str:
    """Normalise a capability token: strip CAP_ prefix, upper-case, trim."""
    if not isinstance(cap, str):
        return ""
    cap = cap.strip().upper()
    if cap.startswith("CAP_"):
        cap = cap[len("CAP_"):]
    return cap


def _as_list(value: Any) -> list:
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        return list(value)
    return [value]


def _security_opt_tokens(service: Mapping[str, Any]) -> list[str]:
    opts = _as_list(service.get("security_opt"))
    # docker-compose allows "seccomp=unconfined" or {"seccomp": "unconfined"}
    tokens: list[str] = []
    for opt in opts:
        if isinstance(opt, Mapping):
            for k, v in opt.items():
                tokens.append(f"{k}={v}")
        else:
            tokens.append(str(opt))
    return tokens


def find_capability_escape_risks(compose: Mapping[str, Any]) -> list[CapabilityFinding]:
    """Return findings for every escape-enabling setting in a compose config.

    Accepts a full compose mapping (``{"services": {...}}``) or a single service
    mapping.
    """
    services = compose.get("services")
    if not isinstance(services, Mapping):
        services = {"<service>": compose}

    findings: list[CapabilityFinding] = []
    for name, service in services.items():
        if not isinstance(service, Mapping):
            continue
        findings.extend(_check_service(str(name), service))
    return findings


def _check_service(name: str, service: Mapping[str, Any]) -> list[CapabilityFinding]:
    findings: list[CapabilityFinding] = []

    # privileged grants all capabilities + device access.
    if bool(service.get("privileged")):
        findings.append(
            CapabilityFinding(
                service=name,
                location="privileged",
                capability="ALL (privileged)",
                reason="privileged grants all capabilities and host device access",
            )
        )

    # cap_add
    seen_all = False
    for cap in _as_list(service.get("cap_add")):
        norm = normalize_cap(cap)
        if norm == "ALL":
            seen_all = True
            findings.append(
                CapabilityFinding(
                    service=name,
                    location="cap_add",
                    capability="ALL",
                    reason="adds every capability, including all escape primitives",
                )
            )
        elif norm in ESCAPE_CAPABILITIES:
            findings.append(
                CapabilityFinding(
                    service=name,
                    location="cap_add",
                    capability=norm,
                    reason=ESCAPE_CAPABILITIES[norm],
                )
            )

    # security_opt: unconfined profiles remove syscall/MAC backstops.
    tokens = _security_opt_tokens(service)
    normalized_tokens = [t.replace(" ", "").lower() for t in tokens]
    for profile in _UNCONFINED_PROFILES:
        if profile in normalized_tokens:
            findings.append(
                CapabilityFinding(
                    service=name,
                    location="security_opt",
                    capability=profile,
                    reason="unconfined profile removes the syscall/MAC backstop",
                    severity="high",
                )
            )

    # no-new-privileges missing while the service is otherwise risky.
    has_nnp = any("no-new-privileges" in t for t in normalized_tokens)
    risky = bool(findings) or seen_all
    if risky and not has_nnp:
        findings.append(
            CapabilityFinding(
                service=name,
                location="security_opt",
                capability="no-new-privileges:absent",
                reason="add 'no-new-privileges:true' to block setuid privilege escalation",
                severity="medium",
            )
        )

    return findings


def assert_safe_capabilities(compose: Mapping[str, Any]) -> None:
    """Raise ``CapabilityEscapeError`` if any escape-enabling setting is present."""
    findings = find_capability_escape_risks(compose)
    if findings:
        summary = "; ".join(
            f"{f.service}.{f.location}: {f.capability} ({f.reason})" for f in findings
        )
        raise CapabilityEscapeError(f"container capability escape risk: {summary}")


def harden_service(service: Mapping[str, Any], *, cap_add: Iterable[str] = SAFE_DEFAULT_CAP_ADD) -> dict:
    """Return a least-privilege copy of ``service`` safe from capability escape.

    Drops all capabilities, disables privileged mode, enables
    ``no-new-privileges``, pins the default seccomp profile, and re-adds only the
    explicitly requested (non-escape) capabilities.
    """
    hardened = dict(service)
    hardened.pop("privileged", None)
    hardened["privileged"] = False
    hardened["cap_drop"] = ["ALL"]

    safe_caps = [normalize_cap(c) for c in cap_add]
    bad = [c for c in safe_caps if c == "ALL" or c in ESCAPE_CAPABILITIES]
    if bad:
        raise ValueError(f"refusing to re-add escape-capable capabilities: {bad}")
    if safe_caps:
        hardened["cap_add"] = safe_caps
    else:
        hardened.pop("cap_add", None)

    # Rebuild security_opt without unconfined profiles, ensure no-new-privileges.
    tokens = [t for t in _security_opt_tokens(service)
              if t.replace(" ", "").lower() not in _UNCONFINED_PROFILES]
    if not any("no-new-privileges" in t.lower() for t in tokens):
        tokens.append("no-new-privileges:true")
    if not any(t.lower().startswith("seccomp=") for t in tokens):
        tokens.append("seccomp=default")
    hardened["security_opt"] = tokens
    return hardened


__all__ = [
    "ESCAPE_CAPABILITIES",
    "CapabilityEscapeError",
    "CapabilityFinding",
    "normalize_cap",
    "find_capability_escape_risks",
    "assert_safe_capabilities",
    "harden_service",
]
