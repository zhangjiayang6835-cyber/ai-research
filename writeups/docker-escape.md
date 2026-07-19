# Docker Container Escape via Capability Abuse

## Description
Container runs with excessive capabilities (CAP_SYS_ADMIN). Attacker escapes via cgroup release_agent by mounting cgroup filesystem, creating a cgroup with notify_on_release, and writing a command to release_agent that executes on the host.

## Impact
Full host compromise, lateral movement across all containers on the host.

## Remediation
Drop all capabilities with --cap-drop=ALL, add only required ones explicitly, use seccomp profiles, run as non-root user, use read-only filesystem.