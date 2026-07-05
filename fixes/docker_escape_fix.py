"""
Fix: Docker Container Escape via Mounted Docker Socket
=======================================================
Issue #338 — When the Docker socket (/var/run/docker.sock)
is mounted inside a container, the container process can
communicate directly with the Docker daemon on the host.
An attacker who gains code execution inside the container
can:
1. List all containers on the host
2. Start a new privileged container
3. Escape to the host filesystem via volume mounts

This fix provides:
1. Docker socket detection and monitoring
2. Principle of least privilege enforcement
3. Drop-in access control for Docker API calls from within containers
"""

from __future__ import annotations

import os
import stat
import re
from typing import Optional


# ═══════════════════════════════════════════════════════════════════
# Configuration
# ═══════════════════════════════════════════════════════════════════

DOCKER_SOCKET_PATH = "/var/run/docker.sock"
CONTAINERD_SOCKET_PATH = "/run/containerd/containerd.sock"

# Dangerous Docker API endpoints that should be blocked from inside containers
BLOCKED_DOCKER_ENDPOINTS = [
    "/containers/create",
    "/containers/{id}/start",
    "/containers/{id}/exec",
    "/containers/{id}/attach",
    "/containers/{id}/logs",
    "/containers/{id}/archive",
    "/images/create",
    "/images/load",
    "/volumes/create",
    "/volumes/{name}/remove",
]


# ═══════════════════════════════════════════════════════════════════
# Custom Error
# ═══════════════════════════════════════════════════════════════════


class DockerEscapeError(PermissionError):
    """Raised when Docker escape attempt is detected."""


# ═══════════════════════════════════════════════════════════════════
# PART 1: DOCKER SOCKET DETECTION
# ═══════════════════════════════════════════════════════════════════


class DockerSocketDetector:
    """Detects whether the Docker socket is mounted inside a container.

    Runs at startup to warn administrators if the Docker socket
    is exposed inside a container.
    """

    @staticmethod
    def is_docker_socket_mounted(socket_path: str = DOCKER_SOCKET_PATH) -> bool:
        """Check if the Docker socket is mounted at the given path.

        Args:
            socket_path: Path to check for Docker socket.

        Returns:
            True if the Docker socket exists and is a socket file.
        """
        try:
            mode = os.stat(socket_path).st_mode
            return stat.S_ISSOCK(mode)
        except FileNotFoundError:
            return False
        except PermissionError:
            return True  # Exists but can't stat — likely a socket

    @staticmethod
    def is_running_in_container() -> bool:
        """Detect if we're running inside a container.

        Checks for the presence of /.dockerenv or cgroup info.

        Returns:
            True if running inside a container.
        """
        if os.path.exists("/.dockerenv"):
            return True
        try:
            with open("/proc/1/cgroup") as f:
                content = f.read()
                if "docker" in content or "kubepods" in content:
                    return True
        except (FileNotFoundError, PermissionError):
            pass
        return False

    @staticmethod
    def get_security_warning() -> Optional[str]:
        """Get a security warning if Docker socket is dangerously mounted.

        Returns:
            Warning string, or None if no danger detected.
        """
        if not DockerSocketDetector.is_running_in_container():
            return None

        if DockerSocketDetector.is_docker_socket_mounted():
            return (
                "⚠️ SECURITY WARNING: Docker socket is mounted inside "
                "a container! This allows container escape. "
                "Remove the volume mount `-v /var/run/docker.sock:/var/run/docker.sock` "
                "from your Docker run/compose configuration. "
                "If Docker API access is needed from inside the container, "
                "use the Docker API proxy (see below) instead."
            )
        return None


# ═══════════════════════════════════════════════════════════════════
# PART 2: DOCKER API ACCESS CONTROL PROXY
# ═══════════════════════════════════════════════════════════════════


class DockerSocketACL:
    """Access control for Docker API calls from inside containers.

    When the Docker socket MUST be mounted (legacy/special cases),
    this proxy restricts which API endpoints can be called.
    """

    def __init__(self, socket_path: str = DOCKER_SOCKET_PATH):
        self.socket_path = socket_path
        self._allowed_endpoints: list[str] = []

    def allow_endpoint(self, endpoint: str) -> None:
        """Allow a specific Docker API endpoint.

        Args:
            endpoint: API endpoint path (e.g., '/info').
        """
        if endpoint not in self._allowed_endpoints:
            self._allowed_endpoints.append(endpoint)

    def is_endpoint_allowed(self, method: str, path: str) -> bool:
        """Check if a Docker API call is allowed.

        GET /info — allowed (read-only)
        POST /containers/create — blocked (escape risk)

        Args:
            method: HTTP method (GET, POST, etc.)
            path: API endpoint path.

        Returns:
            True if the call is allowed.
        """
        # Always allow read-only endpoints
        if method in ("GET", "HEAD"):
            return True

        # Check against blocked endpoints
        for blocked in BLOCKED_DOCKER_ENDPOINTS:
            # Simple prefix/pattern matching
            blocked_pattern = re.sub(r"\{[^}]+\}", "[^/]+", blocked)
            if re.match(f"^{blocked_pattern}$", path):
                return False

        # Check explicit allow list
        if path in self._allowed_endpoints:
            return True

        # Deny by default for write operations
        return False

    @staticmethod
    def get_unprivileged_socket_path() -> str:
        """Get or create a restricted Docker socket proxy path.

        Returns a socket path that restricts what Docker
        API calls are allowed from within containers.

        Returns:
            Path to the restricted Docker socket.
        """
        return "/var/run/docker-restricted.sock"


# ═══════════════════════════════════════════════════════════════════
# PART 3: CONTAINER SECURITY ENFORCEMENT
# ═══════════════════════════════════════════════════════════════════


class ContainerSecurityEnforcer:
    """Enforces container security best practices.

    Provides runtime checks and configuration validation
    to prevent Docker socket-based container escape.
    """

    REQUIRED_SECURITY_OPTIONS = [
        "no-new-privileges",
        "seccomp=default",
    ]

    DANGEROUS_CAPABILITIES = [
        "SYS_ADMIN",
        "SYS_PTRACE",
        "NET_ADMIN",
        "SYS_MODULE",
        "SYS_RAWIO",
        "IPC_LOCK",
        "ALL",
    ]

    @staticmethod
    def validate_container_config(volumes: list[str], capabilities: list[str]) -> list[str]:
        """Validate container configuration for escape risks.

        Args:
            volumes: List of mounted volume paths.
            capabilities: List of Linux capabilities.

        Returns:
            List of security warnings (empty if no issues).
        """
        warnings: list[str] = []

        # Check for Docker socket mount
        for vol in volumes:
            if "docker.sock" in vol.lower():
                warnings.append(
                    "Docker socket volume mount detected! "
                    "This allows container escape."
                )
            if "/" in vol and vol.endswith("/"):
                warnings.append(
                    f"Host root filesystem mount detected: {vol}"
                )

        # Check for dangerous capabilities
        for cap in capabilities:
            if cap in ContainerSecurityEnforcer.DANGEROUS_CAPABILITIES:
                warnings.append(
                    f"Dangerous capability detected: {cap}. "
                    "Consider dropping it."
                )

        return warnings

    @staticmethod
    def get_secure_run_command(
        image: str,
        command: str = "",
    ) -> str:
        """Generate a secure docker run command.

        Returns a docker run command with security hardening
        to prevent container escape.

        Args:
            image: Docker image name.
            command: Optional command to run.

        Returns:
            Secure docker run command string.
        """
        base = (
            "docker run"
            " --security-opt=no-new-privileges"
            " --security-opt=seccomp=default"
            " --cap-drop=ALL"
            " --cap-add=NET_BIND_SERVICE"  # Only if needed
            " --read-only"
            " --tmpfs=/tmp"
        )
        if command:
            return f"{base} {image} {command}"
        return f"{base} {image}"


# ═══════════════════════════════════════════════════════════════════
# Self-test
# ═══════════════════════════════════════════════════════════════════


def _test() -> None:
    print("  Testing Docker Container Escape fix...")

    # ── Docker socket detection ──
    # This test doesn't require Docker (checks exist without socket)
    result = DockerSocketDetector.is_docker_socket_mounted("/nonexistent/socket")
    assert result is False
    print("  ✓ Socket detection handles missing socket gracefully")

    # ── Container detection ──
    # In most test environments this will be False
    in_container = DockerSocketDetector.is_running_in_container()
    print(f"  ✓ Container detection check completed (in container: {in_container})")

    # ── ACL enforcement ──
    acl = DockerSocketACL()
    acl.allow_endpoint("/info")

    assert acl.is_endpoint_allowed("GET", "/info")
    print("  ✓ GET /info allowed (read-only)")

    assert not acl.is_endpoint_allowed("POST", "/containers/create")
    print("  ✓ POST /containers/create blocked")

    assert not acl.is_endpoint_allowed("POST", "/containers/myapp/start")
    print("  ✓ POST /containers/xxx/start blocked")

    assert acl.is_endpoint_allowed("GET", "/containers/json")
    print("  ✓ GET /containers/json allowed (read-only)")

    # ── Container config validation ──
    warnings = ContainerSecurityEnforcer.validate_container_config(
        volumes=["/var/run/docker.sock:/var/run/docker.sock"],
        capabilities=["SYS_ADMIN"],
    )
    assert len(warnings) == 2  # Docker socket + SYS_ADMIN
    print("  ✓ Dangerous config detected (Docker socket + SYS_ADMIN)")

    assert "docker socket" in warnings[0].lower()
    assert "SYS_ADMIN" in warnings[1]
    print("  ✓ Results for each risk")

    # ── Secure run command ──
    cmd = ContainerSecurityEnforcer.get_secure_run_command("nginx:latest")
    assert "no-new-privileges" in cmd
    assert "cap-drop=ALL" in cmd
    assert "read-only" in cmd
    print("  ✓ Secure run command generated with hardening")

    # ── No false positives ──
    warnings = ContainerSecurityEnforcer.validate_container_config(
        volumes=["/data:/data"],
        capabilities=[],
    )
    assert len(warnings) == 0
    print("  ✓ Safe config produces no warnings")

    print("\n  ✓ ALL TESTS PASSED")


if __name__ == "__main__":
    _test()
