"""Defense-in-depth fix for issue #338: mounted Docker socket escape.

Mounting ``/var/run/docker.sock`` into an application container gives that
container effective root control over the Docker host. This module provides a
small, framework-neutral compose validator that rejects direct socket exposure
and only permits a deliberately locked-down socket proxy service.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable, Mapping


DOCKER_SOCKET_UNIX = "/var/run/docker.sock"
DOCKER_SOCKET_WINDOWS = "//./pipe/docker_engine"
SAFE_SOCKET_PROXY_IMAGES = frozenset(
    {
        "tecnativa/docker-socket-proxy",
        "tecnativa/docker-socket-proxy:latest",
    }
)
WRITE_DOCKER_API_FLAGS = frozenset(
    {
        "POST",
        "BUILD",
        "COMMIT",
        "CONFIGS",
        "CONTAINERS_CREATE",
        "CONTAINERS_DELETE",
        "CONTAINERS_UPDATE",
        "EXEC",
        "IMAGES_CREATE",
        "IMAGES_DELETE",
        "NETWORKS_CREATE",
        "NETWORKS_DELETE",
        "NODES",
        "PLUGINS",
        "SECRETS",
        "SERVICES",
        "SWARM",
        "SYSTEM",
        "TASKS",
        "VOLUMES_CREATE",
        "VOLUMES_DELETE",
    }
)


class DockerSocketSecurityError(ValueError):
    """Raised when a compose service exposes the Docker daemon unsafely."""


@dataclass(frozen=True)
class SocketExposure:
    """A Docker socket exposure found in a compose service."""

    service: str
    location: str
    value: str
    reason: str


def _normalize_path(value: Any) -> str:
    text = str(value or "").strip().strip("\"'")
    text = text.replace("\\", "/")
    text = text.replace("unix://", "")
    while "//" in text and not text.startswith("//./"):
        text = text.replace("//", "/")
    return text.lower()


def is_docker_socket_path(value: Any) -> bool:
    """Return True when a path or URI points to the host Docker socket."""

    normalized = _normalize_path(value)
    return normalized in {
        DOCKER_SOCKET_UNIX,
        DOCKER_SOCKET_WINDOWS,
        "var/run/docker.sock",
    }


def _split_volume_string(volume: str) -> tuple[str, str, str]:
    parts = volume.split(":")
    if len(parts) < 2:
        return volume, "", ""
    if len(parts) == 2:
        return parts[0], parts[1], ""
    return parts[0], parts[1], ":".join(parts[2:])


def _volume_parts(volume: Any) -> tuple[str, str, bool]:
    if isinstance(volume, str):
        source, target, mode = _split_volume_string(volume)
        read_only = "ro" in {part.lower() for part in mode.split(",") if part}
        return source, target, read_only

    if isinstance(volume, Mapping):
        source = str(volume.get("source") or volume.get("src") or "")
        target = str(volume.get("target") or volume.get("dst") or volume.get("destination") or "")
        read_only = bool(volume.get("read_only") or volume.get("readonly"))
        return source, target, read_only

    return "", "", False


def _environment_map(environment: Any) -> dict[str, str]:
    if isinstance(environment, Mapping):
        return {str(key): str(value) for key, value in environment.items()}

    env: dict[str, str] = {}
    if isinstance(environment, Iterable) and not isinstance(environment, (str, bytes)):
        for item in environment:
            if isinstance(item, str) and "=" in item:
                key, value = item.split("=", 1)
                env[key] = value
    return env


def _service_mount_exposures(service_name: str, service: Mapping[str, Any]) -> list[SocketExposure]:
    exposures: list[SocketExposure] = []
    for volume in service.get("volumes") or []:
        source, target, read_only = _volume_parts(volume)
        if is_docker_socket_path(source) or is_docker_socket_path(target):
            mode = "read-only" if read_only else "read-write"
            exposures.append(
                SocketExposure(
                    service=service_name,
                    location="volumes",
                    value=str(volume),
                    reason=f"direct Docker socket mount ({mode})",
                )
            )
    return exposures


def _service_environment_exposures(service_name: str, service: Mapping[str, Any]) -> list[SocketExposure]:
    exposures: list[SocketExposure] = []
    docker_host = _environment_map(service.get("environment")).get("DOCKER_HOST", "")
    if is_docker_socket_path(docker_host):
        exposures.append(
            SocketExposure(
                service=service_name,
                location="environment.DOCKER_HOST",
                value=docker_host,
                reason="DOCKER_HOST points at the local daemon socket",
            )
        )
    return exposures


def _is_safe_socket_proxy(service: Mapping[str, Any]) -> bool:
    image = str(service.get("image") or "").split("@", 1)[0]
    if image not in SAFE_SOCKET_PROXY_IMAGES:
        return False

    socket_mounts = _service_mount_exposures("socket-proxy", service)
    if len(socket_mounts) != 1:
        return False

    source, target, read_only = _volume_parts((service.get("volumes") or [None])[0])
    if not read_only or not is_docker_socket_path(source) or not is_docker_socket_path(target):
        return False

    env = {key.upper(): value.strip() for key, value in _environment_map(service.get("environment")).items()}
    for flag in WRITE_DOCKER_API_FLAGS:
        if env.get(flag) == "1":
            return False
    return env.get("POST", "0") == "0"


def find_unsafe_docker_socket_exposures(
    compose: Mapping[str, Any],
    *,
    allowed_proxy_services: frozenset[str] = frozenset({"docker-socket-proxy"}),
) -> list[SocketExposure]:
    """Return unsafe Docker socket exposures in a docker-compose mapping."""

    services = compose.get("services") if isinstance(compose.get("services"), Mapping) else compose
    exposures: list[SocketExposure] = []

    for service_name, service in services.items():
        if not isinstance(service, Mapping):
            continue

        mount_exposures = _service_mount_exposures(str(service_name), service)
        env_exposures = _service_environment_exposures(str(service_name), service)

        if service_name in allowed_proxy_services and _is_safe_socket_proxy(service):
            exposures.extend(env_exposures)
            continue

        exposures.extend(mount_exposures)
        exposures.extend(env_exposures)

    return exposures


def assert_no_unsafe_docker_socket_exposure(
    compose: Mapping[str, Any],
    *,
    allowed_proxy_services: frozenset[str] = frozenset({"docker-socket-proxy"}),
) -> None:
    """Raise if app services can reach the host Docker socket directly."""

    exposures = find_unsafe_docker_socket_exposures(
        compose,
        allowed_proxy_services=allowed_proxy_services,
    )
    if exposures:
        details = "; ".join(
            f"{item.service} {item.location}: {item.reason}" for item in exposures
        )
        raise DockerSocketSecurityError(details)


def safe_socket_proxy_service(*, allowed_read_endpoints: Iterable[str] = ("CONTAINERS",)) -> dict[str, Any]:
    """Return a minimal read-only Docker socket proxy service definition."""

    environment = {"POST": "0"}
    for endpoint in allowed_read_endpoints:
        environment[str(endpoint).upper()] = "1"

    return {
        "image": "tecnativa/docker-socket-proxy:latest",
        "read_only": True,
        "environment": environment,
        "volumes": [
            {
                "type": "bind",
                "source": DOCKER_SOCKET_UNIX,
                "target": DOCKER_SOCKET_UNIX,
                "read_only": True,
            }
        ],
    }


__all__ = [
    "DockerSocketSecurityError",
    "SocketExposure",
    "assert_no_unsafe_docker_socket_exposure",
    "find_unsafe_docker_socket_exposures",
    "is_docker_socket_path",
    "safe_socket_proxy_service",
]
