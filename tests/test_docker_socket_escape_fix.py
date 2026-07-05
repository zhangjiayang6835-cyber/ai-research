"""Tests for issue #338 Docker socket escape hardening."""

from __future__ import annotations

import unittest

from fixes.docker_socket_escape_fix import (
    DockerSocketSecurityError,
    assert_no_unsafe_docker_socket_exposure,
    find_unsafe_docker_socket_exposures,
    is_docker_socket_path,
    safe_socket_proxy_service,
)


class DockerSocketEscapeFixTests(unittest.TestCase):
    def test_detects_common_docker_socket_paths(self) -> None:
        self.assertTrue(is_docker_socket_path("/var/run/docker.sock"))
        self.assertTrue(is_docker_socket_path("unix:///var/run/docker.sock"))
        self.assertTrue(is_docker_socket_path(r"\\.\pipe\docker_engine"))
        self.assertFalse(is_docker_socket_path("tcp://docker-socket-proxy:2375"))

    def test_rejects_raw_string_socket_mount(self) -> None:
        compose = {
            "services": {
                "worker": {
                    "image": "example/worker",
                    "volumes": ["/var/run/docker.sock:/var/run/docker.sock"],
                }
            }
        }

        with self.assertRaises(DockerSocketSecurityError):
            assert_no_unsafe_docker_socket_exposure(compose)

    def test_rejects_read_only_direct_mount_for_app_service(self) -> None:
        compose = {
            "services": {
                "worker": {
                    "image": "example/worker",
                    "volumes": ["/var/run/docker.sock:/var/run/docker.sock:ro"],
                }
            }
        }

        findings = find_unsafe_docker_socket_exposures(compose)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].service, "worker")
        self.assertIn("read-only", findings[0].reason)

    def test_rejects_structured_socket_mount(self) -> None:
        compose = {
            "services": {
                "api": {
                    "image": "example/api",
                    "volumes": [
                        {
                            "type": "bind",
                            "source": "/var/run/docker.sock",
                            "target": "/var/run/docker.sock",
                            "read_only": True,
                        }
                    ],
                }
            }
        }

        with self.assertRaises(DockerSocketSecurityError):
            assert_no_unsafe_docker_socket_exposure(compose)

    def test_rejects_unix_docker_host_environment(self) -> None:
        compose = {
            "services": {
                "api": {
                    "image": "example/api",
                    "environment": ["DOCKER_HOST=unix:///var/run/docker.sock"],
                }
            }
        }

        findings = find_unsafe_docker_socket_exposures(compose)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].location, "environment.DOCKER_HOST")

    def test_allows_app_to_use_locked_down_socket_proxy(self) -> None:
        compose = {
            "services": {
                "api": {
                    "image": "example/api",
                    "environment": {"DOCKER_HOST": "tcp://docker-socket-proxy:2375"},
                },
                "docker-socket-proxy": safe_socket_proxy_service(),
            }
        }

        assert_no_unsafe_docker_socket_exposure(compose)

    def test_rejects_socket_proxy_with_write_api_enabled(self) -> None:
        proxy = safe_socket_proxy_service()
        proxy["environment"]["POST"] = "1"
        compose = {"services": {"docker-socket-proxy": proxy}}

        with self.assertRaises(DockerSocketSecurityError):
            assert_no_unsafe_docker_socket_exposure(compose)

    def test_rejects_socket_proxy_without_read_only_mount(self) -> None:
        proxy = safe_socket_proxy_service()
        proxy["volumes"][0]["read_only"] = False
        compose = {"services": {"docker-socket-proxy": proxy}}

        with self.assertRaises(DockerSocketSecurityError):
            assert_no_unsafe_docker_socket_exposure(compose)


if __name__ == "__main__":
    unittest.main()
