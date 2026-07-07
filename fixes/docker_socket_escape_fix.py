#!/usr/bin/env python3
"""
Fix: Docker Container Escape via Mounted Docker Socket

Detects if the Docker socket is mounted inside the container and
exits to prevent exploitation. This should be called at application
startup to enforce the security policy.
"""

import os
import sys

DOCKER_SOCKET_PATH = "/var/run/docker.sock"

def prevent_docker_socket_mount():
    """Exit if the Docker socket is mounted inside the container."""
    if os.path.exists(DOCKER_SOCKET_PATH):
        print("SECURITY ALERT: Docker socket is mounted. Container escape risk detected. Exiting.")
        sys.exit(1)

