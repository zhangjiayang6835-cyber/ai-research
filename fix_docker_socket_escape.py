#!/usr/bin/env python3
"""
Docker Socket Escape Prevention Utility
- Checks for the presence of /var/run/docker.sock in the container.
- If found, prints a security warning and exits to prevent potential escape.
"""

import os
import sys

DOCKER_SOCK = "/var/run/docker.sock"

def is_docker_socket_mounted():
    """Returns True if the Docker socket is present."""
    return os.path.exists(DOCKER_SOCK)

def main():
    if is_docker_socket_mounted():
        print("ERROR: Docker socket is mounted. This is a security risk.")
        print("Container escape via Docker socket is possible.")
        print("Please remove the Docker socket mount from your container configuration.")
        print("Exiting to prevent potential abuse.")
        sys.exit(1)
    else:
        print("OK: No Docker socket detected. Safe to proceed.")

if __name__ == "__main__":
    main()
