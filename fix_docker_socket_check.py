#!/usr/bin/env python3
"""
Security fix: Prevent Docker container escape via mounted Docker socket.
This script should be set as the container entrypoint or run early in startup.
It checks if /var/run/docker.sock is mounted inside the container and exits
with an error if found, preventing any further container processes from
accessing the socket.
"""
import os
import sys

def check_docker_socket():
    """Check for the presence of the Docker socket and raise an error if found."""
    socket_path = '/var/run/docker.sock'
    if os.path.exists(socket_path):
        print(f"ERROR: Docker socket ({socket_path}) is mounted inside the container. "
              "This is a security risk that allows container escape. "
              "Remove the bind mount from the container configuration.",
              file=sys.stderr)
        sys.exit(1)
    else:
        print("INFO: Docker socket not found. Security check passed.")

def main():
    check_docker_socket()
    # If the check passes, execute the original command (if any)
    if len(sys.argv) > 1:
        os.execvp(sys.argv[1], sys.argv[1:])
    else:
        # If no command provided, just run interactive shell or exit
        # In production, the entrypoint would pass through
        pass

if __name__ == '__main__':
    main()
