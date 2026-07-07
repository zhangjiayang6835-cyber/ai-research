#!/usr/bin/env python3
"""
Fix: Disable TCP Timestamps to prevent Cloud Provider Identification via side-channel.
This mitigates the TCP timestamp side channel that can be used to identify
the cloud provider based on timestamp granularity differences.
"""

import subprocess
import sys


def apply_fix():
    """Disable TCP timestamps via sysctl, both at runtime and persistently."""
    try:
        # Check current value
        result = subprocess.run(
            ["sysctl", "-n", "net.ipv4.tcp_timestamps"],
            capture_output=True, text=True, check=True
        )
        current = result.stdout.strip()
        if current == "0":
            print("TCP timestamps already disabled.")
            return True

        # Apply runtime change
        subprocess.run(
            ["sysctl", "-w", "net.ipv4.tcp_timestamps=0"],
            check=True
        )
        print("TCP timestamps disabled at runtime.")

        # Persist across reboots by adding to sysctl.conf
        with open("/etc/sysctl.conf", "a") as f:
            f.write("\n# Disable TCP timestamps for security\nnet.ipv4.tcp_timestamps = 0\n")
        print("TCP timestamps disabled persistently.")
        return True
    except subprocess.CalledProcessError as e:
        print(f"Error executing sysctl: {e}", file=sys.stderr)
        return False
    except PermissionError:
        print("Permission denied: this script must be run as root.", file=sys.stderr)
        return False

if __name__ == "__main__":
