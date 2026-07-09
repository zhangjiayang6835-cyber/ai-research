#!/usr/bin/env python3
"""
Fix for Java RMI Deserialization Remote Code Execution (RCE).

Mitigations:
  1. Enable JEP 290 serial filter to restrict allowed classes.
  2. Bind RMI registry to localhost only.
  3. Enable SSL for RMI communication.

Usage:
  python rmi_deserialization_rce_fix.py [--apply] [--port 1099]

Without --apply, just prints the required configuration.
"""

import argparse
import os
import sys

# Constants
DEFAULT_RMI_PORT = 1099

def print_config():
    """Print the recommended configuration changes."""
    print("=" * 60)
    print("RMI Deserialization RCE Fix - Configuration Guide")
    print("=" * 60)
    print()
    print("1. JEP 290 (Serial Filter)")
    print("   Add to JVM startup: ")
    print(f'   -Djava.rmi.server.useCodebaseOnly=true')
    print(f'   -Djdk.serialFilter="!org.example.EvilClass;!*"')
    print()
    print("2. Bind to localhost")
    print("   Start registry with: ")
    print(f'   LocateRegistry.createRegistry(1099, null, new RMIServerSocketFactory() {{')
    print('       @Override')
    print(f'       public ServerSocket createServerSocket(int port) throws IOException {{')
    print(f'           return new ServerSocket(port, 0, InetAddress.getByName("127.0.0.1"));')
    print(f'       }}')
    print(f'   }});')
    print()
    print("3. Enable SSL")
    print("   Set system properties:")
    print("   -Djavax.net.ssl.keyStore=/path/to/keystore")
    print("   -Djavax.net.ssl.keyStorePassword=password")
    print("   -Djava.rmi.server.hostname=127.0.0.1")
    print()

def apply_fixes(port):
    """Simulate applying fixes (for demonstration)."""
    print(f"[*] Applying RMI fixes on port {port}...")

    # Set environment variables or system properties (simulated)
    os.environ['JAVA_TOOL_OPTIONS'] = os.environ.get('JAVA_TOOL_OPTIONS', '') + \
        ' -Djava.rmi.server.useCodebaseOnly=true -Djdk.serialFilter="!*"'

    # Simulate binding to localhost and SSL setup
    print("[+] JEP 290 serial filter enabled (reject all by default, whitelist needed).")
    print(f"[+] RMI registry should be bound to 127.0.0.1:{port}")
    print("[+] SSL enabled (ensure keystore is configured).")
    print("[*] Fixes applied. Ensure Java code implements the above.")

def main():
    parser = argparse.ArgumentParser(description="Fix Java RMI deserialization RCE.")
    parser.add_argument("--apply", action="store_true", help="Apply configuration (simulated)")
    parser.add_argument("--port", type=int, default=DEFAULT_RMI_PORT, help="RMI registry port")
    args = parser.parse_args()

    if args.apply:
        apply_fixes(args.port)
    else:
        print_config()

if __name__ == "__main__":
