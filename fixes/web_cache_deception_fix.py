#!/usr/bin/env python3
"""
Fix for Web Cache Deception vulnerability that can leak session tokens.
This fix ensures that dynamic responses containing session tokens are not cached
by intermediate caches (CDN, reverse proxies) by setting proper cache-control headers.

Applies to: Apache HTTP Server, Nginx, and Python WSGI applications.
"""

import os

def apply_apache_fix(conf_path="/etc/apache2/apache2.conf"):
    """Add header rules to prevent caching of pages with session tokens."""
    lines = []
    lines.append("# Begin Web Cache Deception fix")
    lines.append("Header always set Cache-Control \"no-cache, no-store, must-revalidate\"")
    lines.append("Header always set Pragma \"no-cache\"")
    lines.append("Header always set Expires \"0\"")
    lines.append("Header always set Vary \"Cookie\"")
    lines.append("# End Web Cache Deception fix")
    # Insert before </VirtualHost> or at end of global config
    try:
        with open(conf_path, 'r') as f:
            content = f.read()
    except FileNotFoundError:
        print(f"Configuration file {conf_path} not found. Skipping.")
        return False
    if "# Begin Web Cache Deception fix" in content:
        print("Fix already applied.")
        return True
    content += "\n" + "\n".join(lines)
    with open(conf_path, 'w') as f:
        f.write(content)
    print(f"Applied Apache fix to {conf_path}")
    return True

def apply_nginx_fix(conf_path="/etc/nginx/nginx.conf"):
    """Add header rules to Nginx configuration."""
    lines = []
    lines.append("# Begin Web Cache Deception fix")
    lines.append("add_header Cache-Control \"no-cache, no-store, must-revalidate\" always;")
    lines.append("add_header Pragma \"no-cache\" always;")
    lines.append("add_header Expires \"0\" always;")
    lines.append("add_header Vary \"Cookie\" always;")
    lines.append("# End Web Cache Deception fix")
    try:
        with open(conf_path, 'r') as f:
            content = f.read()
