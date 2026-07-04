#!/usr/bin/env python3
"""
Fix for Apache/NGINX misconfiguration that could lead to source code disclosure and RCE.
This script detects and disables directory listing, blocks sensitive file access,
and ensures proper file permissions on static assets.
"""

import os
import subprocess
import sys
import shutil

BLOCKED_PATTERNS = [
    '.git', '.env', '.htpasswd', 'config.php', 'config.py',
    '*.sql', 'private.key', '*.pem', '*.log', '*.crt'
]

APACHE_CONF_DIR = '/etc/apache2'
NGINX_CONF_DIR = '/etc/nginx'


def is_apache_installed():
    return shutil.which('apache2ctl') is not None or shutil.which('httpd') is not None


def is_nginx_installed():
    return shutil.which('nginx') is not None


def disable_directory_listing_apache():
    """Add Options -Indexes to Apache configuration."""
    conf_path = os.path.join(APACHE_CONF_DIR, 'conf-available', 'directory-listing.conf')
    try:
        with open(conf_path, 'w') as f:
            f.write('<Directory /var/www/html>\n')
            f.write('    Options -Indexes\n')
            f.write('</Directory>\n')
        subprocess.run(['a2enconf', 'directory-listing'], check=True, capture_output=True)
        print("[+] Apache: Directory listing disabled.")
    except Exception as e:
        print(f"[-] Apache: Failed to disable directory listing: {e}")


def block_sensitive_files_apache():
    """Add FileMatch rules to deny access to sensitive files."""
    conf_path = os.path.join(APACHE_CONF_DIR, 'conf-available', 'block-sensitive.conf')
    try:
        with open(conf_path, 'w') as f:
            f.write('<FilesMatch "\\.(git|env|htpasswd|htaccess|sql|log|pem|crt|key)$">\n')
            f.write('    Require all denied\n')
            f.write('</FilesMatch>\n')
            f.write('<FilesMatch "(config\.php|config\.py|private\.key)$">\n')
            f.write('    Require all denied\n')
            f.write('</FilesMatch>\n')
        subprocess.run(['a2enconf', 'block-sensitive'], check=True, capture_output=True)
        print("[+] Apache: Sensitive file access blocked.")
    except Exception as e:
        print(f"[-] Apache: Failed to block sensitive files: {e}")


def disable_directory_listing_nginx():
    """Add autoindex off to Nginx configuration."""
    conf_path = os.path.join(NGINX_CONF_DIR, 'conf.d', 'disable-directory-listing.conf')
    try:
        with open(conf_path, 'w') as f:
            f.write('server {\n')
            f.write('    location / {\n')
            f.write('        autoindex off;\n')
            f.write('    }\n')
            f.write('}\n')
        print("[+] Nginx: Directory listing disabled (autoindex off).")
    except Exception as e:
        print(f"[-] Nginx: Failed to disable directory listing: {e}")


def block_sensitive_files_nginx():
    """Add location rules to deny access to sensitive files."""
    conf_path = os.path.join(NGINX_CONF_DIR, 'conf.d', 'block-sensitive.conf')
    try:
        with open(conf_path, 'w') as f:
            f.write('location ~* \\.(git|env|htpasswd|htaccess|sql|log|pem|crt|key)$ {\n')
            f.write('    deny all;\n')
            f.write('}\n')
            f.write('location ~* (config\\.php|config\\.py|private\\.key)$ {\n')
            f.write('    deny all;\n')
            f.write('}\n')
        print("[+] Nginx: Sensitive file access blocked.")
    except Exception as e:
        print(f"[-] Nginx: Failed to block sensitive files: {e}")


def fix_permissions():
    """Ensure webroot files are not world-writable and are owned by www-data."""
    webroot = '/var/www/html'
    if not os.path.isdir(webroot):
        print(f"[-] Webroot {webroot} not found. Skipping permissions fix.")
        return
    try:
        subprocess.run(['find', webroot, '-type', 'f', '-exec', 'chmod', '644', '{}', '+'], check=True)
        subprocess.run(['find', webroot, '-type', 'd', '-exec', 'chmod', '755', '{}', '+'], check=True)
        # Attempt to set owner (may fail if not root)
        subprocess.run(['chown', '-R', 'www-data:www-data', webroot], capture_output=True)
        print(f"[+] Permissions fixed on {webroot}")
    except Exception as e:
        print(f"[-] Failed to fix permissions: {e}")


def main():
    print("[*] Starting Apache/NGINX misconfiguration fix...")
    if is_apache_installed():
        print("[*] Apache detected.")
        disable_directory_listing_apache()
        block_sensitive_files_apache()
    elif is_nginx_installed():
        print("[*] Nginx detected.")
        disable_directory_listing_nginx()
        block_sensitive_files_nginx()
    else:
        print("[!] Neither Apache nor Nginx is installed. Running permissions fix only.")
    fix_permissions()
    print("[*] Fix complete. Please restart your web server for changes to take effect.")


if __name__ == '__main__':
    try:
        main()
    except PermissionError:
