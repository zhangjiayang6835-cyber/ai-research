#!/usr/bin/env python3
"""
Check for dependency confusion vulnerabilities.

Usage:
    python dependency_confusion_check.py --internal-list internal_packages.txt requirements.txt
    python dependency_confusion_check.py --internal-list internal_packages.txt package.json

This script verifies that internal packages (listed in --internal-list) are not
available on public registries with a higher version than specified, which could
indicate a dependency confusion attack.
"""

import argparse
import json
import re
import sys
import urllib.request
import urllib.error

PYPI_API = "https://pypi.org/pypi/{}/json"
NPM_API = "https://registry.npmjs.org/{}"

def get_latest_version_pypi(package):
    """Return the latest version from PyPI, or None if not found."""
    url = PYPI_API.format(package)
    try:
        with urllib.request.urlopen(url, timeout=10) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        return data["info"]["version"]
    except (urllib.error.HTTPError, urllib.error.URLError):
        return None

def get_latest_version_npm(package):
    """Return the latest version from npm, or None if not found."""
    url = NPM_API.format(package)
    try:
        with urllib.request.urlopen(url, timeout=10) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        return data.get("dist-tags", {}).get("latest")
    except (urllib.error.HTTPError, urllib.error.URLError):
        return None

def parse_requirements(filepath):
    """Parse a requirements.txt file and return dict {package: version}."""
    deps = {}
    with open(filepath, "r") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("--"):
                continue
            # Handle options like -e, -r, etc. Skip for simplicity
            if line.startswith("-e") or line.startswith("-r"):
                continue
            # Remove inline comments
            if "#" in line:
                line = line[:line.index("#")].strip()
            match = re.match(r"^([a-zA-Z0-9_\-.]+)\s*(==|>=|<=|!=|~=)?\s*([\w.*]+)?", line)
            if match:
                name = match.group(1).lower()
                # Handle extras like package[extra]
                if "[" in name:
                    name = name[:name.index("[")]
                version = match.group(3)
                deps[name] = version
    return deps

def parse_package_json(filepath):
    """Parse a package.json file and return dict {package: version}."""
    with open(filepath, "r") as f:
        data = json.load(f)
    deps = {}
    for section in ("dependencies", "devDependencies"):
        if section in data:
            for name, ver in data[section].items():
                deps[name.lower()] = ver
    return deps

def compare_versions(required, latest_str):
    """Return True if required version is less than latest_str, else False."""
    from distutils.version import LooseVersion
    try:
        req_ver = LooseVersion(required)
        latest_ver = LooseVersion(latest_str)
        return req_ver < latest_ver
    except:
        return False

def main():
    parser = argparse.ArgumentParser(
        description="Check for dependency confusion vulnerabilities"
    )
    parser.add_argument(
        "--internal-list",
        required=True,
        help="Path to a file listing internal package names (one per line)"
    )
    parser.add_argument(
        "manifest",
        help="Path to requirements.txt or package.json"
    )
    args = parser.parse_args()

    # Read internal package list
    with open(args.internal_list, "r") as f:
        internal_packages = [line.strip().lower() for line in f if line.strip()]

    # Parse manifest
    if args.manifest.endswith(".txt"):
        deps = parse_requirements(args.manifest)
    elif args.manifest.endswith(".json"):
        deps = parse_package_json(args.manifest)
    else:
        print("Unsupported manifest file. Use requirements.txt or package.json.")
        sys.exit(1)

    issues = []
    for pkg_name, req_ver in deps.items():
        if pkg_name not in internal_packages:
            continue
        # Determine registry type based on manifest
        if args.manifest.endswith(".txt"):
            latest = get_latest_version_pypi(pkg_name)
            reg_type = "PyPI"
        else:
            latest = get_latest_version_npm(pkg_name)
            reg_type = "npm"
        if latest is None:
            continue  # package not on public registry, safe
        if not req_ver:
            # No version pinned; just presence is a risk
            issues.append(
                f"{pkg_name} is an internal package but exists on {reg_type} "
                f"(latest {latest}). Consider pinning a version and using private registry."
            )
        elif compare_versions(req_ver, latest):
            issues.append(
                f"{pkg_name} is an internal package with required version {req_ver}, "
                f"but {reg_type} has version {latest} (higher). Possible dependency confusion."
            )

    if issues:
        print("Dependency confusion vulnerabilities detected:")
        for issue in issues:
            print(f"  - {issue}")
        sys.exit(1)
    else:
        print("No dependency confusion issues found.")

if __name__ == "__main__":
    main()
