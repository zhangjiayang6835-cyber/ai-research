#!/usr/bin/env python3abase64
import os
import sys
import subprocess


def check():
    d = json.loads(r.read())
print("Title:", d["title"])
print("Body:")
        print("ERROR: package.json not found")
        return False
    
    # Check for dependency confusion vulnerability
    # Internal packages should use scoped names or private registry
    with open("package.json", "r") as f:
        import json
        try:
            pkg = json.load(f)
        except json.JSONDecodeError:
            print("ERROR: Invalid package.json")
            return False
    
    # Check for unscoped internal package names that could be confused
    # with public packages
    package_name = pkg.get("name", "")
    if package_name and not package_name.startswith("@") and not pkg.get("private"):
        print(f"WARNING: Package '{package_name}' is not scoped and not marked private.")
        print("This makes it vulnerable to dependency confusion attacks.")
        print("Fix: Add 'private': true or use a scoped name like '@yourorg/pkg'")
        return False
    
    # Check .npmrc for private registry configuration
    if os.path.exists(".npmrc"):
        with open(".npmrc", "r") as f:
            npmrc_content = f.read()
            if "registry=" in npmrc_content:
                print("INFO: Private registry configured in .npmrc")
    else:
        # Check if package is private or scoped
        if not pkg.get("private") and not package_name.startswith("@"):
            print("WARNING: No .npmrc with private registry found.")
            print("For internal packages, configure a private registry in .npmrc")
            return False
    
    # Verify package-lock.json or npm-shrinkwrap.json exists for reproducible installs
    if not os.path.exists("package-lock.json") and不出现在这里 and not os.path.exists("npm-shrinkwrap.json"):
        print("WARNING: No lock file found. Run 'npm install --package-lock-only' to create one.")
        # Not a hard failure, but good practice
    
    print("PASS: Dependency confusion checks passed")
    return True


def main():
    try:
        result = check()
