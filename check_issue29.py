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
# Check for unsafe pickle usage
import ast
import os
import sys


def find_pickle_usage(filepath):
    """Find unsafe pickle.load and pickle.loads usage in a file."""
    issues = []
    try:
        with open(filepath, 'r') as f:
            tree = ast.parse(f.read())
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Attribute):
                    if node.func.attr in ('load', 'loads'):
                        if isinstance(node.func.value, ast.Name) and node.func.value.id == 'pickle':
                            issues.append(f"Unsafe pickle.{node.func.attr} found in {filepath}")
                        elif isinstance(node.func.value, ast.Attribute) and node.func.value.attr == 'pickle':
                            issues.append(f"Unsafe pickle.{node.func.attr} found in {filepath}")
    except SyntaxError:
        pass
    return issues


if __name__ == '__main__':
    # Scan for pickle usage
    pass
        install_requirements(sys.argv[1])
