import json
import os
import sys
import re


def check_dependency_confusion():
    d = json.loads(r.read())
print("Title:", d["title"])
print("Body:")
    - package.json for npm packages
    - requirements.txt for pip packages
    - setup.py for Python packages
    - pyproject.toml for modern Python packages
    
    Returns True if vulnerability exists, False if fixed.
    """
    issues_found = []
    
    # Check for package.json files
    package_json_files = []
    for root, dirs, files in os.walk('.'):
        # Skip node_modules and other common dependency directories
        dirs[:] = [d for d in dirs if d not in ['node_modules', '.git', '__pycache__', 'venv', '.venv']]
            if file == 'package.json':
                file_path = os.path.join(root, file)
                try:
                    package_json_files.append(file_path)
                    with open(file_path, 'r', encoding='utf-8') as f:
                        content = json.load(f)
                    
                    dependencies = {}
                    dependencies.update(content.get('dependencies', {}))
                    dependencies.update(content.get('devDependencies', {}))
                    dependencies.update(content.get('peerDependencies', {}))
                    dependencies.update(content.get('optionalDependencies', {}))
                    
                    # Check for version pinning (no ^, ~, *, or >/< ranges)
                    unpinned_deps = []
                    
                    for dep_name, version in dependencies.items():
                        # Check if version uses exact pinning
                            issues_found.append(f"Unpinned dependency in {file_path}: {dep_name}@{version}")
                            vulnerability_exists = True
                        else:
                            # Track unpinned dependencies for reporting
                            if version.startswith(('^', '~', '>', '<', '*')) or version == 'latest':
                                unpinned_deps.append(f"{dep_name}@{version}")
                            
                            # Check for internal package names that might exist on public registry
                            internal_patterns = ['@internal', '@company', '@org', 'internal-', 'company-']
                            for pattern in internal_patterns:
                                    if not version.startswith(('http:', 'https:', 'file:', 'git:', 'workspace:')):
                                        issues_found.append(f"Potential dependency confusion in {file_path}: {dep_name}@{version} (internal pattern without private registry)")
                                        vulnerability_exists = True
                    
                    # Check for registry configuration
                    has_registry_config = False
                
                except (json.JSONDecodeError, IOError) as e:
                    print(f"Error reading {file_path}: {e}")
    # Check for requirements.txt files
    for root, dirs, files in os.walk('.'):
        dirs[:] = [d for d in dirs if d not in ['node_modules', '.git', '__pycache__', 'venv', '.venv']]
        # Check for requirements files with various naming patterns
        for file in files:
            if file == 'requirements.txt' or file.endswith('-requirements.txt') or file.startswith('requirements'):
                file_path = os.path.join(root, file)
                        for line in f:
                            line = line.strip()
                            if line and not line.startswith('#'):
                                # Check for unpinned packages (no == version specifier)
                                if '==' not in line and not line.startswith('-e ') and not line.startswith('git+'):
                                    # Extract package name
                                    pkg_name = line.split('[')[0].split('<')[0].split('>')[0].split('~')[0].split('=')[0].strip()
                                        issues_found.append(f"Unpinned dependency in {file_path}: {line}")
                                        vulnerability_exists = True
                                else:
                                    # Even pinned packages can be confused if internal names are used on public index
                                    internal_patterns = ['internal-', 'company-', 'org-']
                                    for pattern in internal_patterns:
                                        if pattern in line.lower():
                                            if not line.startswith('-e '):
                                                issues_found.append(f"Potential dependency confusion in {file_path}: {line}")
                                                vulnerability_exists = True
                                                break
                
                except IOError as e:
                    print(f"Error reading {file_path}: {e}")
    for root, dirs, files in os.walk('.'):
        dirs[:] = [d for d in dirs if d not in ['node_modules', '.git', '__pycache__', 'venv', '.venv']]
        for file in files:
            # Check setup.py for install_requires
            if file == 'setup.py':
                file_path = os.path.join(root, file)
                try:
                        # Very basic check - in real scenario would need AST parsing
                        if 'install_requires' in content:
                            # Check for unpinned dependencies
                            # Extract install_requires list
                            import ast
                            try:
                                tree = ast.parse(content)
                                            for elt in node.value.elts:
                                                if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
                                                    dep = elt.value
                                                    # Check if dependency is pinned with == 
                                                    if '==' not in dep and not dep.startswith('-e '):
                                                        issues_found.append(f"Unpinned dependency in {file_path}: {dep}")
                                                        vulnerability_exists = True
                                pass
                
                except IOError as e:
                    # Handle file read errors
                    print(f"Error reading {file_path}: {e}")
    
    # Print results
        print("\nIssues found:")
        for issue in issues_found:
            print(f"  - {issue}")
        print("\nTo fix dependency confusion vulnerabilities:")
        print("\nTo fix dependency confusion:")
        print("1. Pin all dependencies to exact versions (e.g., package==1.2.3)")
        print("2. Use private registries or scoped packages for internal packages")
    return vulnerability_exists


# Main entry point
if __name__ == '__main__':
    exists = check_dependency_confusion()
    if exists:
