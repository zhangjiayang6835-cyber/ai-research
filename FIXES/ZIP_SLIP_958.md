# Fix: Zip Slip → Arbitrary File Write via Archive Extraction

## Vulnerability
ZIP file extraction does not validate whether filenames contain ../. Attackers construct ZIP files with entries like ../../etc/cron.d/malicious, overwriting system files.

## Fix Implementation
1. Normalize output paths and validate containment
2. Use canonical path checking
3. Reject entries containing .. traversal

## References
- CWE-22: Path Traversal
- CWE-23: Relative Path Traversal
