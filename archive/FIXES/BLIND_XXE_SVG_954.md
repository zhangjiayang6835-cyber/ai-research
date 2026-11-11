# Fix: Blind XXE via SVG Upload → SSRF + Data Exfil

## Vulnerability
SVG file upload functionality does not disable external entity resolution. Attackers can craft SVGs containing external entities to exfiltrate server files via OOB (Out-of-Band) techniques.

## Fix Implementation
1. Disable DOCTYPE declarations
2. Disable external entity resolution
3. Whitelist SVG tags and attributes

## References
- CWE-611: Improper Restriction of XML External Entity Reference
