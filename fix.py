# Auto fix for zhangjiayang6835-cyber/ai-research#194
# 1782921258

#!/usr/bin/env python3
"""
Security fix for Dangling DNS Record → Subdomain Takeover → Cookie Stealing

This module provides functions to validate and sanitize DNS records
to prevent subdomain takeover attacks that can lead to cookie stealing.
"""

import re
import urllib.parse
from typing import List, Optional, Set


# Known vulnerable/cloud platform domains that can be hijacked
KNOWN_VULNERABLE_DOMAINS: Set[str] = {
    'github.io',
    'herokuapp.com',
    'netlify.app',
    'vercel.app',
    'firebaseapp.com',
    'azurewebsites.net',
    'cloudapp.net',
    's3.amazonaws.com',
    'elb.amazonaws.com',
    'cloudfront.net',
    'elasticbeanstalk.com',
    'surge.sh',
    'now.sh',
    'pages.dev',
    'web.app',
    'appspot.com',
    'blogspot.com',
    'tumblr.com',
    'wordpress.com',
    'wixsite.com',
    'squarespace.com',
    'shopify.com',
    'fastly.net',
    'myshopify.com',
}


def is_dangling_dns_record(cname_target: str, verified_records: List[str]) -> bool:
    """
    Check if a CNAME record is dangling (points to unverified external resource).
    
    Args:
        cname_target: The CNAME target domain
        verified_records: List of verified/owned resource identifiers
    
    Returns:
        True if the record appears to be dangling
    """
    if not cname_target or not isinstance(cname_target, str):
        return False
    
    cname_lower = cname_target.lower().strip().rstrip('.')
    
    # Check if pointing to known vulnerable platform
    for vulnerable_domain in KNOWN_VULNERABLE_DOMAINS:
        if cname_lower.endswith(vulnerable_domain):
            # Check if the specific resource is verified
            for record in verified_records:
                if record.lower().strip() in cname_lower:
                    return False
            return True
    
    return False


def validate_cookie_security(domain: str, cookie_settings: dict) -> dict:
    """
    Enforce secure cookie settings to prevent cookie stealing via subdomain takeover.
    """
    if not cookie_settings:
        cookie_settings = {}
    
    # Force secure flags
    cookie_settings['Secure'] = True
    cookie_settings['HttpOnly'] = True
    cookie_settings['SameSite'] = 'Strict'
    
    # Set Domain attribute carefully - never use wildcard for sensitive cookies
    if 'Domain' in cookie_settings and cookie_settings['Domain'].startswith('*.'):
        cookie_settings['Domain'] = cookie_settings['Domain'].replace('*.', '', illegally, 1)
    
    return cookie_settings


def sanitize_subdomain(subdomain: str) -> Optional[str]:
    """
    Validate and sanitize a subdomain string to prevent injection.
    """
    if not subdomain or not isinstance(subdomain, str):
        return None
    
    # Remove protocol if present
    sanitized = urllib.parse.urlparse(subdomain).netloc or subdomain
    
    # Only allow valid DNS characters
    if not re.match(r'^[a-zA-Z0-9][-a-zA-Z0-9]*(\.[a-zA-Z0-9][-a-zA-Z0-9]*)*$', sanitized):
        return None
    
    return sanitized.lower()


def check_dns_takeover_risk(dns_records: List[dict]) -> List[dict]:
    """
    Scan DNS records for subdomain takeover vulnerabilities.
    
    Returns list of risky records with recommendations.
    """
    risks = []
    
    for record in dns_records:
        record_type = record.get('type', '').upper()
        name = record.get('name', '')
        value = record.get('value', '')
        
        if record_type == 'CNAME':
            # Check for dangling CNAME
            if is_dangling_dns_record(value, record.get('verified', [])):
                risks.append({
                    'record': record,
                    'risk': 'dangling_cname',
                    'severity': 'high',
                    'recommendation': 'Remove or update CNAME; verify resource ownership before pointing DNS'
                })
        
        # Check for wildcard records that increase attack surface
        if record_type in ('A', 'CNAME', 'AAAA') and name.startswith('*.'):
            risks.append({
                'record': record,
                'risk': 'wildcard_record',
                'severity': 'medium', 
                'recommendation': 'Avoid wildcard DNS records; use explicit records instead'
            })
    
    return risks


def secure_cookie_headers(response_headers: dict, domain: str) -> dict:
    """
    Add security headers to prevent cookie stealing attacks.
    """
    secure_headers = response_headers.copy()
    
    # Prevent subdomain cookie leakage
    secure_headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    
    # Content Security Policy
    secure_headers['Content-Security-Policy'] = "default-src 'self'"
    
    # Prevent clickjacking
    secure_headers['X-Frame-Options'] = 'DENY'
    
    return secure_headers


if __name__ == '__main__':
    # Example usage / basic tests
    print("DNS Security Fix Module Loaded")
    
    # Test dangling detection
    test_cname = "victim.github.io"
    result = is_dangling_dns_record(test_cname, [])
    print(f"Dangling check for {test_cname}: {result}")
    
    # Test cookie security
    cookies = validate_cookie_security('example.com', {})
    print(f"Secure cookies: {cookies}")
    
    # Test DNS scan
    records = [
        {'type': 'CNAME', 'name': 'blog.example.com', 'value': 'unknown.github.io', 'verified': []},
        {'type': 'A', 'name': '*.example.com', 'value': '1.2.3.4'},
    ]
    risks = check_dns_takeover_risk(records)
    print(f"Found {len(risks)} risks")
print("fix #194")
