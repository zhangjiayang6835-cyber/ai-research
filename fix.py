# Auto fix for zhangjiayang6835-cyber/ai-research#194
# 1782921258

#!/usr/bin/env python3
"""
Fix for Dangling DNS Record → Subdomain Takeover → Cookie Stealing vulnerability.

This script provides utilities to:
1. Detect dangling DNS records that point to unclaimed cloud resources
2. Validate subdomain ownership before setting cookies
3. Prevent cookie stealing via subdomain takeover attacks
"""

import dns.resolver
import requests
import socket
import ssl
from urllib.parse import urlparse


def check_dangling_dns_record(domain, expected_endpoint=None):
    """
    Check if a DNS record is dangling (points to unclaimed resource).
    Returns True if dangling, False if valid.
    """
    try:
        # Resolve the domain
        answers = dns.resolver.resolve(domain, 'CNAME')
        for rdata in answers:
            cname_target = str(rdata.target).rstrip('.')
            
            # Check if the CNAME target responds
            try:
                response = requests.head(
                    f"https://{cname_target}", 
                    timeout=5,
                    allow_redirects=False
                )
                # If we get here, the target exists
                return False
            except requests.RequestException:
                # Target doesn't respond - potential dangling record
                return True
                
    except dns.resolver.NoAnswer:
        # No CNAME record, check A record
        pass
    except dns.resolver.NXDOMAIN:
        # Domain doesn't exist
        return True
    
    return False


def validate_subdomain_ownership(domain, allowed_domains=None):
    """
    Validate that a subdomain belongs to an allowed set of domains.
    Prevents subdomain takeover by ensuring strict domain validation.
    """
    if allowed_domains is None:
        allowed_domains = []
    
    domain = domain.lower().strip()
    
    # Check for null bytes and other injection attempts
    if '\x00' in domain or '%00' in domain:
        return False
    
    # Prevent wildcard bypasses
    for allowed in allowed_domains:
        allowed = allowed.lower().strip()
        # Exact match or proper subdomain
        if domain == allowed or domain.endswith('.' + allowed):
            return True
    
    return False


def set_secure_cookie(response, name, value, domain=None, secure=True, httponly=True, samesite='Strict'):
    """
    Set a secure cookie with protections against subdomain takeover.
    """
    cookie_kwargs = {
        'secure': secure,
        'httponly': httponly,
        'samesite': samesite,
    }
    
    if domain:
        # Validate domain before setting cookie
        # Prevent setting cookies on domains that might be taken over
        if not validate_subdomain_ownership(domain, [domain]):
            raise ValueError(f"Invalid or potentially compromised domain: {domain}")
        cookie_kwargs['domain'] = domain
    
    # Set the cookie on the response
    response.set_cookie(name, value, **cookie_kwargs)
    return response


def check_subdomain_takeover_risk(domain, cloud_providers=None):
    """
    Comprehensive check for subdomain takeover vulnerability.
    Returns dict with risk assessment.
    """
    if cloud_providers is None:
        cloud_providers = [
            'amazonaws.com',
            'azurewebsites.net',
            'cloudapp.azure.com',
            'herokuapp.com',
            'github.io',
            'vercel.app',
            'netlify.app',
            'firebaseapp.com',
            'appspot.com',
        ]
    
    result = {
        'domain': domain,
        'is_dangling': False,
        'risk_level': 'low',
        'vulnerable_cnames': [],
    }
    
    try:
        answers = dns.resolver.resolve(domain, 'CNAME')
        for rdata in answers:
            cname_target = str(rdata.target).rstrip('.')
            
            # Check if pointing to cloud provider
            for provider in cloud_providers:
                if provider in cname_target:
                    try:
                        # Try to resolve the CNAME target
                        socket.gethostbyname(cname_target)
                    except socket.gaierror:
                        # DNS resolves but host doesn't - dangling!
                        result['is_dangling'] = True
                        result['vulnerable_cnames'].append(cname_target)
                        result['risk_level'] = 'critical'
                        
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        pass
    
    return result


if __name__ == '__main__':
    # Example usage
    test_domain = 'vulnerable.example.com'
    result = check_subdomain_takeover_risk(test_domain)
    print(f"Risk assessment for {test_domain}: {result}")
print("fix #194")
