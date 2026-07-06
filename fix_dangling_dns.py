#!/usr/bin/env python3
"""
Script to detect dangling DNS records that could lead to subdomain takeover.
Uses dnspython to check for CNAME records that point to unclaimed cloud services.
"""
import dns.resolver
import sys

def check_dangling(domain, resolver=dns.resolver.Resolver()):
    """Check if a domain has a dangling CNAME record."""
    try:
        answers = resolver.resolve(domain, 'CNAME')
        for rdata in answers:
            target = str(rdata.target)
            # Try to resolve the target; if it fails, the record is dangling
            try:
                resolver.resolve(target, 'A')
                print(f"[SAFE] {domain} -> {target} resolves correctly")
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
                print(f"[VULNERABLE] {domain} -> {target} does not resolve! Potential subdomain takeover.")
                return True
    except dns.resolver.NoAnswer:
        pass
    except dns.resolver.NXDOMAIN:
        pass
    except Exception as e:
        print(f"[ERROR] {domain}: {e}")
    return False

def main():
    if len(sys.argv) < 2:
        print("Usage: fix_dangling_dns.py <domain> [additional domains...]")
        sys.exit(1)
    domains = sys.argv[1:]
    vulnerable = []
    for domain in domains:
        if check_dangling(domain):
            vulnerable.append(domain)
    if vulnerable:
        print("\nVulnerable domains found:")
        for d in vulnerable:
            print(f" - {d}")
        print("\nRecommended action: Remove or update the dangling DNS records.")
    else:
        print("\nNo dangling DNS records detected.")

if __name__ == "__main__":
    main()
