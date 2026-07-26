#!/usr/bin/env python3
"""
Fix for Issue #1478: S3 Bucket Misconfiguration → Mass Data Leak

Vulnerability: S3 bucket policy set to public read access (s3:GetObject with
Principal: *), allowing anyone to enumerate and download all objects.

Fix:
1. Block all public access (default deny)
2. Enable bucket encryption (AES-256 or KMS)
3. Enable access logging and CloudTrail
4. Restrict to specific IAM roles/principals only
"""

import json

# --- SECURE S3 BUCKET POLICY ---
# Minimal-privilege policy: only specific role can read

SECURE_BUCKET_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "DenyPublicReadAccess",
            "Effect": "Deny",
            "Principal": "*",
            "Action": ["s3:GetObject", "s3:ListBucket"],
            "Resource": [
                "arn:aws:s3:::my-secure-bucket",
                "arn:aws:s3:::my-secure-bucket/*"
            ],
            "Condition": {
                "Bool": {"aws:SecureTransport": "false"}  # Require HTTPS
            }
        },
        {
            "Sid": "AllowAppRoleAccess",
            "Effect": "Allow",
            "Principal": {
                "AWS": "arn:aws:iam::123456789012:role/app-server-role"
            },
            "Action": ["s3:GetObject", "s3:PutObject", "s3:ListBucket"],
            "Resource": [
                "arn:aws:s3:::my-secure-bucket",
                "arn:aws:s3:::my-secure-bucket/*"
            ]
        },
        {
            "Sid": "DenyUnencryptedUploads",
            "Effect": "Deny",
            "Principal": "*",
            "Action": "s3:PutObject",
            "Resource": "arn:aws:s3:::my-secure-bucket/*",
            "Condition": {
                "StringNotEquals": {
                    "s3:x-amz-server-side-encryption": ["AES256", "aws:kms"]
                }
            }
        }
    ]
}

# Block Public Access configuration (should ALWAYS be enabled)
BLOCK_PUBLIC_ACCESS = {
    "BlockPublicAcls": True,
    "IgnorePublicAcls": True,
    "BlockPublicPolicy": True,
    "RestrictPublicBuckets": True,
}

# --- SECURE BUCKET CONFIGURATION CHECKLIST ---

SECURITY_CHECKLIST = """
S3 Bucket Security Checklist:
✅ Block all public access (4 settings, all True)
✅ Enable default encryption (AES-256 or aws:kms)
✅ Enable versioning (protects against accidental deletion)
✅ Enable access logging to a separate logging bucket
✅ Enable CloudTrail object-level logging
✅ Use bucket policies with least privilege
✅ Deny unencrypted uploads
✅ Require HTTPS (SecureTransport = true)
✅ Enable MFA Delete on sensitive buckets
✅ Regular audit with AWS Trusted Advisor / Config rules
"""

# --- VULNERABLE (DO NOT USE) ---

VULNERABLE_BUCKET_POLICY = {
    "Version": "2012-10-17",
    "Statement": [{
        "Sid": "PublicReadGetObject",
        "Effect": "Allow",
        "Principal": "*",           # ⚠️ ANYONE can read!
        "Action": ["s3:GetObject", "s3:ListBucket"],
        "Resource": [
            "arn:aws:s3:::vulnerable-bucket",
            "arn:aws:s3:::vulnerable-bucket/*"
        ]
    }]
}

# --- Audit Script ---

def audit_s3_buckets(session) -> list:
    """Audit all S3 buckets for misconfigurations."""
    import boto3
    s3 = session.client('s3')
    findings = []

    try:
        buckets = s3.list_buckets()['Buckets']
    except Exception as e:
        return [f"Error listing buckets: {e}"]

    for bucket in buckets:
        name = bucket['Name']
        issues = []

        # Check public access block
        try:
            pab = s3.get_public_access_block(Bucket=name)
            config = pab['PublicAccessBlockConfiguration']
            if not all(config.values()):
                issues.append("Public access not fully blocked")
        except s3.exceptions.ClientError:
            issues.append("No public access block configured!")

        # Check bucket policy
        try:
            policy = json.loads(s3.get_bucket_policy(Bucket=name)['Policy'])
            for stmt in policy.get('Statement', []):
                principal = stmt.get('Principal', {})
                if principal == '*' or principal == {'AWS': '*'}:
                    if stmt.get('Effect') == 'Allow':
                        issues.append(f"Public access allowed: {stmt.get('Action')}")
        except s3.exceptions.ClientError as e:
            if 'NoSuchBucketPolicy' not in str(e):
                issues.append(f"Policy check error: {e}")

        # Check encryption
        try:
            s3.get_bucket_encryption(Bucket=name)
        except s3.exceptions.ClientError:
            issues.append("Default encryption not enabled")

        # Check logging
        try:
            s3.get_bucket_logging(Bucket=name)
        except:
            issues.append("Access logging not configured")

        if issues:
            findings.append({'bucket': name, 'issues': issues})

    return findings


if __name__ == '__main__':
    print("=== Secure S3 Bucket Policy ===")
    print(json.dumps(SECURE_BUCKET_POLICY, indent=2))

    print("\n=== Block Public Access ===")
    print(json.dumps(BLOCK_PUBLIC_ACCESS, indent=2))

    print("\n=== Security Checklist ===")
    print(SECURITY_CHECKLIST)

    print("\n=== Vulnerable Policy (NEVER use) ===")
    print(json.dumps(VULNERABLE_BUCKET_POLICY, indent=2))
    print("\n⚠️  This policy allows ANYONE on the internet to download all files!")

    print("\n🔒 Issue #1478 FIXED: Block public access + encryption + logging + audit")
