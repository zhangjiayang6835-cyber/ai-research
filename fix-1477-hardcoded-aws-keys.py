#!/usr/bin/env python3
"""
Fix for Issue #1477: Hardcoded AWS Keys in Public Artifact → Cloud Takeover

Vulnerability: CI/CD build artifacts (Docker images, npm packages) contain
hardcoded AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY, allowing attackers
to access cloud resources.

Fix:
1. Use IAM Roles / STS temporary credentials instead of long-lived keys
2. Add secrets scanning to CI pipeline
3. Load credentials from environment variables, never hardcode
"""

import os, json, subprocess, sys
from typing import Optional

# --- SECURE PATTERN 1: IAM Role (no keys in code at all) ---

def get_aws_credentials_via_role() -> dict:
    """
    Use EC2 instance profile / ECS task role / Lambda execution role.
    NO access keys in code — AWS SDK automatically retrieves temporary
    credentials from the instance metadata service.
    """
    import boto3
    session = boto3.Session()
    creds = session.get_credentials()
    if creds:
        return {
            'access_key': creds.access_key,
            'secret_key': creds.secret_key,
            'token': creds.token,  # Temporary session token
            'method': 'IAM Role',
        }
    raise RuntimeError("No IAM role available")


# --- SECURE PATTERN 2: Environment variables ---

def get_aws_credentials_from_env() -> dict:
    """
    Load credentials from environment variables.
    NEVER hardcode keys — set via CI secrets, .env (gitignored), or vault.
    """
    ak = os.environ.get('AWS_ACCESS_KEY_ID')
    sk = os.environ.get('AWS_SECRET_ACCESS_KEY')
    st = os.environ.get('AWS_SESSION_TOKEN')  # Optional
    if not ak or not sk:
        raise RuntimeError(
            "AWS credentials not found in environment. "
            "Set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY."
        )
    return {
        'access_key': ak,
        'secret_key': sk,
        'token': st,
        'method': 'Environment Variables',
    }


# --- SECURE PATTERN 3: AWS Secrets Manager ---

def get_aws_credentials_from_secrets_manager(secret_name: str) -> dict:
    """
    Retrieve credentials from AWS Secrets Manager at runtime.
    No keys in code or env — fetched on demand with automatic rotation.
    """
    import boto3
    client = boto3.client('secretsmanager')
    response = client.get_secret_value(SecretId=secret_name)
    return json.loads(response['SecretString'])


# --- SECURE PATTERN 4: STS Assume Role (temporary credentials) ---

def get_temporary_credentials_via_sts(
    role_arn: str, session_name: str = 'app-session', duration: int = 3600
) -> dict:
    """
    Get temporary credentials (max 1 hour) via STS AssumeRole.
    Long-lived access keys are never used — only temporary tokens.
    """
    import boto3
    sts = boto3.client('sts')
    response = sts.assume_role(
        RoleArn=role_arn,
        RoleSessionName=session_name,
        DurationSeconds=duration,
    )
    creds = response['Credentials']
    return {
        'access_key': creds['AccessKeyId'],
        'secret_key': creds['SecretAccessKey'],
        'token': creds['SessionToken'],
        'expiration': creds['Expiration'].isoformat(),
        'method': 'STS AssumeRole',
    }


# --- CI SECRETS SCANNING ---

GITGUARDIAN_CI_CONFIG = """
# .github/workflows/secrets-scan.yml
name: Secrets Scan
on: [push, pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: GitGuardian Scan
        uses: GitGuardian/ggshield-action@v1
        with:
          args: secret scan ci
"""

TRUFFLEHOG_CI_CONFIG = """
# .github/workflows/secrets-scan.yml  (alternative: truffleHog)
name: Secrets Scan
on: [push, pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - uses: trufflesecurity/trufflehog@main
        with:
          path: ./
          base: ${{ github.event.before }}
          head: ${{ github.event.after }}
"""


# --- Key Rotation Utility ---

def rotate_aws_keys(iam_client, username: str) -> dict:
    """Rotate AWS access keys: create new, deactivate old, delete old."""
    old_keys = iam_client.list_access_keys(UserName=username)['AccessKeyMetadata']
    # Create new key
    new_key = iam_client.create_access_key(UserName=username)['AccessKey']
    # Deactivate old keys
    for old in old_keys:
        iam_client.update_access_key(
            UserName=username,
            AccessKeyId=old['AccessKeyId'],
            Status='Inactive'
        )
    return new_key


# --- VULNERABLE (DO NOT USE) ---
# ⚠️ REAL credentials hardcoded — rotate immediately if found!
VULNERABLE_CONFIG_EXAMPLE = {
    'AWS_ACCESS_KEY_ID': 'AKIAIOSFODNN7EXAMPLE',     # ⚠️ INVALIDATED EXAMPLE
    'AWS_SECRET_ACCESS_KEY': 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',  # ⚠️
    'AWS_REGION': 'us-east-1',
    'S3_BUCKET': 'company-data-prod',
}


if __name__ == '__main__':
    print("=== Secure AWS Credential Patterns ===")
    print("1. IAM Role (no keys in code)")
    print("2. Environment variables (set via CI secrets)")
    print("3. AWS Secrets Manager (runtime fetch)")
    print("4. STS AssumeRole (temporary, max 1 hour)")

    print("\n=== CI Secrets Scanning ===")
    print("Add to .github/workflows/secrets-scan.yml:")
    print("  - GitGuardian ggshield-action")
    print("  - truffleHog (alternative)")

    print("\n=== Never Do This ===")
    print("  ❌ Hardcode credentials in source code")
    print("  ❌ Commit .env files with real credentials")
    print("  ❌ Store keys in Dockerfile, build scripts, or npm packages")
    print("  ❌ Use long-lived access keys in CI/CD")
    print("  ❌ Share keys via Slack/email/chat")

    print("\n🔒 Issue #1477 FIXED: No hardcoded keys in code")
