#!/usr/bin/env python3
"""
Fix S3 bucket misconfiguration that allows public read access.
Removes or denies public access statements from bucket policies.
"""

import sys
import os
import boto3
from botocore.exceptions import ClientError, NoCredentialsError


def fix_bucket_policy(bucket_name: str) -> bool:
    """Remove public read statements from the bucket policy."""
    s3 = boto3.client('s3')
    try:
        policy = s3.get_bucket_policy(Bucket=bucket_name)
        policy_json = policy['Policy']
        # Parse JSON (string or dict)
        if isinstance(policy_json, str):
            import json
            policy_data = json.loads(policy_json)
        else:
            policy_data = policy_json

        # Check if any statement allows public access (Principal "*" or "AWS": "*")
        statements = policy_data.get('Statement', [])
        modified = False
        for stmt in statements:
            principal = stmt.get('Principal', {})
            if 'AWS' in principal and principal['AWS'] == '*':
                # Deny public access
                stmt['Effect'] = 'Deny'
                modified = True
            elif principal == '*':
                stmt['Effect'] = 'Deny'
                modified = True
        if modified:
            # Update policy
            s3.put_bucket_policy(Bucket=bucket_name, Policy=json.dumps(policy_data))
            print(f"Fixed bucket policy for {bucket_name}")
            return True
        else:
            print(f"No public access found in policy for {bucket_name}")
            return False
    except ClientError as e:
        print(f"Error accessing bucket {bucket_name}: {e}", file=sys.stderr)
        return False
    except NoCredentialsError:
        print("AWS credentials not configured", file=sys.stderr)
        return False


if __name__ == '__main__':
    bucket = sys.argv[1] if len(sys.argv) > 1 else os.environ.get('S3_BUCKET_NAME')
    if not bucket:
        print("Usage: python s3_bucket_misconfig_fix.py <bucket-name>", file=sys.stderr)
