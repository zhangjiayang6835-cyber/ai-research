#!/usr/bin/env python3
"""
S3 Bucket Misconfiguration Detection and Remediation Tool

This script detects S3 buckets with overly permissive policies that could
lead to mass data leakage. It scans for common misconfigurations such as:
  - Public read/write access via bucket policies
  - "Effect": "Allow" with "Principal": "*" (wildcard principal)
  - Missing or overly permissive ACLs
  - Bucket policies granting access to all AWS accounts

Author: Security Research Team
Purpose: Identify and remediate S3 bucket misconfigurations (Bug #1478)
"""

import os
import sys
import json
import logging
import argparse
from datetime import datetime
from typing import Dict, List, Optional, Any, Tuple

try:
    import boto3
    from botocore.exceptions import (
        ClientError,
        NoCredentialsError,
        EndpointConnectionError,
        BotoCoreError,
    )
except ImportError:
    print("ERROR: boto3 is required. Install with: pip install boto3")
    sys.exit(1)


# ---------------------------------------------------------------------------
# Logging configuration
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler("s3_bucket_scan.log"),
    ],
)
logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
RISKY_PRINCIPALS = ["*", "arn:aws:iam::*:root", "everyone"]
RISKY_ACTIONS = [
    "s3:GetObject",
    "s3:PutObject",
    "s3:DeleteObject",
    "s3:ListBucket",
    "s3:*",
]
RISKY_EFFECTS = ["Allow"]


class S3BucketSecurityScanner:
    """
    Scans S3 buckets for misconfigurations that could lead to mass data leakage.
    """

    def __init__(self, region: str = "us-east-1", profile: str = None):
        """
        Initialize the scanner with AWS credentials.

        Args:
            region: AWS region to connect to.
            profile: Optional AWS CLI profile name.
        """
        self.region = region
        self.profile = profile
        self.s3_client = self._get_s3_client()
        self.findings: List[Dict[str, Any]] = []

    def _get_s3_client(self):
        """Create and return an S3 client with proper error handling."""
        try:
            session_kwargs: Dict[str, Any] = {"region_name": self.region}
            if self.profile:
                session_kwargs["profile_name"] = self.profile
            session = boto3.Session(**session_kwargs)
            client = session.client("s3")
            logger.info("S3 client initialized successfully (region=%s).", self.region)
            return client
        except NoCredentialsError:
            logger.error("AWS credentials not found. Configure credentials and retry.")
            sys.exit(1)
        except Exception as exc:
            logger.error("Failed to create S3 client: %s", exc)
            sys.exit(1)

    def list_all_buckets(self) -> List[str]:
        """
        List all S3 buckets in the account.

        Returns:
            List of bucket names.
        """
        try:
            response = self.s3_client.list_buckets()
            bucket_names = [b["Name"] for b in response.get("Buckets", [])]
            logger.info("Found %d bucket(s) in account.", len(bucket_names))
            return bucket_names
        except ClientError as exc:
            logger.error("Failed to list buckets: %s", exc)
            return []
        except Exception as exc:
            logger.error("Unexpected error listing buckets: %s", exc)
            return []

    def get_bucket_policy(self, bucket_name: str) -> Optional[Dict]:
        """
        Retrieve the bucket policy for a given S3 bucket.

        Args:
            bucket_name: Name of the S3 bucket.

        Returns:
            Parsed policy document dict, or None if no policy exists.
        """
        try:
            response = self.s3_client.get_bucket_policy(Bucket=bucket_name)
            policy_str = response.get("Policy", "{}")
            return json.loads(policy_str)
        except ClientError as exc:
            error_code = exc.response.get("Error", {}).get("Code", "")
            if error_code == "NoSuchBucketPolicy":
                logger.debug("Bucket '%s' has no policy attached.", bucket_name)
                return None
            elif error_code == "AccessDenied":
                logger.warning("Access denied when reading policy for '%s'.", bucket_name)
                return None
            else:
                logger.error("Error reading policy for '%s': %s", bucket_name, exc)
                return None
        except json.JSONDecodeError as exc:
            logger.error("Failed to parse policy JSON for '%s': %s", bucket_name, exc)
            return None
        except Exception as exc:
            logger.error("Unexpected error getting policy for '%s': %s", bucket_name, exc)
            return None

    def get_bucket_acl(self, bucket_name: str) -> Optional[Dict]:
        """
        Retrieve the ACL for a given S3 bucket.

        Args:
            bucket_name: Name of the S3 bucket.

        Returns:
            ACL dict, or None on error.
        """
        try:
            response = self.s3_client.get_bucket_acl(Bucket=bucket_name)
            return response
        except ClientError as exc:
            error_code = exc.response.get("Error", {}).get("Code", "")
            if error_code == "AccessDenied":
                logger.warning("Access denied when reading ACL for '%s'.", bucket_name)
                return None
            logger.error("Error reading ACL for '%s': %s", bucket_name, exc)
            return None
        except Exception as exc:
            logger.error("Unexpected error getting ACL for '%s': %s", bucket_name, exc)
            return None

    def get_bucket_public_access_block(self, bucket_name: str) -> Optional[Dict]:
        """
        Retrieve the public access block configuration for a bucket.

        Args:
            bucket_name: Name of the S3 bucket.

        Returns:
            Public access block config dict, or None if not configured.
        """
        try:
            response = self.s3_client.get_public_access_block(Bucket=bucket_name)
            return response.get("PublicAccessBlockConfiguration", None)
        except ClientError as exc:
            error_code = exc.response.get("Error", {}).get("Code", "")
            if error_code == "NoSuchPublicAccessBlockConfiguration":
                logger.debug("Bucket '%s' has no public access block config.", bucket_name)
                return None
            logger.error("Error reading public access block for '%s': %s", bucket_name, exc)
            return None
        except Exception as exc:
            logger.error("Unexpected error for '%s': %s", bucket_name, exc)
            return None

    def _is_wildcard_principal(self, principal: Any) -> bool:
        """
        Check if a principal value is a wildcard or overly broad.

        Args:
            principal: The principal value from the policy statement.

        Returns:
            True if the principal grants access to everyone.
        """
        if principal is None:
            return False

        if isinstance(principal, str):
            return principal in RISKY_PRINCIPALS

        if isinstance(principal, dict):
            # Check both "AWS" and "Service" keys
            for key in ("AWS", "Service", "Federated", "CanonicalUser"):
                val = principal.get(key)
                if val is None:
                    continue
                if isinstance(val, str):
                    if val in RISKY_PRINCIPALS:
                        return True
                elif isinstance(val, list):
                    for v in val:
                        if isinstance(v, str) and v in RISKY_PRINCIPALS:
                            return True
        return False

    def _is_risky_action(self, action: Any) -> bool:
        """
        Check if the action is risky (allows read/write/delete/list).

        Args:
            action: The action value from the policy statement.

        Returns:
            True if the action is risky.
        """
        if action is None:
            return False

        if isinstance(action, str):
            return action in RISKY_ACTIONS or action == "s3:*"

        if isinstance(action, list):
            for a in action:
                if isinstance(a, str) and (a in RISKY_ACTIONS or a == "s3:*"):
                    return True
        return False

    def _is_public_acl(self, acl: Dict) -> Tuple[bool, List[str]]:
        """
        Check if the ACL grants public access.

        Args:
            acl: The ACL dictionary returned by get_bucket_acl.

        Returns:
            Tuple of (is_public, list_of_risky_grants).
        """
        risky_grants = []
        is_public = False

        grants = acl.get("Grants", [])
        for grant in grants:
            grantee = grant.get("Grantee", {})
            permission = grant.get("Permission", "")
            grantee_type = grantee.get("Type", "")

            # AllUsers or AllAuthenticatedUsers indicate public access
            if grantee_type == "Group":
                uri = grantee.get("URI", "")
                if "AllUsers" in uri:
                    is_public = True
                    risky_grants.append(
                        f"Public (AllUsers) granted '{permission}'"
                    )
                elif "AuthenticatedUsers" in uri:
                    is_public = True