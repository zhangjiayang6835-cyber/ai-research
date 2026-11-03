"""
fix_s3_bucket_misconfig.py — S3 Bucket Misconfiguration → Mass Data Leak Fix

VULNERABILITY:
AWS S3 buckets with overly permissive bucket policies (e.g. wildcard principal '*'),
public canned ACLs ('public-read', 'public-read-write'), and disabled Block Public Access
settings allow unauthenticated external actors to read or write sensitive data.

FIX:
1. Enforce S3 Block Public Access settings (block public ACLs and bucket policies).
2. Validate and sanitize bucket policies to remove wildcard principals ('*') without conditions.
3. Validate and sanitize canned ACLs to reject public access.
4. Provide a secure S3 bucket manager and policy validator.
"""

from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class S3BucketConfig:
    """Security configuration for an S3 bucket."""
    bucket_name: str
    block_public_acls: bool = True
    ignore_public_acls: bool = True
    block_public_policy: bool = True
    restrict_public_buckets: bool = True
    canned_acl: str = "private"
    bucket_policy: Optional[Dict[str, Any]] = None


class S3PolicyValidator:
    """Validates S3 bucket policies for public exposure risks."""

    @staticmethod
    def is_public_policy(policy: Dict[str, Any]) -> bool:
        """
        Check if an S3 bucket policy grants public access.

        Detects wildcard principals ('*') in statements allowing Read/List actions
        without secure condition checks.
        """
        if not policy or "Statement" not in policy:
            return False

        public_actions = {
            "s3:GetObject",
            "s3:GetObjectVersion",
            "s3:ListBucket",
            "s3:PutObject",
            "s3:PutObjectAcl",
            "s3:DeleteObject",
            "s3:*"
        }

        for statement in policy.get("Statement", []):
            if statement.get("Effect") != "Allow":
                continue

            principal = statement.get("Principal")
            is_wildcard_principal = False
            if principal == "*" or principal == {"AWS": "*"}:
                is_wildcard_principal = True
            elif isinstance(principal, dict) and "*" in principal.get("AWS", []):
                is_wildcard_principal = True

            if not is_wildcard_principal:
                continue

            actions = statement.get("Action", [])
            if isinstance(actions, str):
                actions = [actions]

            has_public_action = any(
                act == "*" or act in public_actions or act.startswith("s3:Get") or act.startswith("s3:List")
                for act in actions
            )

            if has_public_action:
                condition = statement.get("Condition")
                if not condition:
                    return True

        return False


class S3ACLValidator:
    """Validates S3 canned ACLs and object ACLs."""

    PUBLIC_ACLS = frozenset({
        "public-read",
        "public-read-write",
        "authenticated-read"
    })

    @classmethod
    def validate_acl(cls, acl: str) -> bool:
        """Return True if ACL is secure (private), False if public/exposed."""
        return acl not in cls.PUBLIC_ACLS


class SecureS3BucketManager:
    """Manages S3 bucket security settings and validation."""

    def __init__(self, config: S3BucketConfig):
        self.config = config

    def validate_security(self) -> Tuple[bool, List[str]]:
        """
        Validate S3 bucket security settings.

        Returns (is_secure, list_of_vulnerabilities).
        """
        issues = []

        if not self.config.block_public_acls:
            issues.append("BlockPublicAcls is disabled")
        if not self.config.ignore_public_acls:
            issues.append("IgnorePublicAcls is disabled")
        if not self.config.block_public_policy:
            issues.append("BlockPublicPolicy is disabled")
        if not self.config.restrict_public_buckets:
            issues.append("RestrictPublicBuckets is disabled")

        if not S3ACLValidator.validate_acl(self.config.canned_acl):
            issues.append(f"Insecure canned ACL: {self.config.canned_acl}")

        if self.config.bucket_policy and S3PolicyValidator.is_public_policy(self.config.bucket_policy):
            issues.append("Bucket policy grants public access via wildcard principal")

        return len(issues) == 0, issues

    def sanitize_config(self) -> None:
        """Enforce secure defaults on the S3 bucket configuration."""
        self.config.block_public_acls = True
        self.config.ignore_public_acls = True
        self.config.block_public_policy = True
        self.config.restrict_public_buckets = True
        if not S3ACLValidator.validate_acl(self.config.canned_acl):
            self.config.canned_acl = "private"
        if self.config.bucket_policy and S3PolicyValidator.is_public_policy(self.config.bucket_policy):
            statements = []
            for stmt in self.config.bucket_policy.get("Statement", []):
                temp_policy = {"Statement": [stmt]}
                if not S3PolicyValidator.is_public_policy(temp_policy):
                    statements.append(stmt)
            self.config.bucket_policy = {"Version": "2012-10-17", "Statement": statements} if statements else None


def test_s3_bucket_security():
    """Unit tests for S3 bucket security validation and sanitization."""
    public_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "PublicRead",
                "Effect": "Allow",
                "Principal": "*",
                "Action": ["s3:GetObject"],
                "Resource": ["arn:aws:s3:::my-bucket/*"]
            }
        ]
    }
    assert S3PolicyValidator.is_public_policy(public_policy) is True

    secure_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "SecureAccess",
                "Effect": "Allow",
                "Principal": {"AWS": "arn:aws:iam::123456789012:root"},
                "Action": ["s3:GetObject"],
                "Resource": ["arn:aws:s3:::my-bucket/*"]
            }
        ]
    }
    assert S3PolicyValidator.is_public_policy(secure_policy) is False

    assert S3ACLValidator.validate_acl("private") is True
    assert S3ACLValidator.validate_acl("public-read") is False
    assert S3ACLValidator.validate_acl("public-read-write") is False

    config = S3BucketConfig(
        bucket_name="leaky-bucket",
        block_public_acls=False,
        canned_acl="public-read",
        bucket_policy=public_policy
    )
    manager = SecureS3BucketManager(config)
    is_secure, issues = manager.validate_security()
    assert is_secure is False
    assert len(issues) > 0

    manager.sanitize_config()
    is_secure_after, issues_after = manager.validate_security()
    assert is_secure_after is True
    assert len(issues_after) == 0

    print("PASS: S3 bucket misconfiguration tests passed")


if __name__ == "__main__":
    test_s3_bucket_security()
    print("\n✅ All S3 bucket misconfiguration fixes and tests passed!")
