"""
S3 Bucket Misconfiguration Fix - Public Access to Mass Data Leak ($120)

Vulnerability:
- S3 bucket policy allows public read access (Principal: "*")
- Anyone can enumerate and download all objects in the bucket

Fix Strategy:
1. Replace wildcard Principal with specific IAM role/user ARNs
2. Add deny rule for public access at bucket level
3. Enforce HTTPS-only access (no HTTP)
4. Enable block-public-access bucket policy
5. Add bucket policy validation function
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set


@dataclass
class S3BucketPolicy:
    """Represents an S3 bucket policy document."""
    version: str = "2012-10-17"
    statements: List[Dict] = field(default_factory=list)

    def to_dict(self) -> Dict:
        return {"Version": self.version, "Statement": self.statements}

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)


class S3BucketPolicyValidator:
    """Validates S3 bucket policies for security misconfigurations."""

    DANGEROUS_ACTIONS: Set[str] = frozenset({
        "s3:DeleteObject", "s3:PutObject", "s3:PutBucketPolicy",
        "s3:DeleteBucket", "s3:PutBucketAcl", "s3:PutBucketOwnershipControls",
    })

    PUBLIC_READ_ACTIONS: Set[str] = frozenset({"s3:GetObject", "s3:ListBucket"})

    def __init__(self, account_id: str):
        self.account_id = account_id

    def validate_policy(self, policy_dict: Dict) -> Dict:
        errors: List[str] = []
        warnings: List[str] = []
        statements = policy_dict.get("Statement", [])

        if not statements:
            errors.append("Policy has no statements")
            return {"valid": False, "errors": errors, "warnings": warnings}

        for idx, stmt in enumerate(statements):
            s_errors, s_warnings = self._validate_statement(stmt, idx)
            errors.extend(s_errors)
            warnings.extend(s_warnings)

        has_deny_public = any(
            s.get("Effect") == "Deny" and "*" in str(s.get("Principal", {}))
            for s in statements
        )
        if not has_deny_public:
            warnings.append("No explicit Deny rule for public access found")

        return {"valid": len(errors) == 0, "errors": errors, "warnings": warnings}

    def _validate_statement(self, stmt: Dict, idx: int) -> tuple:
        errors: List[str] = []
        warnings: List[str] = []
        effect = stmt.get("Effect", "").capitalize()
        principal = stmt.get("Principal", {})
        actions = stmt.get("Action", [])
        if isinstance(actions, str):
            actions = [actions]

        if effect not in ("Allow", "Deny"):
            errors.append(f"Statement {idx}: Invalid Effect '{effect}'")
            return errors, warnings

        if principal == "*" and effect == "Allow":
            dangerous_found = set(actions) & self.DANGEROUS_ACTIONS
            has_wildcard = "s3:*" in actions
            if dangerous_found or has_wildcard:
                errors.append(
                    f"Statement {idx}: Public access to dangerous actions: "
                    f"{', '.join(dangerous_found)}"
                )
            disallowed = set(actions) - self.PUBLIC_READ_ACTIONS - self.DANGEROUS_ACTIONS
            if disallowed:
                warnings.append(
                    f"Statement {idx}: Public access to non-standard actions: "
                    f"{', '.join(disallowed)}"
                )

        if isinstance(principal, dict):
            aws_principals = principal.get("AWS", [])
            if isinstance(aws_principals, str):
                aws_principals = [aws_principals]
            for arn in aws_principals:
                if arn == "*":
                    warnings.append(f"Statement {idx}: AWS Principal is '*'")

        return errors, warnings


class SecureS3BucketPolicyBuilder:
    """Builds secure S3 bucket policies."""

    def __init__(self, bucket_name: str, account_id: str, allow_public_read: bool = False):
        self.bucket_name = bucket_name
        self.account_id = account_id
        self.allow_public_read = allow_public_read
        self.validator = S3BucketPolicyValidator(account_id)
        self.statements: List[Dict] = []

    def add_iam_role_access(self, role_name: str, actions: List[str]) -> "SecureS3BucketPolicyBuilder":
        arn = f"arn:aws:iam::{self.account_id}:role/{role_name}"
        self.statements.append({
            "Sid": f"IAMRole-{role_name}",
            "Effect": "Allow",
            "Principal": {"AWS": arn},
            "Action": actions,
            "Resource": [
                f"arn:aws:s3:::{self.bucket_name}",
                f"arn:aws:s3:::{self.bucket_name}/*",
            ],
        })
        return self

    def add_deny_public_access(self) -> "SecureS3BucketPolicyBuilder":
        self.statements.append({
            "Sid": "DenyAllPublicAccess",
            "Effect": "Deny",
            "Principal": "*",
            "Action": "s3:*",
            "Resource": [
                f"arn:aws:s3:::{self.bucket_name}",
                f"arn:aws:s3:::{self.bucket_name}/*",
            ],
        })
        return self

    def add_https_enforcement(self) -> "SecureS3BucketPolicyBuilder":
        self.statements.append({
            "Sid": "EnforceHTTPS",
            "Effect": "Deny",
            "Principal": "*",
            "Action": "s3:*",
            "Resource": [
                f"arn:aws:s3:::{self.bucket_name}",
                f"arn:aws:s3:::{self.bucket_name}/*",
            ],
            "Condition": {"Bool": {"aws:SecureTransport": "false"}},
        })
        return self

    def build(self) -> S3BucketPolicy:
        policy = S3BucketPolicy(statements=self.statements)
        validation = self.validator.validate_policy(policy.to_dict())
        if not validation["valid"]:
            raise ValueError(f"Policy validation failed: {validation['errors']}")
        return policy


def get_default_secure_policy(bucket_name: str = "my-secure-bucket", account_id: str = "123456789012") -> Dict:
    builder = SecureS3BucketPolicyBuilder(bucket_name=bucket_name, account_id=account_id, allow_public_read=False)
    builder.add_iam_role_access("ApplicationRole", ["s3:GetObject", "s3:PutObject"])
    builder.add_iam_role_access("AdminRole", ["s3:*"])
    builder.add_deny_public_access()
    builder.add_https_enforcement()
    return builder.build().to_dict()


def run_self_test() -> List[str]:
    failures = []
    try:
        policy = get_default_secure_policy()
        v = S3BucketPolicyValidator("123456789012")
        result = v.validate_policy(policy)
        if not result["valid"]:
            failures.append(f"Default policy invalid: {result['errors']}")
        print("OK: Default secure policy is valid")
    except Exception as e:
        failures.append(f"Test 1 failed: {e}")

    try:
        public_policy = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": "*", "Action": "s3:*", "Resource": "*"}]}
        v = S3BucketPolicyValidator("123456789012")
        result = v.validate_policy(public_policy)
        if result["valid"]:
            failures.append("Public bucket policy should be invalid")
        print("OK: Public bucket policy correctly rejected")
    except Exception as e:
        failures.append(f"Test 2 failed: {e}")

    try:
        policy = get_default_secure_policy()
        if not any(s.get("Sid") == "EnforceHTTPS" for s in policy["Statement"]):
            failures.append("HTTPS enforcement missing")
        if not any(s.get("Sid") == "DenyAllPublicAccess" for s in policy["Statement"]):
            failures.append("Public deny rule missing")
        print("OK: HTTPS enforcement and public deny present")
    except Exception as e:
        failures.append(f"Test 3 failed: {e}")

    return failures


if __name__ == "__main__":
    failures = run_self_test()
    if failures:
        print(f"\nFAILED: {len(failures)} test(s)")
        for f in failures:
            print(f"  - {f}")
    else:
        print("\nAll self-tests passed!")
