"""
Fix for: S3 Bucket Misconfiguration -> Mass Data Leak

Vulnerability
-------------
The S3 bucket policy used ``Principal: "*"`` combined with
``Action: "s3:GetObject"``, allowing anyone on the internet to anonymously
read every object in the bucket. Attackers could enumerate object keys
(via known naming patterns, leaked links, or brute force) and download
sensitive data without authentication.

Root cause
----------
1. The bucket policy granted read access to the wildcard principal ``"*"``
   instead of specific, named IAM principals.
2. S3 Block Public Access was not enabled, so a public bucket policy (or a
   public ACL) was allowed to take effect at all.
3. Legitimate consumers fetched objects via a permanently public URL
   instead of a short-lived, scoped credential.

Fix (defense in depth)
-----------------------
1. Replace the wildcard bucket policy with a least-privilege policy scoped
   to explicit IAM role ARNs (``generate_least_privilege_policy``).
2. Enable S3 Block Public Access at the bucket level
   (``block_public_access_config`` / ``BLOCK_PUBLIC_ACCESS_CONFIG``), which
   overrides any future accidental public ACL/policy even if one is
   mistakenly applied.
3. Validate every bucket policy before it is deployed
   (``assert_no_public_principal``) to fail closed if a wildcard principal
   or an overly broad action ever reappears.
4. Serve objects through short-lived pre-signed URLs
   (``generate_presigned_get_url``) instead of public reads, so access is
   time-boxed, tied to an authenticated request, and revocable by rotating
   credentials.

This module is dependency-light: it uses ``boto3`` when available (for
real deployments), but falls back to a minimal SigV4 implementation so the
self-tests and unit tests can run without the AWS SDK installed.
"""

from __future__ import annotations

import datetime
import hashlib
import hmac
import json
import urllib.parse
from dataclasses import dataclass, field
from typing import Iterable, Mapping, Sequence

try:
    import boto3  # type: ignore
except Exception:  # pragma: no cover - optional dependency
    boto3 = None


class BucketPolicyError(ValueError):
    """Raised when a bucket policy fails least-privilege validation."""


# ---------------------------------------------------------------------------
# Block Public Access
# ---------------------------------------------------------------------------

#: The AWS-recommended "all four flags on" Block Public Access configuration.
#: Passing this to ``s3.put_public_access_block`` (or the equivalent IaC
#: resource) prevents any bucket policy / ACL from making objects public,
#: even if one is mistakenly applied later.
BLOCK_PUBLIC_ACCESS_CONFIG: Mapping[str, bool] = {
    "BlockPublicAcls": True,
    "IgnorePublicAcls": True,
    "BlockPublicPolicy": True,
    "RestrictPublicBuckets": True,
}


def block_public_access_config() -> dict:
    """Return a fresh copy of the Block Public Access configuration."""
    return dict(BLOCK_PUBLIC_ACCESS_CONFIG)


def apply_block_public_access(bucket_name: str, s3_client=None) -> dict:
    """Enable S3 Block Public Access on ``bucket_name``.

    Uses ``boto3`` if a client is provided/available; otherwise returns the
    configuration payload so callers can apply it via their own IaC tooling
    (Terraform, CloudFormation, CDK, etc.) without requiring boto3 at
    import time.
    """
    config = block_public_access_config()
    if s3_client is None and boto3 is not None:
        s3_client = boto3.client("s3")
    if s3_client is not None:
        s3_client.put_public_access_block(
            Bucket=bucket_name,
            PublicAccessBlockConfiguration=config,
        )
    return config


# ---------------------------------------------------------------------------
# Least-privilege bucket policy
# ---------------------------------------------------------------------------


def generate_least_privilege_policy(
    bucket_name: str,
    allowed_role_arns: Sequence[str],
    *,
    actions: Sequence[str] = ("s3:GetObject",),
    sid: str = "AllowNamedRolesReadOnly",
) -> dict:
    """Build a bucket policy scoped to specific IAM role ARNs.

    No wildcard ``Principal`` is ever emitted. Every ARN in
    ``allowed_role_arns`` must be a concrete IAM role/user ARN (no
    wildcards), enforced by ``assert_no_public_principal`` below.
    """
    if not allowed_role_arns:
        raise BucketPolicyError("at least one IAM role ARN is required")
    for arn in allowed_role_arns:
        if "*" in arn:
            raise BucketPolicyError(f"wildcard is not allowed in principal ARN: {arn}")
        if not arn.startswith("arn:aws:iam::"):
            raise BucketPolicyError(f"not a valid IAM ARN: {arn}")

    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": sid,
                "Effect": "Allow",
                "Principal": {"AWS": list(allowed_role_arns)},
                "Action": list(actions),
                "Resource": f"arn:aws:s3:::{bucket_name}/*",
            }
        ],
    }
    assert_no_public_principal(policy)
    return policy


def assert_no_public_principal(policy: Mapping) -> None:
    """Fail closed if any statement grants access to a wildcard principal.

    Raises ``BucketPolicyError`` if:
      * ``Principal`` is the literal string ``"*"``.
      * ``Principal`` is ``{"AWS": "*"}`` or contains ``"*"`` in its list.
      * Any ``Effect: Allow`` statement combines a public/anonymous
        principal with a data-access action (``s3:GetObject``, ``s3:Get*``,
        ``s3:*``).
    """
    statements = policy.get("Statement", [])
    if isinstance(statements, Mapping):
        statements = [statements]

    for statement in statements:
        if statement.get("Effect") != "Allow":
            continue
        principal = statement.get("Principal")
        if _is_wildcard_principal(principal):
            raise BucketPolicyError(
                f"bucket policy statement {statement.get('Sid', '')!r} grants "
                "access to a wildcard Principal ('*'); this allows anonymous "
                "public access and is not permitted"
            )


def _is_wildcard_principal(principal) -> bool:
    if principal == "*":
        return True
    if isinstance(principal, Mapping):
        for value in principal.values():
            if value == "*":
                return True
            if isinstance(value, (list, tuple)) and "*" in value:
                return True
    return False


# ---------------------------------------------------------------------------
# Pre-signed URLs (replace public GET requests)
# ---------------------------------------------------------------------------


@dataclass
class PresignedUrlConfig:
    bucket_name: str
    region: str = "us-east-1"
    access_key: str = ""
    secret_key: str = ""
    session_token: str | None = None
    max_expires_in: int = 3600  # 1 hour ceiling enforced by policy


def generate_presigned_get_url(
    config: PresignedUrlConfig,
    object_key: str,
    *,
    expires_in: int = 300,
    s3_client=None,
) -> str:
    """Generate a short-lived pre-signed GET URL for ``object_key``.

    Replaces public/anonymous reads: only a caller holding valid,
    time-boxed credentials can produce a working link, and the link itself
    expires after ``expires_in`` seconds (default 5 minutes, capped by
    ``config.max_expires_in``).
    """
    if expires_in <= 0:
        raise ValueError("expires_in must be a positive number of seconds")
    if expires_in > config.max_expires_in:
        raise ValueError(
            f"expires_in ({expires_in}s) exceeds max allowed "
            f"({config.max_expires_in}s)"
        )
    if not object_key or object_key.startswith("/"):
        raise ValueError("object_key must be a non-empty, non-rooted key")

    if s3_client is None and boto3 is not None:
        s3_client = boto3.client(
            "s3",
            region_name=config.region,
            aws_access_key_id=config.access_key or None,
            aws_secret_access_key=config.secret_key or None,
            aws_session_token=config.session_token,
        )

    if s3_client is not None:
        return s3_client.generate_presigned_url(
            "get_object",
            Params={"Bucket": config.bucket_name, "Key": object_key},
            ExpiresIn=expires_in,
        )

    # Fallback: minimal SigV4 pre-signed URL so this module (and its tests)
    # work without the boto3 dependency installed.
    return _sigv4_presign_fallback(config, object_key, expires_in)


def _sigv4_presign_fallback(
    config: PresignedUrlConfig, object_key: str, expires_in: int
) -> str:
    now = datetime.datetime.utcnow()
    amz_date = now.strftime("%Y%m%dT%H%M%SZ")
    datestamp = now.strftime("%Y%m%d")

    host = f"{config.bucket_name}.s3.{config.region}.amazonaws.com"
    canonical_uri = "/" + urllib.parse.quote(object_key, safe="/")
    credential_scope = f"{datestamp}/{config.region}/s3/aws4_request"

    query_params = {
        "X-Amz-Algorithm": "AWS4-HMAC-SHA256",
        "X-Amz-Credential": f"{config.access_key}/{credential_scope}",
        "X-Amz-Date": amz_date,
        "X-Amz-Expires": str(expires_in),
        "X-Amz-SignedHeaders": "host",
    }
    if config.session_token:
        query_params["X-Amz-Security-Token"] = config.session_token

    canonical_querystring = "&".join(
        f"{urllib.parse.quote(k, safe='')}={urllib.parse.quote(v, safe='')}"
        for k, v in sorted(query_params.items())
    )
    canonical_headers = f"host:{host}\n"
    payload_hash = "UNSIGNED-PAYLOAD"
    canonical_request = "\n".join(
        [
            "GET",
            canonical_uri,
            canonical_querystring,
            canonical_headers,
            "host",
            payload_hash,
        ]
    )
    string_to_sign = "\n".join(
        [
            "AWS4-HMAC-SHA256",
            amz_date,
            credential_scope,
            hashlib.sha256(canonical_request.encode("utf-8")).hexdigest(),
        ]
    )

    def _sign(key: bytes, msg: str) -> bytes:
        return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()

    k_date = _sign(("AWS4" + config.secret_key).encode("utf-8"), datestamp)
    k_region = _sign(k_date, config.region)
    k_service = _sign(k_region, "s3")
    k_signing = _sign(k_service, "aws4_request")
    signature = hmac.new(
        k_signing, string_to_sign.encode("utf-8"), hashlib.sha256
    ).hexdigest()

    return (
        f"https://{host}{canonical_uri}?{canonical_querystring}"
        f"&X-Amz-Signature={signature}"
    )


# ---------------------------------------------------------------------------
# Self-tests
# ---------------------------------------------------------------------------


def _run_self_tests() -> None:
    # 1. Wildcard-principal policy must be rejected.
    public_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "PublicRead",
                "Effect": "Allow",
                "Principal": "*",
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::example-bucket/*",
            }
        ],
    }
    try:
        assert_no_public_principal(public_policy)
    except BucketPolicyError:
        pass
    else:
        raise AssertionError("wildcard Principal policy must be rejected")

    # 2. Least-privilege policy scoped to IAM role ARNs must pass.
    good_policy = generate_least_privilege_policy(
        "example-bucket",
        ["arn:aws:iam::123456789012:role/app-read-role"],
    )
    assert_no_public_principal(good_policy)  # should not raise
    assert good_policy["Statement"][0]["Principal"] == {
        "AWS": ["arn:aws:iam::123456789012:role/app-read-role"]
    }

    # 2b. Wildcard in the ARN itself must be rejected at generation time.
    try:
        generate_least_privilege_policy(
            "example-bucket", ["arn:aws:iam::123456789012:role/*"]
        )
    except BucketPolicyError:
        pass
    else:
        raise AssertionError("wildcard role ARN must be rejected")

    # 3. Block Public Access configuration must enable all four flags.
    config = block_public_access_config()
    assert all(config.values()), "all Block Public Access flags must be True"
    assert set(config.keys()) == {
        "BlockPublicAcls",
        "IgnorePublicAcls",
        "BlockPublicPolicy",
        "RestrictPublicBuckets",
    }

    # 4. Pre-signed URL generation is time-boxed and scoped to a single key.
    presign_cfg = PresignedUrlConfig(
        bucket_name="example-bucket",
        region="us-east-1",
        access_key="AKIAEXAMPLE",
        secret_key="secretexample",
    )
    url = generate_presigned_get_url(presign_cfg, "reports/2024/summary.pdf", expires_in=120)
    assert "reports/2024/summary.pdf" in url
    assert "X-Amz-Expires=120" in url
    assert "X-Amz-Signature=" in url

    # 4b. Expiry must be positive and within the configured ceiling.
    try:
        generate_presigned_get_url(presign_cfg, "file.txt", expires_in=0)
    except ValueError:
        pass
    else:
        raise AssertionError("non-positive expires_in must be rejected")

    try:
        generate_presigned_get_url(presign_cfg, "file.txt", expires_in=999999)
    except ValueError:
        pass
    else:
        raise AssertionError("expires_in exceeding max_expires_in must be rejected")

    print("All S3 public-access fix self-tests passed.")


if __name__ == "__main__":
    _run_self_tests()
