"""
Tests for S3 bucket misconfiguration remediation.
"""

from fixes.fix_s3_bucket_misconfig import (
    S3BucketConfig,
    S3PolicyValidator,
    S3ACLValidator,
    SecureS3BucketManager,
)


def test_s3_policy_public_detection():
    """Test public bucket policy detection."""
    public_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": "*",
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::test-bucket/*"
            }
        ]
    }
    assert S3PolicyValidator.is_public_policy(public_policy) is True


def test_s3_policy_secure_detection():
    """Test secure bucket policy detection."""
    secure_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": "arn:aws:iam::111122223333:root"},
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::test-bucket/*"
            }
        ]
    }
    assert S3PolicyValidator.is_public_policy(secure_policy) is False


def test_s3_acl_validation():
    """Test canned ACL validation."""
    assert S3ACLValidator.validate_acl("private") is True
    assert S3ACLValidator.validate_acl("public-read") is False
    assert S3ACLValidator.validate_acl("public-read-write") is False
    assert S3ACLValidator.validate_acl("authenticated-read") is False


def test_secure_bucket_manager():
    """Test SecureS3BucketManager validation and sanitization."""
    config = S3BucketConfig(
        bucket_name="insecure-bucket",
        block_public_acls=False,
        ignore_public_acls=False,
        block_public_policy=False,
        restrict_public_buckets=False,
        canned_acl="public-read"
    )
    manager = SecureS3BucketManager(config)
    is_secure, issues = manager.validate_security()
    assert not is_secure
    assert len(issues) >= 4

    manager.sanitize_config()
    is_secure_after, issues_after = manager.validate_security()
    assert is_secure_after
    assert len(issues_after) == 0
