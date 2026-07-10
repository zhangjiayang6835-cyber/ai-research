"""
S3 Bucket Misconfiguration → Mass Data Leak Fix
Bounty #801 ($120)
=========================================
Vulnerability: S3 bucket policy has Principal: "*" + Action: "s3:GetObject".
Anyone can enumerate and download objects.

Fix: Least privilege + Block Public Access + Pre-signed URLs.
"""


class SecureS3Config:
    """
    Secure S3 bucket configuration.
    Prevents public data leaks.
    """

    # Secure bucket policy template
    SECURE_BUCKET_POLICY = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Deny",
                "Principal": "*",
                "Action": "s3:*",
                "Resource": [
                    "arn:aws:s3:::example-bucket",
                    "arn:aws:s3:::example-bucket/*"
                ],
                "Condition": {
                    "Bool": {
                        "aws:SecureTransport": "false"
                    }
                }
            }
        ]
    }

    # Secure bucket policy for specific IAM roles (no wildcard Principal)
    SECURE_ACCESS_POLICY = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {
                    "AWS": "arn:aws:iam::123456789012:role/AppRole"
                },
                "Action": [
                    "s3:GetObject",
                    "s3:PutObject"
                ],
                "Resource": "arn:aws:s3:::example-bucket/uploads/*"
            }
        ]
    }

    @staticmethod
    def enable_block_public_access() -> dict:
        """Enable S3 Block Public Access settings."""
        return {
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        }

    @staticmethod
    def generate_presigned_url(bucket: str, key: str,
                               expiration: int = 3600) -> str:
        """
        Generate pre-signed URL for temporary access.
        Instead of public read access.
        """
        import boto3
        from botocore.config import Config

        s3 = boto3.client(
            "s3",
            config=Config(signature_version="s3v4"),
        )
        return s3.generate_presigned_url(
            "get_object",
            Params={"Bucket": bucket, "Key": key},
            ExpiresIn=expiration,
        )

    @staticmethod
    def validate_bucket_policy(policy: dict) -> list:
        """Validate bucket policy for security issues."""
        issues = []

        statements = policy.get("Statement", [])
        for stmt in statements:
            principal = stmt.get("Principal", {})
            effect = stmt.get("Effect", "Deny")
            action = stmt.get("Action", [])
            resource = stmt.get("Resource", [])

            # Check for wildcard Principal
            if principal == "*" or principal.get("AWS") == "*":
                if effect == "Allow":
                    issues.append("Wildcard Principal with Allow effect")

            # Check for broad actions
            if isinstance(action, str) and action == "s3:*":
                if effect == "Allow":
                    issues.append("Wildcard Action (s3:*) with Allow effect")

            # Check for broad resources
            if isinstance(resource, str) and resource.endswith("/*"):
                issues.append("Broad resource pattern")

        return issues


# ========== Usage Example ==========
if __name__ == "__main__":
    print("=== S3 Bucket Misconfiguration Prevention ===")
    print()

    # Vulnerable policy
    vulnerable_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": "*",
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::example-bucket/*"
            }
        ]
    }

    print("Vulnerable policy:")
    print(f"  Principal: *")
    print(f"  Action: s3:GetObject")
    print(f"  → Anyone can read all objects!")
    print()

    issues = SecureS3Config.validate_bucket_policy(vulnerable_policy)
    print(f"Issues found: {issues}")
    print()

    print("=== Secure Configuration ===")
    print("1. Block Public Access:")
    for k, v in SecureS3Config.enable_block_public_access().items():
        print(f"   ✓ {k} = {v}")
    print()
    print("2. Use pre-signed URLs instead of public read")
    print("3. No wildcard Principal in policies")
    print("4. Least privilege IAM roles")