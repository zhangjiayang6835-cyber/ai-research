# S3 Bucket Misconfiguration �� Mass Data Leak

## Vulnerability Summary

S3 bucket policy set to public-read allows anyone on the internet to list and download all stored objects, exposing sensitive user data, backups, and configuration files.

## Attack Scenario

1. Bucket policy includes `"Effect": "Allow", "Principal": "*"` with `s3:GetObject` and `s3:ListBucket`
2. Attacker discovers bucket name (via subdomain enumeration, source code, or error messages)
3. Attacker runs `aws s3 ls s3://bucket-name --no-sign-request`
4. All objects are listed and downloadable without authentication

## Impact

- **Mass data exfiltration**: All bucket contents exposed
- **PII leak**: User data, documents, and backups accessible
- **Regulatory fines**: GDPR/CCPA violations for exposed personal data

## Remediation

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyInsecureTransport",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": ["arn:aws:s3:::my-bucket", "arn:aws:s3:::my-bucket/*"],
      "Condition": { "Bool": { "aws:SecureTransport": "false" } }
    },
    {
      "Sid": "AllowAuthenticatedRead",
      "Effect": "Allow",
      "Principal": { "AWS": "arn:aws:iam::123456789012:role/app-role" },
      "Action": ["s3:GetObject", "s3:ListBucket"],
      "Resource": ["arn:aws:s3:::my-bucket", "arn:aws:s3:::my-bucket/*"]
    }
  ]
}
```

Enable Block Public Access at the bucket and account level. Enable S3 Server Access Logging.

## Checklist

- [x] No wildcard principal for read access
- [x] Block Public Access enabled
- [x] Access restricted to specific IAM roles
- [x] TLS-only transport enforced
