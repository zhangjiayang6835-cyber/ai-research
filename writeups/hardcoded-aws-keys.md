# Hardcoded AWS Keys in Public Artifact �� Cloud Takeover

## Vulnerability Summary

CI/CD build artifacts (Docker images, npm packages) contain hardcoded AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY. Attackers extracting these credentials from public registries can access and control the entire cloud infrastructure.

## Attack Scenario

1. Developer hardcodes AWS credentials in Dockerfile or .env committed to repo
2. Docker image is built and pushed to a public registry (Docker Hub, ECR public)
3. Attacker pulls the image and inspects layers: `docker history --no-trunc image:tag`
4. Attacker extracts AWS credentials from environment variables or embedded config
5. Attacker uses credentials to access S3 buckets, databases, IAM, and other AWS services
6. Full cloud environment takeover

## Impact

- **Cloud infrastructure compromise**: Full access to AWS account
- **Data breach**: Access to all S3, RDS, and other data stores
- **Lateral movement**: Create new IAM users/roles for persistent access
- **Financial damage**: Unauthorized resource usage (crypto mining, data transfer)

## Remediation

```dockerfile
# WRONG: Hardcoded credentials
ENV AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
ENV AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY

# CORRECT: Use IAM Role (EKS/ECS/EC2) or STS temporary credentials
# No credentials in Dockerfile at all
# At runtime, the SDK auto-discovers IAM Role from instance metadata

# For local dev, use ~/.aws/credentials or environment variables passed at runtime:
# docker run -e AWS_ROLE_ARN=arn:aws:iam::123:role/app-role ...
```

Add CI secret scanning:
```yaml
# .github/workflows/security.yml
- name: Scan for secrets
  uses: trufflesecurity/trufflehog@main
  with:
    path: .
```

## Checklist

- [x] Uses IAM Role / STS temporary credentials
- [x] CI pipeline includes secret scanning step
- [x] All hardcoded credentials removed from code and artifacts
