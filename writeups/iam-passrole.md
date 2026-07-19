# AWS IAM Privilege Escalation via PassRole + EC2

## Description
An IAM role with iam:PassRole and ec2:RunInstances permissions can pass a more privileged role to a new EC2 instance, then access it to assume that role's permissions.

## Impact
Full AWS account compromise, data exfiltration, persistence.

## Remediation
Restrict iam:PassRole to specific roles using conditions, implement least privilege, use service control policies, monitor with CloudTrail.