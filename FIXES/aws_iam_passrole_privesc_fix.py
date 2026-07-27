"""
Fix: AWS IAM Privilege Escalation via PassRole + EC2 (Issue #1502)
===================================================================
Vulnerability
-------------
An IAM policy that grants `iam:PassRole` with wildcard resources (`Resource: "*"`) 
alongside `ec2:RunInstances` allows low-privileged users to escalate privileges. 
An attacker can launch an EC2 instance associated with an Administrator IAM Role 
and retrieve admin credentials via IMDS.

Fix
---
1. Restrict `iam:PassRole` to explicitly specified, approved Role ARNs.
2. Require `iam:PassedToService` condition matching `ec2.amazonaws.com`.
3. Provide automated IAM Policy Security Validator enforcing least privilege.
"""

import json
from typing import Dict, List, Any


class IAMPolicyValidationError(Exception):
    """Raised when an IAM policy violates PassRole security rules."""
    pass


class AWSIAMPolicyValidator:
    """Validator for AWS IAM policies to prevent PassRole privilege escalation."""

    ALLOWED_SERVICES = {"ec2.amazonaws.com", "ecs-tasks.amazonaws.com", "lambda.amazonaws.com"}

    @staticmethod
    def validate_policy(policy_doc: Dict[str, Any]) -> List[str]:
        """
        Validates IAM Policy Statements for PassRole vulnerabilities.
        Returns a list of violation messages.
        """
        violations = []
        statements = policy_doc.get("Statement", [])
        if isinstance(statements, dict):
            statements = [statements]

        for idx, stmt in enumerate(statements):
            if stmt.get("Effect") != "Allow":
                continue

            actions = stmt.get("Action", [])
            if isinstance(actions, str):
                actions = [actions]

            has_pass_role = any(a == "iam:PassRole" or a == "iam:*" or a == "*" for a in actions)
            if not has_pass_role:
                continue

            resources = stmt.get("Resource", [])
            if isinstance(resources, str):
                resources = [resources]

            # Check 1: Disallow wildcard Resource for iam:PassRole
            if "*" in resources or any(r.endswith(":role/*") for r in resources):
                violations.append(
                    f"Statement [{idx}]: iam:PassRole must not use wildcard Resource '*'. "
                    f"Restrict to explicit Role ARNs."
                )

            # Check 2: Require iam:PassedToService Condition
            conditions = stmt.get("Condition", {})
            string_equals = conditions.get("StringEquals", {})
            passed_service = string_equals.get("iam:PassedToService")

            if not passed_service:
                violations.append(
                    f"Statement [{idx}]: iam:PassRole requires 'iam:PassedToService' Condition."
                )
            elif isinstance(passed_service, str) and passed_service not in AWSIAMPolicyValidator.ALLOWED_SERVICES:
                violations.append(
                    f"Statement [{idx}]: Unapproved PassedToService '{passed_service}'."
                )

        return violations

    @staticmethod
    def create_secure_pass_role_statement(approved_role_arns: List[str], target_service: str = "ec2.amazonaws.com") -> Dict[str, Any]:
        """Generates a secure, hardened iam:PassRole policy statement."""
        if any("*" in arn for arn in approved_role_arns):
            raise IAMPolicyValidationError("Approved role ARNs cannot contain wildcards.")

        return {
            "Sid": "SecureEC2PassRole",
            "Effect": "Allow",
            "Action": ["iam:PassRole"],
            "Resource": approved_role_arns,
            "Condition": {
                "StringEquals": {
                    "iam:PassedToService": target_service
                }
            }
        }


if __name__ == "__main__":
    vulnerable_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["ec2:RunInstances", "iam:PassRole"],
                "Resource": "*"
            }
        ]
    }

    validator = AWSIAMPolicyValidator()
    issues = validator.validate_policy(vulnerable_policy)
    print(f"Vulnerability Audit Output ({len(issues)} issues found):")
    for issue in issues:
        print(f"  - {issue}")

    secure_statement = validator.create_secure_pass_role_statement(
        approved_role_arns=["arn:aws:iam::123456789012:role/AppEC2Role"]
    )
    print("\nSecure Statement Generated:")
    print(json.dumps(secure_statement, indent=2))
