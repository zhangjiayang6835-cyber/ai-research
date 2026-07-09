"""
Fix for: AWS IAM Privilege Escalation via PassRole + EC2

Vulnerability
-------------
An IAM policy grants both ``iam:PassRole`` (often with ``Resource: "*"``) and
``ec2:RunInstances``. An attacker holding these permissions can:

    1. Launch an EC2 instance (``ec2:RunInstances``).
    2. Attach an arbitrary, highly-privileged IAM role to that instance via
       ``iam:PassRole`` (unrestricted because the policy has no Resource
       whitelist or conditions).
    3. Use a ``user-data`` script to curl the Instance Metadata Service
       (IMDS) and retrieve temporary credentials for the passed role.
    4. Use those credentials to escalate privileges far beyond the
       attacker's original grant.

Root cause: the PassRole statement has no Resource whitelist, no
``iam:PassedToService`` condition restricting which AWS service the role may
be passed to, and no ``aws:SourceArn`` condition binding the action to a
specific, trusted calling context.

Fix strategy
------------
1. **Role ARN whitelist** — ``iam:PassRole`` ``Resource`` must be an explicit
   list of approved role ARNs, never ``"*"``.
2. **Service restriction** — a ``StringEquals`` condition on
   ``iam:PassedToService`` pins the passed role to ``ec2.amazonaws.com`` only,
   preventing reuse of the grant against other services (Lambda, ECS, etc.).
3. **aws:SourceArn condition** — requires the PassRole call to originate from
   an approved calling ARN (e.g. a specific automation role / launch
   template / CI pipeline role), closing the confused-deputy gap.
4. **No wildcard Resource** anywhere in the sensitive statements.

This module both *generates* a hardened policy document and *validates* an
arbitrary policy document against these rules, so it can be used in CI to
prevent regressions.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Iterable

# ---------------------------------------------------------------------------
# 1. Policy generation
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PassRolePolicyConfig:
    """Configuration for generating a hardened PassRole + RunInstances policy."""

    # Explicit whitelist of role ARNs that may be passed to EC2. NEVER "*".
    allowed_role_arns: tuple[str, ...]
    # The AWS service the role may be passed to (restricts reuse elsewhere).
    passed_to_service: str = "ec2.amazonaws.com"
    # The ARN(s) of the trusted caller (e.g. CI/automation role) allowed to
    # invoke PassRole. Bound via aws:SourceArn.
    allowed_source_arns: tuple[str, ...] = field(default_factory=tuple)
    # Explicit resource ARNs/patterns for ec2:RunInstances (never "*").
    allowed_ec2_resource_arns: tuple[str, ...] = (
        "arn:aws:ec2:*:*:instance/*",
        "arn:aws:ec2:*:*:volume/*",
        "arn:aws:ec2:*:*:network-interface/*",
        "arn:aws:ec2:*:*:subnet/*",
        "arn:aws:ec2:*:*:security-group/*",
        "arn:aws:ec2:*::image/*",
        "arn:aws:ec2:*::snapshot/*",
        "arn:aws:ec2:*:*:key-pair/*",
    )

    def __post_init__(self) -> None:  # pragma: no cover - trivial guards
        if not self.allowed_role_arns:
            raise ValueError("allowed_role_arns must not be empty")
        if "*" in self.allowed_role_arns:
            raise ValueError("allowed_role_arns must not contain a wildcard")
        if "*" in self.allowed_ec2_resource_arns:
            raise ValueError("allowed_ec2_resource_arns must not contain a wildcard")
        if not self.allowed_source_arns:
            raise ValueError(
                "allowed_source_arns must not be empty - aws:SourceArn is required"
            )


def generate_hardened_passrole_policy(config: PassRolePolicyConfig) -> dict[str, Any]:
    """Build a least-privilege IAM policy document that fixes the
    PassRole + RunInstances privilege-escalation vector."""

    pass_role_statement: dict[str, Any] = {
        "Sid": "RestrictedPassRoleToEC2",
        "Effect": "Allow",
        "Action": "iam:PassRole",
        "Resource": list(config.allowed_role_arns),
        "Condition": {
            "StringEquals": {
                "iam:PassedToService": config.passed_to_service,
                "aws:SourceArn": list(config.allowed_source_arns)
                if len(config.allowed_source_arns) > 1
                else config.allowed_source_arns[0],
            }
        },
    }

    run_instances_statement: dict[str, Any] = {
        "Sid": "ScopedRunInstances",
        "Effect": "Allow",
        "Action": "ec2:RunInstances",
        "Resource": list(config.allowed_ec2_resource_arns),
    }

    return {
        "Version": "2012-10-17",
        "Statement": [pass_role_statement, run_instances_statement],
    }


# ---------------------------------------------------------------------------
# 2. Policy validation
# ---------------------------------------------------------------------------


class IAMPolicyValidationError(ValueError):
    """Raised (or collected) when a policy document violates the fix's rules."""

    def __init__(self, message: str, findings: Iterable[str] | None = None):
        super().__init__(message)
        self.findings: tuple[str, ...] = tuple(findings or [])


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def validate_passrole_policy(policy: dict[str, Any]) -> list[str]:
    """Validate an IAM policy document against the PassRole hardening rules.

    Returns a list of human-readable findings. An empty list means the
    policy passes all checks (PassRole limited to a Role ARN whitelist, no
    wildcard Resource, and an ``aws:SourceArn`` condition present).
    """
    findings: list[str] = []

    statements = _as_list(policy.get("Statement"))
    if not statements:
        return ["policy has no Statement entries"]

    pass_role_statements = []
    for idx, stmt in enumerate(statements):
        if not isinstance(stmt, dict):
            continue
        actions = {a.lower() for a in _as_list(stmt.get("Action"))}
        resources = _as_list(stmt.get("Resource"))

        if stmt.get("Effect") != "Allow":
            continue

        # --- Wildcard resource check (applies to any Allow statement) ---
        if any(r == "*" for r in resources):
            findings.append(
                f"Statement[{idx}] uses wildcard Resource '*' "
                f"(actions={sorted(actions)})"
            )

        if "iam:passrole" in actions:
            pass_role_statements.append((idx, stmt))

    if not pass_role_statements:
        # No PassRole statement present - nothing further to validate for it.
        return findings

    for idx, stmt in pass_role_statements:
        resources = _as_list(stmt.get("Resource"))
        if not resources or any(r == "*" for r in resources):
            findings.append(
                f"PassRole Statement[{idx}] must whitelist explicit Role ARNs "
                f"(found: {resources})"
            )

        condition = stmt.get("Condition", {})
        string_equals = condition.get("StringEquals", {}) if isinstance(condition, dict) else {}

        passed_to_service = string_equals.get("iam:PassedToService")
        if not passed_to_service:
            findings.append(
                f"PassRole Statement[{idx}] is missing an "
                f"'iam:PassedToService' condition restricting the target service"
            )

        source_arn = string_equals.get("aws:SourceArn")
        if not source_arn:
            findings.append(
                f"PassRole Statement[{idx}] is missing the required "
                f"'aws:SourceArn' condition key"
            )

    return findings


def assert_policy_is_hardened(policy: dict[str, Any]) -> None:
    """Raise :class:`IAMPolicyValidationError` if the policy is vulnerable."""
    findings = validate_passrole_policy(policy)
    if findings:
        raise IAMPolicyValidationError(
            "IAM policy violates PassRole privilege-escalation protections",
            findings=findings,
        )


# ---------------------------------------------------------------------------
# 3. Self-tests - run: python fixes/iam_passrole_privesc_fix.py
# ---------------------------------------------------------------------------


def _run_self_tests() -> None:
    # 1. The classic vulnerable policy: wildcard PassRole + RunInstances.
    vulnerable_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "VulnerablePassRole",
                "Effect": "Allow",
                "Action": "iam:PassRole",
                "Resource": "*",
            },
            {
                "Sid": "VulnerableRunInstances",
                "Effect": "Allow",
                "Action": "ec2:RunInstances",
                "Resource": "*",
            },
        ],
    }
    findings = validate_passrole_policy(vulnerable_policy)
    assert findings, "vulnerable policy must be flagged"
    assert any("wildcard Resource" in f for f in findings)
    assert any("whitelist explicit Role ARNs" in f for f in findings)
    assert any("iam:PassedToService" in f for f in findings)
    assert any("aws:SourceArn" in f for f in findings)
    try:
        assert_policy_is_hardened(vulnerable_policy)
    except IAMPolicyValidationError:
        pass
    else:  # pragma: no cover
        raise AssertionError("vulnerable policy passed validation")

    # 2. Generate a hardened policy and confirm it passes validation cleanly.
    config = PassRolePolicyConfig(
        allowed_role_arns=(
            "arn:aws:iam::123456789012:role/app-ec2-instance-role",
        ),
        allowed_source_arns=(
            "arn:aws:iam::123456789012:role/deployment-automation-role",
        ),
    )
    hardened_policy = generate_hardened_passrole_policy(config)
    findings = validate_passrole_policy(hardened_policy)
    assert not findings, f"hardened policy should have no findings, got: {findings}"
    assert_policy_is_hardened(hardened_policy)  # must not raise

    # 3. Removing aws:SourceArn from the hardened policy must fail validation.
    broken_policy = json.loads(json.dumps(hardened_policy))  # deep copy
    del broken_policy["Statement"][0]["Condition"]["StringEquals"]["aws:SourceArn"]
    findings = validate_passrole_policy(broken_policy)
    assert any("aws:SourceArn" in f for f in findings)

    # 4. Wildcard Role ARN in PassRole Resource must fail validation.
    broken_policy2 = json.loads(json.dumps(hardened_policy))
    broken_policy2["Statement"][0]["Resource"] = "*"
    findings = validate_passrole_policy(broken_policy2)
    assert any("whitelist explicit Role ARNs" in f or "wildcard Resource" in f for f in findings)

    # 5. Config construction must reject wildcard/empty inputs up front.
    for bad_kwargs in (
        dict(allowed_role_arns=(), allowed_source_arns=("arn:aws:iam::1:role/x",)),
        dict(allowed_role_arns=("*",), allowed_source_arns=("arn:aws:iam::1:role/x",)),
        dict(allowed_role_arns=("arn:aws:iam::1:role/x",), allowed_source_arns=()),
    ):
        try:
            PassRolePolicyConfig(**bad_kwargs)
        except ValueError:
            pass
        else:  # pragma: no cover
            raise AssertionError(f"invalid config accepted: {bad_kwargs}")

    print("iam_passrole_privesc_fix: all 5 self-tests passed")


if __name__ == "__main__":  # pragma: no cover
    _run_self_tests()
