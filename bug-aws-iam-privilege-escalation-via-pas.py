#!/usr/bin/env python3
"""
AWS IAM Privilege Escalation via PassRole + EC2 - Detection and Remediation Tool

This script detects IAM principals (users/roles) that have the iam:PassRole permission
combined with EC2 instance creation permissions (ec2:RunInstances), which can lead
to privilege escalation. It also provides remediation guidance and optional
automated remediation by attaching a restrictive policy.

Vulnerability: An attacker with iam:PassRole and ec2:RunInstances permissions can
launch an EC2 instance with an elevated IAM role attached, effectively escalating
their privileges by assuming the attached role's permissions.

Author: Security Research Team
Issue: https://github.com/zhangjiayang6835-cyber/ai-research/issues/1502
"""

import argparse
import json
import sys
import time
from typing import Dict, List, Optional, Any, Set, Tuple

try:
    import boto3
    from botocore.exceptions import ClientError, NoCredentialsError, BotoCoreError
except ImportError:
    print("[ERROR] boto3 is required. Install it with: pip install boto3")
    sys.exit(1)


class IAMPrivilegeEscalationScanner:
    """
    Scans AWS IAM policies for PassRole + EC2 privilege escalation vulnerabilities.
    
    This class analyzes IAM users and roles to identify principals that have both
    iam:PassRole and ec2:RunInstances permissions, which could allow privilege
    escalation by attaching an elevated role to a new EC2 instance.
    """

    # Actions that indicate potential privilege escalation when combined with PassRole
    ESCALATION_ACTIONS = {
        'ec2': ['ec2:RunInstances'],
        'lambda': ['lambda:CreateFunction', 'lambda:UpdateFunctionCode'],
        'ecs': ['ecs:RegisterTaskDefinition'],
        'cloudformation': ['cloudformation:CreateStack'],
        'datapipeline': ['datapipeline:CreatePipeline'],
    }

    # Critical roles that should never be passable by non-admin principals
    CRITICAL_ROLE_PATTERNS = [
        'admin',
        'AdministratorAccess',
        'PowerUserAccess',
        'root',
        'FullAccess',
    ]

    def __init__(self, profile: Optional[str] = None, region: str = 'us-east-1'):
        """
        Initialize the scanner with AWS credentials and configuration.
        
        Args:
            profile: AWS profile name from ~/.aws/credentials
            region: AWS region for API calls
        """
        self.region = region
        self.session = self._create_session(profile, region)
        self.iam_client = self.session.client('iam')
        self.sts_client = self.session.client('sts')
        self.account_id: Optional[str] = None
        self.findings: List[Dict] = []
        self.scanned_principals: Set[str] = set()

    def _create_session(self, profile: Optional[str], region: str) -> boto3.Session:
        """
        Create a boto3 session with the specified profile and region.
        
        Args:
            profile: AWS profile name (optional)
            region: AWS region name
            
        Returns:
            boto3.Session: Configured session object
            
        Raises:
            SystemExit: If credentials are not available
        """
        try:
            if profile:
                session = boto3.Session(profile_name=profile, region_name=region)
            else:
                session = boto3.Session(region_name=region)
            
            # Verify credentials are available
            sts = session.client('sts')
            identity = sts.get_caller_identity()
            self.account_id = identity.get('Account')
            print(f"[INFO] Authenticated as: {identity.get('Arn')}")
            print(f"[INFO] Account ID: {self.account_id}")
            return session
        except NoCredentialsError:
            print("[ERROR] No AWS credentials found. Configure credentials or use --profile.")
            sys.exit(1)
        except ClientError as e:
            print(f"[ERROR] Failed to authenticate: {e}")
            sys.exit(1)

    def get_all_users(self) -> List[Dict]:
        """
        Retrieve all IAM users in the account using pagination.
        
        Returns:
            List of user dictionaries containing UserName, Arn, UserId, etc.
        """
        users = []
        try:
            paginator = self.iam_client.get_paginator('list_users')
            for page in paginator.paginate():
                users.extend(page.get('Users', []))
            print(f"[INFO] Found {len(users)} IAM users")
            return users
        except ClientError as e:
            print(f"[ERROR] Failed to list users: {e}")
            return []

    def get_all_roles(self) -> List[Dict]:
        """
        Retrieve all IAM roles in the account using pagination.
        
        Returns:
            List of role dictionaries containing RoleName, Arn, RoleId, etc.
        """
        roles = []
        try:
            paginator = self.iam_client.get_paginator('list_roles')
            for page in paginator.paginate():
                roles.extend(page.get('Roles', []))
            print(f"[INFO] Found {len(roles)} IAM roles")
            return roles
        except ClientError as e:
            print(f"[ERROR] Failed to list roles: {e}")
            return []

    def get_managed_policies(self, principal_arn: str, principal_type: str) -> List[Dict]:
        """
        Get all managed policies attached to a principal (user or role).
        
        Args:
            principal_arn: ARN of the principal
            principal_type: 'user' or 'role'
            
        Returns:
            List of policy document dictionaries
        """
        policies = []
        name_key = 'UserName' if principal_type == 'user' else 'RoleName'
        principal_name = principal_arn.split('/')[-1]

        try:
            if principal_type == 'user':
                attached = self.iam_client.list_attached_user_policies(
                    UserName=principal_name
                )
            else:
                attached = self.iam_client.list_attached_role_policies(
                    RoleName=principal_name
                )

            for policy in attached.get('AttachedPolicies', []):
                policy_arn = policy['PolicyArn']
                version = self.iam_client.get_policy(PolicyArn=policy_arn)['Policy']
                default_version = version['DefaultVersionId']
                policy_doc = self.iam_client.get_policy_version(
                    PolicyArn=policy_arn,
                    VersionId=default_version
                )
                policies.append(policy_doc['PolicyVersion']['Document'])

        except ClientError as e:
            print(f"[WARN] Failed to get managed policies for {principal_name}: {e}")

        return policies

    def get_inline_policies(self, principal_arn: str, principal_type: str) -> List[Dict]:
        """
        Get all inline policies for a principal (user or role).
        
        Args:
            principal_arn: ARN of the principal
            principal_type: 'user' or 'role'
            
        Returns:
            List of policy document dictionaries
        """
        policies = []
        principal_name = principal_arn.split('/')[-1]

        try:
            if principal_type == 'user':
                inline_policies = self.iam_client.list_user_policies(
                    UserName=principal_name
                )
                for policy_name in inline_policies.get('PolicyNames', []):
                    result = self.iam_client.get_user_policy(
                        UserName=principal_name,
                        PolicyName=policy_name
                    )
                    policies.append(result['PolicyDocument'])
            else:
                inline_policies = self.iam_client.list_role_policies(
                    RoleName=principal_name
                )
                for policy_name in inline_policies.get('PolicyNames', []):
                    result = self.iam_client.get_role_policy(
                        RoleName=principal_name,
                        PolicyName=policy_name
                    )
                    policies.append(result['PolicyDocument'])

        except ClientError as e:
            print(f"[WARN] Failed to get inline policies for {principal_name}: {e}")

        return policies

    def analyze_policy_document(self, policy_doc: Dict) -> Dict:
        """
        Analyze a single policy document for PassRole and escalation permissions.
        
        Args:
            policy_doc: IAM policy document dictionary
            
        Returns:
            Dictionary with analysis results including:
                - has_pass_role: bool
                - pass_role_targets: List[str]
                - has_ec2_run_instances: bool
                - has_lambda_create: bool
                - has_cloudformation_create: bool
                - risk_level: str
                - findings: List[str]
        """
        result = {
            'has_pass_role': False,
            'pass_role_targets': [],
            'has_ec2_run_instances': False,
            'has_lambda_create': False,
            'has_cloudformation_create': False,
            'has_ecs_register': False,
            'has_datapipeline_create': False,
            'risk_level': 'LOW',
            'findings': [],
        }

        statements = policy_doc.get('Statement', [])
        if not isinstance(statements, list):
            statements = [statements]

        for statement in statements:
            if statement.get('Effect', '') != 'Allow':
                continue

            actions = statement.get('Action', [])
            if isinstance(actions, str):
                actions = [actions]

            actions_lower = [a.lower() for a in actions]

            # Check for iam:PassRole
            if any(a in ['iam:passrole', 'iam:*', '*'] for a in actions_lower):
                result['has_pass_role'] = True
                resources = statement.get('Resource