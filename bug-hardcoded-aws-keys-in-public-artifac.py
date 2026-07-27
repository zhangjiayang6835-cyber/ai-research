#!/usr/bin/env python3
"""
Bug Fix: Hardcoded AWS Keys in Public Artifact -> Cloud Takeover ($180)

This module resolves the vulnerability by:
1. Utilizing IAM Role / STS temporary credentials instead of long-lived keys.
2. Providing a CI gate (secrets scanner) to detect hardcoded AWS credentials in artifacts.
3. Assisting in the removal of hardcoded credentials by scrubbing configuration files.

Issue URL: https://github.com/zhangjiayang6835-cyber/ai-research/issues/1477
"""

import os
import re
import sys
import json
import boto3
import logging
from botocore.exceptions import ClientError, NoCredentialsError, BotoCoreError
from typing import Optional, Dict, Any, List, Tuple

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Regular expressions for detecting hardcoded AWS credentials
AWS_ACCESS_KEY_ID_REGEX = re.compile(r'(?<![A-Z0-9])AKIA[0-9A-Z]{16}(?![A-Z0-9])')
AWS_SECRET_ACCESS_KEY_REGEX = re.compile(r'(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])')

# Known false positive patterns to ignore during scanning
FALSE_POSITIVE_PATTERNS = [
    re.compile(r'EXAMPLE|PLACEHOLDER|YOUR_KEY|XXXX', re.IGNORECASE),
    re.compile(r'^\s*#', re.MULTILINE)  # Comments
]


class AWSCredentialManager:
    """Manages AWS credentials using IAM Roles and STS temporary credentials."""

    def __init__(self, role_arn: Optional[str] = None, session_name: str = "ai-research-session"):
        """
        Initialize the credential manager.

        Args:
            role_arn: Optional IAM Role ARN to assume. If None, uses environment/EC2 metadata credentials.
            session_name: The session name for STS assumed roles.
        """
        self.role_arn = role_arn
        self.session_name = session_name
        self._client: Optional[boto3.client] = None

    def _validate_no_hardcoded_keys(self) -> None:
        """Ensure no hardcoded AWS keys are present in the environment before proceeding."""
        access_key = os.environ.get('AWS_ACCESS_KEY_ID', '')
        secret_key = os.environ.get('AWS_SECRET_ACCESS_KEY', '')

        if access_key and access_key.startswith('AKIA') and not os.environ.get('AWS_SESSION_TOKEN'):
            logger.warning(
                "Long-lived AWS_ACCESS_KEY_ID detected in environment variables. "
                "Please use IAM roles or STS temporary credentials instead."
            )
            # Do not raise an error to allow local dev, but warn loudly.
            # In strict CI environments, this check can be elevated to an exception.

    def get_credentials(self) -> Dict[str, Any]:
        """
        Retrieve AWS credentials, preferring IAM Role / STS temporary credentials.

        Returns:
            A dictionary containing 'AccessKeyId', 'SecretAccessKey', and 'SessionToken'.

        Raises:
            ClientError: If STS assume role fails.
            NoCredentialsError: If no credentials can be resolved.
        """
        self._validate_no_hardcoded_keys()

        try:
            if self.role_arn:
                logger.info(f"Assuming IAM Role: {self.role_arn}")
                sts_client = boto3.client('sts')
                assumed_role = sts_client.assume_role(
                    RoleArn=self.role_arn,
                    RoleSessionName=self.session_name,
                    DurationSeconds=3600  # 1 hour is standard for temporary credentials
                )
                credentials = assumed_role['Credentials']
                logger.info("Successfully obtained STS temporary credentials.")
                return {
                    'AccessKeyId': credentials['AccessKeyId'],
                    'SecretAccessKey': credentials['SecretAccessKey'],
                    'SessionToken': credentials['SessionToken']
                }
            else:
                # Fallback to IAM Role attached to compute resource (EC2, ECS, EKS, Lambda)
                # or local environment configured via `aws sso login` or `aws configure`
                logger.info("Using default credential provider chain (IAM Role / SSO / Environment).")
                session = boto3.Session()
                creds = session.get_credentials()
                
                if creds is None:
                    raise NoCredentialsError("No AWS credentials could be resolved.")
                
                frozen_creds = creds.get_frozen_credentials()
                return {
                    'AccessKeyId': frozen_creds.access_key,
                    'SecretAccessKey': frozen_creds.secret_key,
                    'SessionToken': frozen_creds.token
                }
                
        except (ClientError, NoCredentialsError, BotoCoreError) as e:
            logger.error(f"Failed to retrieve AWS credentials: {e}")
            raise

    def get_client(self, service_name: str, region_name: str = 'us-east-1') -> boto3.client:
        """
        Get a boto3 client configured with temporary credentials.

        Args:
            service_name: The AWS service name (e.g., 's3', 'ec2').
            region_name: The AWS region.

        Returns:
            A configured boto3 client.
        """
        creds = self.get_credentials()
        return boto3.client(
            service_name,
            aws_access_key_id=creds['AccessKeyId'],
            aws_secret_access_key=creds['SecretAccessKey'],
            aws_session_token=creds['SessionToken'],
            region_name=region_name
        )


class SecretsScanner:
    """CI Gate scanner to detect hardcoded AWS keys in artifacts and source code."""

    def __init__(self, target_path: str):
        """
        Initialize the scanner.

        Args:
            target_path: Directory or file path to scan.
        """
        self.target_path = target_path
        self.violations: List[Tuple[str, int, str]] = []

    def _is_false_positive(self, line: str) -> bool:
        """Check if the line matches known false positive patterns."""
        for pattern in FALSE_POSITIVE_PATTERNS:
            if pattern.search(line):
                return True
        return False

    def scan_file(self, file_path: str) -> List[Tuple[int, str]]:
        """
        Scan a single file for hardcoded AWS credentials.

        Args:
            file_path: Path to the file to scan.

        Returns:
            List of tuples containing (line_number, matched_string).
        """
        violations = []
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line_num, line in enumerate(f, 1):
                    if self._is_false_positive(line):
                        continue
                    
                    # Check for Access Key ID
                    access_key_match = AWS_ACCESS_KEY_ID_REGEX.search(line)
                    if access_key_match:
                        violations.append((line_num, f"AWS_ACCESS_KEY_ID: {access_key_match.group()}"))
                    
                    # Check for Secret Access Key (context-aware: only if near 'secret' or 'aws')
                    # To reduce false positives, we look for 40-char base64 strings near AWS context
                    if re.search(r'aws_secret|secret_access|AWS_SECRET', line, re.IGNORECASE):
                        secret_match = AWS_SECRET_ACCESS_KEY_REGEX.search(line)
                        if secret_match:
                            violations.append((line_num, f"AWS_SECRET_ACCESS_KEY: {secret_match.group()[:4]}..."))
                            
        except Exception as e:
            logger.debug(f"Could not read file {file_path}: {e}")
            
        return violations

    def scan(self) -> bool:
        """
        Scan the target path for hardcoded credentials.

        Returns:
            True if violations are found, False otherwise.
        """
        logger.info(f"Starting secrets scan on: {self.target_path}")
        
        if os.path.isfile(self.target_path):
            file_violations = self.scan_file(self.target_path)
            for line_num, desc in file_violations:
                self.violations.append((self.target_path, line_num, desc))
        elif os.path.isdir(self.target_path):
            for root, dirs, files in os.walk(self.target_path):
                # Skip hidden directories and common non-source dirs
                dirs[:] = [d for d in dirs if not d.startswith('.') and d not in ('node_modules', '__pycache__', 'dist', 'build', '.git')]
                
                for file in files:
                    file_path = os.path.join(root, file)
                    file_violations = self.scan_file(file_path)
                    for line_num, desc in file_violations:
                        self.violations.append((file_path, line_num, desc))
        else:
            logger.error(f"Target path does not exist: {self.target_path}")
            return False

        if self.violations:
            logger.error(f"SECURITY VIOLATION: Found {len(self.violations)} hardcoded credential(s)!")
            for file_path, line_num, desc in self.violations:
                logger.error(f"  -> {file_path}:{line_num} - {desc}")
            return True
        else:
            logger.info("PASS: No hardcoded AWS credentials found.")
            return False


class ConfigSanitizer:
    """Removes hardcoded credentials from configuration files and replaces with environment variables."""

    @staticmethod
    def sanitize_env_file(file_path: str) -> bool:
        """
        Remove hardcoded AWS keys from .env files, replacing with references to environment variables.

        Args:
            file_path: Path to the .env file.

        Returns: