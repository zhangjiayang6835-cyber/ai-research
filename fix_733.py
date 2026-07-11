```python
"""
This module addresses the AWS IAM PassRole privilege escalation issue by implementing restrictive policies.
"""

import boto3

def update_iam_policy():
    """
    Update IAM policy to restrict PassRole and RunInstances operations.
    """
    iam = boto3.client('iam')

    # Define PassRole and RunInstances actions with condition keys
    policy_document = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "PassRoleAndRunInstances",
                "Effect": "Allow",
                "Action": [
                    "iam:PassRole",
                    "ec2:RunInstances"
                ],
                "Resource": "*",
                "Condition": {
                    "StringEquals": {
                        "aws:SourceArn": "arn:aws:lambda:<region>:<account-id>:function:<function-name>"
                    }
                }
            }
        ]
    }

    # Create a new policy with the updated document
    response = iam.create_policy(
        PolicyName='PassRoleAndRunInstancesPolicy',
        Description='Restrict PassRole and RunInstances to specific sources.',
        PolicyDocument=str(policy_document)
    )

    print(f"New IAM Policy Created: {response['Policy']['Arn']}")


def main():
    """
    Main function to execute the policy update.
    """
    update_iam_policy()

if __name__ == "__main__":
    main()
```