import boto3
import json
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def get_iam_client():
    return boto3.client('iam')

def list_roles(iam_client):
    paginator = iam_client.get_paginator('list_roles')
    for page in paginator.paginate():
        for role in page['Roles']:
            yield role

def get_inline_policies_for_role(iam_client, role_name):
    paginator = iam_client.get_paginator('list_role_policies')
    for page in paginator.paginate(RoleName=role_name):
        for policy_name in page['PolicyNames']:
            yield policy_name

def get_policy_document(iam_client, role_name, policy_name):
    response = iam_client.get_role_policy(RoleName=role_name, PolicyName=policy_name)
    return response['PolicyDocument']

def update_policy_document(iam_client, role_name, policy_name, new_policy_document):
    try:
        iam_client.put_role_policy(
            RoleName=role_name,
            PolicyName=policy_name,
            PolicyDocument=json.dumps(new_policy_document)
        )
        logger.info(f"Updated policy {policy_name} for role {role_name}")
    except Exception as e:
        logger.error(f"Failed to update policy {policy_name} for role {role_name}: {e}")

def main(roles_to_deny=None):
    iam_client = get_iam_client()
    
    for role in list_roles(iam_client):
        role_name = role['RoleName']
        for policy_name in get_inline_policies_for_role(iam_client, role_name):
            policy_document = get_policy_document(iam_client, role_name, policy_name)
            
            # Check if the policy allows iam:PassRole
            if 'Statement' in policy_document:
                for statement in policy_document['Statement']:
                    if 'Action' in statement and 'iam:PassRole' in statement['Action']:
                        # Create a new statement to deny iam:PassRole for specific roles
                        new_statement = {
                            "Sid": "DenyPassRole",
                            "Effect": "Deny",
                            "Action": "iam:PassRole",
                            "Resource": [f"arn:aws:iam:::{role_name}" for role_name in roles_to_deny] if roles_to_deny else ["*"]
                        }
                        
                        # Add the new statement to the policy document
                        if 'Statement' not in policy_document:
                            policy_document['Statement'] = []
                        policy_document['Statement'].append(new_statement)
                        
                        # Update the policy document
                        update_policy_document(iam_client, role_name, policy_name, policy_document)

if __name__ == "__main__":
    # Example: Specify roles to deny iam:PassRole
    roles_to_deny = ['specific-role-1','specific-role-2']
    main(roles_to_deny)