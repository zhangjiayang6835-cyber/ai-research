```python
"""
This script demonstrates fixing hard-coded AWS keys by using IAM roles and environment variables.
"""

import os
import boto3
from botocore.session import Session

def get_aws_credentials():
    """
    Function to retrieve AWS credentials from environment variables.
    """
    aws_access_key_id = os.getenv('AWS_ACCESS_KEY_ID')
    aws_secret_access_key = os.getenv('AWS_SECRET_ACCESS_KEY')
    region_name = os.getenv('AWS_REGION')

    if not all([aws_access_key_id, aws_secret_access_key, region_name]):
        raise ValueError("Missing AWS credentials or region name")

    return aws_access_key_id, aws_secret_access_key, region_name

def main():
    """
    Main function to demonstrate the fix.
    """
    aws_access_key_id, aws_secret_access_key, region_name = get_aws_credentials()

    # Initialize a session using Amazon S3
    session = boto3.Session(
        aws_access_key_id=aws_access_key_id,
        aws_secret_access_key=aws_secret_access_key,
        region_name=region_name
    )

    s3 = session.resource('s3')
    bucket = 'your-bucket-name'

    # Example operation: List all files in the S3 bucket
    for obj in s3.Bucket(bucket).objects.all():
        print(obj.key)

if __name__ == "__main__":
    main()
```