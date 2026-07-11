import boto3

s3 = boto3.client('s3')

# Enable S3 Block Public Access
response = s3.put_public_access_block(
    Bucket='your-bucket-name',
    PublicAccessBlockConfiguration={
        'BlockPublicAcls': True,
        'IgnorePublicAcls': True,
        'BlockPublicPolicy': True,
        'RestrictPublicBuckets': True
    }
)

# Update S3 Bucket Policy to remove Principal: "*"
bucket_policy = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "DenyPublicReadAccess",
            "Effect": "Deny",
            "Principal": "*",
            "Action": "s3:GetObject",
            "Resource": f"arn:aws:s3:::your-bucket-name/*",
            "Condition": {
                "Bool": {"aws:SecureTransport": "false"}
            }
        }
    ]
}

response = s3.put_bucket_policy(
    Bucket='your-bucket-name',
    Policy=str(bucket_policy)
)

# Use pre-signed URLs for public access
def get_presigned_url(object_key):
    return s3.generate_presigned_url('get_object', Params={'Bucket': 'your-bucket-name', 'Key': object_key}, ExpiresIn=3600)