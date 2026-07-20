+ import json
+ from botocore.exceptions import ClientError
+ 
+ def secure_bucket(bucket_name: str) -> None:
+     """Apply security best practices to an S3 bucket."""
+     s3 = boto3.client('s3')
+     try:
+         # Block all public access (most effective defense)
+         s3.put_public_access_block(
+             Bucket=bucket_name,
+             PublicAccessBlockConfiguration={
+                 'BlockPublicAcls': True,
+                 'IgnorePublicAcls': True,
+                 'BlockPublicPolicy': True,
+                 'RestrictPublicBuckets': True
+             }
+         )
+         # Deny any public access via bucket policy (defense in depth)
+         deny_policy = {
+             "Version": "2012-10-17",
+             "Statement": [
+                 {
+                     "Effect": "Deny",
+                     "Principal": "*",
+                     "Action": "s3:*",
+                     "Resource": [
+                         f"arn:aws:s3:::{bucket_name}",
+                         f"arn:aws:s3:::{bucket_name}/*"
+                     ],
+                     "Condition": {
+                         "Bool": {
+                             "aws:SecureTransport": "false"
+                         }
+                     }
+                 }
+             ]
+         }
+         s3.put_bucket_policy(Bucket=bucket_name, Policy=json.dumps(deny_policy))
+     except ClientError as e:
+         print(f"Failed to secure bucket {bucket_name}: {e}")
+ 
  # Existing bucket creation code
  s3.create_bucket(Bucket=bucket_name)
+ secure_bucket(bucket_name)   # <-- add this line after bucket creation