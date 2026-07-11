import boto3

def get_s3_client():
    session = boto3.Session()
    return session.client('s3')

# Usage example
client = get_s3_client()
response = client.list_buckets()
print(response)