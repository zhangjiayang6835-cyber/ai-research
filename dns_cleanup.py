#!/usr/bin/env python3
"""
Script to detect and clean up dangling DNS records (CNAME to S3 buckets) in AWS Route53.
Prevents subdomain takeover by removing records pointing to non-existent S3 buckets.
"""
import boto3
import sys
from botocore.exceptions import ClientError, NoCredentialsError, EndpointConnectionError

def check_s3_bucket_exists(bucket_name):
    """Check if an S3 bucket exists."""
    s3 = boto3.client('s3')
    try:
        s3.head_bucket(Bucket=bucket_name)
        return True
    except ClientError as e:
        # If bucket not found, error code is 404 (NoSuchBucket)
        if e.response['Error']['Code'] == '404':
            return False
        # Other errors (e.g., AccessDenied) are unexpected; treat as bucket exists to be safe
        print(f"Unexpected error checking bucket {bucket_name}: {e}", file=sys.stderr)
        return True

def extract_s3_bucket_from_cname(target):
    """Extract S3 bucket name from a CNAME target like 'bucketname.s3.amazonaws.com' or 'bucketname.s3.us-east-1.amazonaws.com'."""
    # Standard S3 endpoint patterns
    if target.endswith('.s3.amazonaws.com'):
        return target[:-len('.s3.amazonaws.com')]
    # Regional endpoints: bucketname.s3.region.amazonaws.com
    parts = target.split('.')
    if len(parts) >= 4 and parts[-4] == 's3' and parts[-1] == 'amazonaws.com':
        # bucketname.s3.region.amazonaws.com -> bucketname
        return parts[-5]
    return None

def clean_dangling_cname(zone_id, dry_run=True):
    """
    Scan all CNAME records in a Route53 hosted zone and remove those pointing to non-existent S3 buckets.
    :param zone_id: Route53 hosted zone ID (e.g., 'Z1234567890ABCDEF')
    :param dry_run: If True, only print what would be deleted; if False, actually delete.
    """
    route53 = boto3.client('route53')
    try:
        paginator = route53.get_paginator('list_resource_record_sets')
        pages = paginator.paginate(HostedZoneId=zone_id)
    except NoCredentialsError:
        print("AWS credentials not configured.", file=sys.stderr)
        sys.exit(1)
    except EndpointConnectionError:
        print("Could not connect to Route53. Check network/credentials.", file=sys.stderr)
        sys.exit(1)

    records_to_delete = []

    for page in pages:
        for rset in page['ResourceRecordSets']:
            if rset['Type'] != 'CNAME':
                continue
            # Skip NS and SOA (already handled by Route53)
            if rset['Name'] in ['NS', 'SOA']:
                continue

            # CNAME records have exactly one value
            if not rset.get('ResourceRecords'):
                continue
            target = rset['ResourceRecords'][0]['Value']
            bucket_name = extract_s3_bucket_from_cname(target)
            if bucket_name is None:
                continue  # Not an S3 CNAME

            if not check_s3_bucket_exists(bucket_name):
                records_to_delete.append(rset)
                print(f"Dangling CNAME detected: {rset['Name']} -> {target} (bucket '{bucket_name}' does not exist)")

    if not records_to_delete:
        print("No dangling CNAME records found.")
        return

    if dry_run:
        print(f"Dry run: {len(records_to_delete)} record(s) would be deleted.")
        for rec in records_to_delete:
            print(f"  {rec['Name']} -> {rec['ResourceRecords'][0]['Value']}")
        return

    # Actually delete records
    print(f"Deleting {len(records_to_delete)} dangling CNAME record(s)...")
    for rec in records_to_delete:
        try:
            route53.change_resource_record_sets(
                HostedZoneId=zone_id,
                ChangeBatch={
                    'Changes': [
                        {
                            'Action': 'DELETE',
                            'ResourceRecordSet': rec
                        }
                    ]
                }
            )
            print(f"Deleted: {rec['Name']}")
        except ClientError as e:
            print(f"Error deleting {rec['Name']}: {e}", file=sys.stderr)

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description='Clean dangling DNS CNAME records to non-existent S3 buckets.')
    parser.add_argument('zone_id', help='Route53 hosted zone ID')
    parser.add_argument('--dry-run', action='store_true', default=True,
                        help='Perform a dry run without deleting (default: True)')
    parser.add_argument('--execute', action='store_false', dest='dry_run',
                        help='Actually delete records (use with caution)')
    args = parser.parse_args()

    clean_dangling_cname(args.zone_id, dry_run=args.dry_run)
