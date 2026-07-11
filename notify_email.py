{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "iam:PassRole"
            ],
            "Resource": "*",
            "Condition": {
                "StringEquals": {
                    "aws:SourceArn": ["arn:aws:sts::*:assumed-role/SpecificRoleName/*"]
                }
            }
        },
        {
            "Effect": "Allow",
            "Action": [
                "ec2:RunInstances"
            ],
            "Resource": "*",
            "Condition": {
                "StringEquals": {
                    "aws:SourceArn": ["arn:aws:sts::*:assumed-role/SpecificRoleName/*"]
                }
            }
        }
    ]
}