#!/bin/bash

# Assume IAM role and get temporary credentials
assume_role() {
  local role_arn="YOUR_IAM_ROLE_ARN"
  local session_name="CI_CD_Session"

  # Assume the role
  credentials=$(aws sts assume-role --role-arn "$role_arn" --role-session-name "$session_name")

  # Extract the temporary credentials
  export AWS_ACCESS_KEY_ID=$(echo $credentials | jq -r '.Credentials.AccessKeyId')
  export AWS_SECRET_ACCESS_KEY=$(echo $credentials | jq -r '.Credentials.SecretAccessKey')
  export AWS_SESSION_TOKEN=$(echo $credentials | jq -r '.Credentials.SessionToken')
}

# Call the function to set up the environment
assume_role
