#!/bin/bash

# Script: enable_aws_config.sh
# Purpose: Enable AWS Config, create delivery channel, configure recording, and enable compliance rules.

# Function to print headers
print_header() {
    echo "===================================="
    echo "🔍 $1"
    echo "===================================="
}

# Function to check if AWS Config is already enabled
check_config_status() {
    print_header "Checking AWS Config Status"

    recorder_status=$(aws configservice describe-configuration-recorders --query "ConfigurationRecorders[0].name" --output text 2>/dev/null)

    if [ "$recorder_status" == "None" ]; then
        echo "⚠️ AWS Config is not yet configured."
    else
        echo "✅ AWS Config is already configured with recorder name: $recorder_status"
        exit 0
    fi
}

# Function to enable AWS Config recording
enable_config_recorder() {
    print_header "Enabling AWS Config Recorder"

    # Create a configuration recorder
    aws configservice put-configuration-recorder --configuration-recorder name=default,roleARN=arn:aws:iam::${AWS_ACCOUNT_ID}:role/service-role/AWS_ConfigRole

    # Start the recorder
    aws configservice start-configuration-recorder --configuration-recorder-name default

    echo "✅ AWS Config Recorder enabled."
}

# Function to create an S3 bucket for AWS Config logs
create_s3_bucket() {
    print_header "Creating S3 Bucket for AWS Config Logs"

    bucket_name="aws-config-logs-$AWS_ACCOUNT_ID"
    aws s3api create-bucket --bucket "$bucket_name" --region "$AWS_REGION" --create-bucket-configuration LocationConstraint="$AWS_REGION"

    echo "✅ S3 Bucket created: $bucket_name"
}

# Function to create a delivery channel for AWS Config logs
create_delivery_channel() {
    print_header "Creating AWS Config Delivery Channel"

    aws configservice put-delivery-channel --delivery-channel name=default,s3BucketName=aws-config-logs-$AWS_ACCOUNT_ID

    echo "✅ Delivery Channel created."
}

# Function to create a basic AWS Config rule
create_config_rule() {
    print_header "Creating AWS Config Rule"

    rule_name="ec2-managed-instance-compliance"
    
    aws configservice put-config-rule \
    --config-rule '{"ConfigRuleName": "'$rule_name'", "Source": {"Owner": "AWS", "SourceIdentifier": "EC2_MANAGED_INSTANCE_COMPLIANCE"}}'

    echo "✅ AWS Config Rule created: $rule_name"
}

# Main execution
print_header "AWS Config Setup Script"

# Step 1: Check if AWS Config is already enabled
check_config_status

# Step 2: Enable AWS Config recorder and start recording changes
enable_config_recorder

# Step 3: Create an S3 bucket to store AWS Config logs
create_s3_bucket

# Step 4: Create a delivery channel to send AWS Config data to S3
create_delivery_channel

# Step 5: Create AWS Config compliance rule
create_config_rule

print_header "AWS Config Setup Completed Successfully!"
