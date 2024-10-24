#!/bin/bash

# Filename: aws_security_analysis.sh
# Purpose: Analyze AWS security settings and generate a security report.

# Function to print headers in the report
print_header() {
    echo "===================================="
    echo "$1"
    echo "===================================="
}

# Function to analyze IAM settings
analyze_iam() {
    print_header "IAM Security Analysis"
    echo "Listing all IAM users..."
    aws iam list-users

    echo "Listing all IAM roles..."
    aws iam list-roles

    echo "Checking MFA for IAM users..."
    for user in $(aws iam list-users --query 'Users[*].UserName' --output text); do
        echo "User: $user"
        aws iam list-mfa-devices --user-name "$user"
    done

    echo "Listing IAM policies..."
    aws iam list-policies --scope Local
}

# Function to analyze S3 bucket security
analyze_s3() {
    print_header "S3 Bucket Security Analysis"
    echo "Checking public access and encryption for all S3 buckets..."
    for bucket in $(aws s3api list-buckets --query 'Buckets[*].Name' --output text); do
        echo "Bucket: $bucket"
        echo "Checking public access settings..."
        aws s3api get-bucket-policy-status --bucket "$bucket"
        echo "Checking bucket encryption..."
        aws s3api get-bucket-encryption --bucket "$bucket" || echo "No encryption enabled for $bucket"
        echo "Checking bucket ACLs..."
        aws s3api get-bucket-acl --bucket "$bucket"
    done
}

# Function to analyze EC2 security
analyze_ec2() {
    print_header "EC2 Security Analysis"
    echo "Listing all EC2 instances..."
    aws ec2 describe-instances --query 'Reservations[*].Instances[*].[InstanceId,InstanceType,State.Name,PublicIpAddress]' --output table

    echo "Checking security groups..."
    aws ec2 describe-security-groups --query 'SecurityGroups[*].[GroupName,GroupId,IpPermissions]' --output table

    echo "Checking EBS volume encryption..."
    aws ec2 describe-volumes --query 'Volumes[*].[VolumeId,Encrypted]' --output table
}

# Function to analyze VPC security
analyze_vpc() {
    print_header "VPC Security Analysis"
    echo "Checking VPC settings..."
    aws ec2 describe-vpcs --query 'Vpcs[*].[VpcId,CidrBlock,IsDefault]' --output table

    echo "Checking network ACLs..."
    aws ec2 describe-network-acls --query 'NetworkAcls[*].[NetworkAclId,VpcId,Entries]' --output table

    echo "Checking VPC flow logs..."
    aws ec2 describe-flow-logs --query 'FlowLogs[*].[FlowLogId,ResourceId,LogDestination,TrafficType]' --output table
}

# Function to analyze KMS key usage and rotation
analyze_kms() {
    print_header "KMS Key Management Analysis"
    echo "Listing all KMS keys..."
    aws kms list-keys

    echo "Checking KMS key rotation status..."
    for key_id in $(aws kms list-keys --query 'Keys[*].KeyId' --output text); do
        echo "Key ID: $key_id"
        aws kms get-key-rotation-status --key-id "$key_id"
    done
}

# Function to analyze GuardDuty and Security Hub
analyze_guardduty_securityhub() {
    print_header "GuardDuty and Security Hub Analysis"
    
    echo "Checking GuardDuty status..."
    aws guardduty list-detectors

    echo "Checking Security Hub findings..."
    aws securityhub get-findings --query 'Findings[*].[Title,Severity.Label,Description]' --output table
}

# Function to analyze CloudTrail logs
analyze_cloudtrail() {
    print_header "CloudTrail Log Analysis"
    echo "Listing CloudTrail trails..."
    aws cloudtrail describe-trails

    echo "Looking up recent CloudTrail events..."
    aws cloudtrail lookup-events --max-results 10
}

# Function to generate the security analysis report
generate_report() {
    echo "Starting AWS Security Analysis..."
    
    analyze_iam
    analyze_s3
    analyze_ec2
    analyze_vpc
    analyze_kms
    analyze_guardduty_securityhub
    analyze_cloudtrail

    echo "AWS Security Analysis Completed."
}

# Run the report generation
generate_report
