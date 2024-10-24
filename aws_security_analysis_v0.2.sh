#!/bin/bash

# Filename: aws_security_insecure_checks.sh
# Purpose: Check for insecure security groups, Lambda permissions, and CloudTrail findings.

# Function to print headers in the report
print_header() {
    echo "===================================="
    echo "$1"
    echo "===================================="
}

# 1. Check for insecure security groups (open to 0.0.0.0/0)
check_insecure_security_groups() {
    print_header "Security Groups: Checking for Insecure (Open) Security Groups"
    
    # Query for security groups with open ingress (wide-open 0.0.0.0/0)
    insecure_sgs=$(aws ec2 describe-security-groups --query 'SecurityGroups[?IpPermissions[?IpRanges[?CidrIp==`0.0.0.0/0`]]].{GroupId:GroupId,GroupName:GroupName}' --output table)
    
    if [ -n "$insecure_sgs" ]; then
        echo "Insecure Security Groups with open access (0.0.0.0/0):"
        echo "$insecure_sgs"
    else
        echo "No insecure security groups found."
    fi
}

# 2. Check Lambda functions for wide-open permissions or security group associations
check_lambda_security() {
    print_header "Lambda Functions: Checking for Insecure Permissions and Security Groups"
    
    # List all Lambda functions
    lambda_functions=$(aws lambda list-functions --query 'Functions[*].FunctionName' --output text)
    
    if [ -n "$lambda_functions" ]; then
        for function_name in $lambda_functions; do
            echo "Checking Lambda function: $function_name"
            
            # Check if the function has a VPC configuration, which might include security groups
            vpc_config=$(aws lambda get-function-configuration --function-name "$function_name" --query 'VpcConfig.SecurityGroupIds' --output text)
            
            if [ -n "$vpc_config" ]; then
                echo "Function $function_name is associated with the following security groups:"
                echo "$vpc_config"
                
                # Check if those security groups are insecure (open to 0.0.0.0/0)
                for sg in $vpc_config; do
                    open_sg=$(aws ec2 describe-security-groups --group-ids "$sg" --query 'SecurityGroups[?IpPermissions[?IpRanges[?CidrIp==`0.0.0.0/0`]]].GroupId' --output text)
                    if [ -n "$open_sg" ]; then
                        echo "Security group $sg associated with Lambda $function_name is open to 0.0.0.0/0!"
                    fi
                done
            else
                echo "Lambda function $function_name does not use VPC security groups."
            fi
            
            # Check Lambda function policies for wide permissions
            lambda_policy=$(aws lambda get-policy --function-name "$function_name" --output text 2>/dev/null)
            if [[ $lambda_policy == *"Principal\":\"*\""* ]]; then
                echo "Warning: Lambda function $function_name has a wide-open principal in its policy!"
            fi
        done
    else
        echo "No Lambda functions found."
    fi
}

# 3. Check CloudTrail findings (for security-related incidents)
check_cloudtrail_findings() {
    print_header "CloudTrail: Checking for Security-Related Findings"
    
    # Query CloudTrail for recent findings related to security events
    cloudtrail_events=$(aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=UnauthorizedOperation --max-results 10 --output table)
    
    if [ -n "$cloudtrail_events" ]; then
        echo "CloudTrail findings related to security incidents (UnauthorizedOperation):"
        echo "$cloudtrail_events"
    else
        echo "No security-related findings found in CloudTrail."
    fi
}

# 4. Check CloudTrail for suspicious activity (optional - expand based on needs)
check_cloudtrail_suspicious_activity() {
    print_header "CloudTrail: Checking for Suspicious Activity"

    # Query for unusual API calls (e.g., CreateUser, AttachRolePolicy)
    suspicious_events=$(aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=CreateUser --max-results 10 --output table)
    
    if [ -n "$suspicious_events" ]; then
        echo "Suspicious activity found in CloudTrail (CreateUser events):"
        echo "$suspicious_events"
    else
        echo "No suspicious activity found in CloudTrail."
    fi
}

# Generate the security analysis report focusing on insecure configurations
generate_insecure_report() {
    echo "Starting AWS Security Insecure Configurations Report..."

    check_insecure_security_groups
    check_lambda_security
    check_cloudtrail_findings
    check_cloudtrail_suspicious_activity

    echo "AWS Security Insecure Configurations Report Completed."
}

# Execute the report generation
generate_insecure_report
