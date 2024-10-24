 #!/bin/bash

# Script: check_aws_security_services.sh
# Purpose: Check the status of various AWS security-related services.

# Function to print a section header
print_header() {
    echo "===================================="
    echo "🔍 $1"
    echo "===================================="
}

# 1. Check GuardDuty status
check_guardduty() {
    print_header "Checking GuardDuty Status"

    detectors=$(aws guardduty list-detectors --query 'DetectorIds' --output text)
    
    if [ -z "$detectors" ]; then
        echo "❌ GuardDuty is NOT enabled."
    else
        echo "✅ GuardDuty is enabled. Detector ID: $detectors"
    fi
}

# 2. Check AWS Config status
check_aws_config() {
    print_header "Checking AWS Config Status"

    config_recorder=$(aws configservice describe-configuration-recorders --query "ConfigurationRecorders[0].name" --output text)
    
    if [ "$config_recorder" == "None" ] || [ -z "$config_recorder" ]; then
        echo "❌ AWS Config is NOT enabled."
    else
        echo "✅ AWS Config is enabled with recorder: $config_recorder"
    fi
}

# 3. Check Inspector status
check_inspector() {
    print_header "Checking AWS Inspector Status"

    inspector_targets=$(aws inspector list-assessment-targets --query 'assessmentTargetArns' --output text)
    
    if [ -z "$inspector_targets" ]; then
        echo "❌ AWS Inspector is NOT configured."
    else
        echo "✅ AWS Inspector is configured. Number of assessment targets: $(echo $inspector_targets | wc -w)"
    fi
}

# 4. Check Security Hub status
check_security_hub() {
    print_header "Checking AWS Security Hub Status"

    security_hub=$(aws securityhub get-findings --query 'Findings' --output text)
    
    if [ -z "$security_hub" ]; then
        echo "❌ AWS Security Hub is NOT enabled."
    else
        echo "✅ AWS Security Hub is enabled."
    fi
}

# 5. Check IAM MFA status
check_iam_mfa() {
    print_header "Checking IAM Users without MFA"

    users_without_mfa=$(aws iam list-users --query 'Users[*].UserName' --output text | while read user; do
        mfa_devices=$(aws iam list-mfa-devices --user-name "$user" --output text)
        if [ -z "$mfa_devices" ]; then
            echo "$user"
        fi
    done)
    
    if [ -z "$users_without_mfa" ]; then
        echo "✅ All users have MFA enabled."
    else
        echo "❌ The following IAM users do NOT have MFA enabled: $users_without_mfa"
    fi
}

# 6. Check CloudTrail status
check_cloudtrail() {
    print_header "Checking CloudTrail Status"

    trails=$(aws cloudtrail describe-trails --query 'trailList[*].Name' --output text)
    
    if [ -z "$trails" ]; then
        echo "❌ CloudTrail is NOT configured."
    else
        echo "✅ CloudTrail is enabled. Trails: $trails"
    fi
}

# 7. Check VPC Flow Logs status
check_vpc_flow_logs() {
    print_header "Checking VPC Flow Logs Status"

    vpcs=$(aws ec2 describe-vpcs --query 'Vpcs[*].VpcId' --output text)
    for vpc in $vpcs; do
        flow_logs=$(aws ec2 describe-flow-logs --filter Name=resource-id,Values=$vpc --query 'FlowLogs[*].FlowLogId' --output text)
        if [ -z "$flow_logs" ]; then
            echo "❌ VPC $vpc does NOT have flow logs enabled."
        else
            echo "✅ VPC $vpc has flow logs enabled. Flow Log ID: $flow_logs"
        fi
    done
}

# 8. Check KMS Key Rotation status
check_kms_key_rotation() {
    print_header "Checking KMS Key Rotation Status"

    kms_keys=$(aws kms list-keys --query 'Keys[*].KeyId' --output text)
    for key_id in $kms_keys; do
        rotation_enabled=$(aws kms get-key-rotation-status --key-id "$key_id" --output text)
        if [ "$rotation_enabled" == "true" ]; then
            echo "✅ Key $key_id has rotation enabled."
        else
            echo "❌ Key $key_id does NOT have rotation enabled."
        fi
    done
}

# 9. Check WAF & Shield status
check_waf_shield() {
    print_header "Checking AWS WAF and Shield Status"

    waf_acls=$(aws wafv2 list-web-acls --scope REGIONAL --output text)
    shield_protections=$(aws shield list-protections --output text)
    
    if [ -z "$waf_acls" ]; then
        echo "❌ No WAF ACLs configured."
    else
        echo "✅ WAF Web ACLs are configured."
    fi

    if [ -z "$shield_protections" ]; then
        echo "❌ No AWS Shield protections configured."
    else
        echo "✅ AWS Shield protections are in place."
    fi
}

# 10. Check S3 Public Access Block settings
check_s3_public_access_block() {
    print_header "Checking S3 Public Access Block Settings"

    s3_buckets=$(aws s3api list-buckets --query 'Buckets[*].Name' --output text)
    for bucket in $s3_buckets; do
        public_access=$(aws s3api get-bucket-policy-status --bucket "$bucket" --query 'PolicyStatus.IsPublic' --output text)
        if [ "$public_access" == "True" ]; then
            echo "❌ S3 Bucket $bucket is publicly accessible."
        else
            echo "✅ S3 Bucket $bucket is NOT publicly accessible."
        fi
    done
}

# 11. Check IAM Access Analyzer status
check_iam_access_analyzer() {
    print_header "Checking IAM Access Analyzer Status"

    analyzers=$(aws accessanalyzer list-analyzers --query 'analyzers[*].name' --output text)
    
    if [ -z "$analyzers" ]; then
        echo "❌ IAM Access Analyzer is NOT configured."
    else
        echo "✅ IAM Access Analyzer is configured. Analyzers: $analyzers"
    fi
}

# Main script execution to check all AWS security services
check_guardduty
check_aws_config
check_inspector
check_security_hub
check_iam_mfa
check_cloudtrail
check_vpc_flow_logs
check_kms_key_rotation
check_waf_shield
check_s3_public_access_block
check_iam_access_analyzer
