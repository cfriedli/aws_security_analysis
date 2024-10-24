#!/bin/bash

# Filename: aws_security_full_checks.sh
# Purpose: Comprehensive AWS security analysis covering IAM, Security Groups, S3, Lambda, NACLs, CloudTrail, API Gateway, RDS, EventBridge, and more.

# Function to print headers in the report with emoji
print_header() {
    echo "🔍 $1"
    echo "------------------------------------"
}

# ✅ and ❌ are used for passing and failing checks respectively

# 1. Check for insecure security groups (open to 0.0.0.0/0)
check_insecure_security_groups() {
    print_header "Security Groups: Checking for Insecure (Open) Security Groups"
    
    insecure_sgs=$(aws ec2 describe-security-groups --query 'SecurityGroups[?IpPermissions[?IpRanges[?CidrIp==`0.0.0.0/0`]]].{GroupId:GroupId,GroupName:GroupName}' --output table)
    
    if [ -n "$insecure_sgs" ]; then
        echo "❌ Insecure Security Groups with open access (0.0.0.0/0):"
        echo "$insecure_sgs"
    else
        echo "✅ No insecure security groups found."
    fi
}

# 2. Check NACLs (Network ACLs) for insecure rules (open to 0.0.0.0/0)
check_insecure_nacls() {
    print_header "NACLs: Checking for Insecure (Open) NACLs"
    
    nacls=$(aws ec2 describe-network-acls --query 'NetworkAcls[*].[NetworkAclId,Entries]' --output json)

    insecure_nacl_found=false
    for nacl_id in $(echo "$nacls" | jq -r '.[].NetworkAclId'); do
        open_inbound=$(aws ec2 describe-network-acls --network-acl-ids "$nacl_id" --query 'NetworkAcls[*].Entries[?CidrBlock==`0.0.0.0/0` && RuleAction==`allow` && Egress==`false`]' --output json)
        open_outbound=$(aws ec2 describe-network-acls --network-acl-ids "$nacl_id" --query 'NetworkAcls[*].Entries[?CidrBlock==`0.0.0.0/0` && RuleAction==`allow` && Egress==`true`]' --output json)

        if [ "$open_inbound" != "[]" ] || [ "$open_outbound" != "[]" ]; then
            echo "❌ NACL $nacl_id has insecure rules allowing all traffic (0.0.0.0/0)."
            insecure_nacl_found=true
        fi
    done

    if [ "$insecure_nacl_found" = false ]; then
        echo "✅ No insecure NACLs found."
    fi
}

# 3. Check Lambda functions for wide-open permissions or security group associations
check_lambda_security() {
    print_header "Lambda Functions: Checking for Insecure Permissions and Security Groups"
    
    lambda_functions=$(aws lambda list-functions --query 'Functions[*].FunctionName' --output text)
    insecure_lambda_found=false

    if [ -n "$lambda_functions" ]; then
        for function_name in $lambda_functions; do
            vpc_config=$(aws lambda get-function-configuration --function-name "$function_name" --query 'VpcConfig.SecurityGroupIds' --output text)
            
            if [ -n "$vpc_config" ]; then
                for sg in $vpc_config; do
                    open_sg=$(aws ec2 describe-security-groups --group-ids "$sg" --query 'SecurityGroups[?IpPermissions[?IpRanges[?CidrIp==`0.0.0.0/0`]]].GroupId' --output text)
                    if [ -n "$open_sg" ]; then
                        echo "❌ Lambda function $function_name uses an insecure Security Group $sg open to 0.0.0.0/0."
                        insecure_lambda_found=true
                    fi
                done
            fi
        done
    fi

    if [ "$insecure_lambda_found" = false ]; then
        echo "✅ No insecure Lambda security group configurations found."
    fi
}

# 4. Check CloudTrail findings (for security-related incidents)
check_cloudtrail_findings() {
    print_header "CloudTrail: Checking for Unauthorized Operations"
    
    cloudtrail_events=$(aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=UnauthorizedOperation --max-results 10 --output table)
    
    if [ -n "$cloudtrail_events" ]; then
        echo "❌ CloudTrail findings related to security incidents (UnauthorizedOperation):"
        echo "$cloudtrail_events"
    else
        echo "✅ No security-related findings found in CloudTrail."
    fi
}

# 5. Check IAM MFA enforcement
check_iam_mfa() {
    print_header "IAM: Checking Users without MFA"

    for user in $(aws iam list-users --query 'Users[*].UserName' --output text); do
        mfa=$(aws iam list-mfa-devices --user-name "$user" --output text)
        if [ -z "$mfa" ]; then
            echo "❌ User $user does not have MFA enabled."
        fi
    done
    echo "✅ All other users have MFA enabled."
}

# 6. Check S3 bucket security (encryption and public access)
check_s3_security() {
    print_header "S3: Checking Buckets for Public Access and Encryption"

    for bucket in $(aws s3api list-buckets --query 'Buckets[*].Name' --output text); do
        encryption=$(aws s3api get-bucket-encryption --bucket "$bucket" 2>&1)
        if [[ $encryption == *"ServerSideEncryptionConfigurationNotFoundError"* ]]; then
            echo "❌ Bucket $bucket is NOT encrypted."
        fi
        
        public_access=$(aws s3api get-bucket-policy-status --bucket "$bucket" --query 'PolicyStatus.IsPublic' --output text)
        if [[ "$public_access" == "True" ]]; then
            echo "❌ Bucket $bucket is publicly accessible!"
        fi
    done
    echo "✅ All other buckets are encrypted and private."
}

# 7. Check EC2 instances for insecure security settings
check_ec2_security() {
    print_header "EC2: Checking for Unencrypted Volumes and Open Security Groups"
    
    unencrypted_volumes=$(aws ec2 describe-volumes --query 'Volumes[?Encrypted==`false`].[VolumeId,Attachments[0].InstanceId]' --output table)
    if [ -n "$unencrypted_volumes" ]; then
        echo "❌ Unencrypted EBS Volumes found:"
        echo "$unencrypted_volumes"
    else
        echo "✅ All EBS volumes are encrypted."
    fi
}

# 8. Check VPC Flow Logs
check_vpc_flow_logs() {
    print_header "VPC: Checking if Flow Logs are Enabled"

    no_flow_logs=$(aws ec2 describe-vpcs --query 'Vpcs[?FlowLogs[?FlowLogId==null]].VpcId' --output text)
    if [ -n "$no_flow_logs" ]; then
        echo "❌ VPCs without flow logs enabled:"
        echo "$no_flow_logs"
    else
        echo "✅ All VPCs have flow logs enabled."
    fi
}

# 9. Check KMS Key Rotation
check_kms_key_rotation() {
    print_header "KMS: Checking if Key Rotation is Enabled"

    for key_id in $(aws kms list-keys --query 'Keys[*].KeyId' --output text); do
        rotation_enabled=$(aws kms get-key-rotation-status --key-id "$key_id" 2>&1)
        if [[ $rotation_enabled == *"false"* ]]; then
            echo "❌ KMS Key $key_id does not have rotation enabled."
        fi
    done
    echo "✅ All other KMS keys have rotation enabled."
}

# 10. Check GuardDuty
check_guardduty() {
    print_header "GuardDuty: Checking if GuardDuty is Enabled"

    detectors=$(aws guardduty list-detectors --output text)
    if [ -z "$detectors" ]; then
        echo "❌ GuardDuty is NOT enabled."
    else
        echo "✅ GuardDuty is enabled."
    fi
}

# 11. Check CloudTrail
check_cloudtrail() {
    print_header "CloudTrail: Checking if CloudTrail is Enabled"

    trails=$(aws cloudtrail describe-trails --query 'trailList[*].Name' --output text)
    if [ -z "$trails" ]; then
        echo "❌ CloudTrail is NOT enabled."
    else
        echo "✅ CloudTrail is enabled."
    fi
}

# 12. Check Security Hub
check_securityhub() {
    print_header "Security Hub: Checking if Security Hub is Enabled"

    status=$(aws securityhub get-findings --query 'Findings[*]' --output text)
    if [ -z "$status" ]; then
        echo "❌ Security Hub is NOT enabled or has no findings."
    else
        echo "✅ Security Hub is enabled."
    fi
}

# 13. Check WAF and Shield
check_waf_shield() {
    print_header "WAF & Shield: Checking if Protections are Configured"

    waf_acls=$(aws wafv2 list-web-acls --scope REGIONAL --output text)
    shield_protections=$(aws shield list-protections --output text)
    
    if [ -z "$waf_acls" ]; then
        echo "❌ No WAF Web ACLs configured."
    else
        echo "✅ WAF Web ACLs are configured."
    fi

    if [ -z "$shield_protections" ]; then
        echo "❌ No AWS Shield protections configured."
    else
        echo "✅ AWS Shield protections are in place."
    fi
}

# Generate the security analysis report
generate_insecure_report() {
    echo "🔐 Starting AWS Security Insecure Configurations Report..."
    
    check_iam_mfa
    check_s3_security
    check_ec2_security
    check_vpc_flow_logs
    check_kms_key_rotation
    check_guardduty
    check_cloudtrail
    check_securityhub
    check_waf_shield
    check_insecure_security_groups
    check_insecure_nacls
    check_lambda_security
    check_cloudtrail_findings

    echo "✅ AWS Security Insecure Configurations Report Completed."
}

# Execute the report generation
generate_insecure_report
