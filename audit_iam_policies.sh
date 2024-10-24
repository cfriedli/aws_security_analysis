#!/bin/bash

# Filename: audit_iam_policies.sh
# Purpose: Perform an audit of all IAM policies, including their permissions and attached resources.

# Print headers for sections
print_header() {
    echo "===================================="
    echo "🔍 $1"
    echo "===================================="
}

# Check for overly permissive policies (wildcards in permissions)
check_policy_permissions() {
    policy_arn=$1
    policy_name=$2

    echo "🔍 Auditing Policy: $policy_name"
    echo "Policy ARN: $policy_arn"

    # Fetch the policy version to get the document
    default_version=$(aws iam get-policy --policy-arn "$policy_arn" --query 'Policy.DefaultVersionId' --output text)
    policy_document=$(aws iam get-policy-version --policy-arn "$policy_arn" --version-id "$default_version" --query 'PolicyVersion.Document' --output json)

    # Check for overly permissive policies ("Action": "*")
    overly_permissive=false
    for statement in $(echo "$policy_document" | jq -c '.Statement[]'); do
        actions=$(echo "$statement" | jq -r '.Action')
        if [[ "$actions" == "*" ]] || [[ "$actions" == *"AdministratorAccess"* ]]; then
            echo "❌ Policy contains overly permissive action (wildcard '*')"
            overly_permissive=true
        fi
    done

    if [ "$overly_permissive" = false ]; then
        echo "✅ No overly permissive actions found."
    fi
}

# Show where the policy is attached (users, groups, roles)
show_policy_attachments() {
    policy_arn=$1
    policy_name=$2

    # Get attached entities (users, groups, roles)
    entities=$(aws iam list-entities-for-policy --policy-arn "$policy_arn" --query '{Users:PolicyUsers[*].UserName,Groups:PolicyGroups[*].GroupName,Roles:PolicyRoles[*].RoleName}' --output json)
    
    attached_users=$(echo "$entities" | jq -r '.Users[]?')
    attached_groups=$(echo "$entities" | jq -r '.Groups[]?')
    attached_roles=$(echo "$entities" | jq -r '.Roles[]?')

    if [ -z "$attached_users" ] && [ -z "$attached_groups" ] && [ -z "$attached_roles" ]; then
        echo "❌ Policy is not attached to any user, group, or role."
    else
        if [ -n "$attached_users" ]; then
            echo "👤 Users attached:"
            echo "$attached_users"
        fi
        if [ -n "$attached_groups" ]; then
            echo "👥 Groups attached:"
            echo "$attached_groups"
        fi
        if [ -n "$attached_roles" ]; then
            echo "🎭 Roles attached:"
            echo "$attached_roles"
        fi
    fi
    echo "------------------------------------"
}

# List all IAM policies and audit them
list_and_audit_iam_policies() {
    print_header "IAM Policies Audit"

    # Get all managed policies
    policies=$(aws iam list-policies --query 'Policies[*].[PolicyName,Arn]' --output json)
    
    # Iterate through each policy and perform an audit
    for policy in $(echo "$policies" | jq -c '.[]'); do
        policy_name=$(echo "$policy" | jq -r '.[0]')
        policy_arn=$(echo "$policy" | jq -r '.[1]')

        # Audit policy permissions and attached entities
        check_policy_permissions "$policy_arn" "$policy_name"
        show_policy_attachments "$policy_arn" "$policy_name"
    done
}

# Run the policy audit
list_and_audit_iam_policies
