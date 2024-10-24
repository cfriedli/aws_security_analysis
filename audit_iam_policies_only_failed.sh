#!/bin/bash

# Filename: audit_overly_permissive_policies.sh
# Purpose: List only IAM policies with overly permissive actions and their attached resources.

print_header() {
    echo "===================================="
    echo "🔍 $1"
    echo "===================================="
}

# Check for overly permissive policies (wildcards in permissions)
check_policy_permissions() {
    policy_arn=$1
    policy_name=$2

    # Fetch the policy version to get the document
    default_version=$(aws iam get-policy --policy-arn "$policy_arn" --query 'Policy.DefaultVersionId' --output text)
    policy_document=$(aws iam get-policy-version --policy-arn "$policy_arn" --version-id "$default_version" --query 'PolicyVersion.Document' --output json)

    overly_permissive=false

    # Check for overly permissive actions
    for statement in $(echo "$policy_document" | jq -c '.Statement[]'); do
        actions=$(echo "$statement" | jq -r '.Action')

        # Check if the policy contains overly permissive actions like "*"
        if [[ "$actions" == "*" ]] || [[ "$actions" == *"AdministratorAccess"* ]]; then
            overly_permissive=true
            break
        fi
    done

    # Return result for processing in main function
    echo $overly_permissive
}

# Show where the policy is attached (users, groups, roles)
show_policy_attachments() {
    policy_arn=$1
    policy_name=$2

    echo "🔍 Policy: $policy_name"
    echo "Policy ARN: $policy_arn"

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

# List and audit only policies with overly permissive actions
list_and_audit_overly_permissive_policies() {
    print_header "Audit: Overly Permissive IAM Policies"

    # Get all managed policies
    policies=$(aws iam list-policies --query 'Policies[*].[PolicyName,Arn]' --output json)
    
    # Iterate through each policy and check for overly permissive actions
    for policy in $(echo "$policies" | jq -c '.[]'); do
        policy_name=$(echo "$policy" | jq -r '.[0]')
        policy_arn=$(echo "$policy" | jq -r '.[1]')

        overly_permissive=$(check_policy_permissions "$policy_arn" "$policy_name")

        if [ "$overly_permissive" = true ]; then
            # If policy is overly permissive, show attachments
            echo "❌ Overly Permissive Policy Detected!"
            show_policy_attachments "$policy_arn" "$policy_name"
        fi
    done
}

# Run the audit
list_and_audit_overly_permissive_policies
