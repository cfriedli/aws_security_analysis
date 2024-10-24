#!/bin/bash

# Filename: lambda_health_check.sh
# Purpose: Perform a health check on all Lambda functions in the AWS account.

# Function to print headers in the report
print_header() {
    echo "===================================="
    echo "$1"
    echo "===================================="
}

# Function to perform health checks on each Lambda function
check_lambda_health() {
    print_header "Starting Lambda Functions Health Check"

    # List all Lambda functions
    lambda_functions=$(aws lambda list-functions --query 'Functions[*].FunctionName' --output text)
    
    if [ -z "$lambda_functions" ]; then
        echo "No Lambda functions found."
        exit 1
    fi

    for function_name in $lambda_functions; do
        print_header "Health Check for Lambda Function: $function_name"
        
        # Get function configuration
        function_config=$(aws lambda get-function-configuration --function-name "$function_name" --output json)
        
        # Check Lambda execution role
        role_arn=$(echo "$function_config" | jq -r '.Role')
        echo "Execution Role: $role_arn"
        
        # Ensure the execution role has required permissions (basic permissions like CloudWatch Logs)
        role_name=$(echo "$role_arn" | cut -d'/' -f2)
        role_policy=$(aws iam list-attached-role-policies --role-name "$role_name" --query 'AttachedPolicies[*].PolicyName' --output text)
        echo "Attached Policies for Execution Role:"
        echo "$role_policy"
        
        # Check if there is no execution role or insufficient policies attached
        if [ -z "$role_policy" ]; then
            echo "Warning: No policies are attached to the execution role $role_name!"
        fi
        
        # Check timeout settings
        timeout=$(echo "$function_config" | jq -r '.Timeout')
        if [ "$timeout" -gt 60 ]; then
            echo "Warning: Lambda function $function_name has a high timeout of $timeout seconds!"
        else
            echo "Timeout: $timeout seconds (OK)"
        fi
        
        # Check memory settings
        memory_size=$(echo "$function_config" | jq -r '.MemorySize')
        if [ "$memory_size" -gt 1024 ]; then
            echo "Warning: Lambda function $function_name has a large memory allocation of $memory_size MB!"
        else
            echo "Memory Size: $memory_size MB (OK)"
        fi

        # Check for environment variables (especially sensitive data)
        env_vars=$(echo "$function_config" | jq -r '.Environment.Variables')
        if [ -n "$env_vars" ]; then
            echo "Environment Variables: Found"
            echo "Review the environment variables for any sensitive data exposure!"
            echo "$env_vars"
        else
            echo "Environment Variables: None"
        fi
        
        # Check if Dead Letter Queue (DLQ) is configured
        dlq_arn=$(echo "$function_config" | jq -r '.DeadLetterConfig.TargetArn')
        if [ "$dlq_arn" == "null" ]; then
            echo "Warning: No Dead Letter Queue (DLQ) configured for Lambda function $function_name!"
        else
            echo "DLQ Configured: $dlq_arn"
        fi
        
        # Check for async invocation settings (error handling)
        max_retry=$(echo "$function_config" | jq -r '.MaximumRetryAttempts')
        if [ "$max_retry" == "null" ]; then
            echo "Warning: No MaximumRetryAttempts configured for async invocations!"
        else
            echo "Maximum Retry Attempts for async invocation: $max_retry"
        fi

        max_age=$(echo "$function_config" | jq -r '.MaximumEventAgeInSeconds')
        if [ "$max_age" == "null" ]; then
            echo "Warning: No MaximumEventAgeInSeconds configured for async invocations!"
        else
            echo "Maximum Event Age for async invocation: $max_age seconds"
        fi
        
        echo "Health check completed for Lambda function: $function_name"
    done
}

# Execute Lambda health check
check_lambda_health
