#!/bin/bash

# Script: list_guardduty_findings_by_service.sh
# Purpose: Enable GuardDuty if not active and list findings related to API Gateway, Lambda, VPC, IAM, Route 53, RDS, and EventBridge.

# Function to print headers
print_header() {
    echo "===================================="
    echo "🔍 $1"
    echo "===================================="
}

# Function to check if GuardDuty is enabled and activate it if needed
check_and_enable_guardduty() {
    print_header "Checking GuardDuty Status"

    detectors=$(aws guardduty list-detectors --query 'DetectorIds' --output text)

    if [ -z "$detectors" ]; then
        echo "⚠️ GuardDuty is not enabled. Enabling GuardDuty now..."
        detector_id=$(aws guardduty create-detector --enable --query 'DetectorId' --output text)
        
        if [ -n "$detector_id" ]; then
            echo "✅ GuardDuty successfully enabled. Detector ID: $detector_id"
        else
            echo "❌ Failed to enable GuardDuty. Please check your AWS permissions."
            exit 1
        fi
    else
        echo "✅ GuardDuty is already enabled. Detector ID: $detectors"
    fi
}

# Function to map findings related to specific services
service_related_finding() {
    finding_type=$1

    case $finding_type in
        # API Gateway-related findings
        *"ApiGateway"*)
            echo "🌐 Finding related to API Gateway detected."
            ;;
        # Lambda-related findings
        *"Lambda"*)
            echo "⚙️ Finding related to Lambda function detected."
            ;;
        # VPC-related findings
        *"PortProbe"|"SSHBruteForce"|"UnprotectedPort"|"DNS*"*)
            echo "🔒 Finding related to VPC security detected."
            ;;
        # IAM-related findings
        *"IAM"*)
            echo "🔐 Finding related to IAM detected."
            ;;
        # Route 53-related findings
        *"Route53"*)
            echo "📡 Finding related to Route 53 DNS detected."
            ;;
        # RDS-related findings
        *"RDS"*)
            echo "🛢️ Finding related to RDS detected."
            ;;
        # EventBridge-related findings
        *"EventBridge"*)
            echo "📅 Finding related to EventBridge detected."
            ;;
        *)
            echo "⚠️ Other finding type: $finding_type"
            ;;
    esac
}

# Function to list GuardDuty findings by specific services
list_guardduty_findings() {
    print_header "Listing GuardDuty Findings Related to API Gateway, Lambda, VPC, IAM, Route 53, RDS, and EventBridge"

    # Retrieve GuardDuty detectors
    detectors=$(aws guardduty list-detectors --query 'DetectorIds' --output text)

    if [ -z "$detectors" ]; then
        echo "❌ No GuardDuty detectors found. Ensure GuardDuty is enabled."
        exit 1
    fi

    # Retrieve findings from GuardDuty
    findings=$(aws guardduty list-findings --detector-id "$detectors" --query 'FindingIds' --output text)

    if [ -z "$findings" ]; then
        echo "✅ No GuardDuty findings detected."
        exit 0
    fi

    # Retrieve details for each finding and check if it is related to the services
    for finding_id in $findings; do
        finding=$(aws guardduty get-findings --detector-id "$detectors" --finding-ids "$finding_id" --query 'Findings[0]' --output json)

        finding_type=$(echo "$finding" | jq -r '.Type')
        resource=$(echo "$finding" | jq -r '.Resource.ResourceType')
        severity=$(echo "$finding" | jq -r '.Severity')
        description=$(echo "$finding" | jq -r '.Title')

        echo "🔍 Finding Type: $finding_type"
        echo "🔹 Severity: $severity"
        echo "🔹 Resource Affected: $resource"
        echo "🔹 Description: $description"
        echo "⚙️ Related Service:"

        # Check if the finding is related to API Gateway, Lambda, VPC, IAM, Route 53, RDS, or EventBridge
        service_related_finding "$finding_type"
        echo "------------------------------------"
    done
}

# Run the GuardDuty activation check and findings listing
check_and_enable_guardduty
list_guardduty_findings
