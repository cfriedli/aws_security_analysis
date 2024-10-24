#!/bin/bash

# Script: aws_inspector_assessment.sh
# Purpose: Automate AWS Inspector setup, run assessments, and display findings.

# Function to print headers
print_header() {
    echo "===================================="
    echo "🔍 $1"
    echo "===================================="
}

# Function to enable AWS Inspector if not already enabled
enable_inspector() {
    print_header "Checking AWS Inspector Status"

    # Check if Inspector is enabled by attempting to describe the assessment targets
    aws inspector list-assessment-targets --output text > /dev/null 2>&1

    if [ $? -ne 0 ]; then
        echo "⚠️ AWS Inspector is not available or not enabled in this region. Ensure you have permissions and Inspector is supported in this region."
        exit 1
    fi

    echo "✅ AWS Inspector is enabled and available."
}

# Function to create an assessment target
create_assessment_target() {
    print_header "Creating AWS Inspector Assessment Target"

    target_name="MyInspectorAssessmentTarget"
    
    # Create an assessment target that includes all EC2 instances in the region
    target_id=$(aws inspector create-assessment-target --assessment-target-name "$target_name" --resource-group-arn "" --query 'assessmentTargetArn' --output text)

    if [ -n "$target_id" ]; then
        echo "✅ Assessment Target created: $target_name (ARN: $target_id)"
    else
        echo "❌ Failed to create the assessment target."
        exit 1
    fi
}

# Function to create an assessment template
create_assessment_template() {
    print_header "Creating AWS Inspector Assessment Template"

    target_id=$(aws inspector list-assessment-targets --query 'assessmentTargetArns[0]' --output text)
    
    if [ -z "$target_id" ]; then
        echo "❌ No assessment targets found. Create one first."
        exit 1
    fi

    template_name="MyInspectorAssessmentTemplate"
    
    # Create an assessment template for the assessment target with the Common Vulnerabilities and Exposures (CVE) rules package
    template_id=$(aws inspector create-assessment-template \
        --assessment-target-arn "$target_id" \
        --assessment-template-name "$template_name" \
        --duration-in-seconds 3600 \
        --rules-package-arns "arn:aws:inspector:us-west-2:758058086616:rulespackage/0-ubzz7qB5" \
        --query 'assessmentTemplateArn' --output text)

    if [ -n "$template_id" ]; then
        echo "✅ Assessment Template created: $template_name (ARN: $template_id)"
    else
        echo "❌ Failed to create the assessment template."
        exit 1
    fi
}

# Function to run the assessment
run_assessment() {
    print_header "Running AWS Inspector Assessment"

    template_id=$(aws inspector list-assessment-templates --query 'assessmentTemplateArns[0]' --output text)

    if [ -z "$template_id" ]; then
        echo "❌ No assessment templates found. Create one first."
        exit 1
    fi

    # Run the assessment
    run_id=$(aws inspector start-assessment-run --assessment-template-arn "$template_id" --query 'assessmentRunArn' --output text)

    if [ -n "$run_id" ]; then
        echo "✅ Assessment run started (ARN: $run_id)"
    else
        echo "❌ Failed to start the assessment run."
        exit 1
    fi
}

# Function to list findings from the last run
list_findings() {
    print_header "Listing Findings from AWS Inspector"

    # Get the most recent assessment run
    run_id=$(aws inspector list-assessment-runs --query 'assessmentRunArns[0]' --output text)

    if [ -z "$run_id" ]; then
        echo "❌ No assessment runs found."
        exit 1
    fi

    # List findings from the last assessment run
    finding_ids=$(aws inspector list-findings --assessment-run-arns "$run_id" --query 'findingArns' --output text)

    if [ -z "$finding_ids" ]; then
        echo "✅ No findings detected from the latest assessment run."
        exit 0
    fi

    echo "Findings from the latest assessment run:"
    for finding_id in $finding_ids; do
        aws inspector describe-findings --finding-arns "$finding_id" --query 'findings[*].[arn,title,severity,description]' --output table
    done
}

# Run the AWS Inspector process
enable_inspector
create_assessment_target
create_assessment_template
run_assessment
list_findings
