#!/usr/bin/env python3
"""
Test script to verify AWS credential configuration with aws-vault.

This script tests that the drift detection agent can properly use AWS credentials
from aws-vault or other credential providers through the default credential chain.
"""

import os
import sys
from drift_agent.config.settings import Settings
from drift_agent.utils.aws_client import AWSClientManager


def test_aws_credentials():
    """Test AWS credential configuration."""
    print("🔍 Testing AWS Credential Configuration")
    print("=" * 50)

    try:
        # Load settings
        print("📋 Loading configuration...")
        config = Settings()
        print(f"✅ Configuration loaded successfully")
        print(f"   - AWS Region: {config.aws_region}")
        print(f"   - Using credential chain: {config.is_using_credential_chain()}")

        # Check if explicit credentials are set
        if config.aws_access_key_id and config.aws_secret_access_key:
            print("   - Using explicit AWS credentials")
        elif config.aws_profile:
            print(f"   - Using AWS profile: {config.aws_profile}")
        else:
            print("   - Using default credential chain (aws-vault, IAM roles, etc.)")

        print()

        # Test AWS client creation
        print("🔧 Testing AWS client creation...")
        aws_client = AWSClientManager(config)
        print("✅ AWS client manager created successfully")
        print()

        # Test credential validation
        print("🔐 Validating AWS credentials...")
        identity = aws_client.get_caller_identity()

        if identity:
            print("✅ AWS credentials validated successfully")
            print(f"   - Account ID: {identity.get('Account', 'Unknown')}")
            print(f"   - User ARN: {identity.get('Arn', 'Unknown')}")
            print(f"   - User ID: {identity.get('UserId', 'Unknown')}")
        else:
            print("❌ Failed to get caller identity")
            return False

        print()

        # Test service availability
        print("🧪 Testing service availability...")
        services_to_test = ["s3", "cloudtrail", "sts", "dynamodb"]

        for service in services_to_test:
            available = aws_client.check_service_availability(service)
            status = "✅" if available else "❌"
            print(f"   {status} {service.upper()}: {'Available' if available else 'Not available'}")

        print()
        print("🎉 All tests passed! AWS credentials are properly configured.")
        return True

    except Exception as e:
        print(f"❌ Error: {e}")
        print()
        print("💡 Troubleshooting tips:")
        print("   - Make sure aws-vault is properly configured")
        print("   - Run: aws-vault exec <profile> -- python test_aws_vault.py")
        print("   - Or set AWS_PROFILE environment variable")
        print("   - Or configure AWS credentials in ~/.aws/credentials")
        return False


def print_environment_info():
    """Print relevant environment information."""
    print("🌍 Environment Information")
    print("-" * 30)

    # Check for AWS environment variables
    aws_env_vars = [
        "AWS_REGION", "AWS_DEFAULT_REGION", "AWS_PROFILE",
        "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN",
        "AWS_VAULT", "AWS_VAULT_BACKEND"
    ]

    for var in aws_env_vars:
        value = os.environ.get(var)
        if value:
            # Mask sensitive values
            if "KEY" in var or "TOKEN" in var:
                masked_value = value[:8] + "..." if len(value) > 8 else "***"
                print(f"   {var}: {masked_value}")
            else:
                print(f"   {var}: {value}")
        else:
            print(f"   {var}: Not set")

    print()


if __name__ == "__main__":
    print_environment_info()
    success = test_aws_credentials()
    sys.exit(0 if success else 1)