"""
Unit tests for Bedrock timeout configuration.

Tests that the timeout settings are properly applied to the Bedrock model.
"""

import unittest
from unittest.mock import Mock, patch
import sys
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from drift_agent.config.settings import Settings
from drift_agent.agent import DriftDetectionAgent


class TestBedrockTimeout(unittest.TestCase):
    """Test cases for Bedrock timeout configuration."""

    def test_bedrock_timeout_settings_validation(self):
        """Test that Bedrock timeout settings are validated correctly."""
        # Test valid timeout settings
        settings = Settings(
            terraform_state_bucket="test-bucket",
            cloudtrail_bucket="test-cloudtrail",
            artifacts_bucket="test-artifacts",
            bedrock_read_timeout=300,
            bedrock_connect_timeout=60
        )

        self.assertEqual(settings.bedrock_read_timeout, 300)
        self.assertEqual(settings.bedrock_connect_timeout, 60)

    def test_bedrock_timeout_validation_errors(self):
        """Test that invalid timeout values raise validation errors."""
        # Test read timeout too low
        with self.assertRaises(ValueError) as context:
            Settings(
                terraform_state_bucket="test-bucket",
                cloudtrail_bucket="test-cloudtrail",
                artifacts_bucket="test-artifacts",
                bedrock_read_timeout=10  # Too low
            )
        self.assertIn("Bedrock read timeout must be between 30 and 1800 seconds", str(context.exception))

        # Test read timeout too high
        with self.assertRaises(ValueError) as context:
            Settings(
                terraform_state_bucket="test-bucket",
                cloudtrail_bucket="test-cloudtrail",
                artifacts_bucket="test-artifacts",
                bedrock_read_timeout=2000  # Too high
            )
        self.assertIn("Bedrock read timeout must be between 30 and 1800 seconds", str(context.exception))

        # Test connect timeout too low
        with self.assertRaises(ValueError) as context:
            Settings(
                terraform_state_bucket="test-bucket",
                cloudtrail_bucket="test-cloudtrail",
                artifacts_bucket="test-artifacts",
                bedrock_connect_timeout=5  # Too low
            )
        self.assertIn("Bedrock connect timeout must be between 10 and 600 seconds", str(context.exception))

    def test_default_timeout_values(self):
        """Test that default timeout values are reasonable."""
        settings = Settings(
            terraform_state_bucket="test-bucket",
            cloudtrail_bucket="test-cloudtrail",
            artifacts_bucket="test-artifacts"
        )

        # Check default values
        self.assertEqual(settings.bedrock_read_timeout, 900)  # 15 minutes
        self.assertEqual(settings.bedrock_connect_timeout, 120)  # 2 minutes


if __name__ == "__main__":
    unittest.main()