"""
Unit tests for Terraform state functionality.

Tests the TerraformStateAnalyzer class and related configuration settings,
including the new bucket prefix support.
"""

import unittest
from unittest.mock import Mock, patch
import sys
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from drift_agent.config.settings import Settings
from drift_agent.tools.terraform import TerraformStateAnalyzer


class TestTerraformStatePrefix(unittest.TestCase):
    """Test cases for Terraform state prefix functionality."""

    def test_get_terraform_state_path_no_prefix(self):
        """Test state path generation without prefix."""
        settings = Settings(
            terraform_state_bucket="test-bucket",
            terraform_state_key="terraform.tfstate",
            terraform_state_prefix="",
            terraform_workspace="default",
            cloudtrail_bucket="test-cloudtrail",
            artifacts_bucket="test-artifacts"
        )

        # Test default workspace
        path = settings.get_terraform_state_path("default")
        self.assertEqual(path, "terraform.tfstate")

        # Test custom workspace
        path = settings.get_terraform_state_path("staging")
        self.assertEqual(path, "env:/staging/terraform.tfstate")

    def test_get_terraform_state_path_with_prefix(self):
        """Test state path generation with prefix."""
        settings = Settings(
            terraform_state_bucket="test-bucket",
            terraform_state_key="terraform.tfstate",
            terraform_state_prefix="demo",
            terraform_workspace="default",
            cloudtrail_bucket="test-cloudtrail",
            artifacts_bucket="test-artifacts"
        )

        # Test default workspace with prefix
        path = settings.get_terraform_state_path("default")
        self.assertEqual(path, "demo/terraform.tfstate")

        # Test custom workspace with prefix
        path = settings.get_terraform_state_path("staging")
        self.assertEqual(path, "demo/env:/staging/terraform.tfstate")

    def test_get_terraform_state_path_with_prefix_trailing_slash(self):
        """Test state path generation with prefix that has trailing slash."""
        settings = Settings(
            terraform_state_bucket="test-bucket",
            terraform_state_key="terraform.tfstate",
            terraform_state_prefix="demo/",
            terraform_workspace="default",
            cloudtrail_bucket="test-cloudtrail",
            artifacts_bucket="test-artifacts"
        )

        # Test default workspace with prefix
        path = settings.get_terraform_state_path("default")
        self.assertEqual(path, "demo/terraform.tfstate")

        # Test custom workspace with prefix
        path = settings.get_terraform_state_path("staging")
        self.assertEqual(path, "demo/env:/staging/terraform.tfstate")

    def test_get_terraform_state_path_nested_prefix(self):
        """Test state path generation with nested prefix."""
        settings = Settings(
            terraform_state_bucket="test-bucket",
            terraform_state_key="terraform.tfstate",
            terraform_state_prefix="projects/myapp/terraform",
            terraform_workspace="default",
            cloudtrail_bucket="test-cloudtrail",
            artifacts_bucket="test-artifacts"
        )

        # Test default workspace with nested prefix
        path = settings.get_terraform_state_path("default")
        self.assertEqual(path, "projects/myapp/terraform/terraform.tfstate")

        # Test custom workspace with nested prefix
        path = settings.get_terraform_state_path("production")
        self.assertEqual(path, "projects/myapp/terraform/env:/production/terraform.tfstate")

    def test_terraform_state_analyzer_uses_prefix(self):
        """Test that TerraformStateAnalyzer uses the prefix when fetching state."""
        mock_config = Mock(spec=Settings)
        mock_config.terraform_state_bucket = "test-bucket"
        mock_config.terraform_state_key = "terraform.tfstate"
        mock_config.terraform_state_prefix = "demo"
        mock_config.terraform_workspace = "default"
        mock_config.get_terraform_state_path = Mock(return_value="demo/terraform.tfstate")

        mock_aws_client = Mock()
        mock_s3_client = Mock()
        mock_aws_client.get_client.return_value = mock_s3_client

        # Mock successful S3 response
        mock_response = {
            "Body": Mock()
        }
        mock_response["Body"].read.return_value = b'{"version": 4, "resources": []}'
        mock_s3_client.get_object.return_value = mock_response

        analyzer = TerraformStateAnalyzer(mock_config, mock_aws_client)
        result = analyzer.get_state("default")

        # Verify that get_terraform_state_path was called with the correct workspace
        mock_config.get_terraform_state_path.assert_called_once_with("default")

        # Verify that S3 get_object was called with the correct parameters
        mock_s3_client.get_object.assert_called_once_with(
            Bucket="test-bucket",
            Key="demo/terraform.tfstate"
        )

        # Verify the result is parsed correctly
        self.assertEqual(result["version"], 4)
        self.assertEqual(result["resources"], [])


if __name__ == "__main__":
    unittest.main()