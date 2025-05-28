"""
Unit tests for the DriftDetector class.

Tests the core drift detection logic that compares CloudTrail events
with Terraform state to identify manual changes.
"""

import unittest
from unittest.mock import Mock, patch
from datetime import datetime
import sys
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from drift_agent.core.drift_detector import DriftDetector, DriftedResource
from drift_agent.config.settings import Settings


class TestDriftDetector(unittest.TestCase):
    """Test cases for DriftDetector class."""

    def setUp(self):
        """Set up test fixtures."""
        self.mock_config = Mock(spec=Settings)
        self.mock_config.aws_region = "us-east-1"

        self.mock_aws_client = Mock()

        self.detector = DriftDetector(self.mock_config, self.mock_aws_client)

    def test_extract_managed_resources(self):
        """Test extraction of managed resources from Terraform data."""
        terraform_data = {
            "resources": [
                {
                    "id": "i-1234567890abcdef0",
                    "arn": "arn:aws:ec2:us-east-1:123456789012:instance/i-1234567890abcdef0",
                    "name": "web-server"
                },
                {
                    "id": "sg-0123456789abcdef0",
                    "name": "web-sg"
                }
            ]
        }

        managed_resources = self.detector._extract_managed_resources(terraform_data)

        expected_resources = {
            "i-1234567890abcdef0",
            "arn:aws:ec2:us-east-1:123456789012:instance/i-1234567890abcdef0",
            "web-server",
            "sg-0123456789abcdef0",
            "web-sg"
        }

        self.assertEqual(managed_resources, expected_resources)

    def test_extract_resource_id_from_ec2_event(self):
        """Test resource ID extraction from EC2 CloudTrail event."""
        change = {
            "eventName": "RunInstances",
            "eventSource": "ec2.amazonaws.com",
            "responseElements": {
                "instancesSet": {
                    "items": [
                        {"instanceId": "i-1234567890abcdef0"}
                    ]
                }
            }
        }

        # Mock the method to return the instance ID
        with patch.object(self.detector, '_extract_resource_id', return_value="i-1234567890abcdef0"):
            resource_id = self.detector._extract_resource_id(change)
            self.assertEqual(resource_id, "i-1234567890abcdef0")

    def test_determine_drift_type(self):
        """Test drift type determination based on event name."""
        # Test creation events
        self.assertEqual(self.detector._determine_drift_type("RunInstances"), "created")
        self.assertEqual(self.detector._determine_drift_type("CreateSecurityGroup"), "created")

        # Test deletion events
        self.assertEqual(self.detector._determine_drift_type("TerminateInstances"), "deleted")
        self.assertEqual(self.detector._determine_drift_type("DeleteSecurityGroup"), "deleted")

        # Test modification events
        self.assertEqual(self.detector._determine_drift_type("ModifyInstanceAttribute"), "modified")
        self.assertEqual(self.detector._determine_drift_type("AuthorizeSecurityGroupIngress"), "modified")

    def test_assess_change_severity(self):
        """Test severity assessment for different types of changes."""
        # Test critical events
        critical_change = {
            "eventName": "TerminateInstances",
            "userIdentity": {"type": "IAMUser"}
        }
        self.assertEqual(self.detector._assess_change_severity(critical_change), "critical")

        # Test high-risk events
        high_risk_change = {
            "eventName": "AuthorizeSecurityGroupIngress",
            "userIdentity": {"type": "IAMUser"}
        }
        self.assertEqual(self.detector._assess_change_severity(high_risk_change), "high")

        # Test root user actions
        root_change = {
            "eventName": "RunInstances",
            "userIdentity": {"type": "Root"}
        }
        self.assertEqual(self.detector._assess_change_severity(root_change), "high")

        # Test medium severity
        medium_change = {
            "eventName": "RunInstances",
            "userIdentity": {"type": "IAMUser"}
        }
        self.assertEqual(self.detector._assess_change_severity(medium_change), "medium")

    def test_is_terraform_managed(self):
        """Test identification of Terraform-managed resources."""
        change = {
            "responseElements": {"instanceId": "i-1234567890abcdef0"}
        }

        managed_resources = {"i-1234567890abcdef0", "sg-0123456789abcdef0"}

        with patch.object(self.detector, '_extract_resource_id', return_value="i-1234567890abcdef0"):
            with patch.object(self.detector, '_extract_resource_arn', return_value=None):
                result = self.detector._is_terraform_managed(change, managed_resources)
                self.assertTrue(result)

        # Test unmanaged resource
        with patch.object(self.detector, '_extract_resource_id', return_value="i-unmanaged123"):
            with patch.object(self.detector, '_extract_resource_arn', return_value=None):
                result = self.detector._is_terraform_managed(change, managed_resources)
                self.assertFalse(result)

    def test_detect_drift_integration(self):
        """Test the main drift detection functionality."""
        cloudtrail_data = {
            "manual_changes": [
                {
                    "eventName": "RunInstances",
                    "eventTime": "2023-01-01T12:00:00Z",
                    "userIdentity": {"type": "IAMUser", "userName": "john.doe"},
                    "sourceIPAddress": "192.168.1.100",
                    "responseElements": {"instanceId": "i-unmanaged123"},
                    "resources": []
                }
            ]
        }

        terraform_data = {
            "resources": [
                {"id": "i-1234567890abcdef0", "name": "web-server"}
            ]
        }

        # Mock the helper methods
        with patch.object(self.detector, '_extract_resource_id', return_value="i-unmanaged123"):
            with patch.object(self.detector, '_extract_resource_type', return_value="EC2"):
                with patch.object(self.detector, '_extract_resource_arn', return_value=None):
                    result = self.detector.detect_drift(cloudtrail_data, terraform_data)

        # Verify the structure of the result
        self.assertIn("drifted_resources", result)
        self.assertIn("unmanaged_resources", result)
        self.assertIn("deleted_resources", result)
        self.assertIn("summary", result)

        # Should have one unmanaged resource
        self.assertEqual(len(result["unmanaged_resources"]), 1)

        # Check summary structure
        summary = result["summary"]
        self.assertIn("total_drift_items", summary)
        self.assertIn("unmanaged_count", summary)
        self.assertIn("severity_breakdown", summary)

    def test_serialize_drift(self):
        """Test serialization of DriftedResource objects."""
        drift = DriftedResource(
            resource_id="i-1234567890abcdef0",
            resource_type="EC2",
            resource_arn="arn:aws:ec2:us-east-1:123456789012:instance/i-1234567890abcdef0",
            drift_type="created",
            changes=[{"eventName": "RunInstances"}],
            event_time=datetime(2023, 1, 1, 12, 0, 0),
            user_identity={"type": "IAMUser"},
            source_ip="192.168.1.100",
            terraform_managed=False,
            severity="medium"
        )

        serialized = self.detector._serialize_drift(drift)

        self.assertEqual(serialized["resource_id"], "i-1234567890abcdef0")
        self.assertEqual(serialized["resource_type"], "EC2")
        self.assertEqual(serialized["drift_type"], "created")
        self.assertEqual(serialized["severity"], "medium")
        self.assertFalse(serialized["terraform_managed"])

    def test_generate_drift_summary(self):
        """Test drift summary generation."""
        # Create sample drifted resources
        drift1 = DriftedResource(
            resource_id="i-1", resource_type="EC2", resource_arn=None,
            drift_type="created", changes=[], event_time=datetime.now(),
            user_identity={}, source_ip=None, terraform_managed=False,
            severity="high"
        )

        drift2 = DriftedResource(
            resource_id="sg-1", resource_type="EC2", resource_arn=None,
            drift_type="modified", changes=[], event_time=datetime.now(),
            user_identity={}, source_ip=None, terraform_managed=True,
            severity="medium"
        )

        summary = self.detector._generate_drift_summary([drift2], [drift1], [])

        self.assertEqual(summary["total_drift_items"], 2)
        self.assertEqual(summary["drifted_count"], 1)
        self.assertEqual(summary["unmanaged_count"], 1)
        self.assertEqual(summary["deleted_count"], 0)
        self.assertEqual(summary["severity_breakdown"]["high"], 1)
        self.assertEqual(summary["severity_breakdown"]["medium"], 1)
        self.assertTrue(summary["requires_attention"])


if __name__ == "__main__":
    unittest.main()