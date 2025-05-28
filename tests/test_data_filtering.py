"""
Unit tests for data filtering functionality.

Tests that CloudTrail and Terraform data is properly filtered to reduce
the amount of data sent to Bedrock for drift detection.
"""

import unittest
import json
import sys
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from drift_agent.agent import _filter_cloudtrail_event, _filter_terraform_resource


class TestDataFiltering(unittest.TestCase):
    """Test cases for data filtering functionality."""

    def test_cloudtrail_event_filtering(self):
        """Test that CloudTrail events are properly filtered."""
        # Sample CloudTrail event with lots of data
        full_event = {
            "EventId": "test-event-id",
            "EventName": "RunInstances",
            "EventTime": "2025-05-25T10:00:00Z",
            "EventSource": "ec2.amazonaws.com",
            "CloudTrailEvent": json.dumps({
                "eventID": "test-event-id",
                "eventName": "RunInstances",
                "eventTime": "2025-05-25T10:00:00Z",
                "eventSource": "ec2.amazonaws.com",
                "sourceIPAddress": "192.168.1.1",
                "userIdentity": {
                    "type": "IAMUser",
                    "userName": "testuser",
                    "arn": "arn:aws:iam::123456789012:user/testuser"
                },
                "requestParameters": {
                    "instanceId": "i-1234567890abcdef0",
                    "imageId": "ami-12345678",
                    "instanceType": "t3.micro",
                    "keyName": "my-key",
                    "securityGroupId": ["sg-12345678"],
                    "subnetId": "subnet-12345678",
                    "userData": "very long base64 encoded user data...",
                    "blockDeviceMapping": [
                        {"deviceName": "/dev/sda1", "ebs": {"volumeSize": 8}}
                    ]
                },
                "responseElements": {
                    "instancesSet": {
                        "items": [
                            {
                                "instanceId": "i-1234567890abcdef0",
                                "imageId": "ami-12345678",
                                "state": {"code": 0, "name": "pending"},
                                "privateDnsName": "",
                                "publicDnsName": "",
                                "reason": "",
                                "keyName": "my-key",
                                "amiLaunchIndex": 0,
                                "productCodes": [],
                                "instanceType": "t3.micro",
                                "launchTime": "2025-05-25T10:00:00.000Z",
                                "placement": {
                                    "availabilityZone": "us-east-1a",
                                    "groupName": "",
                                    "tenancy": "default"
                                }
                            }
                        ]
                    }
                },
                "resources": [
                    {
                        "accountId": "123456789012",
                        "type": "AWS::EC2::Instance",
                        "ARN": "arn:aws:ec2:us-east-1:123456789012:instance/i-1234567890abcdef0"
                    }
                ]
            })
        }

        # Filter the event
        filtered = _filter_cloudtrail_event(full_event)

        # Verify essential fields are preserved
        self.assertEqual(filtered["eventId"], "test-event-id")
        self.assertEqual(filtered["eventName"], "RunInstances")
        self.assertEqual(filtered["eventSource"], "ec2.amazonaws.com")
        self.assertEqual(filtered["sourceIPAddress"], "192.168.1.1")
        self.assertEqual(filtered["userIdentity"]["userName"], "testuser")

        # Verify resource information is preserved
        self.assertEqual(len(filtered["resources"]), 1)
        self.assertEqual(filtered["resources"][0]["type"], "AWS::EC2::Instance")
        self.assertEqual(filtered["resources"][0]["name"], "arn:aws:ec2:us-east-1:123456789012:instance/i-1234567890abcdef0")

        # Verify resource IDs are extracted
        self.assertIn("resourceIds", filtered)
        self.assertEqual(filtered["resourceIds"]["instanceId"], "i-1234567890abcdef0")

        # Verify large fields are not included
        self.assertNotIn("requestParameters", filtered)
        self.assertNotIn("responseElements", filtered)
        self.assertNotIn("CloudTrailEvent", filtered)

    def test_terraform_resource_filtering(self):
        """Test that Terraform resources are properly filtered."""
        # Sample Terraform resource with lots of attributes
        full_resource = {
            "type": "aws_instance",
            "name": "web_server",
            "module": "root",
            "identifiers": ["i-1234567890abcdef0", "arn:aws:ec2:us-east-1:123456789012:instance/i-1234567890abcdef0"],
            "tags": {"Name": "WebServer", "Environment": "prod"},
            "terraform_managed": True,
            "attributes": {
                "id": "i-1234567890abcdef0",
                "arn": "arn:aws:ec2:us-east-1:123456789012:instance/i-1234567890abcdef0",
                "instance_id": "i-1234567890abcdef0",
                "ami": "ami-12345678",
                "instance_type": "t3.micro",
                "key_name": "my-key",
                "security_groups": ["sg-12345678"],
                "subnet_id": "subnet-12345678",
                "user_data": "very long base64 encoded user data...",
                "user_data_base64": "even longer base64 encoded user data...",
                "private_ip": "10.0.1.100",
                "public_ip": "54.123.45.67",
                "private_dns": "ip-10-0-1-100.ec2.internal",
                "public_dns": "ec2-54-123-45-67.compute-1.amazonaws.com",
                "availability_zone": "us-east-1a",
                "placement_group": "",
                "tenancy": "default",
                "ebs_optimized": False,
                "monitoring": False,
                "source_dest_check": True,
                "disable_api_termination": False,
                "instance_initiated_shutdown_behavior": "stop",
                "credit_specification": [{"cpu_credits": "standard"}],
                "metadata_options": [
                    {
                        "http_endpoint": "enabled",
                        "http_tokens": "optional",
                        "http_put_response_hop_limit": 1
                    }
                ],
                "root_block_device": [
                    {
                        "volume_type": "gp2",
                        "volume_size": 8,
                        "delete_on_termination": True,
                        "encrypted": False
                    }
                ]
            }
        }

        # Filter the resource
        filtered = _filter_terraform_resource(full_resource)

        # Verify essential fields are preserved
        self.assertEqual(filtered["type"], "aws_instance")
        self.assertEqual(filtered["name"], "web_server")
        self.assertEqual(filtered["module"], "root")
        self.assertEqual(filtered["identifiers"], ["i-1234567890abcdef0", "arn:aws:ec2:us-east-1:123456789012:instance/i-1234567890abcdef0"])
        self.assertEqual(filtered["tags"], {"Name": "WebServer", "Environment": "prod"})
        self.assertTrue(filtered["terraform_managed"])

        # Verify key attributes are preserved
        self.assertIn("key_attributes", filtered)
        self.assertEqual(filtered["key_attributes"]["id"], "i-1234567890abcdef0")
        self.assertEqual(filtered["key_attributes"]["arn"], "arn:aws:ec2:us-east-1:123456789012:instance/i-1234567890abcdef0")
        self.assertEqual(filtered["key_attributes"]["instance_id"], "i-1234567890abcdef0")

        # Verify large/unnecessary attributes are not included
        self.assertNotIn("attributes", filtered)
        self.assertNotIn("user_data", filtered.get("key_attributes", {}))
        self.assertNotIn("user_data_base64", filtered.get("key_attributes", {}))

    def test_data_size_reduction(self):
        """Test that filtering significantly reduces data size."""
        # Create a large CloudTrail event
        large_event = {
            "EventId": "test-event-id",
            "CloudTrailEvent": json.dumps({
                "eventID": "test-event-id",
                "eventName": "RunInstances",
                "eventTime": "2025-05-25T10:00:00Z",
                "eventSource": "ec2.amazonaws.com",
                "userIdentity": {"type": "IAMUser", "userName": "testuser"},
                "requestParameters": {"instanceId": "i-1234567890abcdef0"},
                "responseElements": {"very": "large", "response": "data" * 1000},
                "additionalEventData": {"more": "data" * 1000},
                "resources": [{"type": "AWS::EC2::Instance", "ARN": "arn:aws:ec2:us-east-1:123456789012:instance/i-1234567890abcdef0"}]
            })
        }

        # Calculate sizes
        original_size = len(json.dumps(large_event))
        filtered_size = len(json.dumps(_filter_cloudtrail_event(large_event)))

        # Verify significant size reduction (should be at least 50% smaller)
        reduction_percentage = (original_size - filtered_size) / original_size * 100
        self.assertGreater(reduction_percentage, 50, f"Data reduction was only {reduction_percentage:.1f}%, expected > 50%")

        print(f"CloudTrail data size reduction: {original_size} -> {filtered_size} bytes ({reduction_percentage:.1f}% reduction)")


if __name__ == "__main__":
    unittest.main()