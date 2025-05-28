"""
CloudTrail analyzer tool for detecting infrastructure changes.

Fetches and analyzes AWS CloudTrail logs to identify manual changes that
bypass Infrastructure as Code workflows.
"""

import logging
import json
import gzip
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)


class CloudTrailAnalyzer:
    """
    CloudTrail log analyzer for drift detection.

    Fetches CloudTrail events from S3 or CloudTrail API and analyzes them
    to identify manual infrastructure changes.
    """

    def __init__(self, config, aws_client):
        """
        Initialize the CloudTrail analyzer.

        Args:
            config: Application configuration
            aws_client: AWS client manager
        """
        self.config = config
        self.aws_client = aws_client
        self.cloudtrail_client = aws_client.get_client("cloudtrail")
        self.s3_client = aws_client.get_client("s3")

        # Infrastructure-related event names to track
        self.infrastructure_events = {
            # EC2 Events
            "RunInstances", "TerminateInstances", "StopInstances", "StartInstances",
            "ModifyInstanceAttribute", "CreateSecurityGroup", "DeleteSecurityGroup",
            "AuthorizeSecurityGroupIngress", "RevokeSecurityGroupIngress",
            "AuthorizeSecurityGroupEgress", "RevokeSecurityGroupEgress",
            "CreateVolume", "DeleteVolume", "AttachVolume", "DetachVolume",
            "CreateSnapshot", "DeleteSnapshot", "CreateImage", "DeregisterImage",

            # VPC Events
            "CreateVpc", "DeleteVpc", "ModifyVpcAttribute", "CreateSubnet", "DeleteSubnet",
            "CreateInternetGateway", "DeleteInternetGateway", "AttachInternetGateway",
            "DetachInternetGateway", "CreateRouteTable", "DeleteRouteTable",
            "CreateRoute", "DeleteRoute", "ReplaceRoute",

            # IAM Events
            "CreateRole", "DeleteRole", "UpdateRole", "AttachRolePolicy", "DetachRolePolicy",
            "CreateUser", "DeleteUser", "CreateGroup", "DeleteGroup",
            "CreatePolicy", "DeletePolicy", "CreateAccessKey", "DeleteAccessKey",

            # S3 Events
            "CreateBucket", "DeleteBucket", "PutBucketPolicy", "DeleteBucketPolicy",
            "PutBucketAcl", "PutBucketVersioning", "PutBucketEncryption", "PutBucketPublicAccessBlock",

            # RDS Events
            "CreateDBInstance", "DeleteDBInstance", "ModifyDBInstance",
            "CreateDBCluster", "DeleteDBCluster", "ModifyDBCluster",
            "CreateDBSubnetGroup", "DeleteDBSubnetGroup",

            # Lambda Events
            "CreateFunction", "DeleteFunction", "UpdateFunctionCode",
            "UpdateFunctionConfiguration", "AddPermission", "RemovePermission",

            # CloudFormation Events (to identify IaC usage)
            "CreateStack", "UpdateStack", "DeleteStack"
        }

        # Users and roles that indicate automated/IaC processes
        self.iac_identifiers = [
            "terraform", "github-actions", "jenkins", "codebuild", "codepipeline",
            "automation", "deploy", "cloudformation", "cdk"
        ]

    def get_events(
        self,
        start_time: datetime,
        end_time: datetime,
        event_types: Optional[List[str]] = None,
        resources: Optional[List[str]] = None
    ) -> List[Dict[str, Any]]:
        """
        Fetch CloudTrail events for the specified time range.

        Args:
            start_time: Start time for event lookup
            end_time: End time for event lookup
            event_types: Specific event types to filter for
            resources: Specific resource types to filter for

        Returns:
            List of CloudTrail events
        """
        logger.info(f"Fetching CloudTrail events from {start_time} to {end_time}")

        events = []

        try:
            # Use CloudTrail LookupEvents API for recent events (last 90 days)
            if (datetime.utcnow() - start_time).days <= 90:
                events.extend(self._get_events_from_api(start_time, end_time, event_types))

            # For older events or additional coverage, try S3 bucket
            if self.config.cloudtrail_bucket:
                s3_events = self._get_events_from_s3(start_time, end_time, event_types)
                events.extend(s3_events)

            # Remove duplicates based on event ID
            seen_event_ids = set()
            unique_events = []
            for event in events:
                event_id = event.get("EventId")
                if event_id and event_id not in seen_event_ids:
                    seen_event_ids.add(event_id)
                    unique_events.append(event)

            logger.info(f"Retrieved {len(unique_events)} unique CloudTrail events")
            return unique_events

        except Exception as e:
            logger.error(f"Error fetching CloudTrail events: {e}")
            return []

    def _get_events_from_api(
        self,
        start_time: datetime,
        end_time: datetime,
        event_types: Optional[List[str]] = None
    ) -> List[Dict[str, Any]]:
        """Fetch events using CloudTrail LookupEvents API."""
        events = []

        try:
            paginator = self.cloudtrail_client.get_paginator("lookup_events")

            # Build lookup attributes for event filtering
            lookup_attributes = []
            if event_types:
                for event_type in event_types:
                    lookup_attributes.append({
                        "AttributeKey": "EventName",
                        "AttributeValue": event_type
                    })

            page_iterator = paginator.paginate(
                StartTime=start_time,
                EndTime=end_time,
                LookupAttributes=lookup_attributes if lookup_attributes else []
            )

            for page in page_iterator:
                for event in page.get("Events", []):
                    if self._is_infrastructure_event(event):
                        events.append(event)

            logger.info(f"Retrieved {len(events)} events from CloudTrail API")

        except ClientError as e:
            logger.error(f"Error using CloudTrail API: {e}")

        return events

    def _get_events_from_s3(
        self,
        start_time: datetime,
        end_time: datetime,
        event_types: Optional[List[str]] = None
    ) -> List[Dict[str, Any]]:
        """Fetch events from CloudTrail S3 bucket."""
        events = []

        try:
            # List objects in the CloudTrail S3 bucket for the time range
            current_time = start_time
            while current_time <= end_time:
                prefix = f"{self.config.cloudtrail_prefix}{current_time.year:04d}/{current_time.month:02d}/{current_time.day:02d}/"

                try:
                    response = self.s3_client.list_objects_v2(
                        Bucket=self.config.cloudtrail_bucket,
                        Prefix=prefix
                    )

                    for obj in response.get("Contents", []):
                        if obj["Key"].endswith(".json.gz"):
                            file_events = self._parse_s3_log_file(obj["Key"])
                            events.extend(file_events)

                except ClientError as e:
                    logger.debug(f"No CloudTrail logs found for {prefix}: {e}")

                current_time += timedelta(days=1)

            # Filter events by time range and type
            filtered_events = []
            for event in events:
                event_time = datetime.fromisoformat(event.get("eventTime", "").replace("Z", "+00:00"))
                if start_time <= event_time <= end_time:
                    if not event_types or event.get("eventName") in event_types:
                        if self._is_infrastructure_event(event):
                            filtered_events.append(event)

            logger.debug(f"Retrieved {len(filtered_events)} events from S3")

        except Exception as e:
            logger.error(f"Error retrieving events from S3: {e}")

        return filtered_events

    def _parse_s3_log_file(self, key: str) -> List[Dict[str, Any]]:
        """Parse a CloudTrail log file from S3."""
        events = []

        try:
            response = self.s3_client.get_object(
                Bucket=self.config.cloudtrail_bucket,
                Key=key
            )

            # Decompress gzipped content
            with gzip.GzipFile(fileobj=response["Body"]) as gz_file:
                content = gz_file.read().decode("utf-8")
                log_data = json.loads(content)

                for record in log_data.get("Records", []):
                    events.append(record)

        except Exception as e:
            logger.debug(f"Error parsing S3 log file {key}: {e}")

        return events

    def _is_infrastructure_event(self, event: Dict[str, Any]) -> bool:
        """Check if an event represents an infrastructure change."""
        # Handle different event formats (API vs S3) - use consistent field names
        event_name = event.get("eventName") or event.get("EventName", "")
        event_source = event.get("eventSource") or event.get("EventSource", "")

        # Skip read-only events
        if event_name.startswith(("Describe", "List", "Get")):
            return False

        # Check if it's an infrastructure-related event
        if event_name not in self.infrastructure_events:
            return False

        # Skip AWS service events
        user_identity = event.get("userIdentity", {})
        if user_identity.get("type") == "AWSService":
            return False

        return True

    def analyze_events(self, events: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Analyze CloudTrail events to categorize manual vs automated changes.

        Args:
            events: List of CloudTrail events

        Returns:
            Dictionary containing analysis results
        """
        logger.info(f"Analyzing {len(events)} CloudTrail events")

        manual_changes = []
        iac_changes = []
        high_risk_events = []

        for event in events:
            if self._is_manual_change(event):
                manual_changes.append(event)

                if self._is_high_risk_event(event):
                    high_risk_events.append(event)
            else:
                iac_changes.append(event)

        # Generate summary
        summary = self._generate_analysis_summary(manual_changes, iac_changes, high_risk_events)

        logger.info(f"Analysis complete: {len(manual_changes)} manual changes, "
                   f"{len(iac_changes)} IaC changes, {len(high_risk_events)} high-risk events")

        return {
            "manual_changes": manual_changes,
            "iac_changes": iac_changes,
            "high_risk_events": high_risk_events,
            "summary": summary
        }

    def _is_manual_change(self, event: Dict[str, Any]) -> bool:
        """Determine if an event represents a manual change.

        Args:
            event: CloudTrail event (can be from API or S3)
                   Sample: {'EventId': '0c05e0af-3f96-4a55-a5ab-5a1bb7847f20', 'EventName': 'PutBucketVersioning', 'ReadOnly': 'false', 'AccessKeyId': 'ASIAVOEASNEVCE7A4F3W', 'EventTime': datetime.datetime(2025, 5, 25, 13, 3, 57, tzinfo=tzlocal()), 'EventSource': 's3.amazonaws.com', 'Username': 'admin', 'Resources': [{'ResourceType': 'AWS::S3::Bucket', 'ResourceName': 'aws-summit-demo-bucket2-9e49c411'}], 'CloudTrailEvent': '{"eventVersion":"1.11","userIdentity":{"type":"IAMUser","principalId":"AIDAVOEASNEVHRYRYOSAA","arn":"arn:aws:iam::373931796778:user/admin","accountId":"373931796778","accessKeyId":"ASIAVOEASNEVCE7A4F3W","userName":"admin","sessionContext":{"attributes":{"creationDate":"2025-05-25T09:41:39Z","mfaAuthenticated":"false"}}},"eventTime":"2025-05-25T10:03:57Z","eventSource":"s3.amazonaws.com","eventName":"PutBucketVersioning","awsRegion":"us-east-1","sourceIPAddress":"89.138.50.99","userAgent":"[APN/1.0 HashiCorp/1.0 Terraform/1.11.4 (+https://www.terraform.io) terraform-provider-aws/5.98.0 (+https://registry.terraform.io/providers/hashicorp/aws) aws-sdk-go-v2/1.36.3 ua/2.1 os/macos lang/go#1.23.8 md/GOOS#darwin md/GOARCH#arm64 api/s3#1.79.3 m/Z,g]","requestParameters":{"bucketName":"aws-summit-demo-bucket2-9e49c411","Host":"aws-summit-demo-bucket2-9e49c411.s3.amazonaws.com","versioning":"","VersioningConfiguration":{"Status":"Enabled","xmlns":"http://s3.amazonaws.com/doc/2006-03-01/"}},"responseElements":null,"additionalEventData":{"SignatureVersion":"SigV4","CipherSuite":"TLS_AES_128_GCM_SHA256","bytesTransferredIn":123,"AuthenticationMethod":"AuthHeader","x-amz-id-2":"RJC7wTJN/WOZFrPOUXxm6i5dCRS1qXrtOj+eDQZOkj+RmMDAYLUZmBOem/AgH7BsqFDI5FrKSY0=","bytesTransferredOut":0},"requestID":"EPRRPW3184QT6C9W","eventID":"0c05e0af-3f96-4a55-a5ab-5a1bb7847f20","readOnly":false,"resources":[{"accountId":"373931796778","type":"AWS::S3::Bucket","ARN":"arn:aws:s3:::aws-summit-demo-bucket2-9e49c411"}],"eventType":"AwsApiCall","managementEvent":true,"recipientAccountId":"373931796778","eventCategory":"Management","tlsDetails":{"tlsVersion":"TLSv1.3","cipherSuite":"TLS_AES_128_GCM_SHA256","clientProvidedHostHeader":"aws-summit-demo-bucket2-9e49c411.s3.amazonaws.com"}}'}

        Returns:
            True if the event represents a manual change, False otherwise
        """
        # Handle different event formats (API vs S3)
        event_data = event

        # If event has CloudTrailEvent field (from LookupEvents API), parse it
        if "CloudTrailEvent" in event and isinstance(event["CloudTrailEvent"], str):
            try:
                event_data = json.loads(event["CloudTrailEvent"])
            except (json.JSONDecodeError, TypeError):
                logger.warning(f"Failed to parse CloudTrailEvent JSON: {event.get('EventId', 'unknown')}")
                # Fall back to using the outer event structure
                event_data = event

        # Extract user identity information
        user_identity = event_data.get("userIdentity", {})
        user_name = user_identity.get("userName", "").lower()

        # Handle assumed roles
        assumed_role_user = ""
        session_context = user_identity.get("sessionContext", {})
        if session_context:
            session_issuer = session_context.get("sessionIssuer", {})
            assumed_role_user = session_issuer.get("userName", "").lower()

        # Check for IaC automation indicators in usernames
        for identifier in self.iac_identifiers:
            if identifier in user_name or identifier in assumed_role_user:
                logger.debug(f"Event {event_data.get('eventName')} identified as IaC: user contains '{identifier}'")
                return False

        # Check source IP for known automation sources
        source_ip = event_data.get("sourceIPAddress", "")
        if source_ip in ["amazonaws.com", "cloudformation.amazonaws.com"]:
            logger.debug(f"Event {event_data.get('eventName')} identified as IaC: AWS service source IP")
            return False

        # Check user agent for automation tools
        user_agent = event_data.get("userAgent", "").lower()

        # Strong automation indicators (always IaC)
        strong_automation_agents = ["terraform", "cloudformation", "cdk", "pulumi"]
        for agent in strong_automation_agents:
            if agent in user_agent:
                logger.debug(f"Event {event_data.get('eventName')} identified as IaC: user agent contains '{agent}'")
                return False

        # Weak automation indicators (need additional context)
        # AWS CLI and boto3 can be used manually or in automation
        weak_automation_agents = ["aws-cli", "boto3"]
        for agent in weak_automation_agents:
            if agent in user_agent:
                # Check if it's likely automated based on additional indicators
                if self._has_automation_context(event_data, user_identity):
                    logger.debug(f"Event {event_data.get('eventName')} identified as IaC: {agent} with automation context")
                    return False

        # Check for service-linked roles or AWS service principals
        user_type = user_identity.get("type", "")
        if user_type in ["AWSService", "AWSAccount"]:
            logger.debug(f"Event {event_data.get('eventName')} identified as IaC: AWS service user type")
            return False

        # Check for automation-related ARNs
        user_arn = user_identity.get("arn", "").lower()
        automation_arn_patterns = ["codebuild", "codepipeline", "github", "jenkins", "automation", "terraform", "deploy"]
        for pattern in automation_arn_patterns:
            if pattern in user_arn:
                logger.debug(f"Event {event_data.get('eventName')} identified as IaC: ARN contains '{pattern}'")
                return False

        # Check for CloudFormation stack operations
        event_name = event_data.get("eventName", "")
        if event_name in ["CreateStack", "UpdateStack", "DeleteStack"]:
            logger.debug(f"Event {event_name} identified as IaC: CloudFormation operation")
            return False

        # If none of the automation indicators are found, consider it a manual change
        logger.debug(f"Event {event_data.get('eventName')} identified as manual change by user {user_name}")
        return True

    def _has_automation_context(self, event_data: Dict[str, Any], user_identity: Dict[str, Any]) -> bool:
        """Check if an event has additional context suggesting automation."""

        # Check for automation-related source IPs (CI/CD systems often have consistent IPs)
        source_ip = event_data.get("sourceIPAddress", "")

        # Check for programmatic access patterns
        # Events from EC2 instances (often automation)
        if source_ip.startswith("10.") or source_ip.startswith("172.") or source_ip.startswith("192.168."):
            return True

        # Check for service-linked roles or automation-related role names
        user_arn = user_identity.get("arn", "").lower()
        if any(pattern in user_arn for pattern in ["service-role", "automation", "pipeline", "build"]):
            return True

        # Check for assumed roles (often used in automation)
        if user_identity.get("type") == "AssumedRole":
            return True

        # Check for rapid sequential events (automation often makes many calls quickly)
        # This would require additional context that we don't have in a single event

        return False

    def _is_high_risk_event(self, event: Dict[str, Any]) -> bool:
        """Determine if an event represents a high-risk change."""
        # Handle different event formats (API vs S3)
        event_data = event

        # If event has CloudTrailEvent field (from LookupEvents API), parse it
        if "CloudTrailEvent" in event and isinstance(event["CloudTrailEvent"], str):
            try:
                event_data = json.loads(event["CloudTrailEvent"])
            except (json.JSONDecodeError, TypeError):
                logger.warning(f"Failed to parse CloudTrailEvent JSON for risk assessment: {event.get('EventId', 'unknown')}")
                # Fall back to using the outer event structure
                event_data = event

        event_name = event_data.get("eventName", "")
        user_identity = event_data.get("userIdentity", {})

        # High-risk events
        high_risk_events = {
            "DeleteBucket", "DeleteDBInstance", "TerminateInstances",
            "DeleteRole", "DeletePolicy", "DeleteSecurityGroup",
            "AuthorizeSecurityGroupIngress", "CreateRole", "AttachRolePolicy",
            "PutBucketPolicy", "DeleteBucketPolicy", "PutBucketAcl"
        }

        if event_name in high_risk_events:
            return True

        # Root user actions are always high risk
        if user_identity.get("type") == "Root":
            return True

        # Actions from external/unknown source IPs (not private networks)
        source_ip = event_data.get("sourceIPAddress", "")
        if source_ip and not source_ip.startswith(("10.", "172.", "192.168.", "127.")):
            # Skip AWS service IPs
            if not source_ip.endswith(".amazonaws.com"):
                return True

        # Actions that modify security-sensitive resources
        security_sensitive_events = {
            "AuthorizeSecurityGroupEgress", "RevokeSecurityGroupEgress",
            "RevokeSecurityGroupIngress", "ModifyDBInstance", "CreateAccessKey"
        }

        if event_name in security_sensitive_events:
            return True

        return False

    def _generate_analysis_summary(
        self,
        manual_changes: List[Dict[str, Any]],
        iac_changes: List[Dict[str, Any]],
        high_risk_events: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Generate a summary of the analysis results."""
        total_events = len(manual_changes) + len(iac_changes)

        # Count events by type
        event_type_counts = {}
        for event in manual_changes + iac_changes:
            event_name = event.get("eventName", "Unknown")
            event_type_counts[event_name] = event_type_counts.get(event_name, 0) + 1

        # Count events by user
        user_counts = {}
        for event in manual_changes:
            user_identity = event.get("userIdentity", {})
            user_name = user_identity.get("userName", "Unknown")
            user_counts[user_name] = user_counts.get(user_name, 0) + 1

        return {
            "total_events": total_events,
            "manual_change_count": len(manual_changes),
            "iac_change_count": len(iac_changes),
            "high_risk_count": len(high_risk_events),
            "manual_change_percentage": (len(manual_changes) / total_events * 100) if total_events > 0 else 0,
            "event_type_breakdown": event_type_counts,
            "top_manual_users": dict(sorted(user_counts.items(), key=lambda x: x[1], reverse=True)[:10]),
            "risk_assessment": "HIGH" if len(high_risk_events) > 0 else "MEDIUM" if len(manual_changes) > 5 else "LOW"
        }