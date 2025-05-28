"""
Core drift detection logic.

Compares CloudTrail events with Terraform state to identify manual changes
that bypass Infrastructure as Code workflows.
"""

import logging
from typing import Dict, Any, List, Set, Optional
from datetime import datetime
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class DriftedResource:
    """Represents a resource that has drifted from its IaC definition."""
    resource_id: str
    resource_type: str
    resource_arn: Optional[str]
    drift_type: str  # "modified", "created", "deleted"
    changes: List[Dict[str, Any]]
    event_time: datetime
    user_identity: Dict[str, Any]
    source_ip: Optional[str]
    terraform_managed: bool
    severity: str  # "low", "medium", "high", "critical"


class DriftDetector:
    """
    Core drift detection engine.

    Analyzes CloudTrail events and compares them with Terraform state to identify
    infrastructure changes that were made outside of IaC workflows.
    """

    def __init__(self, config, aws_client):
        """
        Initialize the drift detector.

        Args:
            config: Application configuration
            aws_client: AWS client manager
        """
        self.config = config
        self.aws_client = aws_client

        # Resource types that indicate infrastructure changes
        self.infrastructure_events = {
            "EC2": [
                "RunInstances", "TerminateInstances", "ModifyInstanceAttribute",
                "CreateSecurityGroup", "DeleteSecurityGroup", "AuthorizeSecurityGroupIngress",
                "RevokeSecurityGroupIngress", "CreateVolume", "DeleteVolume",
                "AttachVolume", "DetachVolume"
            ],
            "RDS": [
                "CreateDBInstance", "DeleteDBInstance", "ModifyDBInstance",
                "CreateDBCluster", "DeleteDBCluster", "ModifyDBCluster"
            ],
            "IAM": [
                "CreateRole", "DeleteRole", "AttachRolePolicy", "DetachRolePolicy",
                "CreateUser", "DeleteUser", "CreateGroup", "DeleteGroup",
                "CreatePolicy", "DeletePolicy"
            ],
            "S3": [
                "CreateBucket", "DeleteBucket", "PutBucketPolicy", "DeleteBucketPolicy",
                "PutBucketAcl", "PutBucketVersioning"
            ],
            "Lambda": [
                "CreateFunction", "DeleteFunction", "UpdateFunctionCode",
                "UpdateFunctionConfiguration", "AddPermission", "RemovePermission"
            ],
            "VPC": [
                "CreateVpc", "DeleteVpc", "CreateSubnet", "DeleteSubnet",
                "CreateInternetGateway", "DeleteInternetGateway",
                "CreateRouteTable", "DeleteRouteTable", "CreateRoute", "DeleteRoute"
            ]
        }

        # Users/roles that indicate IaC automation
        self.iac_indicators = [
            "terraform",
            "github-actions",
            "jenkins",
            "codebuild",
            "codepipeline",
            "arn:aws:iam::*:role/*terraform*",
            "arn:aws:iam::*:role/*automation*",
            "arn:aws:iam::*:role/*deploy*"
        ]

    def detect_drift(
        self,
        cloudtrail_data: Dict[str, Any],
        terraform_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Detect drift between CloudTrail events and Terraform state.

        Args:
            cloudtrail_data: Results from CloudTrail analysis
            terraform_data: Results from Terraform state analysis

        Returns:
            Dictionary containing drift detection results
        """
        logger.info("=== DRIFT DETECTOR: Starting analysis ===")
        logger.info(f"Input CloudTrail data keys: {list(cloudtrail_data.keys())}")
        logger.info(f"Input Terraform data keys: {list(terraform_data.keys())}")

        try:
            # Get managed resources from Terraform state
            logger.info("Extracting managed resources from Terraform state...")
            managed_resources = self._extract_managed_resources(terraform_data)
            logger.info(f"Extracted {len(managed_resources)} managed resource identifiers")

            # Analyze manual changes from CloudTrail
            manual_changes = cloudtrail_data.get("manual_changes", [])
            logger.info(f"Processing {len(manual_changes)} manual changes from CloudTrail")

            # Detect different types of drift
            drifted_resources = []
            unmanaged_resources = []
            deleted_resources = []

            for i, change in enumerate(manual_changes):
                logger.debug(f"Analyzing change {i+1}/{len(manual_changes)}: {change.get('eventName', 'unknown')}")
                try:
                    drift_result = self._analyze_change(change, managed_resources)
                    logger.debug(f"Change {i+1} classified as: {drift_result['type']}")

                    if drift_result["type"] == "drifted":
                        drifted_resources.append(drift_result["resource"])
                    elif drift_result["type"] == "unmanaged":
                        unmanaged_resources.append(drift_result["resource"])
                    elif drift_result["type"] == "deleted":
                        deleted_resources.append(drift_result["resource"])

                except Exception as e:
                    logger.error(f"Error analyzing change {i+1}: {e}")
                    continue

            logger.info(f"Classification complete: {len(drifted_resources)} drifted, "
                       f"{len(unmanaged_resources)} unmanaged, {len(deleted_resources)} deleted")

            # Generate summary
            logger.info("Generating drift summary...")
            summary = self._generate_drift_summary(
                drifted_resources, unmanaged_resources, deleted_resources
            )
            logger.info(f"Summary generated: {summary}")

            # Serialize results
            logger.info("Serializing drift results...")
            serialized_drifted = [self._serialize_drift(d) for d in drifted_resources]
            serialized_unmanaged = [self._serialize_drift(u) for u in unmanaged_resources]
            serialized_deleted = [self._serialize_drift(d) for d in deleted_resources]

            logger.info("=== DRIFT DETECTOR: Analysis complete ===")

            return {
                "drifted_resources": serialized_drifted,
                "unmanaged_resources": serialized_unmanaged,
                "deleted_resources": serialized_deleted,
                "summary": summary
            }

        except Exception as e:
            logger.error(f"=== DRIFT DETECTOR: Error in analysis ===")
            logger.error(f"Error: {e}")
            import traceback
            logger.error(f"Traceback: {traceback.format_exc()}")
            raise

    def _extract_managed_resources(self, terraform_data: Dict[str, Any]) -> Set[str]:
        """Extract resource identifiers from Terraform state."""
        managed_resources = set()

        for resource in terraform_data.get("resources", []):
            # Extract from basic fields (ultra-minimal format)
            for field in ["id", "name"]:
                if field in resource and resource[field]:
                    managed_resources.add(str(resource[field]))

        logger.debug(f"Extracted {len(managed_resources)} managed resource identifiers")
        return managed_resources

    def _analyze_change(
        self,
        change: Dict[str, Any],
        managed_resources: Set[str]
    ) -> Dict[str, Any]:
        """Analyze a single change to determine drift type."""
        event_name = change.get("eventName", "")
        resources = change.get("resources", [])

        logger.debug(f"Analyzing change: {event_name}")
        logger.debug(f"Change data: {change}")

        try:
            # Extract resource information
            resource_id = self._extract_resource_id(change)
            resource_type = self._extract_resource_type(change)
            resource_arn = self._extract_resource_arn(change)
            drift_type = self._determine_drift_type(event_name)
            event_time = self._parse_event_time(change.get("eventTime"))
            terraform_managed = self._is_terraform_managed(change, managed_resources)
            severity = self._assess_change_severity(change)

            logger.debug(f"Extracted: id={resource_id}, type={resource_type}, arn={resource_arn}")
            logger.debug(f"Drift type: {drift_type}, Terraform managed: {terraform_managed}, Severity: {severity}")

            # Create drifted resource object
            drifted_resource = DriftedResource(
                resource_id=resource_id,
                resource_type=resource_type,
                resource_arn=resource_arn,
                drift_type=drift_type,
                changes=[change],
                event_time=event_time,
                user_identity=change.get("userIdentity", {}),
                source_ip=change.get("sourceIPAddress"),
                terraform_managed=terraform_managed,
                severity=severity
            )

            # Determine drift category
            if drifted_resource.terraform_managed:
                if drifted_resource.drift_type == "deleted":
                    category = "deleted"
                else:
                    category = "drifted"
            else:
                category = "unmanaged"

            logger.debug(f"Change categorized as: {category}")
            return {"type": category, "resource": drifted_resource}

        except Exception as e:
            logger.error(f"Error in _analyze_change: {e}")
            logger.error(f"Change data that caused error: {change}")
            raise

    def _extract_resource_id(self, change: Dict[str, Any]) -> str:
        """Extract resource ID from CloudTrail event."""
        # Check single resourceId first (new ultra-minimal format)
        resource_id = change.get("resourceId")
        if resource_id:
            return str(resource_id)

        # Check single resource object
        resource = change.get("resource", {})
        if resource:
            resource_name = resource.get("name")
            if resource_name:
                return resource_name

        # Fallback to event source and name
        return f"{change.get('eventSource', '')}/{change.get('eventName', '')}"

    def _extract_resource_type(self, change: Dict[str, Any]) -> str:
        """Extract resource type from CloudTrail event."""
        event_source = change.get("eventSource", "")
        event_name = change.get("eventName", "")

        # Map event source to resource type
        source_mapping = {
            "ec2.amazonaws.com": "EC2",
            "rds.amazonaws.com": "RDS",
            "iam.amazonaws.com": "IAM",
            "s3.amazonaws.com": "S3",
            "lambda.amazonaws.com": "Lambda"
        }

        return source_mapping.get(event_source, event_source)

    def _extract_resource_arn(self, change: Dict[str, Any]) -> Optional[str]:
        """Extract resource ARN from CloudTrail event if available."""
        # Check single resource object
        resource = change.get("resource", {})
        if resource:
            resource_name = resource.get("name")
            if resource_name and resource_name.startswith("arn:"):
                return resource_name
        return None

    def _determine_drift_type(self, event_name: str) -> str:
        """Determine the type of drift based on event name."""
        if any(word in event_name.lower() for word in ["create", "run", "launch"]):
            return "created"
        elif any(word in event_name.lower() for word in ["delete", "terminate", "remove"]):
            return "deleted"
        else:
            return "modified"

    def _is_terraform_managed(
        self,
        change: Dict[str, Any],
        managed_resources: Set[str]
    ) -> bool:
        """Check if the resource is managed by Terraform."""
        # Check if resource ID is in Terraform state
        resource_id = self._extract_resource_id(change)
        resource_arn = self._extract_resource_arn(change)

        if resource_id in managed_resources:
            return True
        if resource_arn and resource_arn in managed_resources:
            return True

        return False

    def _assess_change_severity(self, change: Dict[str, Any]) -> str:
        """Assess the severity of a change."""
        event_name = change.get("eventName", "")
        user_identity = change.get("userIdentity", {})

        # Critical events
        critical_events = [
            "DeleteBucket", "DeleteDBInstance", "TerminateInstances",
            "DeleteRole", "DeletePolicy"
        ]

        # High risk events
        high_risk_events = [
            "AuthorizeSecurityGroupIngress", "CreateRole", "AttachRolePolicy",
            "PutBucketPolicy", "ModifyDBInstance"
        ]

        if event_name in critical_events:
            return "critical"
        elif event_name in high_risk_events:
            return "high"
        elif user_identity.get("type") == "Root":
            return "high"
        else:
            return "medium"

    def _generate_drift_summary(
        self,
        drifted_resources: List[DriftedResource],
        unmanaged_resources: List[DriftedResource],
        deleted_resources: List[DriftedResource]
    ) -> Dict[str, Any]:
        """Generate a summary of drift detection results."""
        total_drift = len(drifted_resources) + len(unmanaged_resources) + len(deleted_resources)

        # Count by severity
        severity_counts = {"low": 0, "medium": 0, "high": 0, "critical": 0}
        all_resources = drifted_resources + unmanaged_resources + deleted_resources

        for resource in all_resources:
            severity_counts[resource.severity] += 1

        # Count by resource type
        resource_type_counts = {}
        for resource in all_resources:
            resource_type_counts[resource.resource_type] = resource_type_counts.get(
                resource.resource_type, 0
            ) + 1

        return {
            "total_drift_items": total_drift,
            "drifted_count": len(drifted_resources),
            "unmanaged_count": len(unmanaged_resources),
            "deleted_count": len(deleted_resources),
            "severity_breakdown": severity_counts,
            "resource_type_breakdown": resource_type_counts,
            "requires_attention": severity_counts["high"] + severity_counts["critical"] > 0
        }

    def _parse_event_time(self, event_time) -> datetime:
        """Parse event time from various formats."""
        if isinstance(event_time, datetime):
            return event_time
        elif isinstance(event_time, str):
            # Handle ISO format with Z suffix
            if event_time.endswith("Z"):
                event_time = event_time.replace("Z", "+00:00")
            try:
                return datetime.fromisoformat(event_time)
            except ValueError:
                # Fallback to current time if parsing fails
                logger.warning(f"Failed to parse event time: {event_time}")
                return datetime.utcnow()
        else:
            # Fallback to current time
            return datetime.utcnow()

    def _serialize_drift(self, drift: DriftedResource) -> Dict[str, Any]:
        """Serialize a DriftedResource object to dictionary."""
        return {
            "resource_id": drift.resource_id,
            "resource_type": drift.resource_type,
            "resource_arn": drift.resource_arn,
            "drift_type": drift.drift_type,
            "changes": drift.changes,
            "event_time": drift.event_time.isoformat(),
            "user_identity": drift.user_identity,
            "source_ip": drift.source_ip,
            "terraform_managed": drift.terraform_managed,
            "severity": drift.severity
        }