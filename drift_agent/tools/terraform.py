"""
Terraform state analyzer tool for understanding managed infrastructure.

Fetches and analyzes Terraform state files to understand which resources
are managed by Infrastructure as Code.
"""

import logging
import json
from typing import Dict, Any, List, Optional, Set
import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)


class TerraformStateAnalyzer:
    """
    Terraform state analyzer for drift detection.

    Fetches Terraform state from S3 backend and analyzes it to understand
    which infrastructure resources are managed by IaC.
    """

    def __init__(self, config, aws_client):
        """
        Initialize the Terraform state analyzer.

        Args:
            config: Application configuration
            aws_client: AWS client manager
        """
        self.config = config
        self.aws_client = aws_client
        self.s3_client = aws_client.get_client("s3")

        # Mapping of Terraform resource types to AWS resource identifiers
        self.resource_id_mappings = {
            "aws_instance": ["id", "arn"],
            "aws_security_group": ["id", "arn"],
            "aws_s3_bucket": ["id", "arn", "bucket"],
            "aws_iam_role": ["id", "arn", "name"],
            "aws_iam_policy": ["id", "arn"],
            "aws_iam_user": ["id", "arn", "name"],
            "aws_db_instance": ["id", "arn"],
            "aws_lambda_function": ["id", "arn", "function_name"],
            "aws_vpc": ["id", "arn"],
            "aws_subnet": ["id", "arn"],
            "aws_route_table": ["id", "arn"],
            "aws_internet_gateway": ["id", "arn"],
            "aws_ebs_volume": ["id", "arn"],
            "aws_cloudformation_stack": ["id", "arn"],
        }

        # Tags that indicate Terraform management
        self.terraform_tags = [
            "ManagedBy", "terraform", "Terraform", "IaC", "Infrastructure"
        ]

    def get_state(self, workspace: str = "default") -> Dict[str, Any]:
        """
        Fetch Terraform state from S3 backend.

        Args:
            workspace: Terraform workspace name

        Returns:
            Terraform state data as dictionary
        """
        logger.info(f"Fetching Terraform state for workspace: {workspace}")

        try:
            # Get the full S3 key for Terraform state
            state_key = self.config.get_terraform_state_path(workspace)

            logger.debug(f"Fetching Terraform state from S3 key: {state_key}")

            # Fetch state file from S3
            response = self.s3_client.get_object(
                Bucket=self.config.terraform_state_bucket,
                Key=state_key
            )

            # Parse JSON content
            state_content = response["Body"].read().decode("utf-8")
            state_data = json.loads(state_content)

            logger.info(f"Successfully retrieved Terraform state (version: {state_data.get('version', 'unknown')})")
            return state_data

        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "")
            if error_code == "NoSuchKey":
                logger.warning(f"Terraform state not found: {state_key}")
            else:
                logger.error(f"Error fetching Terraform state: {e}")
            return {}

        except json.JSONDecodeError as e:
            logger.error(f"Error parsing Terraform state JSON: {e}")
            return {}

        except Exception as e:
            logger.error(f"Unexpected error fetching Terraform state: {e}")
            return {}

    def parse_resources(
        self,
        state_data: Dict[str, Any],
        modules: Optional[List[str]] = None
    ) -> List[Dict[str, Any]]:
        """
        Parse resources from Terraform state data.

        Args:
            state_data: Terraform state data
            modules: Specific modules to analyze (None for all)

        Returns:
            List of resource information dictionaries
        """
        logger.info("Parsing resources from Terraform state")

        resources = []

        # Handle different Terraform state versions
        if "resources" in state_data:
            # Terraform 0.12+ state format
            resources.extend(self._parse_v4_resources(state_data["resources"], modules))
        elif "modules" in state_data:
            # Terraform 0.11 and older state format
            for module in state_data["modules"]:
                if modules is None or module.get("path", ["root"])[-1] in modules:
                    resources.extend(self._parse_legacy_module_resources(module))

        logger.info(f"Parsed {len(resources)} resources from Terraform state")
        return resources

    def _parse_v4_resources(
        self,
        resources_data: List[Dict[str, Any]],
        modules: Optional[List[str]] = None
    ) -> List[Dict[str, Any]]:
        """Parse resources from Terraform 0.12+ state format."""
        resources = []

        for resource in resources_data:
            # Check if we should include this module
            module_path = resource.get("module", "root")
            if modules is not None and module_path not in modules:
                continue

            resource_type = resource.get("type", "")
            resource_name = resource.get("name", "")
            instances = resource.get("instances", [])

            for instance in instances:
                attributes = instance.get("attributes", {})

                # Extract resource identifiers
                resource_info = {
                    "type": resource_type,
                    "name": resource_name,
                    "module": module_path,
                    "attributes": attributes,
                    "identifiers": self._extract_resource_identifiers(resource_type, attributes),
                    "tags": attributes.get("tags", {}),
                    "terraform_managed": True
                }

                resources.append(resource_info)

        return resources

    def _parse_legacy_module_resources(self, module: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Parse resources from legacy Terraform state format."""
        resources = []
        module_resources = module.get("resources", {})

        for resource_key, resource_data in module_resources.items():
            # Parse resource type and name from key
            if "." not in resource_key:
                continue

            resource_type, resource_name = resource_key.split(".", 1)

            # Handle primary instance
            primary = resource_data.get("primary", {})
            attributes = primary.get("attributes", {})

            resource_info = {
                "type": resource_type,
                "name": resource_name,
                "module": ".".join(module.get("path", ["root"])),
                "attributes": attributes,
                "identifiers": self._extract_resource_identifiers(resource_type, attributes),
                "tags": self._parse_legacy_tags(attributes),
                "terraform_managed": True
            }

            resources.append(resource_info)

        return resources

    def _extract_resource_identifiers(
        self,
        resource_type: str,
        attributes: Dict[str, Any]
    ) -> List[str]:
        """Extract all possible identifiers for a resource."""
        identifiers = []

        # Get identifier fields for this resource type
        id_fields = self.resource_id_mappings.get(resource_type, ["id"])

        for field in id_fields:
            if field in attributes and attributes[field]:
                identifiers.append(str(attributes[field]))

        # Add any additional identifiers from common fields
        common_fields = ["arn", "id", "name"]
        for field in common_fields:
            if field in attributes and attributes[field] and str(attributes[field]) not in identifiers:
                identifiers.append(str(attributes[field]))

        return identifiers

    def _parse_legacy_tags(self, attributes: Dict[str, Any]) -> Dict[str, str]:
        """Parse tags from legacy Terraform state format."""
        tags = {}

        # Look for tag attributes in various formats
        if "tags.%" in attributes:
            # Count-based tag format
            tag_count = int(attributes.get("tags.%", 0))
            for i in range(tag_count):
                key = attributes.get(f"tags.{i}.key", "")
                value = attributes.get(f"tags.{i}.value", "")
                if key:
                    tags[key] = value
        else:
            # Direct tag format
            for key, value in attributes.items():
                if key.startswith("tags.") and not key.endswith(".%"):
                    tag_key = key[5:]  # Remove "tags." prefix
                    tags[tag_key] = str(value)

        return tags

    def get_managed_resource_ids(self, state_data: Dict[str, Any]) -> Set[str]:
        """
        Get a set of all resource IDs managed by Terraform.

        Args:
            state_data: Terraform state data

        Returns:
            Set of resource identifiers
        """
        managed_ids = set()
        resources = self.parse_resources(state_data)

        for resource in resources:
            managed_ids.update(resource["identifiers"])

        logger.debug(f"Found {len(managed_ids)} managed resource identifiers")
        return managed_ids

    def analyze_state_health(self, state_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze the health and characteristics of the Terraform state.

        Args:
            state_data: Terraform state data

        Returns:
            Dictionary containing state analysis
        """
        logger.info("Analyzing Terraform state health")

        resources = self.parse_resources(state_data)

        # Count resources by type
        resource_type_counts = {}
        for resource in resources:
            resource_type = resource["type"]
            resource_type_counts[resource_type] = resource_type_counts.get(resource_type, 0) + 1

        # Count resources by module
        module_counts = {}
        for resource in resources:
            module = resource["module"]
            module_counts[module] = module_counts.get(module, 0) + 1

        # Check for common issues
        issues = []

        # Check for missing tags
        untagged_resources = []
        for resource in resources:
            if not resource["tags"] and resource["type"] in [
                "aws_instance", "aws_s3_bucket", "aws_iam_role"
            ]:
                untagged_resources.append(resource["name"])

        if untagged_resources:
            issues.append({
                "type": "missing_tags",
                "severity": "medium",
                "description": f"{len(untagged_resources)} resources missing tags",
                "resources": untagged_resources[:10]  # Limit to first 10
            })

        # Check state version
        state_version = state_data.get("version", 0)
        terraform_version = state_data.get("terraform_version", "unknown")

        if state_version < 4:
            issues.append({
                "type": "old_state_version",
                "severity": "low",
                "description": f"Using old state version {state_version}",
                "recommendation": "Consider upgrading Terraform"
            })

        return {
            "state_version": state_version,
            "terraform_version": terraform_version,
            "total_resources": len(resources),
            "resource_type_breakdown": resource_type_counts,
            "module_breakdown": module_counts,
            "issues": issues,
            "health_score": self._calculate_health_score(resources, issues),
            "last_modified": state_data.get("lineage", "unknown")
        }

    def _calculate_health_score(self, resources: List[Dict[str, Any]], issues: List[Dict[str, Any]]) -> float:
        """Calculate a health score for the Terraform state."""
        base_score = 100.0

        # Deduct points for issues
        for issue in issues:
            severity = issue.get("severity", "low")
            if severity == "critical":
                base_score -= 30
            elif severity == "high":
                base_score -= 20
            elif severity == "medium":
                base_score -= 10
            elif severity == "low":
                base_score -= 5

        # Bonus points for good practices
        tagged_resources = sum(1 for r in resources if r["tags"])
        if resources:
            tag_percentage = tagged_resources / len(resources)
            base_score += tag_percentage * 10  # Up to 10 bonus points for good tagging

        return max(0.0, min(100.0, base_score))

    def compare_with_live_state(self, state_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Compare Terraform state with live AWS resources (placeholder).

        This method would typically use AWS APIs to compare the state
        with actual resource configurations in AWS.

        Args:
            state_data: Terraform state data

        Returns:
            Dictionary containing comparison results
        """
        logger.info("Comparing Terraform state with live AWS state")

        # This is a placeholder for live state comparison
        # In a full implementation, this would:
        # 1. Query AWS APIs for each resource in the state
        # 2. Compare attributes between state and live resources
        # 3. Identify discrepancies and potential drift

        resources = self.parse_resources(state_data)

        return {
            "total_resources_checked": len(resources),
            "drift_detected": False,  # Placeholder
            "drifted_resources": [],  # Would contain actual drift data
            "missing_resources": [],  # Resources in state but not in AWS
            "extra_resources": [],    # Resources in AWS but not in state
            "comparison_timestamp": "placeholder"  # Would use actual timestamp
        }

if __name__ == "__main__":
    from config.settings import Settings
    from utils.aws_client import AWSClientManager

    config = Settings()
    aws_client = AWSClientManager(config)
    terraform_analyzer = TerraformStateAnalyzer(config, aws_client)
    state_data = terraform_analyzer.get_state()
    print(state_data)