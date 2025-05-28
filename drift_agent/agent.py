"""
Main Drift Detection Agent implementation using AWS Strands framework.

This agent orchestrates the detection of infrastructure drift between IaC and runtime
environments, provides risk assessment, and facilitates remediation workflows.
"""

import logging
import json
from typing import Dict, Any, Optional, List
from datetime import datetime, timedelta

from strands import Agent, tool
from strands.models import BedrockModel

from .tools.cloudtrail import CloudTrailAnalyzer
from .tools.terraform import TerraformStateAnalyzer
from .tools.slack import SlackNotifier
from .tools.risk_assessment import RiskAssessmentTool
from .core.drift_detector import DriftDetector
from .core.risk_analyzer import RiskAnalyzer
from .core.remediation import RemediationEngine
from .utils.logging import setup_logging
from .utils.aws_client import AWSClientManager
from .config.settings import Settings

logger = logging.getLogger(__name__)

# Global instances for tool functions
_config = None
_aws_client = None
_drift_detector = None
_risk_analyzer = None
_remediation_engine = None
_cloudtrail_analyzer = None
_terraform_analyzer = None
_slack_notifier = None
_risk_assessment_tool = None

def _initialize_components(config: Settings):
    """Initialize global components for tool functions."""
    global _config, _aws_client, _drift_detector, _risk_analyzer, _remediation_engine
    global _cloudtrail_analyzer, _terraform_analyzer, _slack_notifier, _risk_assessment_tool

    _config = config
    _aws_client = AWSClientManager(config)
    _drift_detector = DriftDetector(config, _aws_client)
    _risk_analyzer = RiskAnalyzer(config)
    _remediation_engine = RemediationEngine(config, _aws_client)
    _cloudtrail_analyzer = CloudTrailAnalyzer(config, _aws_client)
    _terraform_analyzer = TerraformStateAnalyzer(config, _aws_client)
    _slack_notifier = SlackNotifier(config)
    _risk_assessment_tool = RiskAssessmentTool(config)


# Define tool functions that will be used by the Strands agent
def _filter_cloudtrail_event(event: Dict[str, Any]) -> Dict[str, Any]:
    """Filter CloudTrail event to only essential fields for drift detection."""
    # Handle different event formats (API vs S3)
    event_data = event

    # If event has CloudTrailEvent field (from LookupEvents API), parse it
    if "CloudTrailEvent" in event and isinstance(event["CloudTrailEvent"], str):
        try:
            event_data = json.loads(event["CloudTrailEvent"])
        except (json.JSONDecodeError, TypeError):
            event_data = event

    # Extract only the most essential fields - ultra-minimal for token reduction
    filtered = {
        "eventName": event_data.get("eventName") or event.get("EventName"),
        "eventTime": event_data.get("eventTime") or event.get("EventTime"),
        "eventSource": event_data.get("eventSource") or event.get("EventSource"),
        "userIdentity": {
            "type": event_data.get("userIdentity", {}).get("type"),
            "userName": event_data.get("userIdentity", {}).get("userName")
        }
    }

    # Extract only the first resource (most relevant)
    resources = event_data.get("resources", []) or event.get("Resources", [])
    if resources:
        resource = resources[0]  # Only take the first resource to minimize data
        filtered["resource"] = {
            "type": resource.get("type") or resource.get("ResourceType"),
            "name": resource.get("ARN") or resource.get("ResourceName")
        }

    # Extract only one key resource identifier
    request_params = event_data.get("requestParameters", {})
    if request_params:
        # Only include the first found resource ID
        for key in ["instanceId", "groupId", "volumeId", "bucketName", "functionName", "roleName"]:
            if key in request_params:
                filtered["resourceId"] = request_params[key]
                break

    return filtered


@tool
def analyze_cloudtrail_logs(
    hours_back: int = 12,
    event_types: Optional[List[str]] = None,
    resources: Optional[List[str]] = None
) -> Dict[str, Any]:
    """
    Analyze CloudTrail logs for infrastructure changes.

    Args:
        hours_back: Number of hours back to analyze (default: 12)
        event_types: Specific AWS API events to filter for
        resources: Specific resource types to filter for

    Returns:
        Dictionary containing analysis results with detected changes
    """
    logger.info(f"Analyzing CloudTrail logs for the last {hours_back} hours")

    try:
        start_time = datetime.utcnow() - timedelta(hours=hours_back)
        end_time = datetime.utcnow()

        events = _cloudtrail_analyzer.get_events(
            start_time=start_time,
            end_time=end_time,
            event_types=event_types,
            resources=resources
        )

        analysis = _cloudtrail_analyzer.analyze_events(events)

        # Filter the events to reduce data size for drift detection and limit to most recent
        max_events = 5  # Limit to 5 most recent events to reduce token usage
        filtered_manual_changes = [_filter_cloudtrail_event(event) for event in analysis["manual_changes"][:max_events]]
        filtered_iac_changes = [_filter_cloudtrail_event(event) for event in analysis["iac_changes"][:max_events]]
        filtered_high_risk = [_filter_cloudtrail_event(event) for event in analysis["high_risk_events"][:max_events]]

        logger.info(f"Found {len(events)} CloudTrail events, {len(filtered_manual_changes)} manual changes (limited to {max_events})")
        logger.info(f"Filtered CloudTrail data: {len(analysis['manual_changes'])} -> {len(filtered_manual_changes)} manual changes")

        return {
            "total_events": len(events),
            "manual_changes": filtered_manual_changes,
            "iac_changes": filtered_iac_changes,
            "high_risk_events": filtered_high_risk,
            "summary": analysis["summary"]
        }

    except Exception as e:
        logger.error(f"Error analyzing CloudTrail logs: {e}")
        return {"error": str(e), "manual_changes": [], "iac_changes": []}


def _filter_terraform_resource(resource: Dict[str, Any]) -> Dict[str, Any]:
    """Filter Terraform resource to only essential fields for drift detection."""
    attributes = resource.get("attributes", {})

    # Extract only the most essential fields - ultra-minimal for token reduction
    filtered = {
        "type": resource.get("type"),
        "name": resource.get("name")
    }

    # Add only the first found key identifier
    for key in ["id", "arn", "instance_id", "group_id", "volume_id", "bucket", "function_name"]:
        if key in attributes and attributes[key]:
            filtered["id"] = attributes[key]
            break

    return filtered


@tool
def analyze_terraform_state(
    workspace: Optional[str] = None,
    modules: Optional[List[str]] = None
) -> Dict[str, Any]:
    """
    Analyze Terraform state to understand expected infrastructure.

    Args:
        workspace: Terraform workspace to analyze (default: from config)
        modules: Specific modules to analyze

    Returns:
        Dictionary containing Terraform state analysis
    """
    logger.info("Analyzing Terraform state")

    try:
        state_data = _terraform_analyzer.get_state(workspace or _config.terraform_workspace)
        resources = _terraform_analyzer.parse_resources(state_data, modules)

        # Filter resources to reduce data size for drift detection
        filtered_resources = [_filter_terraform_resource(resource) for resource in resources]

        logger.info(f"Analyzed {len(filtered_resources)} resources from Terraform state")
        logger.info(f"Filtered Terraform data: reduced resource attribute data for {len(filtered_resources)} resources")

        return {
            "workspace": workspace or _config.terraform_workspace,
            "total_resources": len(filtered_resources),
            "resources": filtered_resources,
            "modules": list(set(r.get("module", "root") for r in filtered_resources)),
            "resource_types": list(set(r.get("type") for r in filtered_resources))
        }

    except Exception as e:
        logger.error(f"Error analyzing Terraform state: {e}")
        return {"error": str(e), "resources": []}


@tool
def detect_drift(
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
    logger.info("=== STARTING DRIFT DETECTION ===")
    logger.info(f"CloudTrail data contains {len(cloudtrail_data.get('manual_changes', []))} manual changes")
    logger.info(f"Terraform data contains {len(terraform_data.get('resources', []))} resources")

    # Log sample data for debugging
    if cloudtrail_data.get('manual_changes'):
        logger.info(f"Sample CloudTrail change: {cloudtrail_data['manual_changes'][0]}")
    if terraform_data.get('resources'):
        logger.info(f"Sample Terraform resource: {terraform_data['resources'][0]}")

    try:
        logger.info("Calling drift detector...")
        drift_results = _drift_detector.detect_drift(cloudtrail_data, terraform_data)
        logger.info("Drift detector returned results")

        logger.info(f"=== DRIFT DETECTION COMPLETED SUCCESSFULLY ===")
        logger.info(f"Found {len(drift_results['drifted_resources'])} drifted resources")
        logger.info(f"Found {len(drift_results['unmanaged_resources'])} unmanaged resources")
        logger.info(f"Found {len(drift_results['deleted_resources'])} deleted resources")

        # Log summary details
        summary = drift_results.get("summary", {})
        logger.info(f"Summary: {summary}")

        return {
            "drifted_resources": drift_results["drifted_resources"],
            "unmanaged_resources": drift_results["unmanaged_resources"],
            "deleted_resources": drift_results["deleted_resources"],
            "drift_summary": drift_results["summary"]
        }

    except Exception as e:
        logger.error(f"=== ERROR IN DRIFT DETECTION ===")
        logger.error(f"Error detecting drift: {e}")
        import traceback
        logger.error(f"Full traceback: {traceback.format_exc()}")
        return {"error": str(e), "drifted_resources": [], "unmanaged_resources": [], "deleted_resources": []}


@tool
def assess_risk(
    drift_data: Dict[str, Any],
    additional_context: Optional[str] = None
) -> Dict[str, Any]:
    """
    Assess the risk level of detected drift using GenAI analysis.

    Args:
        drift_data: Results from drift detection
        additional_context: Additional context for risk assessment

    Returns:
        Dictionary containing risk assessment results
    """
    logger.info("Assessing risk of detected drift")

    try:
        risk_assessment = _risk_analyzer.assess_drift_risk(drift_data, additional_context)

        high_risk_count = len([r for r in risk_assessment["resource_risks"] if r["risk_level"] == "HIGH"])
        logger.info(f"Risk assessment complete: {high_risk_count} high-risk resources")

        return risk_assessment

    except Exception as e:
        logger.error(f"Error assessing risk: {e}")
        return {"error": str(e), "overall_risk": "UNKNOWN"}


@tool
def recommend_remediation(
    risk_assessment: Dict[str, Any],
    drift_data: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Generate remediation recommendations based on risk assessment.

    Args:
        risk_assessment: Results from risk assessment
        drift_data: Results from drift detection

    Returns:
        Dictionary containing remediation recommendations
    """
    logger.info("Generating remediation recommendations")

    try:
        recommendations = _remediation_engine.generate_recommendations(
            risk_assessment, drift_data
        )

        auto_approve_count = len([r for r in recommendations["actions"] if r["auto_approve"]])
        logger.info(f"Generated {len(recommendations['actions'])} recommendations, {auto_approve_count} auto-approved")

        return recommendations

    except Exception as e:
        logger.error(f"Error generating recommendations: {e}")
        return {"error": str(e), "actions": []}


@tool
def send_slack_notification(
    message: str,
    risk_level: str = "MEDIUM",
    requires_approval: bool = False,
    metadata: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Send notification to Slack channel with optional approval workflow.

    Args:
        message: Message content to send
        risk_level: Risk level (LOW, MEDIUM, HIGH, CRITICAL)
        requires_approval: Whether this notification requires approval
        metadata: Additional metadata to include

    Returns:
        Dictionary containing notification results
    """
    logger.info(f"Sending Slack notification (risk: {risk_level})")

    try:
        if not _config.slack_bot_token:
            logger.warning("Slack integration not configured, skipping notification")
            return {"status": "skipped", "reason": "Slack not configured"}

        result = _slack_notifier.send_notification(
            message=message,
            risk_level=risk_level,
            requires_approval=requires_approval,
            metadata=metadata
        )

        logger.info(f"Slack notification sent successfully: {result['message_ts']}")
        return result

    except Exception as e:
        logger.error(f"Error sending Slack notification: {e}")
        return {"error": str(e), "status": "failed"}


@tool
def execute_remediation(
    action: Dict[str, Any],
    approved: bool = False,
    dry_run: bool = True
) -> Dict[str, Any]:
    """
    Execute a remediation action with safety checks.

    Args:
        action: Remediation action to execute
        approved: Whether the action has been approved
        dry_run: Whether to perform a dry run (default: True)

    Returns:
        Dictionary containing execution results
    """
    logger.info(f"Executing remediation action: {action.get('type', 'unknown')}")

    try:
        if not approved and action.get("risk_level") in ["HIGH", "CRITICAL"]:
            logger.warning("High-risk action requires approval, skipping execution")
            return {
                "status": "skipped",
                "reason": "High-risk action requires approval",
                "action_id": action.get("id")
            }

        result = _remediation_engine.execute_action(action, dry_run)

        logger.info(f"Remediation action executed: {result['status']}")
        return result

    except Exception as e:
        logger.error(f"Error executing remediation: {e}")
        return {"error": str(e), "status": "failed"}


@tool
def generate_compliance_report(
    drift_data: Dict[str, Any],
    risk_assessment: Dict[str, Any],
    remediation_results: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Generate a compliance report summarizing drift detection and remediation.

    Args:
        drift_data: Drift detection results
        risk_assessment: Risk assessment results
        remediation_results: Remediation execution results

    Returns:
        Dictionary containing the compliance report
    """
    logger.info("Generating compliance report")

    try:
        report = {
            "timestamp": datetime.utcnow().isoformat(),
            "agent_version": _config.agent_version,
            "summary": {
                "total_drift_items": len(drift_data.get("drifted_resources", [])),
                "high_risk_items": len([
                    r for r in risk_assessment.get("resource_risks", [])
                    if r.get("risk_level") == "HIGH"
                ]),
                "remediation_actions": len(remediation_results.get("actions", [])),
                "auto_approved_actions": len([
                    a for a in remediation_results.get("actions", [])
                    if a.get("auto_approve", False)
                ])
            },
            "drift_summary": drift_data.get("drift_summary", {}),
            "risk_summary": risk_assessment.get("summary", {}),
            "remediation_summary": remediation_results.get("summary", {}),
            "recommendations": [
                "Review high-risk drift items with security team",
                "Update IaC templates to prevent future drift",
                "Implement automated policy enforcement",
                "Schedule regular drift detection scans"
            ]
        }

        logger.info("Compliance report generated successfully")
        return report

    except Exception as e:
        logger.error(f"Error generating compliance report: {e}")
        return {"error": str(e)}


class DriftDetectionAgent:
    """
    AWS Infrastructure Drift Detection Agent using Strands framework.

    This agent provides comprehensive drift detection and remediation capabilities:
    - Analyzes CloudTrail logs for manual infrastructure changes
    - Compares runtime state with Terraform state
    - Assesses risks using GenAI
    - Provides automated remediation recommendations
    - Integrates with Slack for notifications and approvals
    """

    def __init__(self, config: Optional[Settings] = None):
        """
        Initialize the Drift Detection Agent.

        Args:
            config: Optional configuration settings. If not provided, will load from environment.
        """
        self.config = config or Settings()

        # Initialize global components for tool functions
        _initialize_components(self.config)

        # Setup logging
        setup_logging(self.config)

        # Initialize Strands agent with Bedrock model and timeout configuration
        from botocore.config import Config

        bedrock_config = Config(
            read_timeout=self.config.bedrock_read_timeout,
            connect_timeout=self.config.bedrock_connect_timeout,
            retries={
                'max_attempts': 3,
                'mode': 'adaptive'
            }
        )

        self.bedrock_model = BedrockModel(
            model_id=self.config.bedrock_model_id,
            region_name=self.config.bedrock_region,
            temperature=self.config.bedrock_temperature,
            boto_client_config=bedrock_config
        )

        # Create the Strands agent with all tools
        self.agent = Agent(
            model=self.bedrock_model,
            tools=[
                analyze_cloudtrail_logs,
                analyze_terraform_state,
                detect_drift,
                assess_risk,
                recommend_remediation,
                send_slack_notification,
                execute_remediation,
                generate_compliance_report,
            ],
            system_prompt=self._get_system_prompt()
        )

        logger.info("Drift Detection Agent initialized successfully")

    def _get_system_prompt(self) -> str:
        """Get the system prompt for the agent."""
        return """
        You are an expert AWS Infrastructure Drift Detection Agent. Your role is to:

        1. DETECT infrastructure drift by analyzing CloudTrail logs and comparing with Terraform state
        2. ASSESS the security and operational risks of detected changes
        3. RECOMMEND appropriate remediation actions (remove, revert, or integrate changes)
        4. FACILITATE human-in-the-loop approval workflows via Slack
        5. EXECUTE approved remediation actions safely

        Key principles:
        - Always prioritize security and compliance
        - Require human approval for high-risk changes
        - Provide clear, actionable recommendations
        - Maintain detailed audit trails
        - Be conservative with automated actions

        IMPORTANT: You MUST use the available tools to perform analysis. Do NOT make up or hallucinate results.
        Always call the appropriate tools to gather real data before providing analysis or recommendations.

        Available tools:
        - analyze_cloudtrail_logs: Analyze AWS CloudTrail events for infrastructure changes
        - analyze_terraform_state: Examine Terraform state to understand expected infrastructure
        - detect_drift: Compare CloudTrail events with Terraform state to identify drift
        - assess_risk: Use AI to assess the security and operational risks of detected changes
        - recommend_remediation: Generate specific remediation recommendations
        - send_slack_notification: Send notifications and collect approvals via Slack
        - execute_remediation: Execute approved remediation actions with safety checks
        - generate_compliance_report: Create comprehensive compliance and audit reports

        Workflow for drift detection:
        1. ALWAYS start by calling analyze_cloudtrail_logs to gather recent infrastructure events
        2. ALWAYS call analyze_terraform_state to understand the expected infrastructure state
        3. Use detect_drift to compare the actual vs expected state and identify drift
        4. Call assess_risk to evaluate the security and operational impact of detected drift
        5. Use recommend_remediation to generate specific action recommendations
        6. If high-risk changes are detected, use send_slack_notification for human approval
        7. Execute approved actions using execute_remediation (with dry_run=True by default)
        8. Generate final compliance report using generate_compliance_report

        Remember: You are an AI agent that uses tools to perform real analysis. Never provide
        made-up data or analysis results. Always use the tools to gather actual information.
        """



    def __call__(self, message: str) -> Any:
        """
        Make the agent callable, forwarding to the Strands agent.

        Args:
            message: User message/query

        Returns:
            Agent response
        """
        return self.agent(message)

    async def run_monitoring_loop(self, interval_minutes: int = 60):
        """
        Run continuous monitoring loop for drift detection.

        Args:
            interval_minutes: Interval between checks in minutes
        """
        import asyncio

        logger.info(f"Starting monitoring loop with {interval_minutes} minute intervals")

        while True:
            try:
                logger.info("Running scheduled drift detection")
                result = self("Check for infrastructure drift in the last hour")
                logger.info(f"Scheduled drift detection completed: {result}")

            except Exception as e:
                logger.error(f"Error in monitoring loop: {e}")

            await asyncio.sleep(interval_minutes * 60)