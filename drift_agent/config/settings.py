"""
Configuration settings for the Drift Detection Agent.

Uses Pydantic Settings for environment variable management with validation.
Supports aws-vault and other AWS credential providers through the default credential chain.
"""

from typing import Optional, List
from pydantic import Field, validator
from pydantic_settings import BaseSettings
import os


class Settings(BaseSettings):
    """Configuration settings loaded from environment variables."""

    # AWS Configuration
    # Note: When using aws-vault or other credential providers, these should be left unset
    # to allow boto3 to use the default credential chain
    aws_region: str = Field(default="us-east-1", env="AWS_REGION")
    aws_access_key_id: Optional[str] = Field(default=None, env="AWS_ACCESS_KEY_ID")
    aws_secret_access_key: Optional[str] = Field(default=None, env="AWS_SECRET_ACCESS_KEY")
    aws_session_token: Optional[str] = Field(default=None, env="AWS_SESSION_TOKEN")
    aws_profile: Optional[str] = Field(default=None, env="AWS_PROFILE")

    # Amazon Bedrock Configuration
    bedrock_model_id: str = Field(
        default="us.anthropic.claude-3-7-sonnet-20250219-v1:0",
        env="BEDROCK_MODEL_ID"
    )
    bedrock_region: str = Field(default="us-east-1", env="BEDROCK_REGION")
    bedrock_temperature: float = Field(default=0.3, env="BEDROCK_TEMPERATURE")
    bedrock_read_timeout: int = Field(default=900, env="BEDROCK_READ_TIMEOUT")  # 15 minutes
    bedrock_connect_timeout: int = Field(default=120, env="BEDROCK_CONNECT_TIMEOUT")  # 2 minutes

    # CloudTrail Configuration
    cloudtrail_bucket: str = Field(..., env="CLOUDTRAIL_BUCKET")
    cloudtrail_prefix: str = Field(default="AWSLogs/", env="CLOUDTRAIL_PREFIX")
    cloudtrail_lookback_hours: int = Field(default=24, env="CLOUDTRAIL_LOOKBACK_HOURS")

    # Terraform Configuration
    terraform_state_bucket: str = Field(..., env="TERRAFORM_STATE_BUCKET")
    terraform_state_key: str = Field(default="terraform.tfstate", env="TERRAFORM_STATE_KEY")
    terraform_state_prefix: str = Field(default="", env="TERRAFORM_STATE_PREFIX")
    terraform_workspace: str = Field(default="default", env="TERRAFORM_WORKSPACE")

    # Slack Integration (Optional)
    slack_bot_token: Optional[str] = Field(default=None, env="SLACK_BOT_TOKEN")
    slack_channel: str = Field(default="#infrastructure-alerts", env="SLACK_CHANNEL")
    slack_webhook_url: Optional[str] = Field(default=None, env="SLACK_WEBHOOK_URL")

    # DynamoDB Configuration
    dynamodb_table_name: str = Field(default="drift-detection-state", env="DYNAMODB_TABLE_NAME")
    dynamodb_region: str = Field(default="us-east-1", env="DYNAMODB_REGION")

    # S3 Configuration for Artifacts
    artifacts_bucket: str = Field(..., env="ARTIFACTS_BUCKET")
    artifacts_prefix: str = Field(default="drift-detection/", env="ARTIFACTS_PREFIX")

    # Logging Configuration
    log_level: str = Field(default="INFO", env="LOG_LEVEL")
    log_format: str = Field(default="json", env="LOG_FORMAT")
    enable_debug_logs: bool = Field(default=False, env="ENABLE_DEBUG_LOGS")

    # Agent Configuration
    agent_name: str = Field(default="drift-detection-agent", env="AGENT_NAME")
    agent_version: str = Field(default="1.0.0", env="AGENT_VERSION")
    max_concurrent_checks: int = Field(default=5, env="MAX_CONCURRENT_CHECKS")

    # Risk Assessment Thresholds
    high_risk_threshold: float = Field(default=8.0, env="HIGH_RISK_THRESHOLD")
    medium_risk_threshold: float = Field(default=5.0, env="MEDIUM_RISK_THRESHOLD")
    auto_approve_threshold: float = Field(default=3.0, env="AUTO_APPROVE_THRESHOLD")

    # Monitoring Configuration
    health_check_interval: int = Field(default=300, env="HEALTH_CHECK_INTERVAL")
    metrics_enabled: bool = Field(default=True, env="METRICS_ENABLED")
    tracing_enabled: bool = Field(default=False, env="TRACING_ENABLED")

    @validator("log_level")
    def validate_log_level(cls, v):
        """Validate log level is one of the standard levels."""
        valid_levels = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
        if v.upper() not in valid_levels:
            raise ValueError(f"Log level must be one of: {valid_levels}")
        return v.upper()

    @validator("log_format")
    def validate_log_format(cls, v):
        """Validate log format is supported."""
        valid_formats = ["json", "text"]
        if v.lower() not in valid_formats:
            raise ValueError(f"Log format must be one of: {valid_formats}")
        return v.lower()

    @validator("bedrock_temperature")
    def validate_temperature(cls, v):
        """Validate temperature is within valid range."""
        if not 0.0 <= v <= 1.0:
            raise ValueError("Temperature must be between 0.0 and 1.0")
        return v

    @validator("cloudtrail_lookback_hours")
    def validate_lookback_hours(cls, v):
        """Validate lookback hours is reasonable."""
        if not 1 <= v <= 720:  # 1 hour to 30 days
            raise ValueError("Lookback hours must be between 1 and 720 (30 days)")
        return v

    @validator("bedrock_read_timeout")
    def validate_bedrock_read_timeout(cls, v):
        """Validate Bedrock read timeout is reasonable."""
        if not 30 <= v <= 1800:  # 30 seconds to 30 minutes
            raise ValueError("Bedrock read timeout must be between 30 and 1800 seconds")
        return v

    @validator("bedrock_connect_timeout")
    def validate_bedrock_connect_timeout(cls, v):
        """Validate Bedrock connect timeout is reasonable."""
        if not 10 <= v <= 600:  # 10 seconds to 10 minutes
            raise ValueError("Bedrock connect timeout must be between 10 and 600 seconds")
        return v

    class Config:
        """Pydantic configuration."""
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = False

    def get_aws_credentials(self) -> dict:
        """
        Get AWS credentials dictionary for boto3 session creation.

        Returns empty dict when using aws-vault or other credential providers
        to allow boto3 to use the default credential chain.

        Returns:
            Dictionary containing AWS credentials, or empty dict for default chain
        """
        credentials = {}

        # Only include credentials if they are explicitly set
        # This allows aws-vault and other credential providers to work properly
        if self.aws_access_key_id and self.aws_secret_access_key:
            credentials["aws_access_key_id"] = self.aws_access_key_id
            credentials["aws_secret_access_key"] = self.aws_secret_access_key

            # Session token is optional (for temporary credentials)
            if self.aws_session_token:
                credentials["aws_session_token"] = self.aws_session_token

        # Include profile if specified (useful for local development)
        if self.aws_profile:
            credentials["profile_name"] = self.aws_profile

        return credentials

    def is_using_credential_chain(self) -> bool:
        """
        Check if we're using the default AWS credential chain.

        Returns:
            True if using default credential chain (aws-vault, IAM roles, etc.)
        """
        return not (self.aws_access_key_id and self.aws_secret_access_key)

    def is_slack_enabled(self) -> bool:
        """Check if Slack integration is properly configured."""
        return bool(self.slack_bot_token or self.slack_webhook_url)

    def get_risk_thresholds(self) -> dict:
        """Get risk assessment thresholds."""
        return {
            "high": self.high_risk_threshold,
            "medium": self.medium_risk_threshold,
            "auto_approve": self.auto_approve_threshold
        }

    def get_terraform_state_path(self, workspace: str = None) -> str:
        """
        Get the full S3 path for Terraform state file.

        Args:
            workspace: Terraform workspace name (defaults to configured workspace)

        Returns:
            Full S3 key path for the Terraform state file
        """
        workspace = workspace or self.terraform_workspace

        # Construct base state key
        if workspace == "default":
            state_key = self.terraform_state_key
        else:
            # Workspace-specific state files are typically in env:/ directory
            state_key = f"env:/{workspace}/{self.terraform_state_key}"

        # Add prefix if configured
        if self.terraform_state_prefix:
            # Ensure prefix ends with / if it doesn't already
            prefix = self.terraform_state_prefix
            if not prefix.endswith('/'):
                prefix += '/'
            state_key = f"{prefix}{state_key}"

        return state_key