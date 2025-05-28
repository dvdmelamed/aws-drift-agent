"""
AWS Client Manager utility.

Manages AWS service clients with proper error handling and credential management.
"""

import logging
from typing import Dict, Any, Optional
import boto3
from botocore.exceptions import ClientError, NoCredentialsError
from botocore.config import Config

logger = logging.getLogger(__name__)


class AWSClientManager:
    """
    AWS client manager for centralized AWS service access.

    Provides centralized management of AWS service clients with proper
    error handling, retries, and credential management.
    """

    def __init__(self, config):
        """
        Initialize AWS client manager.

        Args:
            config: Application configuration containing AWS settings
        """
        self.config = config
        self._clients = {}

        # Configure boto3 with retry settings and timeouts
        self.boto_config = Config(
            region_name=config.aws_region,
            retries={
                'max_attempts': 3,
                'mode': 'adaptive'
            },
            read_timeout=300,  # 5 minutes read timeout
            connect_timeout=60  # 1 minute connect timeout
        )

        # Set up session with credentials
        self.session = self._create_session()

        # Validate credentials on initialization
        self._validate_credentials()

    def _create_session(self) -> boto3.Session:
        """Create boto3 session with proper credentials."""
        try:
            # Get credentials from config
            credentials = self.config.get_aws_credentials()

            if credentials:
                session = boto3.Session(**credentials)
                if self.config.aws_profile:
                    logger.info(f"Created boto3 session with AWS profile: {self.config.aws_profile}")
                else:
                    logger.info("Created boto3 session with explicit credentials")
            else:
                # Use default credential chain (aws-vault, IAM roles, etc.)
                session = boto3.Session()
                if self.config.is_using_credential_chain():
                    logger.info("Created boto3 session with default credential chain (aws-vault, IAM roles, etc.)")
                else:
                    logger.info("Created boto3 session with default credential chain")

            return session

        except Exception as e:
            logger.error(f"Error creating boto3 session: {e}")
            raise

    def _validate_credentials(self):
        """Validate AWS credentials by making a simple API call."""
        try:
            sts_client = self.get_client("sts")
            identity = sts_client.get_caller_identity()

            logger.info(f"AWS credentials validated successfully")
            logger.info(f"Account ID: {identity.get('Account', 'Unknown')}")
            logger.info(f"User ARN: {identity.get('Arn', 'Unknown')}")

        except NoCredentialsError:
            logger.error("No AWS credentials found. Please configure your credentials.")
            raise
        except ClientError as e:
            logger.error(f"AWS credentials validation failed: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error validating credentials: {e}")
            raise

    def get_client(self, service_name: str, region: Optional[str] = None) -> Any:
        """
        Get AWS service client with caching.

        Args:
            service_name: AWS service name (e.g., 's3', 'ec2', 'cloudtrail')
            region: Optional region override

        Returns:
            Boto3 client for the specified service
        """
        # Use custom region if provided, otherwise use default
        client_region = region or self.config.aws_region
        client_key = f"{service_name}_{client_region}"

        # Return cached client if available
        if client_key in self._clients:
            return self._clients[client_key]

        try:
            # Create new client with proper configuration
            config = Config(
                region_name=client_region,
                retries={
                    'max_attempts': 3,
                    'mode': 'adaptive'
                },
                read_timeout=300,  # 5 minutes read timeout
                connect_timeout=60  # 1 minute connect timeout
            )

            client = self.session.client(service_name, config=config)

            # Cache the client
            self._clients[client_key] = client

            logger.debug(f"Created {service_name} client for region {client_region}")
            return client

        except Exception as e:
            logger.error(f"Error creating {service_name} client: {e}")
            raise

    def get_resource(self, service_name: str, region: Optional[str] = None) -> Any:
        """
        Get AWS service resource.

        Args:
            service_name: AWS service name (e.g., 's3', 'ec2', 'dynamodb')
            region: Optional region override

        Returns:
            Boto3 resource for the specified service
        """
        # Use custom region if provided, otherwise use default
        resource_region = region or self.config.aws_region

        try:
            # Create new resource with proper configuration
            config = Config(
                region_name=resource_region,
                retries={
                    'max_attempts': 3,
                    'mode': 'adaptive'
                },
                read_timeout=300,  # 5 minutes read timeout
                connect_timeout=60  # 1 minute connect timeout
            )

            resource = self.session.resource(service_name, config=config)

            logger.debug(f"Created {service_name} resource for region {resource_region}")
            return resource

        except Exception as e:
            logger.error(f"Error creating {service_name} resource: {e}")
            raise

    def list_regions(self, service_name: str = "ec2") -> list:
        """
        List available AWS regions for a service.

        Args:
            service_name: Service to check regions for

        Returns:
            List of region names
        """
        try:
            client = self.get_client(service_name)
            response = client.describe_regions()
            regions = [region["RegionName"] for region in response["Regions"]]

            logger.debug(f"Found {len(regions)} regions for {service_name}")
            return regions

        except Exception as e:
            logger.error(f"Error listing regions for {service_name}: {e}")
            return []

    def check_service_availability(self, service_name: str, region: Optional[str] = None) -> bool:
        """
        Check if a service is available in the specified region.

        Args:
            service_name: AWS service name
            region: Optional region to check

        Returns:
            True if service is available, False otherwise
        """
        try:
            client = self.get_client(service_name, region)

            # Make a simple API call to check availability
            if service_name == "bedrock-runtime":
                # For Bedrock, we can check if we can list models
                client.list_foundation_models()
            elif service_name == "s3":
                client.list_buckets()
            elif service_name == "cloudtrail":
                client.describe_trails(maxRecords=1)
            else:
                # For other services, try a generic describe operation
                # This is a best-effort check
                pass

            logger.debug(f"Service {service_name} is available in {region or self.config.aws_region}")
            return True

        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "")
            if error_code in ["AccessDenied", "UnauthorizedOperation"]:
                # Service exists but we don't have permission
                logger.debug(f"Service {service_name} exists but access denied in {region or self.config.aws_region}")
                return True
            else:
                logger.debug(f"Service {service_name} not available in {region or self.config.aws_region}: {error_code}")
                return False
        except Exception as e:
            logger.debug(f"Error checking {service_name} availability: {e}")
            return False

    def get_account_id(self) -> str:
        """
        Get the AWS account ID.

        Returns:
            AWS account ID
        """
        try:
            sts_client = self.get_client("sts")
            identity = sts_client.get_caller_identity()
            return identity.get("Account", "")

        except Exception as e:
            logger.error(f"Error getting account ID: {e}")
            return ""

    def get_caller_identity(self) -> Dict[str, Any]:
        """
        Get caller identity information.

        Returns:
            Dictionary containing caller identity information
        """
        try:
            sts_client = self.get_client("sts")
            return sts_client.get_caller_identity()

        except Exception as e:
            logger.error(f"Error getting caller identity: {e}")
            return {}

    def clear_client_cache(self):
        """Clear cached clients (useful for credential rotation)."""
        self._clients.clear()
        logger.info("Cleared AWS client cache")