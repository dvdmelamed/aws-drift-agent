# AWS Infrastructure Drift Detection Agent

A production-ready AI agent built with AWS Strands that detects and remediates infrastructure drift between Infrastructure as Code (IaC) and runtime environments.

## Overview

This agent analyzes CloudTrail logs, compares them with Terraform state, and uses GenAI to identify manual changes that bypass IaC workflows. It provides automated risk assessment and remediation recommendations with human-in-the-loop approval.

## Features

### 🔍 Detection
- **CloudTrail Analysis**: Parse and analyze AWS CloudTrail logs for infrastructure changes
- **Terraform State Comparison**: Compare runtime state with Terraform state files
- **Change Attribution**: Identify whether changes were made via IaC or manual operations
- **GenAI Analysis**: Leverage AI to understand the context and impact of detected changes

### 🛠️ Remediation
- **Risk Assessment**: Evaluate security and operational risks of detected drift
- **Smart Recommendations**: Suggest removal, reversion, or integration of manual changes
- **Slack Integration**: Send notifications and collect approvals via Slack
- **Automated Actions**: Execute approved remediation actions safely

### 🔒 Security & Governance
- **Audit Trail**: Complete logging of all detection and remediation activities
- **Human Approval**: Required approval workflow for all remediation actions
- **Role-Based Access**: Integration with AWS IAM for secure operations
- **Compliance Reporting**: Generate reports for governance and compliance

## Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   CloudTrail    │    │  Terraform      │    │   Slack API     │
│     Logs        │    │    State        │    │  Integration    │
└─────────┬───────┘    └─────────┬───────┘    └─────────┬───────┘
          │                      │                      │
          ▼                      ▼                      ▼
┌─────────────────────────────────────────────────────────────────┐
│                 Strands Drift Detection Agent                   │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────┐ │
│  │  Detection  │  │    Risk     │  │ Notification│  │ Action  │ │
│  │   Engine    │  │ Assessment  │  │   System    │  │ Engine  │ │
│  └─────────────┘  └─────────────┘  └─────────────┘  └─────────┘ │
└─────────────────────────────────────────────────────────────────┘
          │                      │                      │
          ▼                      ▼                      ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Bedrock       │    │    S3 Bucket    │    │   DynamoDB      │
│   Claude 3.7    │    │   (Artifacts)   │    │   (State)       │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

## Quick Start

### Prerequisites

- Python 3.10+
- AWS CLI configured with appropriate permissions
- Access to Amazon Bedrock (Claude 3.7 model)
- Slack workspace and bot token (optional)

### Installation

```bash
# Clone the repository
git clone https://github.com/your-org/aws-drift-detection-agent.git
cd aws-drift-detection-agent

# Create virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### Configuration

1. **AWS Credentials**: Configure your AWS credentials using one of these methods:

   **Option A: aws-vault (Recommended for development)**
   ```bash
   # Install aws-vault
   brew install aws-vault  # macOS

   # Add your AWS credentials
   aws-vault add my-profile

   # Test the setup
   aws-vault exec my-profile -- python test_aws_vault.py
   ```

   **Option B: AWS CLI**
   ```bash
   aws configure
   ```

   **Option C: IAM Roles** (for production deployments)

   See [AWS Vault Setup Guide](AWS_VAULT_SETUP.md) for detailed aws-vault configuration.

2. **Environment Variables**: Copy and configure the environment file
   ```bash
   cp .env.example .env
   # Edit .env with your specific configurations
   # Note: When using aws-vault, leave AWS credentials commented out
   ```

   **Key Configuration Options:**

   - `TERRAFORM_STATE_BUCKET`: S3 bucket containing Terraform state files
   - `TERRAFORM_STATE_KEY`: Path to the state file (default: `terraform.tfstate`)
   - `TERRAFORM_STATE_PREFIX`: Optional prefix for state file paths in S3 bucket
   - `TERRAFORM_WORKSPACE`: Terraform workspace to analyze (default: `default`)
   - `BEDROCK_READ_TIMEOUT`: Timeout for Bedrock API responses (default: 900 seconds)
   - `BEDROCK_CONNECT_TIMEOUT`: Timeout for Bedrock connections (default: 120 seconds)

   **Performance Optimizations:**

   The agent automatically filters CloudTrail and Terraform data to reduce the payload size sent to Bedrock by up to 95%, preventing timeout issues while preserving all essential information for drift detection.

   **Terraform State Prefix Examples:**
   ```bash
   # No prefix - state file at root of bucket
   TERRAFORM_STATE_PREFIX=

   # Simple prefix - state file under demo/ directory
   TERRAFORM_STATE_PREFIX=demo

   # Nested prefix - state file under projects/myapp/terraform/
   TERRAFORM_STATE_PREFIX=projects/myapp/terraform
   ```

3. **Slack Integration** (Optional): Set up Slack bot and add webhook URL to `.env`

### Running the Agent

```bash
# Run the agent (with aws-vault)
aws-vault exec my-profile -- python demo.py

# Run the interactive demo
aws-vault exec my-profile -- python interactive_demo.py

# Or if using AWS CLI/profiles
python demo.py

# Run with specific configuration
python -m drift_agent --config config/production.yaml

# Run in monitoring mode
python -m drift_agent --mode monitor --interval 3600
```

## Configuration

The agent supports multiple configuration methods:

- **Environment Variables**: For simple deployments
- **YAML Configuration**: For complex setups
- **AWS Parameter Store**: For production environments

See [Configuration Guide](docs/configuration.md) for detailed setup instructions.

## Usage Examples

### Basic Drift Detection

```python
from drift_agent import DriftDetectionAgent

# Initialize the agent
agent = DriftDetectionAgent()

# Run drift detection
result = agent("Check for infrastructure drift in the last 24 hours")
print(result)
```

### Targeted Analysis

```python
# Check specific resources
result = agent("Analyze EC2 instances created outside of Terraform in us-east-1")

# Check security-related changes
result = agent("Identify manual security group modifications that bypass IaC")
```

## Development

### Project Structure

```
drift_agent/
├── __init__.py
├── agent.py              # Main agent implementation
├── tools/                # Agent tools
│   ├── __init__.py
│   ├── cloudtrail.py     # CloudTrail analysis tools
│   ├── terraform.py      # Terraform state tools
│   ├── slack.py          # Slack integration
│   └── risk_assessment.py
├── core/                 # Core functionality
│   ├── __init__.py
│   ├── drift_detector.py
│   ├── risk_analyzer.py
│   └── remediation.py
├── config/               # Configuration files
│   ├── default.yaml
│   └── production.yaml
└── utils/               # Utility functions
    ├── __init__.py
    ├── aws_client.py
    └── logging.py
```

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=drift_agent --cov-report=html

# Run specific test categories
pytest tests/unit/
pytest tests/integration/
```

### Code Quality

```bash
# Format code
black drift_agent/ tests/

# Lint code
flake8 drift_agent/ tests/

# Type checking
mypy drift_agent/
```

## Deployment

### AWS Lambda

Deploy the agent as a Lambda function for serverless operation:

```bash
# Package for Lambda
./scripts/package-lambda.sh

# Deploy using SAM
sam deploy --guided
```

### AWS ECS/Fargate

Run the agent as a containerized service:

```bash
# Build Docker image
docker build -t drift-agent .

# Deploy to ECS
./scripts/deploy-ecs.sh
```

See [Deployment Guide](docs/deployment.md) for detailed instructions.

## Contributing

We welcome contributions! Please read our [Contributing Guidelines](CONTRIBUTING.md) and [Code of Conduct](CODE_OF_CONDUCT.md).

### Development Setup

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## Security

This project handles sensitive AWS infrastructure data. Please review our [Security Policy](SECURITY.md) and report security issues responsibly.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Built with [AWS Strands](https://strandsagents.com/) agents framework
- Powered by Amazon Bedrock and Claude 3.7
- Inspired by infrastructure governance best practices

## Support

- 📖 [Documentation](docs/)
- 🐛 [Issue Tracker](https://github.com/your-org/aws-drift-detection-agent/issues)
- 💬 [Discussions](https://github.com/your-org/aws-drift-detection-agent/discussions)
- 📧 [Email Support](mailto:support@your-org.com)