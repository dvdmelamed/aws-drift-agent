#!/usr/bin/env python3
"""
Main entry point for the AWS Infrastructure Drift Detection Agent.

This allows the agent to be run as a module:
    python -m drift_agent

Or with specific commands:
    python -m drift_agent --check-drift
    python -m drift_agent --monitor
"""

import sys
import argparse
import logging
from datetime import datetime

from .agent import DriftDetectionAgent
from .config.settings import Settings

def setup_logging():
    """Set up logging for the CLI."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )

def main():
    """Main entry point for the drift detection agent CLI."""
    parser = argparse.ArgumentParser(
        description="AWS Infrastructure Drift Detection Agent",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python -m drift_agent --check-drift
  python -m drift_agent --monitor --interval 60
  python -m drift_agent --interactive
        """
    )

    parser.add_argument(
        "--check-drift",
        action="store_true",
        help="Run a one-time drift detection check"
    )

    parser.add_argument(
        "--monitor",
        action="store_true",
        help="Run continuous monitoring mode"
    )

    parser.add_argument(
        "--interval",
        type=int,
        default=60,
        help="Monitoring interval in minutes (default: 60)"
    )

    parser.add_argument(
        "--interactive",
        action="store_true",
        help="Run in interactive mode"
    )

    parser.add_argument(
        "--hours-back",
        type=int,
        default=6,
        help="Hours back to analyze for drift (default: 6)"
    )

    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose logging"
    )

    args = parser.parse_args()

    # Set up logging
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    setup_logging()

    logger = logging.getLogger(__name__)

    try:
        # Load configuration
        logger.info("Loading configuration...")
        config = Settings()
        logger.info(f"Configuration loaded - AWS Region: {config.aws_region}")

        # Initialize the agent
        logger.info("Initializing Drift Detection Agent...")
        agent = DriftDetectionAgent(config)
        logger.info("Agent initialized successfully")

        if args.check_drift:
            # Run one-time drift check
            logger.info(f"Running drift detection for the last {args.hours_back} hours...")
            response = agent(f"Check for infrastructure drift in the last {args.hours_back} hours")
            print("\n" + "="*60)
            print("DRIFT DETECTION RESULTS")
            print("="*60)
            print(response)
            print("="*60)

        elif args.monitor:
            # Run continuous monitoring
            logger.info(f"Starting continuous monitoring with {args.interval} minute intervals...")
            import asyncio
            asyncio.run(agent.run_monitoring_loop(args.interval))

        elif args.interactive:
            # Run interactive mode
            print("\n" + "="*60)
            print("AWS INFRASTRUCTURE DRIFT DETECTION AGENT")
            print("Interactive Mode - Type 'quit' to exit")
            print("="*60)

            while True:
                try:
                    user_input = input("\n🤖 Enter your query: ").strip()
                    if user_input.lower() in ['quit', 'exit', 'q']:
                        print("Goodbye!")
                        break

                    if user_input:
                        print("\n🔍 Processing...")
                        response = agent(user_input)
                        print(f"\n📋 Response:\n{response}")

                except KeyboardInterrupt:
                    print("\nGoodbye!")
                    break
                except Exception as e:
                    print(f"❌ Error: {e}")

        else:
            # Default: show help and run basic check
            parser.print_help()
            print("\nRunning basic drift check...")
            response = agent("Check for infrastructure drift in the last 24 hours")
            print("\n" + "="*60)
            print("BASIC DRIFT CHECK RESULTS")
            print("="*60)
            print(response)
            print("="*60)

    except Exception as e:
        logger.error(f"Error: {e}")
        print(f"\n❌ Error: {e}")
        print("\nMake sure you have:")
        print("  - AWS credentials configured")
        print("  - Required S3 buckets accessible")
        print("  - Amazon Bedrock access enabled")
        print("  - Environment variables set (see env.example)")
        sys.exit(1)

if __name__ == "__main__":
    main()