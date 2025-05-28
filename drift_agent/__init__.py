"""
AWS Infrastructure Drift Detection Agent

A production-ready AI agent built with AWS Strands that detects and remediates
infrastructure drift between Infrastructure as Code (IaC) and runtime environments.
"""

__version__ = "1.0.0"
__author__ = "David Melamed"
__email__ = "david@jit.io"

from .agent import DriftDetectionAgent
from .core.drift_detector import DriftDetector
from .core.risk_analyzer import RiskAnalyzer
from .core.remediation import RemediationEngine

__all__ = [
    "DriftDetectionAgent",
    "DriftDetector",
    "RiskAnalyzer",
    "RemediationEngine",
]