"""
Risk analyzer core module.

Uses GenAI to assess the security and operational risks of detected
infrastructure drift and provide risk scoring.
"""

import logging
from typing import Dict, Any, List, Optional
from datetime import datetime

logger = logging.getLogger(__name__)


class RiskAnalyzer:
    """
    Risk analyzer for infrastructure drift assessment.

    Uses AI to analyze detected drift and assess security and operational
    risks to provide actionable risk scoring and prioritization.
    """

    def __init__(self, config):
        """
        Initialize the risk analyzer.

        Args:
            config: Application configuration
        """
        self.config = config

        # Risk weight mappings for different factors
        self.risk_weights = {
            "severity": {
                "critical": 10.0,
                "high": 7.5,
                "medium": 5.0,
                "low": 2.5
            },
            "resource_type": {
                "IAM": 9.0,          # Identity and Access Management - highest risk
                "S3": 8.0,           # Data storage - high risk
                "Security Group": 8.5, # Network security - high risk
                "EC2": 6.0,          # Compute instances - medium-high risk
                "Lambda": 5.5,       # Serverless functions - medium risk
                "RDS": 7.0,          # Databases - high risk
                "VPC": 7.5,          # Network infrastructure - high risk
            },
            "drift_type": {
                "deleted": 9.0,      # Deletions are highest risk
                "created": 6.0,      # Creations are medium-high risk
                "modified": 7.0      # Modifications are high risk
            },
            "user_context": {
                "root": 10.0,        # Root user - maximum risk
                "admin": 8.0,        # Admin users - high risk
                "developer": 5.0,    # Developer users - medium risk
                "service": 3.0,      # Service accounts - lower risk
                "unknown": 7.0       # Unknown users - high risk
            }
        }

        # Security-sensitive resource patterns
        self.security_patterns = {
            "network_security": [
                "security group", "nacl", "network acl", "route table",
                "internet gateway", "nat gateway"
            ],
            "identity_access": [
                "iam role", "iam policy", "iam user", "iam group",
                "access key", "assume role"
            ],
            "data_protection": [
                "s3 bucket", "rds instance", "dynamodb table",
                "encryption", "kms key"
            ],
            "compliance": [
                "cloudtrail", "config", "guardduty", "security hub",
                "vpc flow logs"
            ]
        }

    def assess_drift_risk(
        self,
        drift_data: Dict[str, Any],
        additional_context: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Assess the risk level of detected drift.

        Args:
            drift_data: Results from drift detection
            additional_context: Additional context for risk assessment

        Returns:
            Dictionary containing comprehensive risk assessment
        """
        logger.info("Starting risk assessment of detected drift")

        # Analyze all types of drifted resources
        all_resources = []
        all_resources.extend(drift_data.get("drifted_resources", []))
        all_resources.extend(drift_data.get("unmanaged_resources", []))
        all_resources.extend(drift_data.get("deleted_resources", []))

        # Assess risk for each resource
        resource_risks = []
        for resource in all_resources:
            risk_assessment = self._assess_resource_risk(resource)
            resource_risks.append(risk_assessment)

        # Calculate overall risk metrics
        overall_metrics = self._calculate_overall_risk(resource_risks)

        # Generate risk summary and recommendations
        summary = self._generate_risk_summary(resource_risks, overall_metrics)

        # Add contextual analysis if provided
        if additional_context:
            summary["contextual_analysis"] = self._analyze_additional_context(
                additional_context, resource_risks
            )

        logger.info(f"Risk assessment complete: Overall risk level {overall_metrics['risk_level']}")

        return {
            "resource_risks": resource_risks,
            "overall_risk_score": overall_metrics["risk_score"],
            "risk_level": overall_metrics["risk_level"],
            "high_risk_count": overall_metrics["high_risk_count"],
            "critical_findings": overall_metrics["critical_findings"],
            "summary": summary,
            "timestamp": datetime.utcnow().isoformat()
        }

    def _assess_resource_risk(self, resource: Dict[str, Any]) -> Dict[str, Any]:
        """Assess risk for a single resource."""
        base_risk_score = 0.0
        risk_factors = []

        # Factor 1: Resource severity
        severity = resource.get("severity", "medium")
        severity_weight = self.risk_weights["severity"].get(severity, 5.0)
        base_risk_score += severity_weight
        risk_factors.append(f"Severity: {severity} (+{severity_weight})")

        # Factor 2: Resource type
        resource_type = resource.get("resource_type", "Unknown")
        type_weight = self.risk_weights["resource_type"].get(resource_type, 5.0)
        base_risk_score += type_weight
        risk_factors.append(f"Resource type: {resource_type} (+{type_weight})")

        # Factor 3: Drift type
        drift_type = resource.get("drift_type", "modified")
        drift_weight = self.risk_weights["drift_type"].get(drift_type, 5.0)
        base_risk_score += drift_weight
        risk_factors.append(f"Drift type: {drift_type} (+{drift_weight})")

        # Factor 4: User context
        user_identity = resource.get("user_identity", {})
        user_type = self._categorize_user(user_identity)
        user_weight = self.risk_weights["user_context"].get(user_type, 5.0)
        base_risk_score += user_weight
        risk_factors.append(f"User type: {user_type} (+{user_weight})")

        # Factor 5: Security sensitivity
        security_multiplier = self._assess_security_sensitivity(resource)
        if security_multiplier > 1.0:
            base_risk_score *= security_multiplier
            risk_factors.append(f"Security sensitive (+{(security_multiplier-1)*100:.0f}% multiplier)")

        # Factor 6: Terraform management status
        if not resource.get("terraform_managed", False):
            base_risk_score += 2.0
            risk_factors.append("Not managed by Terraform (+2.0)")

        # Factor 7: External source IP
        source_ip = resource.get("source_ip", "")
        if source_ip and not self._is_internal_ip(source_ip):
            base_risk_score += 3.0
            risk_factors.append(f"External source IP: {source_ip} (+3.0)")

        # Normalize risk score (0-10 scale)
        normalized_score = min(10.0, base_risk_score)
        risk_level = self._determine_risk_level(normalized_score)

        return {
            "resource_id": resource.get("resource_id"),
            "resource_type": resource.get("resource_type"),
            "drift_type": resource.get("drift_type"),
            "risk_score": normalized_score,
            "risk_level": risk_level,
            "risk_factors": risk_factors,
            "security_impact": self._assess_security_impact(resource),
            "operational_impact": self._assess_operational_impact(resource),
            "compliance_impact": self._assess_compliance_impact(resource),
            "recommendations": self._generate_resource_recommendations(resource, normalized_score)
        }

    def _categorize_user(self, user_identity: Dict[str, Any]) -> str:
        """Categorize user based on identity information."""
        user_type = user_identity.get("type", "").lower()
        user_name = user_identity.get("userName", "").lower()

        if user_type == "root":
            return "root"
        elif any(keyword in user_name for keyword in ["admin", "administrator"]):
            return "admin"
        elif any(keyword in user_name for keyword in ["dev", "developer", "engineer"]):
            return "developer"
        elif any(keyword in user_name for keyword in ["service", "automation", "system"]):
            return "service"
        else:
            return "unknown"

    def _assess_security_sensitivity(self, resource: Dict[str, Any]) -> float:
        """Assess if resource is security-sensitive and return risk multiplier."""
        resource_type = resource.get("resource_type", "").lower()
        resource_id = resource.get("resource_id", "").lower()

        # Check against security patterns
        for category, patterns in self.security_patterns.items():
            for pattern in patterns:
                if pattern in resource_type or pattern in resource_id:
                    if category == "identity_access":
                        return 1.5  # 50% increase for IAM resources
                    elif category == "network_security":
                        return 1.4  # 40% increase for network security
                    elif category == "data_protection":
                        return 1.3  # 30% increase for data protection
                    elif category == "compliance":
                        return 1.2  # 20% increase for compliance resources

        return 1.0  # No multiplier for non-security resources

    def _is_internal_ip(self, ip_address: str) -> bool:
        """Check if IP address is internal/private."""
        if not ip_address:
            return False

        # Check for private IP ranges
        if (ip_address.startswith("10.") or
            ip_address.startswith("172.") or
            ip_address.startswith("192.168.") or
            ip_address == "localhost" or
            ip_address.startswith("127.")):
            return True

        return False

    def _determine_risk_level(self, risk_score: float) -> str:
        """Determine risk level based on score."""
        thresholds = self.config.get_risk_thresholds()

        if risk_score >= thresholds["high"]:
            return "HIGH"
        elif risk_score >= thresholds["medium"]:
            return "MEDIUM"
        else:
            return "LOW"

    def _assess_security_impact(self, resource: Dict[str, Any]) -> str:
        """Assess security impact of the drift."""
        resource_type = resource.get("resource_type", "").lower()
        drift_type = resource.get("drift_type", "")

        if "iam" in resource_type or "security group" in resource_type:
            if drift_type == "created":
                return "HIGH - New access permissions or network rules created"
            elif drift_type == "deleted":
                return "HIGH - Security controls removed"
            else:
                return "HIGH - Security configuration modified"
        elif "s3" in resource_type or "rds" in resource_type:
            return "MEDIUM - Data access or storage configuration changed"
        else:
            return "LOW - Minimal direct security impact"

    def _assess_operational_impact(self, resource: Dict[str, Any]) -> str:
        """Assess operational impact of the drift."""
        drift_type = resource.get("drift_type", "")
        resource_type = resource.get("resource_type", "").lower()

        if drift_type == "deleted":
            if "instance" in resource_type or "database" in resource_type:
                return "HIGH - Critical infrastructure component removed"
            else:
                return "MEDIUM - Infrastructure component removed"
        elif drift_type == "created":
            return "MEDIUM - New infrastructure component added outside IaC"
        else:
            return "LOW - Configuration change outside IaC"

    def _assess_compliance_impact(self, resource: Dict[str, Any]) -> str:
        """Assess compliance impact of the drift."""
        if not resource.get("terraform_managed", False):
            return "HIGH - Resource not tracked in IaC, compliance audit gap"
        else:
            return "MEDIUM - IaC managed resource modified outside workflow"

    def _generate_resource_recommendations(self, resource: Dict[str, Any], risk_score: float) -> List[str]:
        """Generate specific recommendations for a resource."""
        recommendations = []

        drift_type = resource.get("drift_type", "")
        resource_type = resource.get("resource_type", "")
        terraform_managed = resource.get("terraform_managed", False)

        # Risk-based recommendations
        if risk_score >= 8.0:
            recommendations.append("URGENT: Review this change immediately with security team")
            recommendations.append("Consider reverting change if unauthorized")
        elif risk_score >= 6.0:
            recommendations.append("HIGH PRIORITY: Review change within 24 hours")

        # Drift-type specific recommendations
        if drift_type == "deleted":
            recommendations.append("Verify if deletion was intentional and authorized")
            if terraform_managed:
                recommendations.append("Update Terraform configuration to reflect deletion")
        elif drift_type == "created":
            if not terraform_managed:
                recommendations.append("Add resource to Terraform configuration")
                recommendations.append("Apply appropriate tags for resource management")
        elif drift_type == "modified":
            recommendations.append("Document configuration changes")
            if terraform_managed:
                recommendations.append("Update Terraform state to match current configuration")

        # Resource-type specific recommendations
        if "iam" in resource_type.lower():
            recommendations.append("Review IAM permissions for least privilege compliance")
        elif "security group" in resource_type.lower():
            recommendations.append("Audit security group rules for overly permissive access")
        elif "s3" in resource_type.lower():
            recommendations.append("Verify bucket policies and access controls")

        return recommendations

    def _calculate_overall_risk(self, resource_risks: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Calculate overall risk metrics."""
        if not resource_risks:
            return {
                "risk_score": 0.0,
                "risk_level": "LOW",
                "high_risk_count": 0,
                "critical_findings": []
            }

        # Calculate weighted average risk score
        total_score = sum(r["risk_score"] for r in resource_risks)
        avg_score = total_score / len(resource_risks)

        # Count high-risk resources
        high_risk_count = len([r for r in resource_risks if r["risk_level"] == "HIGH"])

        # Identify critical findings
        critical_findings = []
        for resource_risk in resource_risks:
            if resource_risk["risk_score"] >= 8.0:
                critical_findings.append({
                    "resource_id": resource_risk["resource_id"],
                    "resource_type": resource_risk["resource_type"],
                    "risk_score": resource_risk["risk_score"],
                    "primary_concern": resource_risk["security_impact"]
                })

        # Determine overall risk level
        overall_risk_level = self._determine_risk_level(avg_score)

        # Boost risk level if there are many high-risk items
        if high_risk_count > len(resource_risks) * 0.3:  # More than 30% high-risk
            if overall_risk_level == "MEDIUM":
                overall_risk_level = "HIGH"

        return {
            "risk_score": avg_score,
            "risk_level": overall_risk_level,
            "high_risk_count": high_risk_count,
            "critical_findings": critical_findings
        }

    def _generate_risk_summary(
        self,
        resource_risks: List[Dict[str, Any]],
        overall_metrics: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Generate comprehensive risk summary."""
        if not resource_risks:
            return {
                "message": "No drift detected - infrastructure is in compliance",
                "priority_actions": [],
                "risk_trends": "STABLE"
            }

        # Categorize resources by risk level
        risk_distribution = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for resource_risk in resource_risks:
            risk_level = resource_risk["risk_level"]
            risk_distribution[risk_level] += 1

        # Generate priority actions
        priority_actions = []

        if overall_metrics["critical_findings"]:
            priority_actions.append(
                f"IMMEDIATE: Address {len(overall_metrics['critical_findings'])} critical security findings"
            )

        if risk_distribution["HIGH"] > 0:
            priority_actions.append(
                f"HIGH: Review {risk_distribution['HIGH']} high-risk drift items"
            )

        if risk_distribution["MEDIUM"] > 0:
            priority_actions.append(
                f"MEDIUM: Process {risk_distribution['MEDIUM']} medium-risk changes"
            )

        # Determine risk trend
        high_risk_percentage = (risk_distribution["HIGH"] / len(resource_risks)) * 100
        if high_risk_percentage > 50:
            risk_trend = "DETERIORATING"
        elif high_risk_percentage > 20:
            risk_trend = "CONCERNING"
        else:
            risk_trend = "MANAGEABLE"

        return {
            "message": f"Detected {len(resource_risks)} drift items requiring attention",
            "risk_distribution": risk_distribution,
            "priority_actions": priority_actions,
            "risk_trends": risk_trend,
            "key_concerns": self._identify_key_concerns(resource_risks),
            "next_steps": self._suggest_next_steps(overall_metrics)
        }

    def _identify_key_concerns(self, resource_risks: List[Dict[str, Any]]) -> List[str]:
        """Identify key security and operational concerns."""
        concerns = []

        # Check for IAM-related drift
        iam_resources = [r for r in resource_risks if "iam" in r["resource_type"].lower()]
        if iam_resources:
            concerns.append(f"Identity and Access Management: {len(iam_resources)} IAM changes detected")

        # Check for network security drift
        network_resources = [r for r in resource_risks if "security group" in r["resource_type"].lower()]
        if network_resources:
            concerns.append(f"Network Security: {len(network_resources)} security group changes")

        # Check for data-related drift
        data_resources = [r for r in resource_risks if any(
            keyword in r["resource_type"].lower() for keyword in ["s3", "rds", "dynamodb"]
        )]
        if data_resources:
            concerns.append(f"Data Protection: {len(data_resources)} data storage changes")

        # Check for unmanaged resources
        unmanaged = [r for r in resource_risks if not r.get("terraform_managed", True)]
        if unmanaged:
            concerns.append(f"IaC Compliance: {len(unmanaged)} resources not managed by Terraform")

        return concerns

    def _suggest_next_steps(self, overall_metrics: Dict[str, Any]) -> List[str]:
        """Suggest actionable next steps based on risk assessment."""
        next_steps = []

        if overall_metrics["critical_findings"]:
            next_steps.extend([
                "Immediately investigate critical security findings",
                "Notify security team of high-risk changes",
                "Consider emergency response procedures if needed"
            ])

        if overall_metrics["high_risk_count"] > 0:
            next_steps.extend([
                "Schedule drift review meeting with infrastructure team",
                "Update IaC templates to reflect approved changes",
                "Implement automated policy enforcement where possible"
            ])

        next_steps.extend([
            "Document all approved manual changes",
            "Review and update change management processes",
            "Schedule regular drift detection scans"
        ])

        return next_steps

    def _analyze_additional_context(
        self,
        context: str,
        resource_risks: List[Dict[str, Any]]
    ) -> str:
        """Analyze additional context provided by the user."""
        # This is a placeholder for more sophisticated context analysis
        # In a full implementation, this could use NLP or additional AI models

        context_lower = context.lower()
        analysis = []

        if "emergency" in context_lower or "urgent" in context_lower:
            analysis.append("URGENT CONTEXT: Emergency situation detected - expedite review process")

        if "maintenance" in context_lower or "planned" in context_lower:
            analysis.append("MAINTENANCE CONTEXT: Planned maintenance may explain some changes")

        if "security" in context_lower or "breach" in context_lower:
            analysis.append("SECURITY CONTEXT: Security-related context requires immediate attention")

        if not analysis:
            analysis.append("Additional context noted for investigation")

        return " | ".join(analysis)