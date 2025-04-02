"""
ReportGenerator - Creates human-readable reports with actionable recommendations
"""

import os
import json
import datetime
import logging
from typing import Dict, List, Any, Optional, Tuple
from pathlib import Path

import markdown
import matplotlib.pyplot as plt
import numpy as np
from jinja2 import Environment, FileSystemLoader

from .vector_store import VectorReportStore

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('ReportGenerator')

class ReportGenerator:
    """
    Generates human-readable reports and actionable recommendations
    from security scan results.
    """
    
    def __init__(self, 
                vector_store: VectorReportStore = None,
                templates_dir: str = "./reporting_engine/templates",
                output_dir: str = "./reports"):
        """
        Initialize the report generator.
        
        Args:
            vector_store: Optional VectorReportStore instance. If not provided, a new one will be created.
            templates_dir: Directory containing report templates
            output_dir: Directory to save generated reports
        """
        # Initialize vector store if not provided
        self.vector_store = vector_store or VectorReportStore()
        
        # Set up templates and output directories
        self.templates_dir = Path(templates_dir)
        self.templates_dir.mkdir(parents=True, exist_ok=True)
        
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Set up Jinja for templates
        self._setup_templates()
        
        # Priority mapping for recommendations
        self.priority_levels = {
            "Critical": 1,
            "High": 2,
            "Medium": 3,
            "Low": 4,
            "Informational": 5
        }
        
    def _setup_templates(self):
        """Set up the template environment"""
        # Create default templates if they don't exist
        self._create_default_templates()
        
        # Initialize Jinja environment
        self.jinja_env = Environment(
            loader=FileSystemLoader(str(self.templates_dir)),
            autoescape=True
        )
        
    def _create_default_templates(self):
        """Create default templates if they don't exist"""
        # Main report template
        main_template = """
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{ tenant_name }} - Security Report</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }
        .header {
            border-bottom: 2px solid #2c3e50;
            padding-bottom: 10px;
            margin-bottom: 20px;
        }
        .tenant-info {
            background-color: #f8f9fa;
            padding: 15px;
            border-radius: 5px;
            margin-bottom: 20px;
        }
        .summary-metrics {
            display: flex;
            flex-wrap: wrap;
            gap: 15px;
            margin-bottom: 30px;
        }
        .metric-card {
            background-color: #fff;
            border: 1px solid #ddd;
            border-radius: 5px;
            padding: 15px;
            flex: 1;
            min-width: 200px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .metric-value {
            font-size: 24px;
            font-weight: bold;
            color: #2c3e50;
        }
        .chart-container {
            margin: 30px 0;
            text-align: center;
        }
        .chart-container img {
            max-width: 100%;
            height: auto;
        }
        .actions-section {
            margin: 30px 0;
        }
        .action-item {
            background-color: #f8f9fa;
            border-left: 4px solid #3498db;
            padding: 15px;
            margin-bottom: 15px;
            border-radius: 0 5px 5px 0;
        }
        .action-item.high {
            border-left-color: #e74c3c;
        }
        .action-item.medium {
            border-left-color: #f39c12;
        }
        .action-item.low {
            border-left-color: #2ecc71;
        }
        .action-header {
            font-weight: bold;
            display: flex;
            justify-content: space-between;
        }
        .priority-tag {
            display: inline-block;
            padding: 3px 8px;
            border-radius: 3px;
            font-size: 12px;
            font-weight: bold;
            color: white;
        }
        .priority-high {
            background-color: #e74c3c;
        }
        .priority-medium {
            background-color: #f39c12;
        }
        .priority-low {
            background-color: #2ecc71;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }
        th, td {
            padding: 12px 15px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }
        th {
            background-color: #f8f9fa;
            font-weight: bold;
        }
        .progress-section {
            margin: 30px 0;
        }
        .progress-item {
            background-color: #f8f9fa;
            border-left: 4px solid #2ecc71;
            padding: 15px;
            margin-bottom: 15px;
            border-radius: 0 5px 5px 0;
        }
        .section {
            margin-bottom: 40px;
        }
        .section-title {
            font-size: 20px;
            font-weight: bold;
            margin-bottom: 15px;
            color: #2c3e50;
            border-bottom: 1px solid #eee;
            padding-bottom: 10px;
        }
        .footer {
            margin-top: 50px;
            text-align: center;
            font-size: 12px;
            color: #7f8c8d;
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>Security Assessment Report</h1>
        <p>Generated on {{ report_date }}</p>
    </div>
    
    <div class="tenant-info">
        <h2>{{ tenant_name }}</h2>
        <p>Tenant ID: {{ tenant_id }}</p>
        <p>This report provides an analysis of your Microsoft 365 security posture based on the latest scan results.</p>
    </div>
    
    <div class="section">
        <div class="section-title">Executive Summary</div>
        <p>{{ summary_text }}</p>
        
        <div class="summary-metrics">
            {% for metric in key_metrics %}
            <div class="metric-card">
                <div class="metric-title">{{ metric.name }}</div>
                <div class="metric-value" style="color: {{ metric.color }}">{{ metric.value }}</div>
                <div class="metric-description">{{ metric.description }}</div>
            </div>
            {% endfor %}
        </div>
    </div>
    
    {% if has_comparison %}
    <div class="section">
        <div class="section-title">Progress Since Last Scan</div>
        <div class="chart-container">
            <img src="{{ progress_chart_path }}" alt="Progress Chart">
        </div>
        
        <div class="progress-section">
            <h3>Resolved Issues ({{ resolved_count }})</h3>
            {% for item in resolved_items %}
            <div class="progress-item">
                <div class="action-header">{{ item.title }}</div>
                <p>{{ item.description }}</p>
            </div>
            {% endfor %}
            
            <h3>New Issues ({{ new_count }})</h3>
            {% for item in new_items %}
            <div class="action-item {{ item.severity|lower }}">
                <div class="action-header">
                    {{ item.title }}
                    <span class="priority-tag priority-{{ item.severity|lower }}">{{ item.severity }}</span>
                </div>
                <p>{{ item.description }}</p>
                <p><strong>Recommendation:</strong> {{ item.recommendation }}</p>
            </div>
            {% endfor %}
        </div>
    </div>
    {% endif %}
    
    <div class="section">
        <div class="section-title">Priority Actions</div>
        <div class="actions-section">
            {% for action in priority_actions %}
            <div class="action-item {{ action.severity|lower }}">
                <div class="action-header">
                    {{ action.title }}
                    <span class="priority-tag priority-{{ action.severity|lower }}">{{ action.severity }}</span>
                </div>
                <p>{{ action.description }}</p>
                <p><strong>Recommendation:</strong> {{ action.recommendation }}</p>
                {% if action.impact %}
                <p><strong>Impact:</strong> {{ action.impact }}</p>
                {% endif %}
                {% if action.effort %}
                <p><strong>Effort:</strong> {{ action.effort }}</p>
                {% endif %}
            </div>
            {% endfor %}
        </div>
    </div>
    
    {% if drift_summary %}
    <div class="section">
        <div class="section-title">Configuration Drift Analysis</div>
        <div class="chart-container">
            <img src="{{ drift_chart_path }}" alt="Configuration Drift Chart">
        </div>
        <table>
            <thead>
                <tr>
                    <th>Workload</th>
                    <th>Compliance Score</th>
                    <th>Requirements</th>
                    <th>Compliant</th>
                    <th>Non-Compliant</th>
                </tr>
            </thead>
            <tbody>
                {% for workload in drift_summary %}
                <tr>
                    <td>{{ workload.name }}</td>
                    <td>{{ workload.score }}%</td>
                    <td>{{ workload.total }}</td>
                    <td>{{ workload.compliant }}</td>
                    <td>{{ workload.non_compliant }}</td>
                </tr>
                {% endfor %}
            </tbody>
        </table>
    </div>
    {% endif %}
    
    {% if access_summary %}
    <div class="section">
        <div class="section-title">Identity & Access Analysis</div>
        <div class="summary-metrics">
            <div class="metric-card">
                <div class="metric-title">MFA Adoption</div>
                <div class="metric-value" style="color: {{ access_summary.mfa_color }}">{{ access_summary.mfa_adoption_rate }}%</div>
                <div class="metric-description">of users have MFA enabled</div>
            </div>
            <div class="metric-card">
                <div class="metric-title">Admin MFA Adoption</div>
                <div class="metric-value" style="color: {{ access_summary.admin_mfa_color }}">{{ access_summary.admin_mfa_rate }}%</div>
                <div class="metric-description">of admins have MFA enabled</div>
            </div>
            <div class="metric-card">
                <div class="metric-title">At-Risk Users</div>
                <div class="metric-value" style="color: {{ access_summary.risk_color }}">{{ access_summary.at_risk_count }}</div>
                <div class="metric-description">users without MFA</div>
            </div>
        </div>
        
        {% if access_summary.admin_risk_count > 0 %}
        <div class="action-item high">
            <div class="action-header">
                Administrators Without MFA
                <span class="priority-tag priority-high">Critical</span>
            </div>
            <p>{{ access_summary.admin_risk_count }} administrators do not have MFA enabled, creating a critical security risk.</p>
            <p><strong>Recommendation:</strong> Immediately enable MFA for all administrators.</p>
        </div>
        {% endif %}
        
        {% if access_summary.ca_policy_gaps|length > 0 %}
        <div class="action-item medium">
            <div class="action-header">
                Conditional Access Policy Gaps
                <span class="priority-tag priority-medium">Medium</span>
            </div>
            <p>The following gaps were identified in your Conditional Access policies:</p>
            <ul>
                {% for gap in access_summary.ca_policy_gaps %}
                <li>{{ gap }}</li>
                {% endfor %}
            </ul>
        </div>
        {% endif %}
    </div>
    {% endif %}
    
    {% if license_summary %}
    <div class="section">
        <div class="section-title">License Optimization</div>
        <div class="summary-metrics">
            <div class="metric-card">
                <div class="metric-title">Potential Savings</div>
                <div class="metric-value" style="color: #2ecc71">${{ license_summary.total_savings }}</div>
                <div class="metric-description">monthly cost savings identified</div>
            </div>
            <div class="metric-card">
                <div class="metric-title">Optimization Actions</div>
                <div class="metric-value">{{ license_summary.recommendations|length }}</div>
                <div class="metric-description">recommendations identified</div>
            </div>
        </div>
        
        {% for rec in license_summary.recommendations %}
        <div class="action-item {{ rec.severity|lower }}">
            <div class="action-header">
                {{ rec.title }}
                <span class="priority-tag priority-{{ rec.severity|lower }}">{{ rec.severity }}</span>
            </div>
            <p>{{ rec.description }}</p>
            <p><strong>Impact:</strong> Potential savings of ${{ rec.savings }}/month.</p>
        </div>
        {% endfor %}
    </div>
    {% endif %}
    
    <div class="footer">
        <p>Generated by SecurePulse - © Open Door {{ current_year }}</p>
    </div>
</body>
</html>
"""
        
        # Write the main template
        main_template_path = self.templates_dir / "report.html.j2"
        if not main_template_path.exists():
            with open(main_template_path, "w") as f:
                f.write(main_template)
                
        # Text summary template
        text_template = """
# Security Assessment Report for {{ tenant_name }}
Generated on: {{ report_date }}

## Executive Summary
{{ summary_text }}

{% if has_comparison %}
## Progress Since Last Scan
- Resolved issues: {{ resolved_count }}
- New issues: {{ new_count }}
{% endif %}

## Priority Actions
{% for action in priority_actions %}
### {{ action.title }} ({{ action.severity }})
{{ action.description }}

**Recommendation:** {{ action.recommendation }}
{% if action.impact %}
**Impact:** {{ action.impact }}
{% endif %}
{% if action.effort %}
**Effort:** {{ action.effort }}
{% endif %}

{% endfor %}

{% if drift_summary %}
## Configuration Drift Analysis
Overall compliance score: {{ overall_score }}%

| Workload | Compliance Score | Requirements | Compliant | Non-Compliant |
|----------|-----------------|--------------|-----------|---------------|
{% for workload in drift_summary %}
| {{ workload.name }} | {{ workload.score }}% | {{ workload.total }} | {{ workload.compliant }} | {{ workload.non_compliant }} |
{% endfor %}
{% endif %}

{% if access_summary %}
## Identity & Access Analysis
- MFA Adoption: {{ access_summary.mfa_adoption_rate }}%
- Admin MFA Adoption: {{ access_summary.admin_mfa_rate }}%
- At-Risk Users: {{ access_summary.at_risk_count }}
{% endif %}

{% if license_summary %}
## License Optimization
- Potential Monthly Savings: ${{ license_summary.total_savings }}
- Optimization Actions: {{ license_summary.recommendations|length }}
{% endif %}

Generated by SecurePulse - © Open Door {{ current_year }}
"""

        # Write the text template
        text_template_path = self.templates_dir / "report.md.j2"
        if not text_template_path.exists():
            with open(text_template_path, "w") as f:
                f.write(text_template)
    
    def store_scan_results(self,
                          drift_report: Dict[str, Any] = None,
                          access_report: Dict[str, Any] = None,
                          license_report: Dict[str, Any] = None,
                          tenant_id: str = None,
                          tenant_name: str = None,
                          scan_date: str = None):
        """
        Store scan results in the vector database.
        
        Args:
            drift_report: Optional drift detection report
            access_report: Optional access analysis report
            license_report: Optional license analysis report
            tenant_id: Tenant ID (required)
            tenant_name: Tenant name
            scan_date: Scan date in ISO format (defaults to current time)
        """
        if not tenant_id:
            raise ValueError("tenant_id is required")
            
        # Default the scan date to now if not provided
        if not scan_date:
            scan_date = datetime.datetime.now().isoformat()
            
        # Default tenant name if not provided
        if not tenant_name:
            tenant_name = "Unknown Tenant"
            if drift_report and "tenantName" in drift_report:
                tenant_name = drift_report["tenantName"]
                
        # Extract tenant ID from reports if not explicitly provided
        if not tenant_id and drift_report and "tenantId" in drift_report:
            tenant_id = drift_report["tenantId"]
            
        logger.info(f"Storing scan results for tenant: {tenant_name} ({tenant_id})")
        
        # Store drift findings if provided
        if drift_report:
            # Extract the findings from the drift report
            drift_findings = drift_report.get("driftDetails", [])
            self.vector_store.store_drift_findings(
                tenant_id=tenant_id,
                scan_date=scan_date,
                findings=drift_findings
            )
            
            # Extract overall metrics
            summary = drift_report.get("summary", {})
            workloads = drift_report.get("workloads", {})
            
            # Store tenant metrics
            drift_metrics = {
                "scan_type": "drift",
                "totalRequirements": summary.get("totalRequirements", 0),
                "compliantRequirements": summary.get("compliantRequirements", 0),
                "nonCompliantRequirements": summary.get("nonCompliantRequirements", 0),
                "overallComplianceScore": summary.get("overallComplianceScore", 0)
            }
            
            # Add workload-specific scores
            for workload_name, workload_data in workloads.items():
                drift_metrics[f"workload_{workload_name}_score"] = workload_data.get("complianceScore", 0)
                
            self.vector_store.store_tenant_metrics(
                tenant_id=tenant_id,
                tenant_name=tenant_name,
                scan_date=scan_date,
                metrics=drift_metrics
            )
            
        # Store access findings if provided
        if access_report:
            mfa_compliance = access_report.get("mfaCompliance", {})
            ca_analysis = access_report.get("conditionalAccessAnalysis", {})
            
            # Store access findings
            self.vector_store.store_access_findings(
                tenant_id=tenant_id,
                scan_date=scan_date,
                compliance_data=mfa_compliance,
                ca_analysis=ca_analysis
            )
            
            # Store access metrics
            access_metrics = {
                "scan_type": "access",
                "mfaAdoptionRate": mfa_compliance.get("mfaAdoptionRate", 0),
                "adminMfaAdoptionRate": mfa_compliance.get("adminMfaAdoptionRate", 0),
                "totalUsers": mfa_compliance.get("totalUsers", 0),
                "enabledUsers": mfa_compliance.get("enabledUsers", 0),
                "usersWithMfa": mfa_compliance.get("usersWithMfa", 0),
                "atRiskUsers": len(mfa_compliance.get("atRiskUsers", [])),
                "mfaPolicies": ca_analysis.get("mfaPolicies", 0),
                "mfaPolicyCoverage": ca_analysis.get("mfaPolicyCoverage", "None")
            }
            
            self.vector_store.store_tenant_metrics(
                tenant_id=tenant_id,
                tenant_name=tenant_name,
                scan_date=scan_date,
                metrics=access_metrics
            )
            
        # Store license findings if provided
        if license_report:
            recommendations = license_report.get("recommendations", [])
            
            # Store license findings
            self.vector_store.store_license_findings(
                tenant_id=tenant_id,
                scan_date=scan_date,
                license_data=license_report
            )
            
            # Calculate total potential savings
            total_savings = sum(rec.get("estimatedSavings", 0) for rec in recommendations)
            
            # Store license metrics
            license_metrics = {
                "scan_type": "license",
                "totalAssignedLicenses": license_report.get("totalAssignedLicenses", 0),
                "totalActiveLicenses": license_report.get("totalActiveLicenses", 0),
                "totalInactiveLicenses": license_report.get("totalInactiveLicenses", 0),
                "totalPotentialSavings": total_savings,
                "optimizationRecommendations": len(recommendations)
            }
            
            self.vector_store.store_tenant_metrics(
                tenant_id=tenant_id,
                tenant_name=tenant_name,
                scan_date=scan_date,
                metrics=license_metrics
            )
            
        logger.info(f"Successfully stored scan results for tenant: {tenant_name}")
            
    def generate_report(self,
                       tenant_id: str,
                       scan_date: str = None,
                       previous_date: str = None,
                       drift_report: Dict[str, Any] = None,
                       access_report: Dict[str, Any] = None,
                       license_report: Dict[str, Any] = None,
                       format: str = "html",
                       output_path: str = None):
        """
        Generate a comprehensive report for a tenant based on scan results.
        
        Args:
            tenant_id: The ID of the tenant
            scan_date: Scan date in ISO format (defaults to current date)
            previous_date: Optional previous scan date for comparison
            drift_report: Optional drift detection report (will be used instead of fetching from DB)
            access_report: Optional access analysis report (will be used instead of fetching from DB)
            license_report: Optional license analysis report (will be used instead of fetching from DB)
            format: Report format ("html" or "markdown")
            output_path: Optional path to save the report (will use default if not provided)
            
        Returns:
            Path to the generated report
        """
        # Default the scan date to now if not provided
        if not scan_date:
            scan_date = datetime.datetime.now().isoformat()
            
        # Get tenant metadata
        tenant_metadata = self._get_tenant_metadata(tenant_id, scan_date)
        tenant_name = tenant_metadata.get("tenant_name", "Unknown Tenant")
        
        logger.info(f"Generating {format} report for tenant: {tenant_name} ({tenant_id})")
        
        # Get data for the report
        # If reports are directly provided, use them
        # Otherwise, fetch from the vector database
        
        # Process comparison data if a previous date is provided
        comparison_data = None
        if previous_date:
            comparison_data = self._process_comparison_data(tenant_id, scan_date, previous_date)
            
        # Process drift data
        drift_data = self._process_drift_data(tenant_id, scan_date, drift_report)
            
        # Process access data
        access_data = self._process_access_data(tenant_id, scan_date, access_report)
            
        # Process license data
        license_data = self._process_license_data(tenant_id, scan_date, license_report)
        
        # Generate priority actions
        priority_actions = self._generate_priority_actions(
            drift_data, access_data, license_data, comparison_data
        )
        
        # Generate summary metrics
        key_metrics = self._generate_key_metrics(drift_data, access_data, license_data)
        
        # Generate charts (if needed)
        charts_data = self._generate_charts(tenant_id, scan_date, drift_data, access_data, license_data)
        
        # Create a summary text
        summary_text = self._generate_summary_text(tenant_id, tenant_name, drift_data, access_data, license_data)
        
        # Prepare template data
        template_data = {
            "tenant_id": tenant_id,
            "tenant_name": tenant_name,
            "report_date": self._format_date(scan_date),
            "summary_text": summary_text,
            "key_metrics": key_metrics,
            "priority_actions": priority_actions,
            "drift_summary": drift_data.get("workload_summary") if drift_data else None,
            "overall_score": drift_data.get("overall_score") if drift_data else None,
            "access_summary": access_data,
            "license_summary": license_data,
            "current_year": datetime.datetime.now().year,
            "has_comparison": comparison_data is not None,
            "progress_chart_path": charts_data.get("progress_chart") if charts_data else None,
            "drift_chart_path": charts_data.get("drift_chart") if charts_data else None
        }
        
        # Add comparison data if available
        if comparison_data:
            template_data.update({
                "resolved_count": comparison_data.get("resolved_count", 0),
                "new_count": comparison_data.get("new_count", 0),
                "resolved_items": comparison_data.get("resolved_items", []),
                "new_items": comparison_data.get("new_items", [])
            })
        
        # Render the template
        if format.lower() == "html":
            output_path = self._render_html_report(template_data, output_path)
        else:
            output_path = self._render_markdown_report(template_data, output_path)
            
        logger.info(f"Report generated and saved to: {output_path}")
        return output_path
    
    def _get_tenant_metadata(self, tenant_id: str, scan_date: str) -> Dict[str, str]:
        """Get tenant metadata from the vector database"""
        # Due to Chroma version compatibility issues, just use the tenant info we have
        return {
            "tenant_id": tenant_id,
            "tenant_name": "Unknown Tenant",
            "scan_date": scan_date
            }
        
        return {
            "tenant_id": tenant_id,
            "tenant_name": "Unknown Tenant",
            "scan_date": scan_date
        }
        
    def _process_comparison_data(self, tenant_id: str, current_date: str, previous_date: str) -> Dict[str, Any]:
        """Process comparison data between two scans"""
        # Compare all finding types
        comparison = self.vector_store.compare_findings(
            tenant_id=tenant_id,
            current_date=current_date,
            previous_date=previous_date
        )
        
        # Extract resolved and new issues
        resolved_issues = comparison.get("resolved_issues", [])
        new_issues = comparison.get("new_issues", [])
        
        # Format resolved issues for display
        resolved_items = []
        for issue in resolved_issues:
            finding = issue.get("finding", {})
            metadata = issue.get("metadata", {})
            
            if metadata.get("finding_type") == "drift":
                resolved_items.append({
                    "title": f"{finding.get('workload', 'Unknown')}: {finding.get('title', 'Unknown')}",
                    "description": finding.get('description', 'No description available.')
                })
            elif "user" in metadata:
                resolved_items.append({
                    "title": f"MFA Enabled: {metadata.get('user', 'Unknown User')}",
                    "description": "This user now has multi-factor authentication enabled."
                })
            elif "policy_name" in metadata:
                resolved_items.append({
                    "title": f"Conditional Access Gap Fixed: {metadata.get('policy_name', 'Unknown Policy')}",
                    "description": finding.get('description', 'A conditional access policy gap has been resolved.')
                })
            elif "license_type" in metadata:
                resolved_items.append({
                    "title": f"License Optimization: {metadata.get('license_type', 'Unknown')}",
                    "description": finding.get('description', 'A license optimization issue has been addressed.')
                })
                
        # Format new issues for display
        new_items = []
        for issue in new_issues:
            finding = issue.get("finding", {})
            metadata = issue.get("metadata", {})
            severity = metadata.get("severity", "Medium")
            
            if metadata.get("finding_type") == "drift":
                new_items.append({
                    "title": f"{finding.get('workload', 'Unknown')}: {finding.get('title', 'Unknown')}",
                    "description": finding.get('description', 'No description available.'),
                    "recommendation": finding.get('remediation', 'No recommendation available.'),
                    "severity": severity
                })
            elif "user" in metadata:
                new_items.append({
                    "title": f"MFA Missing: {metadata.get('user', 'Unknown User')}",
                    "description": "This user does not have multi-factor authentication enabled.",
                    "recommendation": "Enable MFA for this user through the Microsoft 365 admin center.",
                    "severity": severity
                })
            elif "policy_name" in metadata:
                new_items.append({
                    "title": f"Conditional Access Gap: {metadata.get('policy_name', 'Unknown Policy')}",
                    "description": finding.get('description', 'A gap in conditional access policies has been identified.'),
                    "recommendation": "Review and update your conditional access policies to address this gap.",
                    "severity": severity
                })
            elif "license_type" in metadata:
                new_items.append({
                    "title": f"License Optimization: {metadata.get('license_type', 'Unknown')}",
                    "description": finding.get('description', 'A license optimization opportunity has been identified.'),
                    "recommendation": "Adjust license assignments as recommended to optimize costs.",
                    "severity": "Medium"
                })
                
        return {
            "resolved_count": len(resolved_items),
            "new_count": len(new_items),
            "resolved_items": resolved_items,
            "new_items": new_items,
            "total_previous": comparison.get("total_previous_findings", 0),
            "total_current": comparison.get("total_current_findings", 0)
        }
        
    def _process_drift_data(self, tenant_id: str, scan_date: str, drift_report: Dict[str, Any] = None) -> Dict[str, Any]:
        """Process drift detection data"""
        if drift_report:
            # Use the provided drift report
            summary = drift_report.get("summary", {})
            workloads = drift_report.get("workloads", {})
            findings = drift_report.get("driftDetails", [])
        else:
            # Fetch drift findings from the vector store
            findings_data = self.vector_store.get_tenant_findings(
                tenant_id=tenant_id,
                finding_type="drift",
                start_date=scan_date,
                end_date=scan_date,
                limit=1000
            )
            
            if not findings_data:
                return None
                
            # Extract findings
            findings = [f.get("finding", {}) for f in findings_data]
            
            # Get metrics for summary data
            metrics_over_time = self.vector_store.get_tenant_metrics_over_time(
                tenant_id=tenant_id,
                metric_names=["overallComplianceScore", "totalRequirements", "compliantRequirements", "nonCompliantRequirements"],
                start_date=scan_date,
                end_date=scan_date
            )
            
            # Extract summary data
            summary = {
                "totalRequirements": 0,
                "compliantRequirements": 0,
                "nonCompliantRequirements": 0,
                "overallComplianceScore": 0
            }
            
            for metric_name, values in metrics_over_time.items():
                if values:  # If we have values for this metric
                    summary[metric_name] = values[-1][1]  # Use the most recent value
            
            # Get workload compliance scores
            workload_metrics = {}
            workload_metrics_pattern = r"workload_(.+)_score"
            
            all_metrics = self.vector_store.get_tenant_metrics_over_time(
                tenant_id=tenant_id,
                start_date=scan_date,
                end_date=scan_date
            )
            
            import re
            for metric_name, values in all_metrics.items():
                match = re.match(workload_metrics_pattern, metric_name)
                if match and values:
                    workload_name = match.group(1)
                    workload_metrics[workload_name] = values[-1][1]  # Most recent value
                    
            # Construct workloads data structure
            workloads = {}
            for workload_name, score in workload_metrics.items():
                workloads[workload_name] = {
                    "complianceScore": score
                }
        
        # Format workload summary for the report
        workload_summary = []
        for workload_name, workload_data in workloads.items():
            # Count requirements for this workload
            workload_findings = [f for f in findings if f.get("workload") == workload_name]
            total_reqs = len(workload_findings)
            compliant_reqs = len([f for f in workload_findings if f.get("status") == "Compliant"])
            non_compliant_reqs = len([f for f in workload_findings if f.get("status") == "Non-compliant"])
            
            workload_summary.append({
                "name": workload_name,
                "score": workload_data.get("complianceScore", 0),
                "total": total_reqs,
                "compliant": compliant_reqs,
                "non_compliant": non_compliant_reqs
            })
            
        # Sort workloads by compliance score (ascending, so worst comes first)
        workload_summary.sort(key=lambda w: w["score"])
        
        # Extract non-compliant findings for action items
        non_compliant = [f for f in findings if f.get("status") == "Non-compliant"]
        
        # Sort by impact (High first, then Medium, then Low)
        impact_order = {"High": 0, "Medium": 1, "Low": 2}
        non_compliant.sort(key=lambda f: impact_order.get(f.get("impact", "Medium"), 1))
        
        return {
            "overall_score": summary.get("overallComplianceScore", 0),
            "total_requirements": summary.get("totalRequirements", 0),
            "compliant_requirements": summary.get("compliantRequirements", 0),
            "non_compliant_requirements": summary.get("nonCompliantRequirements", 0),
            "workload_summary": workload_summary,
            "non_compliant_findings": non_compliant
        }
        
    def _process_access_data(self, tenant_id: str, scan_date: str, access_report: Dict[str, Any] = None) -> Dict[str, Any]:
        """Process access control data"""
        if access_report:
            # Use the provided access report
            mfa_compliance = access_report.get("mfaCompliance", {})
            ca_analysis = access_report.get("conditionalAccessAnalysis", {})
        else:
            # Fetch access metrics from the vector store
            metrics_over_time = self.vector_store.get_tenant_metrics_over_time(
                tenant_id=tenant_id,
                metric_names=[
                    "mfaAdoptionRate", "adminMfaAdoptionRate", "atRiskUsers", 
                    "mfaPolicies", "mfaPolicyCoverage"
                ],
                start_date=scan_date,
                end_date=scan_date
            )
            
            if not any(metrics_over_time.values()):
                return None
                
            # Extract metrics
            mfa_compliance = {
                "mfaAdoptionRate": self._get_latest_metric(metrics_over_time, "mfaAdoptionRate", 0),
                "adminMfaAdoptionRate": self._get_latest_metric(metrics_over_time, "adminMfaAdoptionRate", 0),
                "atRiskUsers": []
            }
            
            ca_analysis = {
                "mfaPolicies": self._get_latest_metric(metrics_over_time, "mfaPolicies", 0),
                "mfaPolicyCoverage": self._get_latest_metric(metrics_over_time, "mfaPolicyCoverage", "None"),
                "mfaPolicyGaps": []
            }
            
            # Fetch at-risk users
            at_risk_users = self.vector_store.get_tenant_findings(
                tenant_id=tenant_id,
                finding_type="access_mfa",
                start_date=scan_date,
                end_date=scan_date,
                limit=1000
            )
            
            mfa_compliance["atRiskUsers"] = [u.get("finding", {}) for u in at_risk_users]
            
            # Fetch CA policy gaps
            ca_gaps = self.vector_store.get_tenant_findings(
                tenant_id=tenant_id,
                finding_type="access_ca",
                start_date=scan_date,
                end_date=scan_date,
                limit=100
            )
            
            ca_analysis["mfaPolicyGaps"] = [g.get("finding", {}) for g in ca_gaps]
            
        # Format the access data for the report
        at_risk_users = mfa_compliance.get("atRiskUsers", [])
        at_risk_count = len(at_risk_users)
        admin_risk_count = len([u for u in at_risk_users if u.get("isAdmin", False)])
        
        # Generate color codes based on compliance rates
        mfa_rate = mfa_compliance.get("mfaAdoptionRate", 0)
        admin_mfa_rate = mfa_compliance.get("adminMfaAdoptionRate", 0)
        
        mfa_color = "#e74c3c"  # Red for < 50%
        if mfa_rate >= 90:
            mfa_color = "#2ecc71"  # Green for >= 90%
        elif mfa_rate >= 70:
            mfa_color = "#f39c12"  # Orange for >= 70%
            
        admin_mfa_color = "#e74c3c"  # Red for < 90%
        if admin_mfa_rate >= 100:
            admin_mfa_color = "#2ecc71"  # Green for 100%
        elif admin_mfa_rate >= 90:
            admin_mfa_color = "#f39c12"  # Orange for >= 90%
            
        risk_color = "#2ecc71"  # Green for 0
        if at_risk_count > 10:
            risk_color = "#e74c3c"  # Red for > 10
        elif at_risk_count > 0:
            risk_color = "#f39c12"  # Orange for 1-10
            
        # Extract CA policy gaps
        ca_policy_gaps = []
        for gap in ca_analysis.get("mfaPolicyGaps", []):
            description = gap.get("description", "")
            coverage = gap.get("coverage", "Unknown")
            policy_name = gap.get("policyName", "N/A")
            
            if policy_name:
                ca_policy_gaps.append(f"{description} (Policy: {policy_name}, Coverage: {coverage})")
            else:
                ca_policy_gaps.append(f"{description} (Coverage: {coverage})")
                
        return {
            "mfa_adoption_rate": round(mfa_rate, 1),
            "admin_mfa_rate": round(admin_mfa_rate, 1),
            "at_risk_count": at_risk_count,
            "admin_risk_count": admin_risk_count,
            "mfa_color": mfa_color,
            "admin_mfa_color": admin_mfa_color,
            "risk_color": risk_color,
            "ca_policy_gaps": ca_policy_gaps,
            "mfa_policy_coverage": ca_analysis.get("mfaPolicyCoverage", "None"),
            "at_risk_users": at_risk_users
        }
        
    def _process_license_data(self, tenant_id: str, scan_date: str, license_report: Dict[str, Any] = None) -> Dict[str, Any]:
        """Process license data"""
        if license_report:
            # Use the provided license report
            recommendations = license_report.get("recommendations", [])
        else:
            # Fetch license findings from the vector store
            license_findings = self.vector_store.get_tenant_findings(
                tenant_id=tenant_id,
                finding_type="license",
                start_date=scan_date,
                end_date=scan_date,
                limit=100
            )
            
            if not license_findings:
                return None
                
            # Extract recommendations
            recommendations = [f.get("finding", {}) for f in license_findings]
            
        # Calculate total potential savings
        total_savings = sum(rec.get("estimatedSavings", 0) for rec in recommendations)
        
        # Format recommendations for the report
        formatted_recs = []
        for rec in recommendations:
            severity = "Medium"
            savings = rec.get("estimatedSavings", 0)
            
            if savings > 1000:
                severity = "High"
            elif savings < 300:
                severity = "Low"
                
            formatted_recs.append({
                "title": f"Optimize {rec.get('licenseType', 'Unknown')} Licenses",
                "description": rec.get("description", "No description available."),
                "savings": savings,
                "severity": severity
            })
            
        # Sort by savings (highest first)
        formatted_recs.sort(key=lambda r: r["savings"], reverse=True)
        
        return {
            "total_savings": total_savings,
            "recommendations": formatted_recs
        }
        
    def _generate_priority_actions(self, drift_data, access_data, license_data, comparison_data) -> List[Dict[str, Any]]:
        """Generate priority action items from the scan data"""
        priority_actions = []
        
        # Add critical admin MFA issues
        if access_data and access_data.get("admin_risk_count", 0) > 0:
            priority_actions.append({
                "title": "Enable MFA for Administrators",
                "description": f"{access_data['admin_risk_count']} administrators do not have MFA enabled, creating a critical security risk.",
                "recommendation": "Immediately enable MFA for all administrators through the Microsoft 365 admin center.",
                "impact": "High - Administrators without MFA are prime targets for credential theft attacks.",
                "effort": "Low - Can typically be completed in under 1 hour.",
                "severity": "High"
            })
            
        # Add CA policy gaps
        if access_data and access_data.get("mfa_policy_coverage") != "Complete":
            priority_actions.append({
                "title": "Implement Comprehensive MFA Policies",
                "description": f"Your Conditional Access policies for MFA have coverage gaps ({access_data.get('mfa_policy_coverage', 'None')}).",
                "recommendation": "Implement a baseline Conditional Access policy that requires MFA for all users without exceptions.",
                "impact": "High - Proper MFA policies are essential for preventing unauthorized access.",
                "effort": "Medium - Requires planning and testing to avoid disruption.",
                "severity": "High"
            })
            
        # Add top drift findings
        if drift_data and drift_data.get("non_compliant_findings"):
            # Get the top 3 highest impact non-compliant findings
            for i, finding in enumerate(drift_data["non_compliant_findings"][:3]):
                priority_actions.append({
                    "title": f"{finding.get('workload', 'Unknown')}: {finding.get('title', 'Configuration Drift')}",
                    "description": finding.get("description", "A configuration drift from secure baseline was detected."),
                    "recommendation": finding.get("remediation", "Review and update configuration to match secure baseline."),
                    "impact": finding.get("impact", "Medium"),
                    "severity": "High" if finding.get("impact") == "High" else "Medium"
                })
                
        # Add license optimizations if significant savings
        if license_data and license_data.get("total_savings", 0) > 500:
            # Add up to 2 license recommendations with highest savings
            for i, rec in enumerate(license_data["recommendations"][:2]):
                priority_actions.append({
                    "title": rec["title"],
                    "description": rec["description"],
                    "recommendation": f"Optimize license assignments to save ${rec['savings']}/month.",
                    "impact": f"Cost savings of ${rec['savings']}/month (${rec['savings']*12}/year).",
                    "effort": "Medium - Requires careful review of user license requirements.",
                    "severity": rec["severity"]
                })
                
        # Sort priority actions by severity
        priority_actions.sort(key=lambda a: self.priority_levels.get(a["severity"], 99))
        
        return priority_actions[:5]  # Return top 5 priority actions
        
    def _generate_key_metrics(self, drift_data, access_data, license_data) -> List[Dict[str, Any]]:
        """Generate key metrics for the executive summary"""
        key_metrics = []
        
        # Add overall compliance score
        if drift_data and "overall_score" in drift_data:
            score = drift_data["overall_score"]
            color = "#e74c3c"  # Red for < 70%
            if score >= 90:
                color = "#2ecc71"  # Green for >= 90%
            elif score >= 70:
                color = "#f39c12"  # Orange for >= 70%
                
            key_metrics.append({
                "name": "Overall Compliance",
                "value": f"{score}%",
                "description": "Secure baseline compliance",
                "color": color
            })
            
        # Add MFA adoption rate
        if access_data and "mfa_adoption_rate" in access_data:
            key_metrics.append({
                "name": "MFA Adoption",
                "value": f"{access_data['mfa_adoption_rate']}%",
                "description": "of users have MFA enabled",
                "color": access_data["mfa_color"]
            })
            
        # Add admin MFA adoption
        if access_data and "admin_mfa_rate" in access_data:
            key_metrics.append({
                "name": "Admin MFA",
                "value": f"{access_data['admin_mfa_rate']}%",
                "description": "of admins have MFA enabled",
                "color": access_data["admin_mfa_color"]
            })
            
        # Add license savings
        if license_data and "total_savings" in license_data:
            key_metrics.append({
                "name": "Monthly Savings",
                "value": f"${license_data['total_savings']}",
                "description": "potential license savings",
                "color": "#2ecc71"
            })
            
        return key_metrics
        
    def _generate_charts(self, tenant_id, scan_date, drift_data, access_data, license_data) -> Dict[str, str]:
        """Generate charts for the report"""
        # Create output directory for charts
        charts_dir = self.output_dir / "charts"
        charts_dir.mkdir(parents=True, exist_ok=True)
        
        chart_paths = {}
        
        # Generate drift chart if we have workload data
        if drift_data and drift_data.get("workload_summary"):
            try:
                # Create the drift chart
                plt.figure(figsize=(10, 6))
                
                workloads = drift_data["workload_summary"]
                names = [w["name"] for w in workloads]
                scores = [w["score"] for w in workloads]
                
                # Set colors based on scores
                colors = []
                for score in scores:
                    if score >= 90:
                        colors.append("#2ecc71")  # Green
                    elif score >= 70:
                        colors.append("#f39c12")  # Orange
                    else:
                        colors.append("#e74c3c")  # Red
                
                # Create horizontal bar chart
                y_pos = np.arange(len(names))
                plt.barh(y_pos, scores, color=colors)
                plt.yticks(y_pos, names)
                plt.xlabel('Compliance Score (%)')
                plt.title('Workload Compliance Scores')
                
                # Add percentage labels
                for i, v in enumerate(scores):
                    plt.text(v + 1, i, f"{v}%", va='center')
                    
                # Set x-axis limits
                plt.xlim(0, 105)
                
                # Add a vertical line at 70% and 90%
                plt.axvline(x=70, color='orange', linestyle='--', alpha=0.5)
                plt.axvline(x=90, color='green', linestyle='--', alpha=0.5)
                
                # Save the chart
                chart_filename = f"drift_chart_{tenant_id}_{scan_date.replace(':', '-')}.png"
                chart_path = charts_dir / chart_filename
                plt.tight_layout()
                plt.savefig(chart_path)
                plt.close()
                
                chart_paths["drift_chart"] = f"charts/{chart_filename}"
                
            except Exception as e:
                logger.error(f"Error generating drift chart: {e}")
                
        # Get historical metrics for progress chart
        metrics_over_time = self.vector_store.get_tenant_metrics_over_time(
            tenant_id=tenant_id,
            metric_names=["overallComplianceScore", "mfaAdoptionRate"],
            start_date=None,  # Get all history
            end_date=None
        )
        
        if metrics_over_time and any(len(v) > 1 for v in metrics_over_time.values()):
            try:
                plt.figure(figsize=(10, 6))
                
                # Plot compliance score over time
                if "overallComplianceScore" in metrics_over_time and len(metrics_over_time["overallComplianceScore"]) > 1:
                    dates = [self._parse_date(d[0]) for d in metrics_over_time["overallComplianceScore"]]
                    values = [d[1] for d in metrics_over_time["overallComplianceScore"]]
                    
                    plt.plot(dates, values, 'o-', label="Compliance Score", color="#3498db")
                    
                # Plot MFA adoption over time
                if "mfaAdoptionRate" in metrics_over_time and len(metrics_over_time["mfaAdoptionRate"]) > 1:
                    dates = [self._parse_date(d[0]) for d in metrics_over_time["mfaAdoptionRate"]]
                    values = [d[1] for d in metrics_over_time["mfaAdoptionRate"]]
                    
                    plt.plot(dates, values, 'o-', label="MFA Adoption", color="#2ecc71")
                    
                plt.title("Security Metrics Progress Over Time")
                plt.xlabel("Date")
                plt.ylabel("Score (%)")
                plt.ylim(0, 105)
                plt.legend()
                plt.grid(True, linestyle='--', alpha=0.7)
                
                # Format the x-axis to show dates nicely
                plt.gcf().autofmt_xdate()
                
                # Save the chart
                chart_filename = f"progress_chart_{tenant_id}_{scan_date.replace(':', '-')}.png"
                chart_path = charts_dir / chart_filename
                plt.tight_layout()
                plt.savefig(chart_path)
                plt.close()
                
                chart_paths["progress_chart"] = f"charts/{chart_filename}"
                
            except Exception as e:
                logger.error(f"Error generating progress chart: {e}")
                
        return chart_paths
        
    def _generate_summary_text(self, tenant_id, tenant_name, drift_data, access_data, license_data) -> str:
        """Generate the executive summary text"""
        summary_parts = []
        
        # Add compliance status
        if drift_data:
            score = drift_data.get("overall_score", 0)
            status = "excellent" if score >= 90 else "acceptable" if score >= 70 else "concerning"
            
            summary_parts.append(
                f"Your Microsoft 365 tenant shows a {status} compliance score of {score}% against secure baseline configurations. "
                f"Out of {drift_data.get('total_requirements', 0)} security requirements, "
                f"{drift_data.get('non_compliant_requirements', 0)} need attention."
            )
            
        # Add MFA status
        if access_data:
            mfa_rate = access_data.get("mfa_adoption_rate", 0)
            admin_rate = access_data.get("admin_mfa_rate", 0)
            
            if admin_rate < 100:
                summary_parts.append(
                    f"Critical security gap: {access_data.get('admin_risk_count', 0)} administrators do not have MFA enabled. "
                    f"Overall MFA adoption is at {mfa_rate}%, which is {'sufficient' if mfa_rate >= 90 else 'insufficient'}."
                )
            else:
                summary_parts.append(
                    f"MFA adoption is at {mfa_rate}% across all users, with 100% of administrators properly secured."
                )
                
        # Add license status
        if license_data:
            savings = license_data.get("total_savings", 0)
            if savings > 0:
                summary_parts.append(
                    f"Potential cost savings of ${savings}/month (${savings*12}/year) "
                    f"identified through license optimization opportunities."
                )
                
        # Combine the parts
        if summary_parts:
            return " ".join(summary_parts)
        else:
            return f"Security assessment for {tenant_name} completed. Review the report for details and recommendations."
            
    def _render_html_report(self, template_data, output_path=None):
        """Render the HTML report"""
        # Get the template
        template = self.jinja_env.get_template("report.html.j2")
        
        # Render the template
        rendered_html = template.render(**template_data)
        
        # Determine output path
        if not output_path:
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            tenant_id = template_data.get("tenant_id", "unknown").split('-')[0]  # Use first part of tenant ID
            output_path = self.output_dir / f"{tenant_id}_security_report_{timestamp}.html"
        else:
            output_path = Path(output_path)
            
        # Write the rendered template to file
        with open(output_path, "w") as f:
            f.write(rendered_html)
            
        return output_path
        
    def _render_markdown_report(self, template_data, output_path=None):
        """Render the markdown report"""
        # Get the template
        template = self.jinja_env.get_template("report.md.j2")
        
        # Render the template
        rendered_md = template.render(**template_data)
        
        # Determine output path
        if not output_path:
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            tenant_id = template_data.get("tenant_id", "unknown").split('-')[0]  # Use first part of tenant ID
            output_path = self.output_dir / f"{tenant_id}_security_report_{timestamp}.md"
        else:
            output_path = Path(output_path)
            
        # Write the rendered template to file
        with open(output_path, "w") as f:
            f.write(rendered_md)
            
        return output_path
        
    def _get_latest_metric(self, metrics_over_time, metric_name, default_value):
        """Get the latest value for a metric"""
        if metric_name in metrics_over_time and metrics_over_time[metric_name]:
            return metrics_over_time[metric_name][-1][1]
        return default_value
        
    def _format_date(self, iso_date):
        """Format an ISO date for display"""
        try:
            date_obj = self._parse_date(iso_date)
            return date_obj.strftime("%B %d, %Y at %I:%M %p")
        except:
            return iso_date
            
    def _parse_date(self, iso_date):
        """Parse an ISO date string to a datetime object"""
        try:
            return datetime.datetime.fromisoformat(iso_date)
        except:
            # Handle different ISO formats
            try:
                return datetime.datetime.strptime(iso_date, "%Y-%m-%dT%H:%M:%S.%fZ")
            except:
                return datetime.datetime.strptime(iso_date, "%Y-%m-%dT%H:%M:%SZ")