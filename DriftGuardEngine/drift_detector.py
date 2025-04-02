"""
DriftDetector - Module for detecting drift between Microsoft 365 configurations and SCuBA baselines
"""

import os
import json
import logging
import datetime
from pathlib import Path
from .m365_config import M365ConfigFetcher
from .baseline_manager import BaselineManager

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('DriftDetector')

class DriftDetector:
    """
    Detects drift between Microsoft 365 configurations and SCuBA baselines
    """
    def __init__(self, 
                client_id=None, 
                client_secret=None, 
                tenant_id=None,
                baselines_dir="./baselines",
                output_dir="./reports"):
        """Initialize the drift detector"""
        self.config_fetcher = M365ConfigFetcher(client_id, client_secret, tenant_id)
        self.baseline_manager = BaselineManager(baselines_dir)
        
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
    def run_drift_detection(self, output_filename=None):
        """
        Run a full drift detection scan
        
        Args:
            output_filename: Name for the output report file (defaults to timestamp-based name)
            
        Returns:
            Tuple of (drift_report, output_path)
        """
        logger.info("Starting drift detection scan...")
        
        # Step 1: Fetch current configurations
        configurations = self.config_fetcher.fetch_all_configurations()
        
        # Step 2: Load baselines
        baselines = self.baseline_manager.load_all_baselines()
        
        # Step 3: Generate drift report
        drift_report = self.generate_drift_report(configurations, baselines)
        
        # Step 4: Save the report
        if not output_filename:
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            output_filename = f"drift_report_{timestamp}.json"
            
        output_path = self.output_dir / output_filename
        self.save_drift_report(drift_report, output_path)
        
        return drift_report, output_path
        
    def generate_drift_report(self, configurations, baselines):
        """
        Generate a drift report by comparing configurations against baselines
        
        Args:
            configurations: Current Microsoft 365 configurations
            baselines: SCuBA baselines
            
        Returns:
            Drift report dictionary
        """
        logger.info("Generating drift report...")
        
        # Extract tenant info for the report
        tenant_info = configurations.get("tenant", {})
        tenant_name = tenant_info.get("displayName", "Unknown Tenant")
        tenant_id = tenant_info.get("id", "Unknown ID")
        
        # Initialize the report
        drift_report = {
            "reportDate": datetime.datetime.now().isoformat(),
            "tenantName": tenant_name,
            "tenantId": tenant_id,
            "summary": {
                "totalRequirements": 0,
                "compliantRequirements": 0,
                "nonCompliantRequirements": 0,
                "unknownRequirements": 0
            },
            "workloads": {},
            "driftDetails": []
        }
        
        # Map of SCuBA baseline files to their corresponding workloads
        baseline_to_workload = {
            "aad.md": "Azure Active Directory",
            "defender.md": "Microsoft Defender",
            "exo.md": "Exchange Online",
            "powerbi.md": "Power BI",
            "powerplatform.md": "Power Platform",
            "sharepoint.md": "SharePoint",
            "teams.md": "Teams"
        }
        
        # Process each baseline and check for drift
        for baseline_name, baseline_data in baselines.items():
            workload_name = baseline_to_workload.get(baseline_name, baseline_name.replace('.json', ''))
            
            logger.info(f"Checking drift for {workload_name}...")
            
            # Get requirements for this baseline
            requirements = self.baseline_manager.get_baseline_requirements(baseline_name)
            total_reqs = len(requirements)
            
            # Track compliance for this workload
            workload_compliance = {
                "totalRequirements": total_reqs,
                "compliantRequirements": 0,
                "nonCompliantRequirements": 0,
                "unknownRequirements": 0,
                "complianceScore": 0.0
            }
            
            # Check each requirement
            for req in requirements:
                # Extract requirement info
                req_id = req.get("Id", "Unknown")
                req_title = req.get("Title", "Unknown Requirement")
                
                # Initialize result (default to unknown)
                result = {
                    "requirementId": req_id,
                    "workload": workload_name,
                    "title": req_title,
                    "status": "Unknown",
                    "description": req.get("Description", ""),
                    "impact": req.get("Impact", "Unknown"),
                    "requiredValue": req.get("ValueRequired", None),
                    "currentValue": None,
                    "remediation": req.get("Remediation", "")
                }
                
                # Check for drift based on the workload and requirement
                # This is a simplified implementation - in a real-world scenario,
                # you would need detailed mapping of each requirement to the corresponding
                # Graph API endpoint and property
                
                # Example: Security defaults in AAD
                if workload_name == "Azure Active Directory" and "security defaults" in req_title.lower():
                    security_defaults = configurations.get("securityDefaults", {})
                    is_enabled = security_defaults.get("isEnabled", False)
                    
                    result["currentValue"] = is_enabled
                    result["status"] = "Compliant" if is_enabled else "Non-compliant"
                    
                # Example: Conditional Access policies for MFA
                elif workload_name == "Azure Active Directory" and "multi-factor authentication" in req_title.lower():
                    ca_policies = configurations.get("conditionalAccessPolicies", [])
                    has_mfa_policy = False
                    
                    for policy in ca_policies:
                        if (policy.get("state") == "enabled" and 
                            "grantControls" in policy and 
                            "builtInControls" in policy["grantControls"] and 
                            "mfa" in policy["grantControls"]["builtInControls"]):
                            has_mfa_policy = True
                            break
                    
                    result["currentValue"] = has_mfa_policy
                    result["status"] = "Compliant" if has_mfa_policy else "Non-compliant"
                    
                # Add other mappings for different workloads and requirements here
                # In a production implementation, this would be much more extensive
                # and would cover all possible requirements
                
                # Update workload compliance counts
                if result["status"] == "Compliant":
                    workload_compliance["compliantRequirements"] += 1
                elif result["status"] == "Non-compliant":
                    workload_compliance["nonCompliantRequirements"] += 1
                else:
                    workload_compliance["unknownRequirements"] += 1
                    
                # Add the result to the drift details
                drift_report["driftDetails"].append(result)
                
            # Calculate compliance score for the workload
            if workload_compliance["totalRequirements"] > 0:
                compliance_score = (
                    workload_compliance["compliantRequirements"] / 
                    workload_compliance["totalRequirements"]
                ) * 100
                workload_compliance["complianceScore"] = round(compliance_score, 1)
                
            # Add workload compliance to the report
            drift_report["workloads"][workload_name] = workload_compliance
            
            # Update summary totals
            drift_report["summary"]["totalRequirements"] += workload_compliance["totalRequirements"]
            drift_report["summary"]["compliantRequirements"] += workload_compliance["compliantRequirements"]
            drift_report["summary"]["nonCompliantRequirements"] += workload_compliance["nonCompliantRequirements"]
            drift_report["summary"]["unknownRequirements"] += workload_compliance["unknownRequirements"]
            
        # Calculate overall compliance score
        if drift_report["summary"]["totalRequirements"] > 0:
            overall_score = (
                drift_report["summary"]["compliantRequirements"] / 
                drift_report["summary"]["totalRequirements"]
            ) * 100
            drift_report["summary"]["overallComplianceScore"] = round(overall_score, 1)
            
        logger.info(f"Drift report generated with {len(drift_report['driftDetails'])} requirements checked")
        return drift_report
        
    def save_drift_report(self, drift_report, output_path):
        """
        Save the drift report to a file
        
        Args:
            drift_report: The drift report dictionary
            output_path: Path to save the report
            
        Returns:
            True if successful, False otherwise
        """
        logger.info(f"Saving drift report to {output_path}...")
        
        try:
            with open(output_path, 'w') as f:
                json.dump(drift_report, f, indent=2, default=str)
            logger.info(f"Drift report saved to {output_path}")
            return True
        except Exception as e:
            logger.error(f"Error saving drift report: {str(e)}")
            return False

    def get_drift_summary(self, drift_report):
        """
        Generate a text summary of a drift report
        
        Args:
            drift_report: The drift report dictionary
            
        Returns:
            Text summary of the drift report
        """
        summary = drift_report.get("summary", {})
        tenant_name = drift_report.get("tenantName", "Unknown Tenant")
        report_date = drift_report.get("reportDate", "Unknown Date")
        
        total_reqs = summary.get("totalRequirements", 0)
        compliant_reqs = summary.get("compliantRequirements", 0)
        non_compliant_reqs = summary.get("nonCompliantRequirements", 0)
        unknown_reqs = summary.get("unknownRequirements", 0)
        overall_score = summary.get("overallComplianceScore", 0.0)
        
        text_summary = f"""
        DriftGuard Configuration Analysis Report
        =======================================
        
        Tenant: {tenant_name}
        Date: {report_date}
        
        Overall Compliance Score: {overall_score}%
        
        Summary:
        - Total requirements: {total_reqs}
        - Compliant: {compliant_reqs} ({(compliant_reqs/max(total_reqs, 1))*100:.1f}%)
        - Non-compliant: {non_compliant_reqs} ({(non_compliant_reqs/max(total_reqs, 1))*100:.1f}%)
        - Unknown/not checked: {unknown_reqs} ({(unknown_reqs/max(total_reqs, 1))*100:.1f}%)
        
        Workload Compliance:
        """
        
        # Add workload details
        for workload_name, workload_data in drift_report.get("workloads", {}).items():
            wl_total = workload_data.get("totalRequirements", 0)
            wl_compliant = workload_data.get("compliantRequirements", 0)
            wl_score = workload_data.get("complianceScore", 0.0)
            
            text_summary += f"- {workload_name}: {wl_score}% ({wl_compliant}/{wl_total} requirements)\n"
            
        # Add non-compliant requirements
        non_compliant = [r for r in drift_report.get("driftDetails", []) if r.get("status") == "Non-compliant"]
        if non_compliant:
            text_summary += f"""
        Non-compliant Requirements:
        """
            
            for req in non_compliant:
                text_summary += f"""
        {req.get('workload')}: {req.get('requirementId')} - {req.get('title')}
        Description: {req.get('description')}
        Current Value: {req.get('currentValue')}
        Required Value: {req.get('requiredValue')}
        Remediation: {req.get('remediation')}
        """
        
        return text_summary.strip()

# Example usage
if __name__ == "__main__":
    detector = DriftDetector()
    drift_report, output_path = detector.run_drift_detection()
    
    # Print a summary
    summary = detector.get_drift_summary(drift_report)
    print(summary)