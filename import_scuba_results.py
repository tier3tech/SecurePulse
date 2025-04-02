#!/usr/bin/env python3
"""
Import SCuBA assessment results into SecurePulse
"""

import os
import json
import argparse
import datetime
from pathlib import Path

def import_scuba_results(scuba_path):
    """
    Import SCuBA assessment results into SecurePulse
    
    Args:
        scuba_path: Path to SCuBA assessment results
    """
    print(f"Importing SCuBA results from: {scuba_path}")
    
    # Find the latest SCuBA results directory
    scuba_dirs = [d for d in os.listdir(scuba_path) if os.path.isdir(os.path.join(scuba_path, d))]
    if not scuba_dirs:
        print("No SCuBA results found")
        return
    
    # Sort by timestamp in directory name
    scuba_dirs.sort(reverse=True)
    latest_dir = os.path.join(scuba_path, scuba_dirs[0])
    print(f"Using latest SCuBA results: {latest_dir}")
    
    # Load SCuBA results
    results_file = os.path.join(latest_dir, "Results", "results.json")
    if not os.path.exists(results_file):
        print(f"Error: SCuBA results file not found: {results_file}")
        return
    
    with open(results_file, 'r') as f:
        scuba_results = json.load(f)
    
    # Convert SCuBA results to DriftGuard format
    drift_report = convert_scuba_to_driftguard(scuba_results)
    
    # Save converted results
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    output_dir = Path("./verified_scan/drift")
    output_dir.mkdir(parents=True, exist_ok=True)
    
    output_file = output_dir / f"drift_report_scuba_{timestamp}.json"
    with open(output_file, 'w') as f:
        json.dump(drift_report, f, indent=2)
    
    print(f"SCuBA results imported and saved to: {output_file}")
    return str(output_file)

def convert_scuba_to_driftguard(scuba_results):
    """
    Convert SCuBA results to DriftGuard format
    """
    # Extract tenant info
    tenant_id = scuba_results.get("tenant", {}).get("tenantId", "Unknown")
    tenant_name = scuba_results.get("tenant", {}).get("displayName", "Unknown")
    
    # Create base drift report structure
    drift_report = {
        "reportDate": datetime.datetime.now().isoformat(),
        "tenantName": tenant_name,
        "tenantId": tenant_id,
        "summary": {
            "totalRequirements": 0,
            "compliantRequirements": 0,
            "nonCompliantRequirements": 0,
            "unknownRequirements": 0,
            "overallComplianceScore": 0.0
        },
        "workloads": {},
        "driftDetails": []
    }
    
    # Process each product assessment
    for product in scuba_results.get("products", []):
        product_name = product.get("productName", "Unknown").lower()
        
        # Skip products not in our workload mapping
        workload_map = {
            "aad": "aad",
            "defender": "defender",
            "exo": "exo",
            "powerplatform": "powerplatform",
            "sharepoint": "sharepoint",
            "teams": "teams"
        }
        
        if product_name not in workload_map:
            continue
        
        workload = workload_map[product_name]
        
        # Initialize workload summary
        if workload not in drift_report["workloads"]:
            drift_report["workloads"][workload] = {
                "totalRequirements": 0,
                "compliantRequirements": 0,
                "nonCompliantRequirements": 0,
                "unknownRequirements": 0,
                "complianceScore": 0.0
            }
        
        # Process each control
        for control in product.get("controls", []):
            requirement_id = control.get("controlId", "Unknown")
            title = control.get("controlName", "Unknown Requirement")
            status = "Compliant" if control.get("controlResult", False) else "Non-Compliant"
            
            # Update counters
            drift_report["workloads"][workload]["totalRequirements"] += 1
            drift_report["summary"]["totalRequirements"] += 1
            
            if status == "Compliant":
                drift_report["workloads"][workload]["compliantRequirements"] += 1
                drift_report["summary"]["compliantRequirements"] += 1
            else:
                drift_report["workloads"][workload]["nonCompliantRequirements"] += 1
                drift_report["summary"]["nonCompliantRequirements"] += 1
            
            # Add drift detail
            drift_detail = {
                "requirementId": requirement_id,
                "workload": workload,
                "title": title,
                "status": status,
                "description": control.get("description", ""),
                "impact": "Medium",
                "requiredValue": control.get("expectedValue", None),
                "currentValue": control.get("actualValue", None),
                "remediation": control.get("remediation", "")
            }
            
            drift_report["driftDetails"].append(drift_detail)
    
    # Calculate compliance scores
    for workload, summary in drift_report["workloads"].items():
        if summary["totalRequirements"] > 0:
            summary["complianceScore"] = (summary["compliantRequirements"] / summary["totalRequirements"]) * 100
    
    if drift_report["summary"]["totalRequirements"] > 0:
        drift_report["summary"]["overallComplianceScore"] = (drift_report["summary"]["compliantRequirements"] / drift_report["summary"]["totalRequirements"]) * 100
    
    return drift_report

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Import SCuBA assessment results')
    parser.add_argument('--scuba-path', required=True, help='Path to SCuBA assessment results')
    args = parser.parse_args()
    
    import_scuba_results(args.scuba_path)