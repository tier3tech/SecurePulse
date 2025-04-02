#!/usr/bin/env python3
"""
Generate a comprehensive HTML report from security scan results
"""

import os
import json
import datetime
import sys
import argparse
from pathlib import Path

# Import reporting engine
from reporting_engine.report_generator import ReportGenerator

def generate_html_report(results_file=None):
    """
    Generate an HTML report from the latest verified scan results
    
    Args:
        results_file: Path to the specific results file to use. If None, uses the latest one.
    """
    # Get the latest scan results from verified_scan directory
    verified_scan_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "verified_scan")
    
    if not results_file:
        # Find the latest results file
        results_files = [f for f in os.listdir(verified_scan_dir) 
                         if f.startswith("verified_scan_results_") and f.endswith(".json")]
        if not results_files:
            print("Error: No results files found in verified_scan directory")
            return
        
        # Sort by timestamp in filename (newest first)
        results_files.sort(reverse=True)
        results_file = os.path.join(verified_scan_dir, results_files[0])
    
    print(f"Using results file: {results_file}")
    
    if not os.path.exists(results_file):
        print(f"Error: Results file not found: {results_file}")
        return
    
    # Load the consolidated results
    with open(results_file, 'r') as f:
        results = json.load(f)
    
    # Load the individual reports
    drift_report_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), results["reports"]["drift"])
    access_report_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), results["reports"]["access"])
    license_report_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), results["reports"]["licenses"])
    
    drift_report = None
    access_report = None
    license_report = None
    
    if os.path.exists(drift_report_path):
        with open(drift_report_path, 'r') as f:
            drift_report = json.load(f)
    
    if os.path.exists(access_report_path):
        with open(access_report_path, 'r') as f:
            access_report = json.load(f)
    
    if os.path.exists(license_report_path):
        with open(license_report_path, 'r') as f:
            license_report = json.load(f)
    
    # Initialize the report generator
    report_generator = ReportGenerator()
    
    # Create reports directory if it doesn't exist
    reports_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "reports")
    os.makedirs(reports_dir, exist_ok=True)
    
    # Generate the HTML report
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    output_path = os.path.join(reports_dir, f"comprehensive_report_{timestamp}.html")
    
    report_generator.generate_report(
        drift_report=drift_report,
        access_report=access_report,
        license_report=license_report,
        tenant_id=results["tenant_id"],
        output_path=output_path,
        format='html'
    )
    
    print(f"HTML report generated: {output_path}")
    return output_path

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Generate a comprehensive HTML report from security scan results')
    parser.add_argument('--results-file', help='Path to the specific results file to use')
    
    args = parser.parse_args()
    
    report_path = generate_html_report(args.results_file)
    if report_path:
        print(f"Report successfully generated at: {report_path}")
        print(f"Open this file in a web browser to view the report.")
    else:
        print("Failed to generate report.")