#!/usr/bin/env python3
"""
Run verified SecurePulse modules
------------------------------
This script runs the core modules that have been verified to work:
- DriftGuard Engine: Config drift detection with local SCuBA baselines 
- AccessWatch: Conditional access and MFA policy auditing
- LicenseLogic: M365 license audits
"""

import os
import json
import datetime
import argparse
from pathlib import Path
import sys

# Create output directory
output_path = Path("./verified_scan")
output_path.mkdir(parents=True, exist_ok=True)

# Create timestamp for reports
timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(description='Run verified SecurePulse modules')
    parser.add_argument('--client-id', help='Microsoft Graph client ID')
    parser.add_argument('--client-secret', help='Microsoft Graph client secret')
    parser.add_argument('--tenant-id', help='Microsoft 365 tenant ID')
    parser.add_argument('--modules', help='Comma-separated list of modules to run (e.g., "DriftGuard,AccessWatch")', default="DriftGuard,AccessWatch,LicenseLogic")
    
    return parser.parse_args()

def main():
    """Main function to run verified modules"""
    args = parse_arguments()
    
    # Check environment variables if not provided as arguments
    client_id = args.client_id or os.environ.get("MS_CLIENT_ID", "")
    client_secret = args.client_secret or os.environ.get("MS_CLIENT_SECRET", "")
    tenant_id = args.tenant_id or os.environ.get("MS_TENANT_ID", "")
    
    # Parse modules to run
    modules_to_run = [m.strip() for m in args.modules.split(",") if m.strip()]
    
    if not client_id or not client_secret or not tenant_id:
        print("❌ Error: Microsoft Graph credentials not set.")
        print("Please set the following environment variables or provide as arguments:")
        print("  --client-id or export MS_CLIENT_ID='your-client-id'")
        print("  --client-secret or export MS_CLIENT_SECRET='your-client-secret'")
        print("  --tenant-id or export MS_TENANT_ID='your-tenant-id'")
        sys.exit(1)
    
    print("🔍 Running verified SecurePulse modules...")
    
    # Results dictionary
    results = {
        "timestamp": datetime.datetime.now().isoformat(),
        "tenant_id": tenant_id,
        "modules_run": [],
        "reports": {}
    }
    
    # Run DriftGuard Engine
    if "DriftGuard" in modules_to_run:
        print("\n==== Running DriftGuard Engine ====")
        try:
            from DriftGuardEngine.drift_detector import DriftDetector
            
            detector = DriftDetector(output_dir=str(output_path / "drift"))
            drift_report, drift_path = detector.run_drift_detection(f"drift_report_{timestamp}.json")
            
            if drift_report:
                results["reports"]["drift"] = str(drift_path)
                results["modules_run"].append("DriftGuard Engine")
                
                # Display summary
                print(f"\n🔍 DriftGuard Engine Summary:")
                print(f"Requirements checked: {drift_report.get('totalRequirements', 0)}")
                
                # Try to get more detailed compliance info
                if "summary" in drift_report:
                    compliance_score = drift_report["summary"].get("overallComplianceScore", 0)
                    print(f"Overall compliance score: {compliance_score:.1f}%")
                
                # Generate drift summary if possible
                try:
                    drift_summary = detector.get_drift_summary(drift_report)
                    summary_path = output_path / f"drift_summary_{timestamp}.txt"
                    with open(summary_path, "w") as f:
                        f.write(drift_summary)
                    print(f"Drift summary saved to {summary_path}")
                except Exception as se:
                    print(f"⚠️ Could not generate drift summary: {str(se)}")
        except Exception as e:
            print(f"❌ Error running DriftGuard Engine: {str(e)}")
    
    # Run AccessWatch
    if "AccessWatch" in modules_to_run:
        print("\n==== Running AccessWatch ====")
        try:
            from AccessWatch.access_analyzer import AccessAnalyzer
            
            analyzer = AccessAnalyzer()
            access_report = analyzer.generate_report(str(output_path / f"access_report_{timestamp}.json"))
            
            if access_report:
                results["reports"]["access"] = str(output_path / f"access_report_{timestamp}.json")
                results["modules_run"].append("AccessWatch")
                
                # Display summary
                print(f"\n🔒 AccessWatch Analysis Summary:")
                print(f"MFA Adoption Rate: {access_report['mfaCompliance']['mfaAdoptionRate']:.1f}%")
                print(f"Admin MFA Adoption: {access_report['mfaCompliance']['adminMfaAdoptionRate']:.1f}%")
                print(f"At-Risk Users: {len(access_report['mfaCompliance']['atRiskUsers'])}")
                print(f"MFA Policy Coverage: {access_report['conditionalAccessAnalysis']['mfaPolicyCoverage']}")
        except Exception as e:
            print(f"❌ Error running AccessWatch: {str(e)}")
    
    # Run LicenseLogic
    if "LicenseLogic" in modules_to_run:
        print("\n==== Running LicenseLogic ====")
        try:
            import LicenseLogic
            
            license_skus = LicenseLogic.get_license_skus()
            users_with_licenses = LicenseLogic.get_users_with_licenses()
            license_report = LicenseLogic.build_license_report(license_skus, users_with_licenses)
            
            license_report_path = str(output_path / f"license_report_{timestamp}.json")
            with open(license_report_path, "w") as f:
                json.dump(license_report, f, indent=2, default=str)
            
            results["reports"]["licenses"] = license_report_path
            results["modules_run"].append("LicenseLogic")
            
            # Display summary
            print(f"\n📊 LicenseLogic Analysis Summary:")
            print(f"Total Users: {license_report['metadata']['totalUsers']}")
            print(f"Total License SKUs: {license_report['metadata']['totalSkus']}")
            print(f"Users with No License: {license_report['metadata']['usersWithNoLicense']}")
            print(f"Disabled Users with License: {license_report['metadata']['disabledWithLicense']}")
            
            # Generate Notion report
            try:
                LicenseLogic.generate_notion_license_report(license_report)
                notion_report_path = "LicenseLogic_Notion_Report.md"
                print(f"Generated Notion license report: {notion_report_path}")
                results["reports"]["license_notion"] = notion_report_path
            except Exception as ne:
                print(f"⚠️ Error generating Notion license report: {str(ne)}")
        except Exception as e:
            print(f"❌ Error running LicenseLogic: {str(e)}")
    
    # Save consolidated results
    consolidated_path = output_path / f"verified_scan_results_{timestamp}.json"
    with open(consolidated_path, "w") as f:
        json.dump(results, f, indent=2, default=str)
    
    # Print summary
    print("\n==== SCAN SUMMARY ====")
    print(f"Modules run: {', '.join(results['modules_run'])}")
    print(f"All reports saved to: {output_path}")
    print(f"Consolidated results saved to: {consolidated_path}")

if __name__ == "__main__":
    main()