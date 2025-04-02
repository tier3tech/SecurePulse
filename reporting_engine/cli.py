"""
CLI interface for the reporting engine
"""

import os
import sys
import argparse
import datetime
import json
import logging
from pathlib import Path

from .vector_store import VectorReportStore
from .report_generator import ReportGenerator

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('ReportCLI')

def parse_args():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(description='SecurePulse Reporting Engine CLI')
    
    subparsers = parser.add_subparsers(dest='command', help='Commands')
    
    # Store command
    store_parser = subparsers.add_parser('store', help='Store scan results in vector database')
    store_parser.add_argument('--tenant-id', required=True, help='Tenant ID')
    store_parser.add_argument('--tenant-name', help='Tenant name (optional)')
    store_parser.add_argument('--scan-date', help='Scan date in ISO format (defaults to current time)')
    store_parser.add_argument('--drift-report', help='Path to drift detection report JSON file')
    store_parser.add_argument('--access-report', help='Path to access analysis report JSON file')
    store_parser.add_argument('--license-report', help='Path to license analysis report JSON file')
    
    # Generate command
    generate_parser = subparsers.add_parser('generate', help='Generate a report')
    generate_parser.add_argument('--tenant-id', required=True, help='Tenant ID')
    generate_parser.add_argument('--scan-date', help='Scan date in ISO format (defaults to most recent)')
    generate_parser.add_argument('--previous-date', help='Previous scan date for comparison')
    generate_parser.add_argument('--format', choices=['html', 'markdown'], default='html', help='Report format')
    generate_parser.add_argument('--output', help='Output path for the report')
    generate_parser.add_argument('--drift-report', help='Path to drift detection report JSON file (optional)')
    generate_parser.add_argument('--access-report', help='Path to access analysis report JSON file (optional)')
    generate_parser.add_argument('--license-report', help='Path to license analysis report JSON file (optional)')
    
    # List command
    list_parser = subparsers.add_parser('list', help='List available scan data')
    list_parser.add_argument('--tenant-id', help='Tenant ID (optional, lists all tenants if not specified)')
    
    return parser.parse_args()

def load_report_file(file_path):
    """Load a report file from disk"""
    if not file_path:
        return None
        
    try:
        with open(file_path, 'r') as f:
            return json.load(f)
    except Exception as e:
        logger.error(f"Error loading report file {file_path}: {e}")
        return None

def handle_store_command(args):
    """Handle the store command"""
    # Initialize vector store and report generator
    vector_store = VectorReportStore()
    report_generator = ReportGenerator(vector_store=vector_store)
    
    # Load report files
    drift_report = load_report_file(args.drift_report)
    access_report = load_report_file(args.access_report)
    license_report = load_report_file(args.license_report)
    
    # Store the data
    report_generator.store_scan_results(
        drift_report=drift_report,
        access_report=access_report,
        license_report=license_report,
        tenant_id=args.tenant_id,
        tenant_name=args.tenant_name,
        scan_date=args.scan_date
    )
    
    logger.info("Scan results stored successfully")
    
def handle_generate_command(args):
    """Handle the generate command"""
    # Initialize vector store and report generator
    vector_store = VectorReportStore()
    report_generator = ReportGenerator(vector_store=vector_store)
    
    # Load report files (optional)
    drift_report = load_report_file(args.drift_report)
    access_report = load_report_file(args.access_report)
    license_report = load_report_file(args.license_report)
    
    # Generate the report
    output_path = report_generator.generate_report(
        tenant_id=args.tenant_id,
        scan_date=args.scan_date,
        previous_date=args.previous_date,
        drift_report=drift_report,
        access_report=access_report,
        license_report=license_report,
        format=args.format,
        output_path=args.output
    )
    
    logger.info(f"Report generated successfully: {output_path}")
    print(f"\nReport generated: {output_path}")
    
def handle_list_command(args):
    """Handle the list command"""
    # Initialize vector store
    vector_store = VectorReportStore()
    
    # Query metrics collection for tenant data
    results = vector_store.metrics_collection.query(
        query_texts=None,
        where={"tenant_id": args.tenant_id} if args.tenant_id else {},
        limit=1000
    )
    
    metadatas = results.get("metadatas", [])
    
    if not metadatas:
        print(f"No scan data found{' for tenant ' + args.tenant_id if args.tenant_id else ''}")
        return
        
    # Group by tenant and scan date
    tenant_data = {}
    for meta in metadatas:
        tenant_id = meta.get("tenant_id")
        tenant_name = meta.get("tenant_name", "Unknown")
        scan_date = meta.get("scan_date")
        scan_type = meta.get("scan_type", "Unknown")
        
        if tenant_id not in tenant_data:
            tenant_data[tenant_id] = {
                "name": tenant_name,
                "scans": {}
            }
            
        if scan_date not in tenant_data[tenant_id]["scans"]:
            tenant_data[tenant_id]["scans"][scan_date] = []
            
        tenant_data[tenant_id]["scans"][scan_date].append(scan_type)
        
    # Print the results
    print("\nAvailable scan data:")
    print("===================")
    
    for tenant_id, data in tenant_data.items():
        print(f"\nTenant: {data['name']} ({tenant_id})")
        print("-" * 50)
        
        # Sort scans by date (newest first)
        sorted_scans = sorted(data["scans"].items(), key=lambda x: x[0], reverse=True)
        
        for scan_date, scan_types in sorted_scans:
            try:
                # Format the date for display
                date_obj = datetime.datetime.fromisoformat(scan_date)
                friendly_date = date_obj.strftime("%B %d, %Y at %I:%M %p")
            except:
                friendly_date = scan_date
                
            scan_types_str = ", ".join(scan_types)
            print(f"  • {friendly_date}")
            print(f"    Types: {scan_types_str}")
            print(f"    ID: {scan_date}")
    
def main():
    """Main entry point for the CLI"""
    args = parse_args()
    
    if args.command == 'store':
        handle_store_command(args)
    elif args.command == 'generate':
        handle_generate_command(args)
    elif args.command == 'list':
        handle_list_command(args)
    else:
        print("No command specified. Use -h for help.")
        
if __name__ == "__main__":
    main()