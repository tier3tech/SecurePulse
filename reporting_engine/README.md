# SecurePulse Reporting Engine

The SecurePulse Reporting Engine is a powerful component that enables tracking security posture improvements over time and generating human-readable reports with actionable recommendations.

## 🌟 Features

- **Vector-Based Storage**: Store scan results in a vector database organized by tenant
- **Historical Tracking**: Monitor security improvements over time with historical data
- **Tenant Comparison**: Compare multiple tenants' security postures
- **Human-Readable Reports**: Generate HTML and Markdown reports with actionable items
- **Progress Visualization**: Visual charts showing progress and compliance levels
- **Prioritized Recommendations**: Automatically prioritized remediation steps
- **Client Tracking**: Track security posture by client/tenant for long-term ROI measurement

## 📋 Components

- **VectorReportStore**: Vector database to store and retrieve scan results by tenant
- **ReportGenerator**: Generate rich reports with actionable recommendations
- **CLI Interface**: Command-line tool for storing and retrieving scan data

## 🚀 Usage Examples

### Basic Usage

```python
from reporting_engine.vector_store import VectorReportStore
from reporting_engine.report_generator import ReportGenerator

# Initialize the components
vector_store = VectorReportStore()
report_generator = ReportGenerator(vector_store=vector_store)

# Store scan results
report_generator.store_scan_results(
    drift_report=drift_report,
    access_report=access_report,
    license_report=license_report,
    tenant_id="tenant-id-123",
    tenant_name="Customer Name",
    scan_date="2025-01-01T12:00:00"
)

# Generate a report
report_path = report_generator.generate_report(
    tenant_id="tenant-id-123",
    scan_date="2025-01-01T12:00:00",
    format="html"
)

print(f"Report generated at: {report_path}")
```

### CLI Usage

```bash
# Store scan results
python -m reporting_engine.cli store --tenant-id "tenant-id-123" --tenant-name "Customer Name" --drift-report path/to/drift_report.json --access-report path/to/access_report.json

# Generate a report
python -m reporting_engine.cli generate --tenant-id "tenant-id-123" --format html --output customer_report.html

# Compare with previous scan
python -m reporting_engine.cli generate --tenant-id "tenant-id-123" --previous-date "2024-12-01T12:00:00" --format html

# List available scan data
python -m reporting_engine.cli list
```

### Comprehensive Scan Example

For a full example that runs all scan modules and generates a report, see the `examples/comprehensive_scan.py` script:

```bash
python examples/comprehensive_scan.py --output-dir ./client_reports --report-format html
```

## 📊 Report Types

### HTML Reports

HTML reports include:
- Executive summary with key metrics
- Visual charts showing compliance by workload
- Progress tracking compared to previous scans
- Prioritized action items with severity ratings
- Detailed section for each security domain

### Markdown Reports

Markdown reports include the same information in a format suitable for:
- Documentation repositories
- Client email sharing
- Integration with ticketing systems

## 📈 Long-term Value

The reporting engine is designed to demonstrate the long-term value of security improvements:
- Track metrics over time to show security improvements
- Compare compliance scores across multiple scan dates
- Identify resolved issues and new issues
- Calculate potential cost savings from recommendations

This enables quantitative measurement of the security improvements you deliver to clients over time, providing concrete ROI metrics for your security services.

## 🧠 Vector Database Benefits

Using vector embeddings for storing findings provides:
- Semantic similarity matching between issues
- Natural language querying of security findings
- Flexible data schema for different finding types
- Efficient storage and retrieval by tenant ID

## 📦 Requirements

- sentence-transformers
- chromadb
- numpy
- jinja2
- markdown
- matplotlib

These are included in the project's requirements.txt file.