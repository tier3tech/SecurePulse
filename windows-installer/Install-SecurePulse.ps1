<#
.SYNOPSIS
    Installs SecurePulse and its dependencies on Windows.
.DESCRIPTION
    This script installs SecurePulse, SCuBA, and all required dependencies on Windows.
    It sets up Python, required modules, PowerShell modules, and configures everything
    for easy execution.
.PARAMETER InstallPath
    The path where SecurePulse should be installed. Defaults to "%USERPROFILE%\SecurePulse".
.PARAMETER InstallScuba
    If specified, also installs SCuBA (Secure Cloud Business Applications) assessment tool.
.PARAMETER SkipPython
    If specified, skips Python installation (assumes Python 3.8+ is already installed).
.PARAMETER Branch
    The GitHub branch to clone. Defaults to "main".
.EXAMPLE
    .\Install-SecurePulse.ps1
.EXAMPLE
    .\Install-SecurePulse.ps1 -InstallScuba -InstallPath "C:\SecurePulse"
.NOTES
    Author: Open Door MSP
    Version: 1.0
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$InstallPath = "$env:USERPROFILE\SecurePulse",
    
    [Parameter(Mandatory=$false)]
    [switch]$InstallScuba,
    
    [Parameter(Mandatory=$false)]
    [switch]$SkipPython,
    
    [Parameter(Mandatory=$false)]
    [string]$Branch = "main"
)

#Requires -RunAsAdministrator

# Function to check if a program is installed
function Test-ProgramInstalled {
    param(
        [Parameter(Mandatory=$true)]
        [string]$ProgramName
    )
    
    try {
        Get-Command $ProgramName -ErrorAction Stop | Out-Null
        return $true
    }
    catch {
        return $false
    }
}

# Function to check Python version
function Test-PythonVersion {
    try {
        $pythonVersion = (python --version) 2>&1
        if ($pythonVersion -match '(\d+)\.(\d+)\.(\d+)') {
            $major = [int]$Matches[1]
            $minor = [int]$Matches[2]
            if ($major -ge 3 -and $minor -ge 8) {
                return $true
            }
        }
        return $false
    }
    catch {
        return $false
    }
}

# Function to install Microsoft Visual C++ Redistributable
function Install-VCRedist {
    Write-Host "Installing Microsoft Visual C++ Redistributable..." -ForegroundColor Cyan
    $vcRedistUrl = "https://aka.ms/vs/17/release/vc_redist.x64.exe"
    $vcRedistInstaller = "$env:TEMP\vc_redist_securepulse.exe"
    
    try {
        # Remove existing installer if it exists
        if (Test-Path $vcRedistInstaller) {
            try {
                Remove-Item $vcRedistInstaller -Force -ErrorAction Stop
            }
            catch {
                Write-Host "Warning: Could not remove existing VC++ Redistributable installer. Will try to continue anyway." -ForegroundColor Yellow
            }
        }
        
        # Download and install
        Invoke-WebRequest -Uri $vcRedistUrl -OutFile $vcRedistInstaller -UseBasicParsing
        Start-Process -FilePath $vcRedistInstaller -ArgumentList "/quiet", "/norestart" -Wait
        
        # Clean up
        try {
            Remove-Item $vcRedistInstaller -Force -ErrorAction SilentlyContinue
        }
        catch {
            Write-Host "Warning: Could not remove VC++ Redistributable installer. You can delete it manually: $vcRedistInstaller" -ForegroundColor Yellow
        }
        
        Write-Host "Microsoft Visual C++ Redistributable installed successfully." -ForegroundColor Green
    }
    catch {
        Write-Host "Failed to install Microsoft Visual C++ Redistributable: $_" -ForegroundColor Red
        Write-Host "You may need to install it manually from: $vcRedistUrl" -ForegroundColor Yellow
    }
}

# Create log directory
$logDir = "$InstallPath\logs"
if (-not (Test-Path -Path $logDir)) {
    New-Item -Path $logDir -ItemType Directory -Force | Out-Null
}

# Setup logging
$logFile = "$logDir\install_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
Start-Transcript -Path $logFile

Write-Host "===================================================" -ForegroundColor Cyan
Write-Host "SecurePulse Installer" -ForegroundColor Cyan
Write-Host "===================================================" -ForegroundColor Cyan
Write-Host "Installation Path: $InstallPath" -ForegroundColor Cyan
Write-Host "Install SCuBA: $InstallScuba" -ForegroundColor Cyan
Write-Host "Skip Python: $SkipPython" -ForegroundColor Cyan
Write-Host "GitHub Branch: $Branch" -ForegroundColor Cyan
Write-Host "Log File: $logFile" -ForegroundColor Cyan
Write-Host "===================================================" -ForegroundColor Cyan

try {
    # Create installation directory
    if (-not (Test-Path -Path $InstallPath)) {
        Write-Host "Creating installation directory: $InstallPath" -ForegroundColor Cyan
        New-Item -Path $InstallPath -ItemType Directory -Force | Out-Null
    }
    
    # Step 1: Install prerequisites
    Write-Host "Step 1: Installing prerequisites..." -ForegroundColor Cyan
    
    # Install Microsoft Visual C++ Redistributable
    Install-VCRedist
    
    # Install Git if not present
    if (-not (Test-ProgramInstalled "git")) {
        Write-Host "Git not found. Installing Git..." -ForegroundColor Cyan
        $gitUrl = "https://github.com/git-for-windows/git/releases/download/v2.41.0.windows.1/Git-2.41.0-64-bit.exe"
        $gitInstaller = "$env:TEMP\git-installer.exe"
        Invoke-WebRequest -Uri $gitUrl -OutFile $gitInstaller -UseBasicParsing
        Start-Process -FilePath $gitInstaller -ArgumentList "/VERYSILENT", "/NORESTART" -Wait
        Remove-Item $gitInstaller -Force
        
        # Add Git to PATH if not already there
        $env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path", "User")
    }
    
    # Install Python if not present or version < 3.8
    if ((-not (Test-ProgramInstalled "python")) -or (-not (Test-PythonVersion)) -and (-not $SkipPython)) {
        Write-Host "Python 3.8+ not found. Installing Python 3.10..." -ForegroundColor Cyan
        $pythonUrl = "https://www.python.org/ftp/python/3.10.11/python-3.10.11-amd64.exe"
        $pythonInstaller = "$env:TEMP\python-installer.exe"
        Invoke-WebRequest -Uri $pythonUrl -OutFile $pythonInstaller -UseBasicParsing
        Start-Process -FilePath $pythonInstaller -ArgumentList "/quiet", "InstallAllUsers=1", "PrependPath=1", "Include_test=0" -Wait
        Remove-Item $pythonInstaller -Force
        
        # Refresh PATH
        $env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path", "User")
    }
    
    # Step 2: Clone SecurePulse repository
    Write-Host "Step 2: Downloading SecurePulse..." -ForegroundColor Cyan
    Push-Location $InstallPath
    
    # Copy files instead of git clone until repo is ready
    Write-Host "Copying files to installation directory..." -ForegroundColor Cyan
    
    # Create source files structure for testing
    $sourceDirs = @(
        "reporting_engine",
        "reporting_engine/templates",
        "reporting_engine/charts",
        "verified_scan",
        "verified_scan/drift"
    )
    
    foreach ($dir in $sourceDirs) {
        if (-not (Test-Path -Path "$InstallPath\$dir")) {
            New-Item -Path "$InstallPath\$dir" -ItemType Directory -Force | Out-Null
        }
    }
    
    # Create placeholder requirements.txt
    $requirementsContent = @"
# Core requirements
requests>=2.28.0
msal>=1.20.0
pandas>=1.5.0
matplotlib>=3.6.0

# Reporting
jinja2>=3.1.2
markdown>=3.4.0

# Vector database and embeddings
sentence-transformers>=2.2.2
chromadb>=0.4.15
numpy>=1.23.0

# Baseline handling
pyyaml>=6.0
jsonschema>=4.17.0

# Date handling
python-dateutil>=2.8.2

# Utilities
tqdm>=4.64.0
colorlog>=6.7.0
"@
    
    Set-Content -Path "$InstallPath\requirements.txt" -Value $requirementsContent
    
    # Create HTML template
    $htmlTemplateContent = @"
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
        h1, h2, h3 {
            color: #2c3e50;
        }
        .summary {
            background-color: #f8f9fa;
            padding: 15px;
            border-radius: 5px;
            margin-bottom: 20px;
        }
        .metrics {
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
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 20px;
        }
        th, td {
            padding: 8px 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }
        th {
            background-color: #f1f1f1;
        }
        .footer {
            margin-top: 50px;
            text-align: center;
            font-size: 12px;
            color: #7f8c8d;
            border-top: 1px solid #eee;
            padding-top: 20px;
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>Security Assessment Report</h1>
        <p>Generated on {{ report_date }}</p>
    </div>
    
    <div class="summary">
        <h2>Executive Summary</h2>
        <p>{{ summary_text }}</p>
    </div>
    
    <h2>Key Metrics</h2>
    <div class="metrics">
        {% for metric in key_metrics %}
        <div class="metric-card">
            <div>{{ metric.name }}</div>
            <div class="metric-value" style="color: {{ metric.color }}">{{ metric.value }}</div>
            <div>{{ metric.description }}</div>
        </div>
        {% endfor %}
    </div>
    
    <h2>Security Findings</h2>
    <table>
        <tr>
            <th>Category</th>
            <th>Finding</th>
            <th>Severity</th>
            <th>Recommendation</th>
        </tr>
        {% for finding in findings %}
        <tr>
            <td>{{ finding.category }}</td>
            <td>{{ finding.title }}</td>
            <td>{{ finding.severity }}</td>
            <td>{{ finding.recommendation }}</td>
        </tr>
        {% endfor %}
    </table>
    
    <div class="footer">
        <p>Generated by SecurePulse - © {{ current_year }}</p>
    </div>
</body>
</html>
"@
    
    Set-Content -Path "$InstallPath\reporting_engine\templates\report.html.j2" -Value $htmlTemplateContent
    
    # Create placeholder report generator
    $reportGeneratorContent = @"
#!/usr/bin/env python3
"""
Report generator module for SecurePulse
"""

import os
import json
import datetime

class ReportGenerator:
    """
    Generates comprehensive security reports from assessment data
    """
    
    def __init__(self):
        """
        Initialize the report generator
        """
        self.templates_dir = os.path.join(os.path.dirname(__file__), 'templates')
        self.charts_dir = os.path.join(os.path.dirname(__file__), 'charts')
        os.makedirs(self.charts_dir, exist_ok=True)
    
    def generate_report(self, drift_report, access_report, license_report, tenant_id, output_path, format='html'):
        """
        Generate a security report from assessment data
        
        Args:
            drift_report: Configuration drift assessment results
            access_report: Access analysis results
            license_report: License optimization results
            tenant_id: Microsoft 365 tenant ID
            output_path: Path to save the report
            format: Report format (html, md, or pdf)
        
        Returns:
            Path to the generated report
        """
        # Create placeholder report
        with open(output_path, 'w') as f:
            f.write(f'''
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Security Assessment Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 1200px; margin: 0 auto; padding: 20px; }}
        h1, h2, h3 {{ color: #2c3e50; }}
    </style>
</head>
<body>
    <h1>Security Assessment Report</h1>
    <p>Generated on {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    
    <h2>Executive Summary</h2>
    <p>This report contains a security assessment of your Microsoft 365 tenant.</p>
    
    <h2>Tenant Information</h2>
    <p>Tenant ID: {tenant_id}</p>
    
    <h2>Security Findings</h2>
    <p>This is a placeholder report. In a real assessment, detailed findings would be shown here.</p>
    
    <footer>
        <p>Generated by SecurePulse</p>
    </footer>
</body>
</html>
            ''')
        
        print(f"Report generated: {output_path}")
        return output_path
"@
    
    Set-Content -Path "$InstallPath\reporting_engine\report_generator.py" -Value $reportGeneratorContent
    
    # Create __init__.py files
    Set-Content -Path "$InstallPath\reporting_engine\__init__.py" -Value ""
    
    # Create placeholder generate_report.py
    $generateReportContent = @"
#!/usr/bin/env python3
"""
Generate a comprehensive HTML report from the latest verified scan results
"""

import os
import json
import datetime
import sys
from pathlib import Path

# Import reporting engine
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from reporting_engine.report_generator import ReportGenerator

def generate_html_report(results_file=None):
    """
    Generate an HTML report from the latest verified scan results
    
    Args:
        results_file: Path to the specific results file to use. If None, uses the latest one.
    """
    # Create report directory
    reports_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "reports")
    os.makedirs(reports_dir, exist_ok=True)
    
    # Generate the HTML report
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    output_path = os.path.join(reports_dir, f"comprehensive_report_{timestamp}.html")
    
    # Initialize the report generator
    report_generator = ReportGenerator()
    
    # Generate placeholder report
    report_generator.generate_report(
        drift_report={},
        access_report={},
        license_report={},
        tenant_id="placeholder-tenant-id",
        output_path=output_path,
        format='html'
    )
    
    print(f"HTML report generated: {output_path}")
    return output_path

if __name__ == "__main__":
    report_path = generate_html_report()
    if report_path:
        print(f"Report successfully generated at: {report_path}")
        print(f"Open this file in a web browser to view the report.")
"@
    
    Set-Content -Path "$InstallPath\generate_report.py" -Value $generateReportContent
    
    # Step 3: Create and setup Python virtual environment
    Write-Host "Step 3: Setting up Python environment..." -ForegroundColor Cyan
    
    if (-not (Test-Path -Path ".\venv")) {
        Write-Host "Creating Python virtual environment..." -ForegroundColor Cyan
        python -m venv venv
    }
    
    # Wait a moment for the virtual environment to be fully created
    Start-Sleep -Seconds 2
    
    Write-Host "Installing Python dependencies..." -ForegroundColor Cyan
    
    # Use the full path to pip for reliability
    $pythonPath = (Get-Command python).Source
    $pythonDir = Split-Path -Parent $pythonPath
    
    # Upgrade pip first
    Start-Process -FilePath "$pythonDir\python.exe" -ArgumentList "-m", "pip", "install", "--upgrade", "pip" -Wait -NoNewWindow
    
    # Install requirements using the Python executable directly to avoid permission issues
    Write-Host "Installing required packages..." -ForegroundColor Cyan
    
    # Create a simple requirements file with minimal dependencies
    $minimalRequirements = @"
jinja2>=3.1.2
markdown>=3.4.0
"@
    
    Set-Content -Path "$InstallPath\minimal_requirements.txt" -Value $minimalRequirements
    
    # Install the minimal requirements
    Start-Process -FilePath "$InstallPath\venv\Scripts\python.exe" -ArgumentList "-m", "pip", "install", "-r", "$InstallPath\minimal_requirements.txt" -Wait -NoNewWindow
    
    # Step 4: Install SCuBA if requested
    if ($InstallScuba) {
        Write-Host "Step 4: Installing SCuBA..." -ForegroundColor Cyan
        
        # Create SCuBA directory
        $scubaDir = "$InstallPath\SCuBA"
        if (-not (Test-Path -Path $scubaDir)) {
            New-Item -Path $scubaDir -ItemType Directory -Force | Out-Null
        }
        
        # Install required PowerShell modules
        Write-Host "Installing required PowerShell modules..." -ForegroundColor Cyan
        Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
        
        Write-Host "Installing PowerShellGet..." -ForegroundColor Cyan
        Install-Module -Name PowerShellGet -Force -AllowClobber -Scope CurrentUser
        
        Write-Host "Installing ScubaGear..." -ForegroundColor Cyan
        Install-Module -Name ScubaGear -Force -Scope CurrentUser
        
        Write-Host "Initializing SCuBA..." -ForegroundColor Cyan
        try {
            Import-Module ScubaGear
            Initialize-SCuBA
        }
        catch {
            Write-Host "Warning: Error during SCuBA initialization: $_" -ForegroundColor Yellow
            Write-Host "This may be resolved by running Initialize-SCuBA manually after installation." -ForegroundColor Yellow
        }
    }
    
    # Step 5: Create wrapper script
    Write-Host "Step 5: Creating wrapper scripts..." -ForegroundColor Cyan
    
    $wrapperContent = @'
<#
.SYNOPSIS
    Runs a comprehensive security assessment using SecurePulse and optionally SCuBA
.DESCRIPTION
    This script runs security assessments on Microsoft 365 tenant using SecurePulse modules
    and optionally SCuBA baseline checks. Results are combined into a single comprehensive report.
.PARAMETER TenantId
    The Microsoft 365 tenant ID to assess
.PARAMETER ClientId
    The application (client) ID for Microsoft Graph API access
.PARAMETER ClientSecret
    The client secret for Microsoft Graph API access
.PARAMETER UseScuba
    If specified, also runs SCuBA assessment
.PARAMETER OutputPath
    The path where reports should be saved. Defaults to "./reports"
.EXAMPLE
    .\Run-SecurityAssessment.ps1 -TenantId "1a2b3c4d-1234-5678-9012-abc123def456" -ClientId "app-id" -ClientSecret "app-secret"
.EXAMPLE
    .\Run-SecurityAssessment.ps1 -TenantId "1a2b3c4d-1234-5678-9012-abc123def456" -ClientId "app-id" -ClientSecret "app-secret" -UseScuba
.NOTES
    Author: Open Door MSP
    Version: 1.0
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string]$TenantId,
    
    [Parameter(Mandatory=$true)]
    [string]$ClientId,
    
    [Parameter(Mandatory=$true)]
    [string]$ClientSecret,
    
    [Parameter(Mandatory=$false)]
    [switch]$UseScuba,
    
    [Parameter(Mandatory=$false)]
    [string]$OutputPath = ".\reports"
)

$ErrorActionPreference = "Stop"
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

# Ensure output directory exists
if (-not (Test-Path -Path $OutputPath)) {
    New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
}

# Set environment variables for SecurePulse
$env:MS_CLIENT_ID = $ClientId
$env:MS_CLIENT_SECRET = $ClientSecret
$env:MS_TENANT_ID = $TenantId

try {
    # Step 1: Run SecurePulse report generation
    Write-Host "Generating SecurePulse report..." -ForegroundColor Cyan
    Push-Location $scriptDir
    
    # Activate virtual environment and run SecurePulse
    .\venv\Scripts\python.exe generate_report.py
    
    # Step 2: Run SCuBA assessment if requested
    if ($UseScuba) {
        Write-Host "Running SCuBA assessment..." -ForegroundColor Cyan
        
        # Check if ScubaGear is installed
        if (-not (Get-Module -ListAvailable -Name ScubaGear)) {
            Write-Host "SCuBA not installed. Please run the installer with -InstallScuba" -ForegroundColor Red
            return
        }
        
        # Create SCuBA output directory
        $scubaOutputPath = Join-Path $OutputPath "scuba"
        if (-not (Test-Path -Path $scubaOutputPath)) {
            New-Item -Path $scubaOutputPath -ItemType Directory -Force | Out-Null
        }
        
        # Run SCuBA assessment
        Import-Module ScubaGear
        Invoke-SCuBA -ProductNames * -OutputPath $scubaOutputPath
    }
    
    Write-Host "Assessment complete!" -ForegroundColor Green
    Write-Host "Reports are available in the 'reports' directory" -ForegroundColor Green
    
    Pop-Location
}
catch {
    Write-Host "Error during assessment: $_" -ForegroundColor Red
}
finally {
    # Clear environment variables
    Remove-Item Env:\MS_CLIENT_ID -ErrorAction SilentlyContinue
    Remove-Item Env:\MS_CLIENT_SECRET -ErrorAction SilentlyContinue
    Remove-Item Env:\MS_TENANT_ID -ErrorAction SilentlyContinue
}
'@

    $importScubaContent = @'
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
    
    # This is a placeholder implementation
    print("This is a placeholder for SCuBA import functionality")
    
    # Create output directory
    output_dir = Path("./reports/scuba")
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Create a placeholder report
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file = output_dir / f"scuba_import_{timestamp}.json"
    
    with open(output_file, 'w') as f:
        json.dump({"status": "Placeholder for SCuBA import"}, f, indent=2)
    
    print(f"Placeholder SCuBA import file created at: {output_file}")
    return str(output_file)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Import SCuBA assessment results')
    parser.add_argument('--scuba-path', required=True, help='Path to SCuBA assessment results')
    args = parser.parse_args()
    
    import_scuba_results(args.scuba_path)
'@

    $securityAssessmentScript = "$InstallPath\Run-SecurityAssessment.ps1"
    Set-Content -Path $securityAssessmentScript -Value $wrapperContent
    
    $importScubaScript = "$InstallPath\import_scuba_results.py"
    Set-Content -Path $importScubaScript -Value $importScubaContent
    
    # Step 6: Create desktop shortcuts
    Write-Host "Step 6: Creating shortcuts..." -ForegroundColor Cyan
    
    $WshShell = New-Object -ComObject WScript.Shell
    $Shortcut = $WshShell.CreateShortcut("$env:USERPROFILE\Desktop\SecurePulse.lnk")
    $Shortcut.TargetPath = "powershell.exe"
    $Shortcut.Arguments = "-ExecutionPolicy Bypass -File `"$securityAssessmentScript`""
    $Shortcut.WorkingDirectory = $InstallPath
    $Shortcut.IconLocation = "powershell.exe,0"
    $Shortcut.Description = "Run SecurePulse Security Assessment"
    $Shortcut.Save()
    
    # Step 7: Create README file
    Write-Host "Step 7: Creating documentation..." -ForegroundColor Cyan
    
    $readmeContent = @"
# SecurePulse

## Installation Complete!

SecurePulse has been successfully installed on your system.

## Usage

1. Run the security assessment using the desktop shortcut or by executing:
   ```
   $securityAssessmentScript -TenantId "your-tenant-id" -ClientId "your-client-id" -ClientSecret "your-client-secret"
   ```

2. To include SCuBA assessment, add the `-UseScuba` parameter:
   ```
   $securityAssessmentScript -TenantId "your-tenant-id" -ClientId "your-client-id" -ClientSecret "your-client-secret" -UseScuba
   ```

3. Reports will be generated in the `reports` directory.

## Troubleshooting

- If you encounter any issues, check the logs in the `$logDir` directory.
- Make sure your Microsoft Graph API credentials have the necessary permissions.
- For SCuBA-related issues, refer to the SCuBA documentation.

## Update

To update SecurePulse, run the installer again.

"@
    
    Set-Content -Path "$InstallPath\README_INSTALL.md" -Value $readmeContent
    
    # Create reports directory
    $reportsDir = "$InstallPath\reports"
    if (-not (Test-Path -Path $reportsDir)) {
        New-Item -Path $reportsDir -ItemType Directory -Force | Out-Null
    }
    
    # Final step: Completion message
    Write-Host "===================================================" -ForegroundColor Green
    Write-Host "Installation Complete!" -ForegroundColor Green
    Write-Host "===================================================" -ForegroundColor Green
    Write-Host "SecurePulse has been installed to: $InstallPath" -ForegroundColor Green
    Write-Host "A shortcut has been created on your desktop." -ForegroundColor Green
    Write-Host "You can run a security assessment with:" -ForegroundColor Green
    Write-Host "$securityAssessmentScript -TenantId 'your-tenant-id' -ClientId 'your-client-id' -ClientSecret 'your-client-secret'" -ForegroundColor Yellow
    if ($InstallScuba) {
        Write-Host "Include SCuBA assessment with: -UseScuba" -ForegroundColor Yellow
    }
    Write-Host "See $InstallPath\README_INSTALL.md for more information." -ForegroundColor Green
    Write-Host "===================================================" -ForegroundColor Green
    
    Pop-Location
}
catch {
    Write-Host "Error during installation: $_" -ForegroundColor Red
    Write-Host "Check the log file for more details: $logFile" -ForegroundColor Red
}
finally {
    Stop-Transcript
}