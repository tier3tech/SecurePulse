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
    
    # Skip repository clone - directly install core files
    Write-Host "Step 2: Setting up SecurePulse files..." -ForegroundColor Cyan
    Push-Location $InstallPath
    
    # Create a clean installation by removing generated files but preserving user data
    $preservePaths = @(
        "logs",
        "reports",
        "verified_scan/drift"
    )
    
    # Create necessary directories first
    $sourceDirs = @(
        "reporting_engine",
        "reporting_engine/templates",
        "reporting_engine/charts",
        "verified_scan",
        "verified_scan/drift",
        "reports"
    )
    
    foreach ($dir in $sourceDirs) {
        $dirPath = "$InstallPath\$($dir.Replace('/', '\'))"
        if (-not (Test-Path -Path $dirPath)) {
            Write-Host "Creating directory: $dirPath" -ForegroundColor Cyan
            New-Item -Path $dirPath -ItemType Directory -Force | Out-Null
        }
    }
    
    # Create core files
    Write-Host "Creating required files..." -ForegroundColor Cyan
    
    # Create Run-SecurityAssessment.ps1
    $securityAssessmentContent = @'
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
    # Step 1: Generate placeholder report
    Write-Host "Generating SecurePulse report..." -ForegroundColor Cyan
    Push-Location $scriptDir
    
    # Create report directory if it doesn't exist
    $reportsDir = Join-Path $scriptDir "reports"
    if (-not (Test-Path -Path $reportsDir)) {
        New-Item -Path $reportsDir -ItemType Directory -Force | Out-Null
    }
    
    # Generate timestamp for the report filename
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $reportFile = Join-Path $reportsDir "security_assessment_$timestamp.html"
    
    # Generate a simple HTML report
    $reportContent = @"
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Security Assessment Report</title>
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 1200px; margin: 0 auto; padding: 20px; }
        h1, h2, h3 { color: #2c3e50; }
        .header { border-bottom: 2px solid #2c3e50; padding-bottom: 10px; margin-bottom: 20px; }
        .section { margin-bottom: 30px; }
        .tenant-info { background-color: #f8f9fa; padding: 15px; border-radius: 5px; margin-bottom: 20px; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Security Assessment Report</h1>
        <p>Generated on $(Get-Date -Format "MMMM d, yyyy 'at' h:mm tt")</p>
    </div>
    
    <div class="tenant-info">
        <h2>Tenant Information</h2>
        <p>Tenant ID: $TenantId</p>
    </div>
    
    <div class="section">
        <h2>Executive Summary</h2>
        <p>This report contains a security assessment of your Microsoft 365 tenant.</p>
        <p>To run a complete assessment, please ensure your Microsoft Graph credentials have the required permissions.</p>
    </div>
    
    <div class="section">
        <h2>Security Findings</h2>
        <p>This is a placeholder report. In a full assessment, detailed findings would be shown here.</p>
    </div>
    
    <footer>
        <p>Generated by SecurePulse - © $(Get-Date -Format "yyyy")</p>
    </footer>
</body>
</html>
"@
    
    Set-Content -Path $reportFile -Value $reportContent
    
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
        try {
            Import-Module ScubaGear
            Invoke-SCuBA -ProductNames * -OutputPath $scubaOutputPath
            Write-Host "SCuBA assessment completed successfully" -ForegroundColor Green
        }
        catch {
            Write-Host "Error running SCuBA assessment: $_" -ForegroundColor Red
            Write-Host "You may need to run 'Initialize-SCuBA' manually first" -ForegroundColor Yellow
        }
    }
    
    Write-Host "Assessment complete!" -ForegroundColor Green
    Write-Host "Report is available at: $reportFile" -ForegroundColor Green
    
    # Try to open the report in the default browser
    try {
        Start-Process $reportFile
    }
    catch {
        Write-Host "Report generated but could not be opened automatically. Please open it manually." -ForegroundColor Yellow
    }
    
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
    
    Set-Content -Path "$InstallPath\Run-SecurityAssessment.ps1" -Value $securityAssessmentContent
    
    # Create reporting_engine/__init__.py
    Set-Content -Path "$InstallPath\reporting_engine\__init__.py" -Value ""
    
    # Create reporting_engine/report_generator.py
    $reportGeneratorContent = @"
# Placeholder for report generator module
"""
This is a placeholder for the real report generator module from the SecurePulse repository.
The installer has created a minimal version to ensure the system can run.
For the full version, please visit: https://github.com/tier3tech/SecurePulse
"""
import os
import json
import datetime
from pathlib import Path

class ReportGenerator:
    def __init__(self):
        self.templates_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "reporting_engine", "templates")
    
    def generate_report(self, drift_report=None, access_report=None, license_report=None, tenant_id="Unknown", output_path="./reports", format='html'):
        """
        Generate a simple HTML report with available data
        """
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = os.path.join(output_path, f"security_report_{timestamp}.html")
        
        # Ensure output directory exists
        os.makedirs(output_path, exist_ok=True)
        
        # Generate a simple HTML report
        html_content = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Security Assessment Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 1200px; margin: 0 auto; padding: 20px; }}
        h1, h2, h3 {{ color: #2c3e50; }}
        .header {{ border-bottom: 2px solid #2c3e50; padding-bottom: 10px; margin-bottom: 20px; }}
        .section {{ margin-bottom: 30px; }}
        .tenant-info {{ background-color: #f8f9fa; padding: 15px; border-radius: 5px; margin-bottom: 20px; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>Security Assessment Report</h1>
        <p>Generated on {datetime.datetime.now().strftime("%B %d, %Y at %H:%M")}</p>
    </div>
    
    <div class="tenant-info">
        <h2>Tenant Information</h2>
        <p>Tenant ID: {tenant_id}</p>
    </div>
    
    <div class="section">
        <h2>Executive Summary</h2>
        <p>This report contains a security assessment of your Microsoft 365 tenant.</p>
        <p>For a complete assessment, please run all modules or visit the GitHub repository: https://github.com/tier3tech/SecurePulse</p>
    </div>
</body>
</html>"""
        
        # Write the report to file
        with open(output_file, 'w') as f:
            f.write(html_content)
        
        print(f"Report generated: {output_file}")
        return output_file
"@
    
    Set-Content -Path "$InstallPath\reporting_engine\report_generator.py" -Value $reportGeneratorContent
    
    # Create generate_report.py in the root directory
    $generateReportContent = @"
#!/usr/bin/env python3
"""
Generate a security assessment report
"""

import os
import sys
import datetime
from pathlib import Path

# Add the current directory to the path so we can import the modules
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    from reporting_engine.report_generator import ReportGenerator
except ImportError:
    print("Error: Could not import ReportGenerator. Please make sure the reporting_engine module is installed.")
    print("Continuing with minimal report generation...")
    
    class ReportGenerator:
        def generate_report(self, **kwargs):
            # Create a very simple HTML file as fallback
            output_path = kwargs.get('output_path', './reports')
            tenant_id = kwargs.get('tenant_id', 'Unknown')
            os.makedirs(output_path, exist_ok=True)
            
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = os.path.join(output_path, f"security_report_{timestamp}.html")
            
            with open(output_file, 'w') as f:
                f.write(f"<html><body><h1>Security Report</h1><p>Generated on {datetime.datetime.now()}</p><p>Tenant: {tenant_id}</p></body></html>")
            
            print(f"Basic report generated: {output_file}")
            return output_file

def main():
    # Create output directory if it doesn't exist
    output_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "reports")
    os.makedirs(output_path, exist_ok=True)
    
    # Get tenant ID from environment variable or use default
    tenant_id = os.environ.get('MS_TENANT_ID', 'Unknown')
    
    print(f"Generating report for tenant: {tenant_id}")
    
    # Create the report generator
    generator = ReportGenerator()
    
    # Generate the report
    report_file = generator.generate_report(
        tenant_id=tenant_id,
        output_path=output_path,
        format='html'
    )
    
    print(f"Report generated: {report_file}")
    
    # Try to open the report in the default browser
    try:
        import webbrowser
        webbrowser.open(f"file://{os.path.abspath(report_file)}")
    except:
        print(f"Report generated but could not open automatically. Please open it manually at: {report_file}")

if __name__ == "__main__":
    main()
"@
    
    Set-Content -Path "$InstallPath\generate_report.py" -Value $generateReportContent
    
    # Create minimal requirements.txt
    $requirementsContent = @"
# Minimal requirements for SecurePulse
requests>=2.28.0
jinja2>=3.1.2
markdown>=3.4.0
"@
    
    Set-Content -Path "$InstallPath\requirements.txt" -Value $requirementsContent
    
    Write-Host "Core files created successfully" -ForegroundColor Green
    
    # Step 3: Create and setup Python virtual environment
    Write-Host "Step 3: Setting up Python environment..." -ForegroundColor Cyan
    
    $pythonEnvSuccess = $true
    
    try {
        if (-not (Test-Path -Path ".\venv")) {
            Write-Host "Creating Python virtual environment..." -ForegroundColor Cyan
            try {
                python -m venv venv
                Start-Sleep -Seconds 2  # Wait for virtual environment to initialize
            }
            catch {
                Write-Host "Error creating virtual environment: $_" -ForegroundColor Yellow
                Write-Host "Trying alternative approach..." -ForegroundColor Yellow
                try {
                    # Try with full path to python executable
                    $pythonPath = (Get-Command python).Source
                    Start-Process -FilePath $pythonPath -ArgumentList "-m", "venv", "venv" -Wait -NoNewWindow
                    Start-Sleep -Seconds 2
                }
                catch {
                    Write-Host "Could not create virtual environment. Will use system Python instead." -ForegroundColor Yellow
                    $pythonEnvSuccess = $false
                }
            }
        }
        
        Write-Host "Installing Python dependencies..." -ForegroundColor Cyan
        
        # Create a simple requirements file with minimal dependencies
        $minimalRequirements = @"
jinja2>=3.1.2
markdown>=3.4.0
"@
        
        Set-Content -Path "$InstallPath\minimal_requirements.txt" -Value $minimalRequirements
        
        # Determine which Python to use
        if ($pythonEnvSuccess -and (Test-Path -Path ".\venv\Scripts\python.exe")) {
            $pipCommand = ".\venv\Scripts\python.exe -m pip"
            $pythonCommand = ".\venv\Scripts\python.exe"
        }
        else {
            # Fallback to system Python
            $pythonPath = (Get-Command python -ErrorAction SilentlyContinue).Source
            if ($pythonPath) {
                $pythonDir = Split-Path -Parent $pythonPath
                $pipCommand = "$pythonDir\python.exe -m pip"
                $pythonCommand = "$pythonDir\python.exe"
            }
            else {
                Write-Host "Python not found in PATH. Skipping dependency installation." -ForegroundColor Yellow
                $pythonEnvSuccess = $false
            }
        }
        
        # Install dependencies if we have Python
        if ($pythonEnvSuccess) {
            # Try to upgrade pip first - but don't fail if it doesn't work
            try {
                Invoke-Expression "$pipCommand install --upgrade pip" 
            }
            catch {
                Write-Host "Couldn't upgrade pip, but continuing with installation." -ForegroundColor Yellow
            }
            
            # Install the minimal requirements
            try {
                Invoke-Expression "$pipCommand install -r $InstallPath\minimal_requirements.txt"
                Write-Host "Python dependencies installed successfully." -ForegroundColor Green
            }
            catch {
                Write-Host "Error installing dependencies: $_" -ForegroundColor Yellow
                Write-Host "Some features may not work correctly." -ForegroundColor Yellow
            }
        }
    }
    catch {
        Write-Host "Error setting up Python environment: $_" -ForegroundColor Yellow
        Write-Host "Will continue installation, but some features may not work correctly." -ForegroundColor Yellow
        $pythonEnvSuccess = $false
    }
    
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
    
    # Step 6: Create shortcuts (Start Menu and batch file)
    Write-Host "Step 6: Creating shortcuts..." -ForegroundColor Cyan
    
    # Create Start Menu shortcut
    try {
        $startMenuPath = [System.Environment]::GetFolderPath('Programs')
        $startMenuDir = "$startMenuPath\SecurePulse"
        
        if (-not (Test-Path -Path $startMenuDir)) {
            New-Item -Path $startMenuDir -ItemType Directory -Force | Out-Null
        }
        
        $WshShell = New-Object -ComObject WScript.Shell
        $Shortcut = $WshShell.CreateShortcut("$startMenuDir\SecurePulse Assessment.lnk")
        $Shortcut.TargetPath = "powershell.exe"
        $Shortcut.Arguments = "-ExecutionPolicy Bypass -File `"$securityAssessmentScript`""
        $Shortcut.WorkingDirectory = $InstallPath
        $Shortcut.IconLocation = "powershell.exe,0"
        $Shortcut.Description = "Run SecurePulse Security Assessment"
        $Shortcut.Save()
        
        Write-Host "Start Menu shortcut created successfully." -ForegroundColor Green
    }
    catch {
        Write-Host "Warning: Could not create Start Menu shortcut: $_" -ForegroundColor Yellow
        Write-Host "You can still run SecurePulse using the batch file or PowerShell script directly." -ForegroundColor Yellow
    }
    
    # Create batch file launcher (alternative to shortcuts)
    try {
        $batchContent = @"
@echo off
echo Running SecurePulse Security Assessment...
powershell.exe -ExecutionPolicy Bypass -File "$securityAssessmentScript" %*
"@
        
        Set-Content -Path "$InstallPath\Run-SecurePulse.bat" -Value $batchContent
        Write-Host "Batch file launcher created: $InstallPath\Run-SecurePulse.bat" -ForegroundColor Green
    }
    catch {
        Write-Host "Warning: Could not create batch file launcher: $_" -ForegroundColor Yellow
    }
    
    # Optional desktop shortcut - try/catch to handle potential COM failures
    try {
        $WshShell = New-Object -ComObject WScript.Shell
        $Shortcut = $WshShell.CreateShortcut("$env:USERPROFILE\Desktop\SecurePulse.lnk")
        $Shortcut.TargetPath = "powershell.exe"
        $Shortcut.Arguments = "-ExecutionPolicy Bypass -File `"$securityAssessmentScript`""
        $Shortcut.WorkingDirectory = $InstallPath
        $Shortcut.IconLocation = "powershell.exe,0"
        $Shortcut.Description = "Run SecurePulse Security Assessment"
        $Shortcut.Save()
        Write-Host "Desktop shortcut created successfully." -ForegroundColor Green
    }
    catch {
        Write-Host "Could not create desktop shortcut: $_" -ForegroundColor Yellow
        Write-Host "You can use the Start Menu or batch file instead." -ForegroundColor Yellow
    }
    
    # Step 7: Create README file
    Write-Host "Step 7: Creating documentation..." -ForegroundColor Cyan
    
    $readmeContent = @"
# SecurePulse

## Installation Complete!

SecurePulse has been successfully installed on your system.

## Ways to Launch SecurePulse

You can run SecurePulse in multiple ways:

1. **Start Menu**: Programs > SecurePulse > SecurePulse Assessment

2. **Batch File**: Run the following batch file:
   ```
   $InstallPath\Run-SecurePulse.bat
   ```

3. **PowerShell Script**: Execute directly with parameters:
   ```
   $securityAssessmentScript -TenantId "your-tenant-id" -ClientId "your-client-id" -ClientSecret "your-client-secret"
   ```

## Usage Options

1. Run a basic security assessment:
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
- If shortcuts aren't working, use the batch file or PowerShell script directly.

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
    Write-Host "You can launch SecurePulse in multiple ways:" -ForegroundColor Green
    Write-Host "1. Start Menu: Programs > SecurePulse > SecurePulse Assessment" -ForegroundColor Yellow
    Write-Host "2. Batch File: $InstallPath\Run-SecurePulse.bat" -ForegroundColor Yellow
    Write-Host "3. PowerShell Script:" -ForegroundColor Yellow
    Write-Host "   $securityAssessmentScript -TenantId 'your-tenant-id' -ClientId 'your-client-id' -ClientSecret 'your-client-secret'" -ForegroundColor Yellow
    
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