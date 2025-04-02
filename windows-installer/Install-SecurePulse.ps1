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
    
    if (Test-Path -Path ".git") {
        Write-Host "Updating existing repository..." -ForegroundColor Cyan
        git pull origin $Branch
    }
    else {
        Write-Host "Cloning repository from GitHub..." -ForegroundColor Cyan
        git clone --branch $Branch --depth 1 https://github.com/tier3tech/SecurePulse.git .
        
        if (-not $?) {
            Write-Host "Warning: Git clone failed. Attempting to download using direct HTTP..." -ForegroundColor Yellow
            
            # Create minimal directory structure if git clone fails
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
            
            # Download key files directly if needed
            try {
                $baseUrl = "https://raw.githubusercontent.com/tier3tech/SecurePulse/$Branch"
                
                $filesToDownload = @(
                    "requirements.txt",
                    "generate_report.py",
                    "import_scuba_results.py",
                    "run_verified_modules.py",
                    "reporting_engine/report_generator.py",
                    "reporting_engine/__init__.py",
                    "reporting_engine/templates/report.html.j2",
                    "windows-installer/Install-SecurePulse.ps1"
                )
                
                foreach ($file in $filesToDownload) {
                    $url = "$baseUrl/$file"
                    $outputFile = "$InstallPath\$file"
                    $outputDir = Split-Path -Parent $outputFile
                    
                    if (-not (Test-Path -Path $outputDir)) {
                        New-Item -Path $outputDir -ItemType Directory -Force | Out-Null
                    }
                    
                    Write-Host "Downloading $file..." -ForegroundColor Cyan
                    Invoke-WebRequest -Uri $url -OutFile $outputFile -UseBasicParsing
                }
                
                Write-Host "Essential files downloaded successfully" -ForegroundColor Green
            }
            catch {
                Write-Host "Error downloading files: $_" -ForegroundColor Red
                Write-Host "Will proceed with minimal functionality" -ForegroundColor Yellow
            }
        }
    }
    
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