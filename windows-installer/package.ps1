<#
.SYNOPSIS
    Creates a self-contained installer package for SecurePulse
.DESCRIPTION
    This script bundles the SecurePulse installer along with any necessary
    dependencies into a self-extracting package for easy distribution.
.PARAMETER OutputPath
    Path where the installer package should be saved
.PARAMETER Version
    Version number for the package
.EXAMPLE
    .\package.ps1 -OutputPath "C:\Packages" -Version "1.0.0"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$OutputPath = "$PSScriptRoot\dist",
    
    [Parameter(Mandatory=$false)]
    [string]$Version = "1.0.0"
)

$ErrorActionPreference = "Stop"

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

# Ensure output directory exists
if (-not (Test-Path -Path $OutputPath)) {
    New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
}

# Define paths
$packagingDir = "$PSScriptRoot\temp"
$installerScript = "$PSScriptRoot\Install-SecurePulse.ps1"
$packageFilename = "SecurePulse-$Version-Setup.exe"
$packagePath = "$OutputPath\$packageFilename"

# Create temporary directory
if (Test-Path -Path $packagingDir) {
    Remove-Item -Path $packagingDir -Recurse -Force
}
New-Item -Path $packagingDir -ItemType Directory -Force | Out-Null

# Copy installer script
Copy-Item -Path $installerScript -Destination "$packagingDir\Install-SecurePulse.ps1"

# Create bootstrap script
$bootstrapContent = @'
@echo off
setlocal

echo SecurePulse Installer
echo =====================
echo.

:: Check for administrative privileges
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo This installer requires administrative privileges.
    echo Please right-click and select "Run as administrator".
    echo.
    pause
    exit /b 1
)

:: Parse command line arguments
set INSTALL_ARGS=
set SILENT_MODE=false

:parse_args
if "%~1"=="" goto end_parse_args
if /i "%~1"=="-Silent" (
    set SILENT_MODE=true
    shift
    goto parse_args
)
if /i "%~1"=="-InstallPath" (
    set INSTALL_ARGS=%INSTALL_ARGS% -InstallPath "%~2"
    shift
    shift
    goto parse_args
)
if /i "%~1"=="-InstallScuba" (
    set INSTALL_ARGS=%INSTALL_ARGS% -InstallScuba
    shift
    goto parse_args
)
if /i "%~1"=="-SkipPython" (
    set INSTALL_ARGS=%INSTALL_ARGS% -SkipPython
    shift
    goto parse_args
)
if /i "%~1"=="-Branch" (
    set INSTALL_ARGS=%INSTALL_ARGS% -Branch "%~2"
    shift
    shift
    goto parse_args
)
set INSTALL_ARGS=%INSTALL_ARGS% %1
shift
goto parse_args
:end_parse_args

:: Create temporary directory
set TEMP_DIR=%TEMP%\SecurePulse_Install
mkdir "%TEMP_DIR%" 2>nul

:: Extract files
echo Extracting installation files...
copy "%~dp0Install-SecurePulse.ps1" "%TEMP_DIR%\"

:: Run PowerShell installer
echo Starting installation...
if "%SILENT_MODE%"=="true" (
    powershell.exe -ExecutionPolicy Bypass -Command "& '%TEMP_DIR%\Install-SecurePulse.ps1' %INSTALL_ARGS%"
) else (
    powershell.exe -ExecutionPolicy Bypass -File "%TEMP_DIR%\Install-SecurePulse.ps1" %INSTALL_ARGS%
)

:: Check for errors
if %errorLevel% neq 0 (
    echo.
    echo Installation failed. Please check the logs for more information.
    echo.
    if "%SILENT_MODE%"=="false" pause
    exit /b 1
)

:: Cleanup
rmdir /s /q "%TEMP_DIR%" 2>nul

echo.
echo Installation completed successfully!
echo.
if "%SILENT_MODE%"=="false" pause
exit /b 0
'@

Set-Content -Path "$packagingDir\setup.bat" -Value $bootstrapContent

# Check if 7-Zip is installed
if (-not (Test-ProgramInstalled "7z")) {
    Write-Host "7-Zip is required to create the package. Please install it and try again." -ForegroundColor Red
    exit 1
}

# Create self-extracting archive
Write-Host "Creating package..." -ForegroundColor Cyan
7z a -sfx7z.sfx "$packagePath" "$packagingDir\*" -r

# Clean up
Remove-Item -Path $packagingDir -Recurse -Force

Write-Host "Package created successfully: $packagePath" -ForegroundColor Green