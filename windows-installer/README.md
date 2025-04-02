# SecurePulse Windows Installer

This directory contains the Windows installer for SecurePulse, a comprehensive security assessment tool for Microsoft 365 environments.

## Features

- Full installation of SecurePulse with all dependencies
- Optional SCuBA (Secure Cloud Business Applications) integration
- Python virtual environment setup
- PowerShell wrapper scripts
- Multiple launch options (Start Menu, desktop shortcuts, batch file)
- Robust error handling and fallback mechanisms

## Installation Instructions

### Option 1: Run the pre-packaged installer

1. Download the latest installer from the releases page
2. Right-click the installer and select "Run as administrator"
3. Follow the on-screen instructions

### Option 2: Run the PowerShell installer directly

1. Open PowerShell as Administrator
2. Navigate to this directory
3. Run the installer script:

```powershell
.\Install-SecurePulse.ps1
```

With SCuBA integration:

```powershell
.\Install-SecurePulse.ps1 -InstallScuba
```

Custom installation path:

```powershell
.\Install-SecurePulse.ps1 -InstallPath "C:\SecurePulse"
```

Silent installation (for automation):

```powershell
.\Install-SecurePulse.ps1 -InstallPath "C:\SecurePulse" -InstallScuba
```

## Usage

After installation, you can run SecurePulse in multiple ways:

1. **Start Menu**: Go to Start Menu > Programs > SecurePulse > SecurePulse Assessment
2. **Desktop Shortcut**: Use the desktop shortcut (if created successfully)
3. **Batch File**: Run the batch file directly:
   ```
   %USERPROFILE%\SecurePulse\Run-SecurePulse.bat
   ```
4. **PowerShell Script**: Run the script directly with parameters:
   ```powershell
   %USERPROFILE%\SecurePulse\Run-SecurityAssessment.ps1 -TenantId "your-tenant-id" -ClientId "your-client-id" -ClientSecret "your-client-secret"
   ```

To include SCuBA assessment, add the `-UseScuba` parameter:

```powershell
%USERPROFILE%\SecurePulse\Run-SecurityAssessment.ps1 -TenantId "your-tenant-id" -ClientId "your-client-id" -ClientSecret "your-client-secret" -UseScuba
```

## Package Creation

To create a self-contained installer package:

1. Open PowerShell as Administrator
2. Navigate to this directory
3. Run the packaging script:

```powershell
.\package.ps1
```

The package will be created in the `.\dist` directory.

## Requirements

- Windows 10/11 or Windows Server 2016 or newer
- PowerShell 5.1 or newer
- Administrative privileges for installation
- Internet connection for downloading dependencies

## SCuBA Integration

When installed with the `-InstallScuba` parameter, the installer will:

1. Install the ScubaGear PowerShell module
2. Initialize SCuBA dependencies
3. Add SCuBA integration to the security assessment script

This allows you to run both SecurePulse and SCuBA assessments with a single command and combine the results into a unified report.

## Troubleshooting

- Check the installation logs in `%USERPROFILE%\SecurePulse\logs`
- Make sure your Microsoft Graph API credentials have the necessary permissions
- For SCuBA-related issues, refer to the [SCuBA documentation](https://github.com/cisagov/ScubaGear)

## Uninstallation

To uninstall SecurePulse:

1. Remove the installation directory (default: `%USERPROFILE%\SecurePulse`)
2. Remove the desktop shortcut (if created)
3. Remove the Start Menu folder: `%APPDATA%\Microsoft\Windows\Start Menu\Programs\SecurePulse`

If you installed SCuBA:

```powershell
Uninstall-Module -Name ScubaGear -Force
```

## Silent Installation

For automated deployment, you can run the installer silently:

```batch
SecurePulse-Setup.exe -Silent -InstallPath "C:\SecurePulse" -InstallScuba
```

Command-line parameters:
- `-Silent`: Runs the installer without user interaction
- `-InstallPath`: Specifies the installation directory
- `-InstallScuba`: Installs SCuBA integration
- `-SkipPython`: Skips Python installation (if already installed)
- `-Branch`: Specifies the GitHub branch to use (default: main)
```