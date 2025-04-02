# SecurePulse Windows Installer

This directory contains the Windows installer for SecurePulse, a comprehensive security assessment tool for Microsoft 365 environments.

## Features

- Full installation of SecurePulse with all dependencies
- Optional SCuBA (Secure Cloud Business Applications) integration
- Python virtual environment setup
- PowerShell wrapper scripts
- Desktop shortcuts for easy access

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

## Usage

After installation, you can run SecurePulse in two ways:

1. Use the desktop shortcut 
2. Run the security assessment script directly:

```powershell
%USERPROFILE%\SecurePulse\Run-SecurityAssessment.ps1 -TenantId "your-tenant-id" -ClientId "your-client-id" -ClientSecret "your-client-secret"
```

To include SCuBA assessment:

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
2. Remove the desktop shortcut

If you installed SCuBA:

```powershell
Uninstall-Module -Name ScubaGear -Force
```