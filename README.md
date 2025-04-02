# SecurePulse

SecurePulse is a comprehensive security assessment and compliance monitoring solution for Microsoft 365 environments. It combines multiple security modules to provide a holistic view of your organization's security posture.

## Features

- **DriftGuard Engine**: Detects configuration drift against security baselines
- **AccessWatch**: Monitors identity and access management settings, including MFA compliance
- **LicenseLogic**: Optimizes license utilization and costs
- **SCuBA Integration**: Optional integration with CISA's Secure Cloud Business Applications (SCuBA) assessment tool

## Installation

### Windows

1. Download the latest installer from the releases page
2. Run the installer as Administrator:
   ```powershell
   .\Install-SecurePulse.ps1
   ```

3. For SCuBA integration, add the `-InstallScuba` parameter:
   ```powershell
   .\Install-SecurePulse.ps1 -InstallScuba
   ```

### Linux/macOS

1. Clone the repository:
   ```bash
   git clone https://github.com/tier3tech/SecurePulse.git
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

### Running a Security Assessment

```powershell
.\Run-SecurityAssessment.ps1 -TenantId "your-tenant-id" -ClientId "your-client-id" -ClientSecret "your-client-secret"
```

With SCuBA integration:

```powershell
.\Run-SecurityAssessment.ps1 -TenantId "your-tenant-id" -ClientId "your-client-id" -ClientSecret "your-client-secret" -UseScuba
```

### Viewing Reports

Reports are generated in the `reports` directory in HTML format. Open the most recent report in a web browser to view the results.

## Modules

### DriftGuard Engine

Detects and reports on configuration drift against security baselines in:
- Azure Active Directory 
- Exchange Online
- SharePoint Online
- Microsoft Teams
- Microsoft Defender

### AccessWatch

Analyzes identity and access settings, including:
- MFA adoption and compliance
- Privileged account security
- Conditional Access policies
- Sign-in risk assessment

### LicenseLogic

Optimizes Microsoft 365 license utilization:
- Identifies unused or underutilized licenses
- Recommends license reassignments
- Calculates potential cost savings

## SCuBA Integration

SecurePulse can integrate with CISA's [Secure Cloud Business Applications (SCuBA)](https://github.com/cisagov/ScubaGear) assessment tool to provide comprehensive compliance reporting against government security baselines.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.