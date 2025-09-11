WN10-CC-000007

<#
.SYNOPSIS
    This PowerShell script ensures that the maximum size of the Windows Application event log is at least 32768 KB (32 MB).

.NOTES
    Author          : Corey Mitchell
    LinkedIn        : https://www.linkedin.com/in/corey-mitchell182/
    GitHub          : https://github.com/coreym182/Internship/new/main/STIG
    Date Created    : 2024-09-11
    Last Modified   : 2024-09-11
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-CC-000007

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    Put any usage instructions here.
    Example syntax:
    PS C:\> .\__remediation_template(STIG-ID-WN10-AU-000500).ps1 
#>

# WN10-CC-000007

# Run this in an elevated PowerShell window (Run as Administrator)

# Define the registry hive and path
$basePath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore"
$regKey   = "webcam"

# Ensure the base path exists
if (-not (Test-Path $basePath)) {
    New-Item -Path $basePath -Force | Out-Null
}

# Create the "webcam" subkey if it doesn't exist
if (-not (Test-Path "$basePath\$regKey")) {
    New-Item -Path $basePath -Name $regKey -Force | Out-Null
}

# Now set the Value property to "Deny" (REG_SZ)
Set-ItemProperty -Path "$basePath\$regKey" -Name "Value" -Value "Deny"

# Verify the change
Get-ItemProperty -Path "$basePath\$regKey" | Select-Object Value
