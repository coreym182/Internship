<#
.SYNOPSIS
    This PowerShell script ensures that the Connections to non-domain networks when connected to a domain authenticated network must be blocked.

.NOTES
    Author          : Corey Mitchell
    LinkedIn        : https://www.linkedin.com/in/corey-mitchell182/
    GitHub          : https://github.com/coreym182/Internship    
    Date Created    : 2024-09-14
    Last Modified   : 2024-09-14
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-AU-000060

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

# WN10-AU-000060


# Run this script in an elevated PowerShell (Run as Administrator)

# Define registry path
$regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy"

# Ensure the registry key exists
if (-not (Test-Path $regPath)) {
    New-Item -Path $regPath -Force | Out-Null
}

# Create or update the DWORD value
New-ItemProperty -Path $regPath -Name "fBlockNonDomain" -PropertyType DWord -Value 1 -Force | Out-Null

# Confirm the result
Get-ItemProperty -Path $regPath | Select-Object fBlockNonDomain
 
