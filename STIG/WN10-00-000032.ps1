<#
.SYNOPSIS
    This PowerShell script ensures that the maximum size of the Windows Application event log is at least 32768 KB (32 MB).

.NOTES
    Author          : Corey Mitchell
    LinkedIn        : https://www.linkedin.com/in/corey-mitchell182/
    GitHub          : https://github.com/coreym182/Internship
    Date Created    : 2024-09-13
    Last Modified   : 2024-09-13
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-00-000032

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

# WN10-00-000032

# Define the registry path
$regPath = "HKLM:\SOFTWARE\Policies\Microsoft\FVE"

# Ensure the registry path exists
if (-not (Test-Path $regPath)) {
    New-Item -Path $regPath -Force | Out-Null
}

# Set the MinimumPIN value (REG_DWORD = 6)
Set-ItemProperty -Path $regPath -Name "MinimumPIN" -Value 6 -Type DWord

# Confirm the change
Get-ItemProperty -Path $regPath | Select-Object MinimumPIN
