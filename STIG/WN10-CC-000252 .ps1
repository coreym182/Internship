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
    STIG-ID         : WN10-CC-000252 

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

# WN10-CC-000252 

 # Ensure the registry path exists
$regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR"
if (-not (Test-Path $regPath)) {
    New-Item -Path $regPath -Force | Out-Null
}

# Set AllowGameDVR to 0 (REG_DWORD)
New-ItemProperty -Path $regPath -Name "AllowGameDVR" -Value 0 -PropertyType DWord -Force | Out-Null
 
