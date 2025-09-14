<#
.SYNOPSIS
    This PowerShell script ensures that Autoplay must be turned off for non-volume devices.

.NOTES
    Author          : Corey Mitchell
    LinkedIn        : https://www.linkedin.com/in/corey-mitchell182/
    GitHub          : https://github.com/coreym182/Internship
    Date Created    : 2024-09-13
    Last Modified   : 2024-09-13
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-CC-000180

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

# YOUR CODE GOES HERE

Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer]
"NoAutoplayfornonVolume"=dword:00000001


WN10-CC-000180

# Ensure the registry path exists
$regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer"
if (-not (Test-Path $regPath)) {
    New-Item -Path $regPath -Force | Out-Null
}

# Set the NoAutoplayfornonVolume value to 1 (REG_DWORD)
Set-ItemProperty -Path $regPath -Name "NoAutoplayfornonVolume" -Value 1 -Type DWord

# Confirm the value
Get-ItemProperty -Path $regPath | Select-Object NoAutoplayfornonVolume
