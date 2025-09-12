WN10-CC-000038

<#
.SYNOPSIS
    This PowerShell script ensures that the maximum size of the Windows Application event log is at least 32768 KB (32 MB).

.NOTES
    Author          : Corey Mitchell
    LinkedIn        : www.linkedin.com/in/corey-mitchell182/
    GitHub          : https://github.com/coreym182/Internship
    Date Created    : 2024-09-12
    Last Modified   : 2024-09-12
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-CC-000038

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

# WN10-CC-000038

# Run this in 32-bit PowerShell as Administrator

# Define registry path
$regHive   = [Microsoft.Win32.RegistryHive]::LocalMachine
$regView   = [Microsoft.Win32.RegistryView]::Registry32
$regSubKey = "SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest"

# Open the base key (32-bit view)
$baseKey = [Microsoft.Win32.RegistryKey]::OpenBaseKey($regHive, $regView)

# Open or create the subkey
$subKey = $baseKey.CreateSubKey($regSubKey)

# Explicitly create UseLogonCredential as REG_DWORD = 0
$subKey.SetValue("UseLogonCredential", 0, [Microsoft.Win32.RegistryValueKind]::DWord)

# Verify
Write-Host "UseLogonCredential set to:" $subKey.GetValue("UseLogonCredential")

# Close handles
$subKey.Close()
$baseKey.Close()
