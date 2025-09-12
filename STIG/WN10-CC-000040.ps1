Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation]
"AllowInsecureGuestAuth"=dword:00000000

WN10-CC-000040

<#
.SYNOPSIS
    This PowerShell script ensures that the maximum size of the Windows Application event log is at least 32768 KB (32 MB).

.NOTES
    Author          : Corey Mitchell
    LinkedIn        : https://www.linkedin.com/in/corey-mitchell182/
    GitHub          : https://github.com/coreym182/Internship/tree/main/STIG
    Date Created    : 2024-09-12
    Last Modified   : 2024-09-12
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-CC-000040

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

# WN10-CC-000040

# Ensure script is running as Administrator
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltinRole] "Administrator")) {
    Write-Error "You must run this script as Administrator!"
    exit
}

# Define registry path and value
$regPath = "SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation"
$valueName = "AllowInsecureGuestAuth"
$valueData = 0

# Open 32-bit LocalMachine hive
$baseKey = [Microsoft.Win32.RegistryKey]::OpenBaseKey(
    [Microsoft.Win32.RegistryHive]::LocalMachine,
    [Microsoft.Win32.RegistryView]::Registry32
)

# Ensure all parent keys exist
$parentPath = "SOFTWARE\Policies\Microsoft\Windows"
$parentKey = $baseKey.CreateSubKey($parentPath, [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree)
$parentKey.Close()

# Create or open LanmanWorkstation key
$lanmanKey = $baseKey.CreateSubKey($regPath, [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree)

# Set the DWORD value (create or overwrite)
$lanmanKey.SetValue($valueName, $valueData, [Microsoft.Win32.RegistryValueKind]::DWord)
$lanmanKey.Close()

# Verification
$checkKey = $baseKey.OpenSubKey($regPath)
if ($checkKey -ne $null -and $checkKey.GetValue($valueName) -eq $valueData) {
    Write-Host "Success: 'LanmanWorkstation' key and 'AllowInsecureGuestAuth' DWORD set in 32-bit registry."
} else {
    Write-Error "Failed to create key or set value. Make sure you are running as Administrator."
}
