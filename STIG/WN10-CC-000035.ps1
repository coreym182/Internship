WN10-CC-000035
<#
.SYNOPSIS
    This PowerShell script ensures that the system must be configured to ignore NetBIOS name release requests except from WINS servers.


.NOTES
    Author          : Corey Mitchell
    LinkedIn        : https://www.linkedin.com/in/corey-mitchell182/
    GitHub          : https://github.com/coreym182/Internship
    Date Created    : 2024-09-14
    Last Modified   : 2024-09-14
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-CC-000035

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

# WN10-CC-000035

 # Run this script in an elevated PowerShell session (Run as Administrator)

# Base registry path
$basePath = "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters"

# Ensure the Parameters key exists
if (-not (Test-Path $basePath)) {
    New-Item -Path $basePath -Force | Out-Null
}

# Set DWORD values under Parameters
Set-ItemProperty -Path $basePath -Name "BcastNameQueryCount" -Value 3 -Type DWord
Set-ItemProperty -Path $basePath -Name "BcastQueryTimeout" -Value 0x2EE -Type DWord
Set-ItemProperty -Path $basePath -Name "CacheTimeout" -Value 0x927C0 -Type DWord
Set-ItemProperty -Path $basePath -Name "EnableLMHOSTS" -Value 1 -Type DWord
Set-ItemProperty -Path $basePath -Name "NameServerPort" -Value 0x89 -Type DWord
Set-ItemProperty -Path $basePath -Name "NameSrvQueryCount" -Value 3 -Type DWord
Set-ItemProperty -Path $basePath -Name "NameSrvQueryTimeout" -Value 0x5DC -Type DWord
Set-ItemProperty -Path $basePath -Name "SessionKeepAlive" -Value 0x36EE80 -Type DWord
Set-ItemProperty -Path $basePath -Name "Size/Small/Medium/Large" -Value 1 -Type DWord
Set-ItemProperty -Path $basePath -Name "UseNewSmb" -Value 1 -Type DWord
Set-ItemProperty -Path $basePath -Name "NoNameReleaseOnDemand" -Value 1 -Type DWord

# Set string values
New-ItemProperty -Path $basePath -Name "NbProvider" -Value "_tcp" -PropertyType String -Force | Out-Null
New-ItemProperty -Path $basePath -Name "TransportBindName" -Value "\\Device\\" -PropertyType String -Force | Out-Null

# Ensure Interfaces key exists
$interfacesPath = Join-Path $basePath "Interfaces"
if (-not (Test-Path $interfacesPath)) {
    New-Item -Path $interfacesPath -Force | Out-Null
}

# Define interface subkeys
$interfaces = @(
    "Tcpip_{3a6b8ddb-6853-41f6-accd-cc86e5af432f}",
    "Tcpip_{c4cbdbe3-8492-4790-93cc-eb85b077ae7b}"
)

foreach ($if in $interfaces) {
    $ifPath = Join-Path $interfacesPath $if
    if (-not (Test-Path $ifPath)) {
        New-Item -Path $ifPath -Force | Out-Null
    }

    # Set NameServerList as REG_MULTI_SZ with empty string
    New-ItemProperty -Path $ifPath -Name "NameServerList" -Value @("") -PropertyType MultiString -Force | Out-Null
    
    # Set NetbiosOptions
    Set-ItemProperty -Path $ifPath -Name "NetbiosOptions" -Value 0 -Type DWord
}
 
