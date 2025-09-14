IPv6 source routing must be configured to highest protection.

.NOTES
    Author          : Corey Mitchell
    LinkedIn        : https://www.linkedin.com/in/corey-mitchell182/
    GitHub          : https://github.com/coreym182/Internship/new/main/STIG
    Date Created    : 2024-09-10
    Last Modified   : 2024-09-10
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-CC-000020 

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    Put any usage instructions here.
    Example syntax:
    PS C:\> .\__remediation_template(STIG-ID-WN10-AU-000500).ps1 


# WN10-CC-000020

Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters]
"Dhcpv6DUID"=hex:00,01,00,01,30,51,fe,14,00,0d,3a,7b,f5,41
"DisableIpSourceRouting"=dword:00000002

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\Interfaces]

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\Interfaces\{07374750-e68b-490e-9330-9fd785cd71b6}]
"EnableDHCP"=dword:00000001

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\Interfaces\{2ee2c70c-a092-4d88-a654-98c8d7645cd5}]
"EnableDHCP"=dword:00000001

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\Interfaces\{3a6b8ddb-6853-41f6-accd-cc86e5af432f}]
"EnableDHCP"=dword:00000001

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\Interfaces\{93123211-9629-4e04-82f0-ea2e4f221468}]
"EnableDHCP"=dword:00000001

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\Interfaces\{c4cbdbe3-8492-4790-93cc-eb85b077ae7b}]
"EnableDHCP"=dword:00000001
"Dhcpv6Iaid"=dword:06000d3a
"Dhcpv6State"=dword:00000001

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\Winsock]
"UseDelayedAcceptance"=dword:00000000
"MaxSockAddrLength"=dword:0000001c
"MinSockAddrLength"=dword:0000001c
"HelperDllName"=hex(2):25,00,53,00,79,00,73,00,74,00,65,00,6d,00,52,00,6f,00,\
  6f,00,74,00,25,00,5c,00,53,00,79,00,73,00,74,00,65,00,6d,00,33,00,32,00,5c,\
  00,77,00,73,00,68,00,69,00,70,00,36,00,2e,00,64,00,6c,00,6c,00,00,00
"ProviderGUID"=hex:c0,b0,ea,f9,d4,26,d0,11,bb,bf,00,aa,00,6c,34,e4
"OfflineCapable"=dword:00000001
"Mapping"=hex:08,00,00,00,03,00,00,00,17,00,00,00,01,00,00,00,06,00,00,00,17,\
  00,00,00,01,00,00,00,00,00,00,00,17,00,00,00,00,00,00,00,06,00,00,00,17,00,\
  00,00,02,00,00,00,11,00,00,00,17,00,00,00,02,00,00,00,00,00,00,00,17,00,00,\
  00,00,00,00,00,11,00,00,00,17,00,00,00,03,00,00,00,ff,00,00,00,17,00,00,00,\
  03,00,00,00,00,00,00,00

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\Winsock\0]
"Version"=dword:00000002
"AddressFamily"=dword:00000017
"MaxSockAddrLength"=dword:0000001c
"MinSockAddrLength"=dword:0000001c
"SocketType"=dword:00000001
"Protocol"=dword:00000006
"ProtocolMaxOffset"=dword:00000000
"ByteOrder"=dword:00000000
"MessageSize"=dword:00000000
"szProtocol"=hex(2):40,00,25,00,53,00,79,00,73,00,74,00,65,00,6d,00,52,00,6f,\
  00,6f,00,74,00,25,00,5c,00,53,00,79,00,73,00,74,00,65,00,6d,00,33,00,32,00,\
  5c,00,6d,00,73,00,77,00,73,00,6f,00,63,00,6b,00,2e,00,64,00,6c,00,6c,00,2c,\
  00,2d,00,36,00,30,00,32,00,30,00,30,00
"ProviderFlags"=dword:00000008
"ServiceFlags"=dword:00020066

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\Winsock\1]
"Version"=dword:00000002
"AddressFamily"=dword:00000017
"MaxSockAddrLength"=dword:0000001c
"MinSockAddrLength"=dword:0000001c
"SocketType"=dword:00000002
"Protocol"=dword:00000011
"ProtocolMaxOffset"=dword:00000000
"ByteOrder"=dword:00000000
"MessageSize"=dword:0000fff7
"szProtocol"=hex(2):40,00,25,00,53,00,79,00,73,00,74,00,65,00,6d,00,52,00,6f,\
  00,6f,00,74,00,25,00,5c,00,53,00,79,00,73,00,74,00,65,00,6d,00,33,00,32,00,\
  5c,00,6d,00,73,00,77,00,73,00,6f,00,63,00,6b,00,2e,00,64,00,6c,00,6c,00,2c,\
  00,2d,00,36,00,30,00,32,00,30,00,31,00
"ProviderFlags"=dword:00000008
"ServiceFlags"=dword:00020609

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\Winsock\2]
"Version"=dword:00000002
"AddressFamily"=dword:00000017
"MaxSockAddrLength"=dword:0000001c
"MinSockAddrLength"=dword:0000001c
"SocketType"=dword:00000003
"Protocol"=dword:00000000
"ProtocolMaxOffset"=dword:000000ff
"ByteOrder"=dword:00000000
"MessageSize"=dword:00008000
"szProtocol"=hex(2):40,00,25,00,53,00,79,00,73,00,74,00,65,00,6d,00,52,00,6f,\
  00,6f,00,74,00,25,00,5c,00,53,00,79,00,73,00,74,00,65,00,6d,00,33,00,32,00,\
  5c,00,6d,00,73,00,77,00,73,00,6f,00,63,00,6b,00,2e,00,64,00,6c,00,6c,00,2c,\
  00,2d,00,36,00,30,00,32,00,30,00,32,00
"ProviderFlags"=dword:0000000c
"ServiceFlags"=dword:00020609

