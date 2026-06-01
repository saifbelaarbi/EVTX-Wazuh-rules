# Wazuh Rule Database Report

> Generated: 2026-06-01 21:35 UTC
> Pipeline version: 1.0.0

## Overview

| Metric | Value |
|--------|-------|
| Total rules generated | **3289** |
| EVTX files processed | 2292 |
| EVTX sources used | 1 |
| MITRE tactics covered | 12 / 12 |
| MITRE techniques covered | 270 |
| Rule ID range | 100000 - 120000 |

## Alert Level Distribution

| Level | Wazuh Severity | Count | Percentage |
|-------|----------------|-------|------------|
| 6 | Low relevance | 88 | 2.7% █ |
| 7 | Bad word matching | 76 | 2.3% █ |
| 8 | First time seen | 556 | 16.9% ████████ |
| 9 | Error from invalid source | 1400 | 42.6% █████████████████████ |
| 10 | Multiple user-generated errors | 446 | 13.6% ██████ |
| 11 | Integrity checking warning | 352 | 10.7% █████ |
| 12 | High importance event | 233 | 7.1% ███ |
| 13 | Unusual error (high importance) | 106 | 3.2% █ |
| 14 | High importance security event | 32 | 1.0%  |

## Detection Confidence Distribution

| Confidence | Count | Description |
|------------|-------|-------------|
| high | 1582 | Exact tool/process name match |
| medium | 1699 | Command-line pattern or behavioral indicator |
| low | 8 | Heuristic / generic event |

## Rules by MITRE ATT&CK Tactic

### Initial Access (TA0001) — 32 rules

| Rule ID | Level | Technique | Description | Confidence | Parent SID |
|---------|-------|-----------|-------------|------------|------------|
| `100000` | 8 | `T1200` T1200 | Device Installation Blocked | medium | 60100 |
| `100001` | 8 | `T1566.001` T1566.001 | ISO Image Mounted | medium | 60100 |
| `100002` | 9 | `T1078` Valid Accounts | Win Susp Computer Name Containing Samtheadmin | high | 60100 |
| `100003` | 9 | `T1078` Valid Accounts | Win Susp Computer Name Containing Samtheadmin | high | 60100 |
| `100004` | 9 | `T1027` Obfuscated Files or Information | Password Protected ZIP File Opened (Email Attachment) | high | 60100 |
| `100005` | 8 | `T1078` Valid Accounts | User Added to Local Administrator Group | medium | 60100 |
| `100006` | 9 | `T1566.001` T1566.001 | ISO File Created Within Temp Folders | high | 61613 |
| `100007` | 9 | `T1566.001` T1566.001 | ISO File Created Within Temp Folders | high | 61613 |
| `100008` | 8 | `T1566.001` T1566.001 | ISO or Image Mount Indicator in Recent Files | medium | 61613 |
| `100009` | 9 | `T1195` T1195 | Octopus Scanner Malware | high | 61613 |
| `100010` | 9 | `T1566.001` T1566.001 | Office Macro File Creation From Suspicious Process | high | 61613 |
| `100011` | 9 | `T1566.001` T1566.001 | Suspicious File Created in Outlook Temporary Directory | high | 61613 |
| `100012` | 9 | `T1190` Exploit Public-Facing Application | Suspicious MSExchangeMailboxReplication ASPX Write | high | 61613 |
| `100013` | 9 | `T1190` Exploit Public-Facing Application | Suspicious File Write to SharePoint Layouts Directory | high | 61613 |
| `100014` | 9 | `T1566.001` T1566.001 | Suspicious HWP Sub Processes | high | 61603 |
| `100015` | 9 | - | Suspicious Shells Spawn by Java Utility Keytool | high | 61603 |
| `100016` | 9 | - | Suspicious Processes Spawned by Java.EXE | high | 61603 |
| `100017` | 8 | - | Shell Process Spawned by Java.EXE | medium | 61603 |
| `100018` | 9 | `T1505.003` T1505.003 | Suspicious Child Process Of SQL Server | high | 61603 |
| `100019` | 9 | - | Suspicious Child Process Of Veeam Dabatase | high | 61603 |
| `100020` | 8 | `T1021.002` T1021.002 | Password Provided In Command Line Of Net.EXE | medium | 61603 |
| `100021` | 9 | `T1566` Phishing | Suspicious Microsoft OneNote Child Process | high | 61603 |
| `100022` | 9 | `T1566.001` T1566.001 | Suspicious Execution From Outlook Temporary Folder | high | 61603 |
| `100023` | 9 | `T1190` Exploit Public-Facing Application | Remote Access Tool - ScreenConnect Server Web Shell Execution | high | 61603 |
| `100024` | 9 | `T1133` T1133 | User Added to Remote Desktop Users Group | high | 61603 |
| `100025` | 9 | `T1566` Phishing | Phishing Pattern ISO in Archive | high | 61603 |
| `100026` | 9 | `T1566.001` T1566.001 | Suspicious Double Extension File Execution | high | 61603 |
| `100027` | 9 | `T1204.002` T1204.002 | Suspicious LNK Command-Line Padding with Whitespace Characters | high | 61603 |
| `100028` | 9 | `T1190` Exploit Public-Facing Application | Terminal Service Process Spawn | high | 61603 |
| `100029` | 9 | `T1190` Exploit Public-Facing Application | Suspicious Processes Spawned by WinRM | high | 61603 |
| `100030` | 8 | `T1566.001` T1566.001 | Windows Registry Trust Record Modification | medium | 61615 |
| `100031` | 9 | `T1133` T1133 | Running Chrome VPN Extensions via the Registry 2 VPN Extension | high | 61615 |

### Execution (TA0002) — 1163 rules

| Rule ID | Level | Technique | Description | Confidence | Parent SID |
|---------|-------|-----------|-------------|------------|------------|
| `102000` | 9 | `T1047` T1047 | Suspicious process: wmic | high | 61603 |
| `102001` | 8 | `T1059.001` T1059.001 | Suspicious command: iex( | medium | 61603 |
| `102002` | 8 | `T1047` T1047 | File created by wmic | medium | 61613 |
| `102003` | 9 | `T1047` T1047 | Network connection by wmic | high | 61605 |
| `102004` | 8 | `T1059.001` T1059.001 | Suspicious command: -nop  | medium | 61603 |
| `102005` | 9 | `T1047` T1047 | DLL sideloading by wmic | high | 61609 |
| `102006` | 9 | `T1047` T1047 | Network connection by wmic | high | 61605 |
| `102007` | 8 | `T1059.001` T1059.001 | Suspicious command: bypass | medium | 61603 |
| `102008` | 8 | `T1059.001` T1059.001 | Suspicious command: -w hidden | medium | 61603 |
| `102009` | 8 | `T1059.001` T1059.001 | Suspicious PowerShell: downloadstring | medium | 91801 |
| `102010` | 8 | `T1059.001` T1059.001 | Suspicious PowerShell: iex( | medium | 91801 |
| `102011` | 8 | `T1059.001` T1059.001 | PowerShell module: downloadstring | medium | 91801 |
| `102012` | 8 | `T1059.001` T1059.001 | PowerShell module: iex( | medium | 91801 |
| `102013` | 8 | `T1059.001` T1059.001 | PowerShell module: invoke-expression | medium | 91801 |
| `102014` | 8 | `T1059.001` T1059.001 | Suspicious PowerShell: bypass | medium | 91801 |
| `102015` | 8 | `T1047` T1047 | Suspicious PowerShell: invoke-wmimethod | medium | 91801 |
| `102016` | 8 | `T1059.001` T1059.001 | Suspicious PowerShell: invoke-expression | medium | 91801 |
| `102017` | 8 | `T1059.001` T1059.001 | Suspicious PowerShell: invoke-webrequest | medium | 91801 |
| `102018` | 8 | `T1059.001` T1059.001 | Suspicious PowerShell: -nop  | medium | 91801 |
| `102019` | 9 | `T1211` T1211 | Microsoft Malware Protection Engine Crash | high | 60003 |
| `102020` | 8 | - | Dump Ntds.dit To Suspicious Location | medium | 60003 |
| `102021` | 9 | `T1203` T1203 | Audit CVE Event | high | 60003 |
| `102022` | 8 | `T1070.004` T1070.004 | Backup Catalog Deleted | medium | 60003 |
| `102023` | 8 | - | MSI Installation From Suspicious Locations | medium | 60003 |
| `102024` | 8 | `T1218` T1218 | MSI Installation From Web | medium | 60003 |
| `102025` | 9 | - | MSSQL Disable Audit Settings | high | 60003 |
| `102026` | 9 | - | MSSQL XPCmdshell Suspicious Execution | high | 60003 |
| `102027` | 9 | - | MSSQL XPCmdshell Option Change | high | 60003 |
| `102028` | 9 | `T1211` T1211 | Microsoft Malware Protection Engine Crash - WER | high | 60003 |
| `102029` | 8 | `T1204.002` T1204.002 | AppLocker Prevented Application or Script from Running | medium | 60000 |
| `102030` | 8 | - | Deployment AppX Package Was Blocked By AppLocker | medium | 60000 |
| `102031` | 9 | - | Remote AppX Package Downloaded from File Sharing or CDN Domain | high | 60000 |
| `102032` | 8 | - | AppX Package Deployment Failed Due to Signing Requirements | medium | 60000 |
| `102033` | 9 | - | AppX Located in Known Staging Directory Added to Deployment Pipeline | high | 60000 |
| `102034` | 8 | - | Potential Malicious AppX Package Installation Attempts | medium | 60000 |
| `102035` | 8 | - | Deployment Of The AppX Package Was Blocked By The Policy | medium | 60000 |
| `102036` | 8 | - | AppX Located in Uncommon Directory Added to Deployment Pipeline | medium | 60000 |
| `102037` | 8 | `T1204.002` T1204.002 | Windows AppX Deployment Full Trust Package Installation | medium | 60000 |
| `102038` | 8 | `T1204.002` T1204.002 | Windows AppX Deployment Unsigned Package Installation | medium | 60000 |
| `102039` | 8 | - | Suspicious Digital Signature Of AppX Package | medium | 60000 |
| `102040` | 9 | - | Loading Diagcab Package From Remote Path | high | 60000 |
| `102041` | 8 | `T1590.002` T1590.002 | Failed DNS Zone Transfer | medium | 60000 |
| `102042` | 8 | `T1686.003` T1686.003 | Uncommon New Firewall Rule Added In Windows Firewall Exception List | medium | 60016 |
| `102043` | 9 | `T1686.003` T1686.003 | New Firewall Rule Added In Windows Firewall Exception List For Pote... | high | 60016 |
| `102044` | 8 | `T1686.003` T1686.003 | New Firewall Rule Added In Windows Firewall Exception List Via WmiP... | medium | 60016 |
| `102045` | 9 | `T1686.003` T1686.003 | All Rules Have Been Deleted From The Windows Firewall Configuration | high | 60016 |
| `102046` | 8 | `T1686.003` T1686.003 | A Rule Has Been Deleted From The Windows Firewall Exception List | medium | 60016 |
| `102047` | 9 | `T1587.001` T1587.001 | ProxyLogon MSExchange OabVirtualDirectory | high | 60000 |
| `102048` | 9 | `T1070` Indicator Removal | Remove Exported Mailbox from Exchange Webserver | high | 60000 |
| `102049` | 9 | `T1685` T1685 | Windows Filtering Platform Blocked Connection From EDR Agent Binary | high | 60100 |
| `102050` | 9 | `T1222.001` T1222.001 | AD Object WriteDAC Access | high | 60100 |
| `102051` | 9 | `T1685` T1685 | Weak Encryption Enabled and Kerberoast | high | 60100 |
| `102052` | 9 | `T1685.005` T1685.005 | Security Eventlog Cleared | high | 60100 |
| `102053` | 9 | `T1685.005` T1685.005 | Security Eventlog Cleared | high | 60100 |
| `102054` | 9 | `T1685.001` T1685.001 | Important Windows Event Auditing Disabled | high | 60100 |
| `102055` | 9 | `T1685.001` T1685.001 | Important Windows Event Auditing Disabled | high | 60100 |
| `102056` | 9 | `T1685` T1685 | HackTool - EDRSilencer Execution - Filter Added | high | 60100 |
| `102057` | 9 | `T1027` Obfuscated Files or Information | Invoke-Obfuscation CLIP+ Launcher - Security | high | 60100 |
| `102058` | 9 | `T1027` Obfuscated Files or Information | Invoke-Obfuscation Obfuscated IEX Invocation - Security | high | 60100 |
| `102059` | 9 | `T1027` Obfuscated Files or Information | Invoke-Obfuscation STDIN+ Launcher - Security | high | 60100 |
| `102060` | 9 | `T1027` Obfuscated Files or Information | Invoke-Obfuscation VAR+ Launcher - Security | high | 60100 |
| `102061` | 8 | `T1027` Obfuscated Files or Information | Invoke-Obfuscation COMPRESS OBFUSCATION - Security | medium | 60100 |
| `102062` | 8 | `T1027` Obfuscated Files or Information | Invoke-Obfuscation RUNDLL LAUNCHER - Security | medium | 60100 |
| `102063` | 9 | `T1027` Obfuscated Files or Information | Invoke-Obfuscation Via Stdin - Security | high | 60100 |
| `102064` | 9 | `T1027` Obfuscated Files or Information | Invoke-Obfuscation Via Use Clip - Security | high | 60100 |
| `102065` | 9 | `T1027` Obfuscated Files or Information | Invoke-Obfuscation Via Use MSHTA - Security | high | 60100 |
| `102066` | 9 | `T1027` Obfuscated Files or Information | Invoke-Obfuscation Via Use Rundll32 - Security | high | 60100 |
| `102067` | 9 | `T1027` Obfuscated Files or Information | Invoke-Obfuscation VAR++ LAUNCHER OBFUSCATION - Security | high | 60100 |
| `102068` | 8 | - | Potential AS-REP Roasting via Kerberos TGT Requests | medium | 60100 |
| `102069` | 8 | `T1036` T1036 | New or Renamed User Account with '$' Character | medium | 60100 |
| `102070` | 8 | `T1036` T1036 | New or Renamed User Account with '$' Character | medium | 60100 |
| `102071` | 9 | `T1569.002` T1569.002 | PowerShell Scripts Installed as Services - Security | high | 60100 |
| `102072` | 9 | `T1059.001` T1059.001 | Remote PowerShell Sessions Network Connections (WinRM) | high | 60100 |
| `102073` | 8 | `T1027` Obfuscated Files or Information | Password Protected ZIP File Opened | medium | 60100 |
| `102074` | 9 | `T1053.005` T1053.005 | Suspicious Scheduled Task Creation | high | 60100 |
| `102075` | 9 | `T1053.005` T1053.005 | Important Scheduled Task Deleted/Disabled | high | 60100 |
| `102076` | 9 | `T1053.005` T1053.005 | Suspicious Scheduled Task Update | high | 60100 |
| `102077` | 8 | `T1685` T1685 | Potential Privileged System Service Operation - SeLoadDriverPrivilege | medium | 60100 |
| `102078` | 8 | `T1685` T1685 | Windows Defender Exclusion List Modified | medium | 60100 |
| `102079` | 8 | `T1685` T1685 | Windows Defender Exclusion Registry Key - Write Access Requested | medium | 60100 |
| `102080` | 9 | `T1047` T1047 | T1047 Wmiprvse Wbemcomn DLL Hijack | high | 60100 |
| `102081` | 8 | - | Suspicious Application Installed | medium | 60000 |
| `102082` | 8 | - | Suspicious Application Installed | medium | 60000 |
| `102083` | 9 | `T1685` T1685 | Sysmon Application Crashed | high | 60106 |
| `102084` | 8 | `T1685.005` T1685.005 | Eventlog Cleared | medium | 60106 |
| `102085` | 9 | `T1685.005` T1685.005 | Important Windows Eventlog Cleared | high | 60106 |
| `102086` | 8 | `T1685` T1685 | Windows Defender Threat Detection Service Disabled | medium | 60106 |
| `102087` | 9 | `T1027` Obfuscated Files or Information | Invoke-Obfuscation CLIP+ Launcher - System | high | 60106 |
| `102088` | 9 | `T1027` Obfuscated Files or Information | Invoke-Obfuscation Obfuscated IEX Invocation - System | high | 60106 |
| `102089` | 9 | `T1027` Obfuscated Files or Information | Invoke-Obfuscation STDIN+ Launcher - System | high | 60106 |
| `102090` | 9 | `T1027` Obfuscated Files or Information | Invoke-Obfuscation VAR+ Launcher - System | high | 60106 |
| `102091` | 8 | `T1027` Obfuscated Files or Information | Invoke-Obfuscation COMPRESS OBFUSCATION - System | medium | 60106 |
| `102092` | 8 | `T1027` Obfuscated Files or Information | Invoke-Obfuscation RUNDLL LAUNCHER - System | medium | 60106 |
| `102093` | 9 | `T1027` Obfuscated Files or Information | Invoke-Obfuscation Via Stdin - System | high | 60106 |
| `102094` | 9 | `T1027` Obfuscated Files or Information | Invoke-Obfuscation Via Use Clip - System | high | 60106 |
| `102095` | 9 | `T1027` Obfuscated Files or Information | Invoke-Obfuscation Via Use MSHTA - System | high | 60106 |
| `102096` | 9 | `T1027` Obfuscated Files or Information | Invoke-Obfuscation Via Use Rundll32 - System | high | 60106 |
| `102097` | 9 | `T1027` Obfuscated Files or Information | Invoke-Obfuscation VAR++ LAUNCHER OBFUSCATION - System | high | 60106 |
| `102098` | 9 | `T1569.002` T1569.002 | PowerShell Scripts Installed as Services | high | 60106 |
| `102099` | 8 | `T1569.002` T1569.002 | CSExec Service Installation | medium | 60106 |
| `102100` | 9 | `T1569.002` T1569.002 | HackTool Service Registration or Execution | high | 60106 |
| `102101` | 8 | `T1569.002` T1569.002 | PAExec Service Installation | medium | 60106 |
| `102102` | 8 | `T1569.002` T1569.002 | RemCom Service Installation | medium | 60106 |
| `102103` | 8 | `T1569.002` T1569.002 | PsExec Service Installation | medium | 60106 |
| `102104` | 9 | - | Important Windows Service Terminated With Error | high | 60106 |
| `102105` | 9 | - | Important Windows Service Terminated Unexpectedly | high | 60106 |
| `102106` | 9 | `T1685` T1685 | Windows Defender Grace Period Expired | high | 60005 |
| `102107` | 9 | `T1047` T1047 | PSExec and WMI Process Creations Block | high | 60005 |
| `102108` | 8 | `T1685` T1685 | Windows Defender Exclusions Added | medium | 60005 |
| `102109` | 9 | `T1685` T1685 | Windows Defender Exploit Guard Tamper | high | 60005 |
| `102110` | 9 | `T1685` T1685 | Windows Defender Malware And PUA Scanning Disabled | high | 60005 |
| `102111` | 9 | `T1059` Command and Scripting Interpreter | Windows Defender AMSI Trigger Detected | high | 60005 |
| `102112` | 9 | `T1685` T1685 | Windows Defender Real-time Protection Disabled | high | 60005 |
| `102113` | 8 | `T1685` T1685 | Windows Defender Real-Time Protection Failure/Restart | medium | 60005 |
| `102114` | 9 | `T1685` T1685 | Win Defender Restored Quarantine File | high | 60005 |
| `102115` | 9 | `T1685` T1685 | Windows Defender Configuration Changes | high | 60005 |
| `102116` | 9 | `T1685` T1685 | Microsoft Defender Tamper Protection Trigger | high | 60005 |
| `102117` | 9 | `T1059` Command and Scripting Interpreter | Windows Defender Threat Detected | high | 60005 |
| `102118` | 9 | `T1685` T1685 | Windows Defender Virus Scanning Feature Disabled | high | 60005 |
| `102119` | 8 | `T1218.011` T1218.011 | Remote Thread Creation Via PowerShell In Uncommon Target | medium | 61610 |
| `102120` | 9 | `T1127` T1127 | Remote Thread Creation Ttdinject.exe Proxy | high | 61610 |
| `102121` | 8 | `T1564.004` T1564.004 | Hidden Executable In NTFS Alternate Data Stream | medium | 61617 |
| `102122` | 8 | - | Creation Of a Suspicious ADS File Outside a Browser Download | medium | 61617 |
| `102123` | 9 | `T1564.004` T1564.004 | Suspicious File Download From File Sharing Websites -  File Stream | high | 61617 |
| `102124` | 8 | `T1564.004` T1564.004 | Unusual File Download From File Sharing Websites - File Stream | medium | 61617 |
| `102125` | 9 | `T1564.004` T1564.004 | HackTool Named File Stream Created | high | 61617 |
| `102126` | 9 | `T1564.004` T1564.004 | Exports Registry Key To an Alternate Data Stream | high | 61617 |
| `102127` | 9 | `T1564.004` T1564.004 | Unusual File Download from Direct IP Address | high | 61617 |
| `102128` | 9 | - | Potentially Suspicious File Download From ZIP TLD | high | 61617 |
| `102129` | 8 | `T1559.001` T1559.001 | DNS Query Request By Regsvr32.EXE | medium | 61624 |
| `102130` | 8 | `T1590` T1590 | Suspicious DNS Query for IP Lookup Service APIs | medium | 61624 |
| `102131` | 8 | `T1070` Indicator Removal | EventLog EVTX File Deleted | medium | 61625 |
| `102132` | 9 | `T1070` Indicator Removal | Exchange PowerShell Cmdlet History Deleted | high | 61625 |
| `102133` | 8 | `T1070` Indicator Removal | IIS WebServer Access Logs Deleted | medium | 61625 |
| `102134` | 8 | - | Process Deletion of Its Own Executable | medium | 61625 |
| `102135` | 8 | `T1070` Indicator Removal | PowerShell Console History Logs Deleted | medium | 61625 |
| `102136` | 9 | `T1070.004` T1070.004 | Prefetch File Deleted | high | 61625 |
| `102137` | 8 | `T1070` Indicator Removal | Tomcat WebServer Logs Deleted | medium | 61625 |
| `102138` | 8 | `T1070.004` T1070.004 | File Deleted Via Sysinternals SDelete | medium | 61625 |
| `102139` | 8 | `T1070.004` T1070.004 | ADS Zone.Identifier Deleted By Uncommon Application | medium | 61625 |
| `102140` | 8 | - | Assembly DLL Creation Via AspNetCompiler | medium | 61613 |
| `102141` | 8 | `T1685.001` T1685.001 | EVTX Created In Uncommon Location | medium | 61613 |
| `102142` | 8 | `T1036.005` T1036.005 | Files With System DLL Name In Unsuspected Locations | medium | 61613 |
| `102143` | 12 | `T1036.005` T1036.005 | Files With System Process Name In Unsuspected Locations | medium | 61613 |
| `102144` | 9 | `T1059.005` T1059.005 | WScript or CScript Dropper - File | high | 61613 |
| `102145` | 8 | `T1569.002` T1569.002 | CSExec Service File Creation | medium | 61613 |
| `102146` | 8 | - | Potentially Suspicious DMP/HDMP File Creation | medium | 61613 |
| `102147` | 9 | `T1021.002` T1021.002 | HackTool - NetExec File Indicators | high | 61613 |
| `102148` | 9 | `T1021.002` T1021.002 | HackTool - NetExec File Indicators | high | 61613 |
| `102149` | 9 | `T1059.005` T1059.005 | Adwind RAT / JRAT File Artifact | high | 61613 |
| `102150` | 9 | `T1059.005` T1059.005 | Adwind RAT / JRAT File Artifact | high | 61613 |
| `102151` | 9 | - | Uncommon File Creation By Mysql Daemon Process | high | 61613 |
| `102152` | 9 | `T1218` T1218 | Suspicious DotNET CLR Usage Log Artifact | high | 61613 |
| `102153` | 9 | - | Suspicious File Creation In Uncommon AppData Folder | high | 61613 |
| `102154` | 8 | `T1218.011` T1218.011 | SCR File Write Event | medium | 61613 |
| `102155` | 8 | - | OneNote Attachment File Dropped In Suspicious Location | medium | 61613 |
| `102156` | 9 | - | Suspicious File Created Via OneNote Application | high | 61613 |
| `102157` | 8 | - | Publisher Attachment File Dropped In Suspicious Location | medium | 61613 |
| `102158` | 9 | `T1204.002` T1204.002 | File With Uncommon Extension Created By An Office Application | high | 61613 |
| `102159` | 9 | `T1587.001` T1587.001 | Uncommon File Created In Office Startup Folder | high | 61613 |
| `102160` | 9 | `T1059` Command and Scripting Interpreter | PCRE.NET Package Temp Files | high | 61613 |
| `102161` | 8 | `T1059` Command and Scripting Interpreter | Suspicious File Created In PerfLogs | medium | 61613 |
| `102162` | 13 | `T1059.001` T1059.001 | Malicious PowerShell Scripts - FileCreation | high | 61613 |
| `102163` | 9 | `T1059.001` T1059.001 | Malicious PowerShell Scripts - FileCreation | high | 61613 |
| `102164` | 8 | - | PSScriptPolicyTest Creation By Uncommon Process | medium | 61613 |
| `102165` | 9 | - | .RDP File Created By Uncommon Application | high | 61613 |
| `102166` | 9 | `T1027` Obfuscated Files or Information | Potential Winnti Dropper Activity | high | 61613 |
| `102167` | 9 | - | PDF File Created By RegEdit.EXE | high | 61613 |
| `102168` | 8 | `T1569.002` T1569.002 | RemCom Service File Creation | medium | 61613 |
| `102169` | 8 | `T1218` T1218 | Self Extraction Directive File Created In Potentially Suspicious Lo... | medium | 61613 |
| `102170` | 9 | `T1059` Command and Scripting Interpreter | Windows Shell/Scripting Application File Write to Suspicious Folder | high | 61613 |
| `102171` | 9 | `T1059` Command and Scripting Interpreter | Windows Shell/Scripting Application File Write to Suspicious Folder | high | 61613 |
| `102172` | 12 | `T1036` T1036 | Windows Binaries Write Suspicious Extensions | high | 61613 |
| `102173` | 9 | `T1036` T1036 | Windows Binaries Write Suspicious Extensions | high | 61613 |
| `102174` | 9 | `T1564` T1564 | Suspicious Creation with Colorcpl | high | 61613 |
| `102175` | 8 | `T1036.005` T1036.005 | Suspicious Files in Default GPO Folder | medium | 61613 |
| `102176` | 8 | - | Creation of a Diagcab | medium | 61613 |
| `102177` | 9 | `T1036.007` T1036.007 | Suspicious Double Extension Files | high | 61613 |
| `102178` | 9 | `T1036.007` T1036.007 | Suspicious Double Extension Files | high | 61613 |
| `102179` | 9 | `T1564` T1564 | Suspicious Executable File Creation | high | 61613 |
| `102180` | 8 | `T1564.004` T1564.004 | Potential Hidden Directory Creation Via NTFS INDEX_ALLOCATION Stream | medium | 61613 |
| `102181` | 8 | `T1036` T1036 | Potential Homoglyph Attack Using Lookalike Characters in Filename | medium | 61613 |
| `102182` | 8 | `T1036` T1036 | Potential Homoglyph Attack Using Lookalike Characters in Filename | medium | 61613 |
| `102183` | 9 | `T1218` T1218 | Legitimate Application Dropped Archive | high | 61613 |
| `102184` | 9 | `T1218` T1218 | Legitimate Application Dropped Executable | high | 61613 |
| `102185` | 9 | `T1218` T1218 | Legitimate Application Dropped Script | high | 61613 |
| `102186` | 8 | `T1036.007` T1036.007 | Suspicious LNK Double Extension File Created | medium | 61613 |
| `102187` | 8 | `T1685` T1685 | Suspicious PROCEXP152.sys File Created In TMP | medium | 61613 |
| `102188` | 9 | `T1204` User Execution | Suspicious Binaries and Scripts in Public Folder | high | 61613 |
| `102189` | 9 | `T1036.002` T1036.002 | Potential File Extension Spoofing Using Right-to-Left Override | high | 61613 |
| `102190` | 8 | - | Drop Binaries Into Spool Drivers Color Folder | medium | 61613 |
| `102191` | 9 | `T1059.001` T1059.001 | Suspicious Interactive PowerShell as SYSTEM | high | 61613 |
| `102192` | 8 | - | Potentially Suspicious WDAC Policy File Creation | medium | 61613 |
| `102193` | 8 | - | WinSxS Executable File Creation By Non-System Process | medium | 61613 |
| `102194` | 9 | `T1548.002` T1548.002 | UAC Bypass Using IDiagnostic Profile - File | high | 61613 |
| `102195` | 8 | `T1587.001` T1587.001 | VHD Image Download Via Browser | medium | 61613 |
| `102196` | 8 | `T1216` T1216 | AWL Bypass with Winrm.vbs and Malicious WsmPty.xsl/WsmTxt.xsl - File | medium | 61613 |
| `102197` | 9 | `T1047` T1047 | Wmiprvse Wbemcomn DLL Hijack - File | high | 61613 |
| `102198` | 8 | `T1218` T1218 | Potentially Suspicious Self Extraction Directive File Created | medium | 61613 |
| `102199` | 8 | `T1059` Command and Scripting Interpreter | Clfs.SYS Loaded By Process Located In a Potential Suspicious Location | medium | 61609 |
| `102200` | 9 | `T1218.003` T1218.003 | DLL Loaded From Suspicious Location Via Cmspt.EXE | high | 61609 |
| `102201` | 8 | - | Amsi.DLL Loaded Via LOLBIN Process | medium | 61609 |
| `102202` | 9 | `T1059` Command and Scripting Interpreter | PCRE.NET Package Image Load | high | 61609 |
| `102203` | 9 | `T1202` T1202 | Diagnostic Library Sdiageng.DLL Loaded By Msdt.EXE | high | 61609 |
| `102204` | 8 | `T1059.001` T1059.001 | PowerShell Core DLL Loaded By Non PowerShell Process | medium | 61609 |
| `102205` | 8 | `T1129` T1129 | Unsigned .node File Loaded | medium | 61609 |
| `102206` | 9 | `T1685.001` T1685.001 | HackTool - SharpEvtMute DLL Load | high | 61609 |
| `102207` | 8 | `T1204.002` T1204.002 | DotNET Assembly DLL Loaded Via Office Application | medium | 61609 |
| `102208` | 8 | `T1204.002` T1204.002 | CLR DLL Loaded Via Office Applications | medium | 61609 |
| `102209` | 9 | `T1204.002` T1204.002 | GAC DLL Loaded Via Office Applications | high | 61609 |
| `102210` | 8 | `T1204.002` T1204.002 | Microsoft Excel Add-In Loaded From Uncommon Location | medium | 61609 |
| `102211` | 8 | `T1204.002` T1204.002 | Microsoft VBA For Outlook Addin Loaded Via Outlook | medium | 61609 |
| `102212` | 8 | - | PowerShell Core DLL Loaded Via Office Application | medium | 61609 |
| `102213` | 9 | `T1204.002` T1204.002 | VBA DLL Loaded Via Office Application | high | 61609 |
| `102214` | 8 | `T1204.002` T1204.002 | Remote DLL Load Via Rundll32.EXE | medium | 61609 |
| `102215` | 9 | `T1059` Command and Scripting Interpreter | Abusable DLL Potential Sideloading From Suspicious Location | high | 61609 |
| `102216` | 8 | `T1070` Indicator Removal | DLL Load By System Process From Suspicious Locations | medium | 61609 |
| `102217` | 9 | `T1055` Process Injection | DotNet CLR DLL Loaded By Scripting Applications | high | 61609 |
| `102218` | 8 | `T1218.011` T1218.011 | Unsigned DLL Loaded by Windows Utility | medium | 61609 |
| `102219` | 8 | `T1059.005` T1059.005 | MMC Loading Script Engines DLLs | medium | 61609 |
| `102220` | 8 | `T1220` T1220 | WMIC Loading Scripting Libraries | medium | 61609 |
| `102221` | 9 | `T1047` T1047 | Wmiprvse Wbemcomn DLL Hijack | high | 61609 |
| `102222` | 8 | `T1059.001` T1059.001 | Suspicious WSMAN Provider Image Loads | medium | 61609 |
| `102223` | 9 | `T1218` T1218 | Network Connection Initiated By AddinUtil.EXE | high | 61605 |
| `102224` | 9 | `T1218.003` T1218.003 | Outbound Network Connection Initiated By Cmstp.EXE | high | 61605 |
| `102225` | 9 | `T1071.001` T1071.001 | Outbound Network Connection Initiated By Microsoft Dialer | high | 61605 |
| `102226` | 9 | `T1203` T1203 | Network Connection Initiated By Eqnedt32.EXE | high | 61605 |
| `102227` | 8 | `T1203` T1203 | Office Application Initiated Network Connection To Non-Local IP | medium | 61605 |
| `102228` | 8 | `T1218.009` T1218.009 | RegAsm.EXE Initiating Network Connection To Public IP | medium | 61605 |
| `102229` | 8 | `T1559.001` T1559.001 | Network Connection Initiated By Regsvr32.EXE | medium | 61605 |
| `102230` | 8 | `T1218.011` T1218.011 | Rundll32 Internet Connection | medium | 61605 |
| `102231` | 9 | `T1127.001` T1127.001 | Silenttrinity Stager Msbuild Activity | high | 61605 |
| `102232` | 9 | - | Suspicious Network Connection Binary No CommandLine | high | 61605 |
| `102233` | 9 | `T1059.001` T1059.001 | Potential Remote PowerShell Session Initiated | high | 61605 |
| `102234` | 8 | `T1218.011` T1218.011 | Outbound Network Connection To Public IP Via Winlogon | medium | 61605 |
| `102235` | 8 | `T1218` T1218 | Potentially Suspicious Wuauclt Network Connection | medium | 61605 |
| `102236` | 8 | `T1059.001` T1059.001 | Alternate PowerShell Hosts Pipe | medium | 61619 |
| `102237` | 8 | `T1569.002` T1569.002 | PUA - PAExec Default Named Pipe | medium | 61619 |
| `102238` | 8 | `T1047` T1047 | WMI Event Consumer Created Named Pipe | medium | 61619 |
| `102239` | 8 | `T1569.002` T1569.002 | PsExec Tool Execution From Suspicious Locations - PipeName | medium | 61619 |
| `102240` | 8 | `T1059.001` T1059.001 | Nslookup PowerShell Download Cradle | medium | 91801 |
| `102241` | 8 | `T1059.001` T1059.001 | PowerShell Downgrade Attack - PowerShell | medium | 91801 |
| `102242` | 9 | `T1059.001` T1059.001 | PowerShell Called from an Executable Version Mismatch | high | 91801 |
| `102243` | 9 | `T1218` T1218 | Potential RemoteFXvGPUDisablement.EXE Abuse | high | 91801 |
| `102244` | 9 | `T1685` T1685 | Tamper Windows Defender - PSClassic | high | 91801 |
| `102245` | 8 | `T1059.001` T1059.001 | Suspicious Non PowerShell WSMAN COM Provider | medium | 91801 |
| `102246` | 8 | `T1059.001` T1059.001 | Alternate PowerShell Hosts - PowerShell Module | medium | 91801 |
| `102247` | 9 | `T1059.001` T1059.001 | Bad Opsec Powershell Code Artifacts | high | 91801 |
| `102248` | 8 | `T1070.003` T1070.003 | Clear PowerShell History - PowerShell Module | medium | 91801 |
| `102249` | 8 | `T1070.003` T1070.003 | Clear PowerShell History - PowerShell Module | medium | 91801 |
| `102250` | 13 | `T1059.001` T1059.001 | Malicious PowerShell Scripts - PoshModule | high | 91801 |
| `102251` | 9 | `T1059.001` T1059.001 | Malicious PowerShell Scripts - PoshModule | high | 91801 |
| `102252` | 9 | `T1027` Obfuscated Files or Information | Invoke-Obfuscation CLIP+ Launcher - PowerShell Module | high | 91801 |
| `102253` | 9 | `T1027` Obfuscated Files or Information | Invoke-Obfuscation Obfuscated IEX Invocation - PowerShell Module | high | 91801 |
| `102254` | 9 | `T1027` Obfuscated Files or Information | Invoke-Obfuscation STDIN+ Launcher - PowerShell Module | high | 91801 |
| `102255` | 9 | `T1027` Obfuscated Files or Information | Invoke-Obfuscation VAR+ Launcher - PowerShell Module | high | 91801 |
| `102256` | 8 | `T1027` Obfuscated Files or Information | Invoke-Obfuscation COMPRESS OBFUSCATION - PowerShell Module | medium | 91801 |
| `102257` | 8 | `T1027` Obfuscated Files or Information | Invoke-Obfuscation RUNDLL LAUNCHER - PowerShell Module | medium | 91801 |
| `102258` | 9 | `T1027` Obfuscated Files or Information | Invoke-Obfuscation Via Stdin - PowerShell Module | high | 91801 |
| `102259` | 9 | `T1027` Obfuscated Files or Information | Invoke-Obfuscation Via Use Clip - PowerShell Module | high | 91801 |
| `102260` | 9 | `T1027` Obfuscated Files or Information | Invoke-Obfuscation Via Use MSHTA - PowerShell Module | high | 91801 |
| `102261` | 9 | `T1027` Obfuscated Files or Information | Invoke-Obfuscation Via Use Rundll32 - PowerShell Module | high | 91801 |
| `102262` | 9 | `T1027` Obfuscated Files or Information | Invoke-Obfuscation VAR++ LAUNCHER OBFUSCATION - PowerShell Module | high | 91801 |
| `102263` | 13 | `T1482` T1482 | Malicious PowerShell Commandlets - PoshModule | high | 91801 |
| `102264` | 9 | `T1059.001` T1059.001 | Remote PowerShell Session (PS Module) | high | 91801 |
| `102265` | 9 | `T1218` T1218 | Potential RemoteFXvGPUDisablement.EXE Abuse - PowerShell Module | high | 91801 |
| `102266` | 8 | `T1059.001` T1059.001 | Suspicious PowerShell Download - PoshModule | medium | 91801 |
| `102267` | 9 | `T1059.001` T1059.001 | Suspicious PowerShell Invocations - Generic - PowerShell Module | high | 91801 |
| `102268` | 9 | `T1059.001` T1059.001 | Suspicious PowerShell Invocations - Specific - PowerShell Module | high | 91801 |
| `102269` | 9 | `T1059.001` T1059.001 | Suspicious PowerShell Invocations - Specific - PowerShell Module | high | 91801 |
| `102270` | 9 | `T1059.001` T1059.001 | Suspicious PowerShell Invocations - Specific - PowerShell Module | high | 91801 |
| `102271` | 9 | `T1059.001` T1059.001 | Suspicious PowerShell Invocations - Specific - PowerShell Module | high | 91801 |
| `102272` | 9 | `T1059.001` T1059.001 | Suspicious PowerShell Invocations - Specific - PowerShell Module | high | 91801 |
| `102273` | 9 | `T1059.001` T1059.001 | Suspicious PowerShell Invocations - Specific - PowerShell Module | high | 91801 |
| `102274` | 8 | `T1218` T1218 | SyncAppvPublishingServer Bypass Powershell Restriction - PS Module | medium | 91801 |
| `102275` | 9 | - | AADInternals PowerShell Cmdlets Execution - PsScript | high | 91801 |
| `102276` | 8 | - | Add Windows Capability Via PowerShell Script | medium | 91801 |
| `102277` | 9 | `T1685` T1685 | AMSI Bypass Pattern Assembly GetType | high | 91801 |
| `102278` | 8 | `T1685` T1685 | Potential AMSI Bypass Script Using NULL Bits | medium | 91801 |
| `102279` | 9 | `T1059.001` T1059.001 | Silence.EDA Detection | high | 91801 |
| `102280` | 8 | `T1070.003` T1070.003 | Clear PowerShell History - PowerShell | medium | 91801 |
| `102281` | 8 | `T1070.003` T1070.003 | Clear PowerShell History - PowerShell | medium | 91801 |
| `102282` | 9 | `T1070` Indicator Removal | Clearing Windows Console History | high | 91801 |
| `102283` | 8 | `T1059.001` T1059.001 | PowerShell Create Local User | medium | 91801 |
| `102284` | 9 | `T1070.003` T1070.003 | Disable Powershell Command History | high | 91801 |
| `102285` | 9 | `T1685` T1685 | Disable-WindowsOptionalFeature Command PowerShell | high | 91801 |
| `102286` | 8 | `T1620` T1620 | Potential In-Memory Execution Using Reflection.Assembly | medium | 91801 |
| `102287` | 9 | `T1059.001` T1059.001 | DSInternals Suspicious PowerShell Cmdlets - ScriptBlock | high | 91801 |
| `102288` | 8 | - | Potential Suspicious Windows Feature Enabled | medium | 91801 |
| `102289` | 9 | `T1070` Indicator Removal | Disable of ETW Trace - Powershell | high | 91801 |
| `102290` | 9 | `T1070` Indicator Removal | Disable of ETW Trace - Powershell | high | 91801 |
| `102291` | 8 | `T1059.001` T1059.001 | Import PowerShell Modules From Suspicious Directories | medium | 91801 |
| `102292` | 9 | `T1027` Obfuscated Files or Information | Invoke-Obfuscation CLIP+ Launcher - PowerShell | high | 91801 |
| `102293` | 9 | `T1027` Obfuscated Files or Information | Invoke-Obfuscation Obfuscated IEX Invocation - PowerShell | high | 91801 |
| `102294` | 9 | `T1027` Obfuscated Files or Information | Invoke-Obfuscation STDIN+ Launcher - Powershell | high | 91801 |
| `102295` | 9 | `T1027` Obfuscated Files or Information | Invoke-Obfuscation VAR+ Launcher - PowerShell | high | 91801 |
| `102296` | 8 | `T1027` Obfuscated Files or Information | Invoke-Obfuscation COMPRESS OBFUSCATION - PowerShell | medium | 91801 |
| `102297` | 8 | `T1027` Obfuscated Files or Information | Invoke-Obfuscation RUNDLL LAUNCHER - PowerShell | medium | 91801 |
| `102298` | 9 | `T1027` Obfuscated Files or Information | Invoke-Obfuscation Via Stdin - Powershell | high | 91801 |
| `102299` | 9 | `T1027` Obfuscated Files or Information | Invoke-Obfuscation Via Use Clip - Powershell | high | 91801 |
| `102300` | 9 | `T1027` Obfuscated Files or Information | Invoke-Obfuscation Via Use MSHTA - PowerShell | high | 91801 |
| `102301` | 9 | `T1027` Obfuscated Files or Information | Invoke-Obfuscation Via Use Rundll32 - PowerShell | high | 91801 |
| `102302` | 9 | `T1027` Obfuscated Files or Information | Invoke-Obfuscation VAR++ LAUNCHER OBFUSCATION - PowerShell | high | 91801 |
| `102303` | 13 | `T1482` T1482 | Malicious PowerShell Commandlets - ScriptBlock | high | 91801 |
| `102304` | 13 | `T1059.001` T1059.001 | Malicious PowerShell Keywords | medium | 91801 |
| `102305` | 8 | `T1059.001` T1059.001 | Powershell MsXml COM Object | medium | 91801 |
| `102306` | 13 | `T1059.001` T1059.001 | Malicious Nishang PowerShell Commandlets | high | 91801 |
| `102307` | 9 | `T1564.004` T1564.004 | NTFS Alternate Data Stream | high | 91801 |
| `102308` | 9 | `T1059.001` T1059.001 | PowerView PowerShell Cmdlets - ScriptBlock | high | 91801 |
| `102309` | 9 | `T1059.001` T1059.001 | PSAsyncShell - Asynchronous TCP Reverse Shell | high | 91801 |
| `102310` | 9 | `T1059.001` T1059.001 | PowerShell PSAttack | high | 91801 |
| `102311` | 8 | `T1059.001` T1059.001 | PowerShell Remote Session Creation | medium | 91801 |
| `102312` | 9 | `T1218` T1218 | Potential RemoteFXvGPUDisablement.EXE Abuse - PowerShell ScriptBlock | high | 91801 |
| `102313` | 8 | `T1553.004` T1553.004 | Root Certificate Installed - PowerShell | medium | 91801 |
| `102314` | 8 | `T1553.004` T1553.004 | Root Certificate Installed - PowerShell | medium | 91801 |
| `102315` | 8 | `T1553.005` T1553.005 | Suspicious Invoke-Item From Mount-DiskImage | medium | 91801 |
| `102316` | 9 | `T1222` T1222 | PowerShell Set-Acl On Windows Folder - PsScript | high | 91801 |
| `102317` | 8 | `T1059.001` T1059.001 | Change PowerShell Policies to an Insecure Level - PowerShell | medium | 91801 |
| `102318` | 9 | `T1059.001` T1059.001 | Malicious ShellIntel PowerShell Commandlets | high | 91801 |
| `102319` | 8 | `T1564.004` T1564.004 | Powershell Store File In Alternate Data Stream | medium | 91801 |
| `102320` | 8 | `T1685.005` T1685.005 | Suspicious Eventlog Clear | medium | 91801 |
| `102321` | 8 | `T1685.005` T1685.005 | Suspicious Eventlog Clear | medium | 91801 |
| `102322` | 8 | `T1685.005` T1685.005 | Suspicious Eventlog Clear | medium | 91801 |
| `102323` | 8 | `T1059.001` T1059.001 | Suspicious PowerShell Download - Powershell Script | medium | 91801 |
| `102324` | 8 | `T1059.003` T1059.003 | Powershell Execute Batch Script | medium | 91801 |
| `102325` | 8 | `T1202` T1202 | Troubleshooting Pack Cmdlet Execution | medium | 91801 |
| `102326` | 8 | `T1564.006` T1564.006 | Suspicious Hyper-V Cmdlets | medium | 91801 |
| `102327` | 9 | `T1059.001` T1059.001 | Suspicious PowerShell Invocations - Generic | high | 91801 |
| `102328` | 9 | `T1059.001` T1059.001 | Suspicious PowerShell Invocations - Specific | high | 91801 |
| `102329` | 9 | `T1059.001` T1059.001 | Suspicious PowerShell Invocations - Specific | high | 91801 |
| `102330` | 9 | `T1059.001` T1059.001 | Suspicious PowerShell Invocations - Specific | high | 91801 |
| `102331` | 9 | `T1059.001` T1059.001 | Suspicious PowerShell Invocations - Specific | high | 91801 |
| `102332` | 9 | `T1059.001` T1059.001 | Suspicious PowerShell Invocations - Specific | high | 91801 |
| `102333` | 9 | `T1059.001` T1059.001 | Suspicious PowerShell Invocations - Specific | high | 91801 |
| `102334` | 8 | `T1070.003` T1070.003 | Suspicious IO.FileStream | medium | 91801 |
| `102335` | 8 | `T1059.001` T1059.001 | Potential Suspicious PowerShell Keywords | medium | 91801 |
| `102336` | 8 | `T1070.005` T1070.005 | PowerShell Deleted Mounted Share | medium | 91801 |
| `102337` | 8 | `T1036.003` T1036.003 | Suspicious Start-Process PassThru | medium | 91801 |
| `102338` | 8 | `T1553.005` T1553.005 | Suspicious Unblock-File | medium | 91801 |
| `102339` | 8 | `T1564.003` T1564.003 | Suspicious PowerShell WindowStyle Option | medium | 91801 |
| `102340` | 8 | - | PowerShell Write-EventLog Usage | medium | 91801 |
| `102341` | 8 | `T1218` T1218 | SyncAppvPublishingServer Execution to Bypass Powershell Restriction | medium | 91801 |
| `102342` | 9 | `T1685` T1685 | Tamper Windows Defender Remove-MpPreference - ScriptBlockLogging | high | 91801 |
| `102343` | 9 | `T1685` T1685 | Tamper Windows Defender - ScriptBlockLogging | high | 91801 |
| `102344` | 8 | `T1070.006` T1070.006 | Powershell Timestomp | medium | 91801 |
| `102345` | 8 | `T1059.001` T1059.001 | Usage Of Web Request Commands And Cmdlets - ScriptBlock | medium | 91801 |
| `102346` | 8 | - | Potentially Suspicious Call To Win32_NTEventlogFile Class - PSScript | medium | 91801 |
| `102347` | 8 | `T1218.007` T1218.007 | PowerShell WMI Win32_Product Install MSI | medium | 91801 |
| `102348` | 9 | `T1059.001` T1059.001 | Potential WinAPI Calls Via PowerShell Scripts | high | 91801 |
| `102349` | 9 | `T1059.001` T1059.001 | Potential WinAPI Calls Via PowerShell Scripts | high | 91801 |
| `102350` | 9 | `T1059.001` T1059.001 | Potential WinAPI Calls Via PowerShell Scripts | high | 91801 |
| `102351` | 9 | `T1059.001` T1059.001 | Potential WinAPI Calls Via PowerShell Scripts | high | 91801 |
| `102352` | 8 | `T1685` T1685 | Windows Defender Exclusions Added - PowerShell | medium | 91801 |
| `102353` | 8 | `T1686.003` T1686.003 | Windows Firewall Profile Disabled | medium | 91801 |
| `102354` | 8 | `T1047` T1047 | WMIC Unquoted Services Path Lookup - PowerShell | medium | 91801 |
| `102355` | 9 | `T1047` T1047 | WMImplant Hack Tool | high | 91801 |
| `102356` | 8 | `T1553.004` T1553.004 | Suspicious X509Enrollment - Ps Script | medium | 91801 |
| `102357` | 8 | `T1059.001` T1059.001 | Powershell XML Execute Command | medium | 91801 |
| `102358` | 9 | `T1218.003` T1218.003 | CMSTP Execution Process Access | high | 61612 |
| `102359` | 13 | `T1106` T1106 | HackTool - CobaltStrike BOF Injection Pattern | high | 61612 |
| `102360` | 12 | `T1106` T1106 | HackTool - HandleKatz Duplicating LSASS Handle | high | 61612 |
| `102361` | 9 | `T1204.002` T1204.002 | HackTool - LittleCorporal Generated Maldoc Injection | high | 61612 |
| `102362` | 9 | `T1685.001` T1685.001 | HackTool - SysmonEnte Execution | high | 61612 |
| `102363` | 8 | `T1106` T1106 | Potential Direct Syscall of NtOpenProcess | medium | 61612 |
| `102364` | 9 | `T1685.001` T1685.001 | Suspicious Svchost Process Access | high | 61612 |
| `102365` | 9 | `T1685` T1685 | Suspicious Process Access of MsMpEng by WerFaultSecure - EDR-Freeze | high | 61612 |
| `102366` | 8 | - | Potential DLL Injection Via AccCheckConsole | medium | 61603 |
| `102367` | 9 | `T1218` T1218 | Suspicious AddinUtil.EXE CommandLine Execution | high | 61603 |
| `102368` | 8 | `T1218` T1218 | Uncommon Child Process Of AddinUtil.EXE | medium | 61603 |
| `102369` | 8 | `T1218` T1218 | Uncommon AddinUtil.EXE CommandLine Execution | medium | 61603 |
| `102370` | 8 | `T1218` T1218 | AddinUtil.EXE Execution From Uncommon Directory | medium | 61603 |
| `102371` | 9 | `T1003.001` T1003.001 | Potential Adplus.EXE Abuse | high | 61603 |
| `102372` | 8 | `T1218` T1218 | AgentExecutor PowerShell Execution | medium | 61603 |
| `102373` | 9 | `T1218` T1218 | Suspicious AgentExecutor PowerShell Execution | high | 61603 |
| `102374` | 9 | `T1685` T1685 | Windows AMSI Related Registry Tampering Via CommandLine | high | 61603 |
| `102375` | 8 | `T1218` T1218 | Uncommon Child Process Of Appvlp.EXE | medium | 61603 |
| `102376` | 9 | `T1059` Command and Scripting Interpreter | Suspicious ArcSOC.exe Child Process | high | 61603 |
| `102377` | 8 | `T1127` T1127 | AspNetCompiler Execution | medium | 61603 |
| `102378` | 9 | `T1127` T1127 | Suspicious Child Process of AspNetCompiler | high | 61603 |
| `102379` | 9 | `T1127` T1127 | Potentially Suspicious ASP.NET Compilation Via AspNetCompiler | high | 61603 |
| `102380` | 8 | `T1218` T1218 | Uncommon  Assistive Technology Applications Execution Via AtBroker.EXE | medium | 61603 |
| `102381` | 8 | `T1564.001` T1564.001 | Hiding Files with Attrib.exe | medium | 61603 |
| `102382` | 9 | `T1564.001` T1564.001 | Set Suspicious Files as System Files Using Attrib.EXE | high | 61603 |
| `102383` | 9 | `T1685.001` T1685.001 | Audit Policy Tampering Via NT Resource Kit Auditpol | high | 61603 |
| `102384` | 9 | `T1685.001` T1685.001 | Audit Policy Tampering Via Auditpol | high | 61603 |
| `102385` | 9 | `T1685.001` T1685.001 | Windows EventLog Autologger Session Registry Modification Via Comma... | high | 61603 |
| `102386` | 8 | `T1202` T1202 | Indirect Inline Command Execution Via Bash.EXE | medium | 61603 |
| `102387` | 8 | `T1202` T1202 | Indirect Command Execution From Script File Via Bash.EXE | medium | 61603 |
| `102388` | 8 | `T1048` T1048 | Data Export From MSSQL Table Via BCP.EXE | medium | 61603 |
| `102389` | 9 | `T1059.005` T1059.005 | Suspicious Child Process Of BgInfo.EXE | high | 61603 |
| `102390` | 8 | `T1059.005` T1059.005 | Uncommon Child Process Of BgInfo.EXE | medium | 61603 |
| `102391` | 9 | - | Chromium Browser Headless Execution To Mockbin Like Site | high | 61603 |
| `102392` | 9 | `T1036` T1036 | Suspicious Calculator Usage | high | 61603 |
| `102393` | 8 | `T1106` T1106 | Potential Binary Proxy Execution Via Cdb.EXE | medium | 61603 |
| `102394` | 8 | `T1553.004` T1553.004 | New Root Certificate Installed Via CertMgr.EXE | medium | 61603 |
| `102395` | 8 | `T1218` T1218 | DLL Loaded via CertOC.EXE | medium | 61603 |
| `102396` | 9 | `T1218` T1218 | Suspicious DLL Loaded via CertOC.EXE | high | 61603 |
| `102397` | 8 | `T1553.004` T1553.004 | New Root Certificate Installed Via Certutil.EXE | medium | 61603 |
| `102398` | 9 | `T1027` Obfuscated Files or Information | File Decoded From Base64/Hex Via Certutil.EXE | high | 61603 |
| `102399` | 8 | `T1027` Obfuscated Files or Information | File Encoded To Base64 Via Certutil.EXE | medium | 61603 |
| `102400` | 9 | `T1027` Obfuscated Files or Information | Suspicious File Encoded To Base64 Via Certutil.EXE | high | 61603 |
| `102401` | 9 | `T1027` Obfuscated Files or Information | File In Suspicious Location Encoded To Base64 Via Certutil.EXE | high | 61603 |
| `102402` | 8 | `T1027` Obfuscated Files or Information | Certificate Exported Via Certutil.EXE | medium | 61603 |
| `102403` | 9 | `T1218` T1218 | Potential NTLM Coercion Via Certutil.EXE | high | 61603 |
| `102404` | 8 | `T1036` T1036 | Suspicious CodePage Switch Via CHCP | medium | 61603 |
| `102405` | 8 | `T1070.004` T1070.004 | Greedy File Deletion Using Del | medium | 61603 |
| `102406` | 8 | `T1059` Command and Scripting Interpreter | Potential Dosfuscation Activity | medium | 61603 |
| `102407` | 8 | `T1059.003` T1059.003 | Command Line Execution with Suspicious URL and AppData Strings | medium | 61603 |
| `102408` | 8 | `T1564.003` T1564.003 | Cmd Launched with Hidden Start Flags to Suspicious Targets | medium | 61603 |
| `102409` | 9 | `T1059.001` T1059.001 | Suspicious File Execution From Internet Hosted WebDav Share | high | 61603 |
| `102410` | 9 | `T1059.001` T1059.001 | Cmd.EXE Missing Space Characters Execution Anomaly | high | 61603 |
| `102411` | 9 | `T1059.001` T1059.001 | Cmd.EXE Missing Space Characters Execution Anomaly | high | 61603 |
| `102412` | 9 | `T1059.001` T1059.001 | Cmd.EXE Missing Space Characters Execution Anomaly | high | 61603 |
| `102413` | 9 | - | NtdllPipe Like Activity Execution | high | 61603 |
| `102414` | 9 | `T1059.003` T1059.003 | Potential CommandLine Path Traversal Via Cmd.EXE | high | 61603 |
| `102415` | 8 | `T1070.004` T1070.004 | Potentially Suspicious Ping/Copy Command Combination | medium | 61603 |
| `102416` | 9 | `T1070.004` T1070.004 | Suspicious Ping/Del Command Combination | high | 61603 |
| `102417` | 8 | `T1218` T1218 | Potentially Suspicious CMD Shell Output Redirect | medium | 61603 |
| `102418` | 8 | `T1059.003` T1059.003 | Read Contents From Stdin Via Cmd.EXE | medium | 61603 |
| `102419` | 12 | `T1059` Command and Scripting Interpreter | Unusual Parent Process For Cmd.EXE | medium | 61603 |
| `102420` | 8 | `T1218` T1218 | Potential Arbitrary File Download Via Cmdl32.EXE | medium | 61603 |
| `102421` | 9 | `T1218.003` T1218.003 | CMSTP Execution Process Creation | high | 61603 |
| `102422` | 8 | `T1059.003` T1059.003 | OpenEDR Spawning Command Shell | medium | 61603 |
| `102423` | 8 | `T1059.001` T1059.001 | Powershell Executed From Headless ConHost Process | medium | 61603 |
| `102424` | 9 | `T1059.003` T1059.003 | Conhost.exe CommandLine Path Traversal | high | 61603 |
| `102425` | 8 | `T1202` T1202 | Uncommon Child Process Of Conhost.EXE | medium | 61603 |
| `102426` | 9 | `T1202` T1202 | Potentially Suspicious Child Processes Spawned by ConHost | high | 61603 |
| `102427` | 12 | `T1059` Command and Scripting Interpreter | Conhost Spawned By Uncommon Parent Process | medium | 61603 |
| `102428` | 9 | `T1685` T1685 | Windows Credential Guard Registry Tampering Via CommandLine | high | 61603 |
| `102429` | 8 | `T1027.004` T1027.004 | Dynamic .NET Compilation Via Csc.EXE | medium | 61603 |
| `102430` | 9 | `T1059.005` T1059.005 | Csc.EXE Execution Form Potentially Suspicious Parent | high | 61603 |
| `102431` | 9 | `T1127` T1127 | Suspicious Use of CSharp Interactive Console | high | 61603 |
| `102432` | 8 | - | Potential Cookies Session Hijacking | medium | 61603 |
| `102433` | 8 | - | Curl Web Request With Potential Custom User-Agent | medium | 61603 |
| `102434` | 8 | - | File Download From IP URL Via Curl.EXE | medium | 61603 |
| `102435` | 9 | - | Suspicious File Download From IP Via Curl.EXE | high | 61603 |
| `102436` | 9 | - | Suspicious File Download From File Sharing Domain Via Curl.EXE | high | 61603 |
| `102437` | 8 | - | Insecure Transfer Via Curl.EXE | medium | 61603 |
| `102438` | 8 | - | Insecure Proxy/DOH Transfer Via Curl.EXE | medium | 61603 |
| `102439` | 8 | - | Local File Read Using Curl.EXE | medium | 61603 |
| `102440` | 9 | `T1216` T1216 | Suspicious CustomShellHost Execution | high | 61603 |
| `102441` | 8 | `T1218` T1218 | Uncommon Child Process Of Defaultpack.EXE | medium | 61603 |
| `102442` | 9 | `T1685` T1685 | PowerShell Defender Threat Severity Default Action Set to 'Allow' o... | high | 61603 |
| `102443` | 9 | `T1685` T1685 | Windows Defender Context Menu Removed | high | 61603 |
| `102444` | 8 | `T1218` T1218 | DeviceCredentialDeployment Execution | medium | 61603 |
| `102445` | 8 | `T1218` T1218 | Arbitrary MSI Download Via Devinit.EXE | medium | 61603 |
| `102446` | 8 | - | Potentially Suspicious Child Process Of ClickOnce Application | medium | 61603 |
| `102447` | 8 | `T1218` T1218 | Potentially Suspicious Child Process Of DiskShadow.EXE | medium | 61603 |
| `102448` | 8 | `T1218` T1218 | Diskshadow Script Mode - Uncommon Script Extension Execution | medium | 61603 |
| `102449` | 8 | `T1218` T1218 | Diskshadow Script Mode - Execution From Potential Suspicious Location | medium | 61603 |
| `102450` | 8 | `T1685` T1685 | Dism Remove Online Package | medium | 61603 |
| `102451` | 8 | `T1685` T1685 | Dism Remove Online Package | medium | 61603 |
| `102452` | 8 | `T1218` T1218 | Potential Application Whitelisting Bypass via Dnx.EXE | medium | 61603 |
| `102453` | 8 | `T1218` T1218 | Arbitrary DLL or Csproj Code Execution Via Dotnet.EXE | medium | 61603 |
| `102454` | 8 | `T1218` T1218 | Binary Proxy Execution Via Dotnet-Trace.EXE | medium | 61603 |
| `102455` | 8 | `T1218` T1218 | Process Memory Dump Via Dotnet-Dump | medium | 61603 |
| `102456` | 8 | `T1218` T1218 | Potentially Over Permissive Permissions Granted Using Dsacls.EXE | medium | 61603 |
| `102457` | 8 | `T1218` T1218 | Potential Password Spraying Attempt Using Dsacls.EXE | medium | 61603 |
| `102458` | 8 | `T1218` T1218 | New Capture Session Launched Via DXCap.EXE | medium | 61603 |
| `102459` | 8 | `T1218` T1218 | Potentially Suspicious Cabinet File Expansion | medium | 61603 |
| `102460` | 8 | `T1036` T1036 | Explorer Process Tree Break | medium | 61603 |
| `102461` | 8 | `T1036` T1036 | Explorer Process Tree Break | medium | 61603 |
| `102462` | 8 | `T1036` T1036 | Findstr Launching .lnk File | medium | 61603 |
| `102463` | 8 | `T1070` Indicator Removal | Filter Driver Unloaded Via Fltmc.EXE | medium | 61603 |
| `102464` | 9 | `T1070` Indicator Removal | Sysmon Driver Unloaded Via Fltmc.EXE | high | 61603 |
| `102465` | 9 | `T1036` T1036 | Forfiles.EXE Child Process Masquerading | high | 61603 |
| `102466` | 8 | `T1059` Command and Scripting Interpreter | Forfiles Command Execution | medium | 61603 |
| `102467` | 9 | - | Uncommon FileSystem Load Attempt By Format.com | high | 61603 |
| `102468` | 8 | `T1059` Command and Scripting Interpreter | Use of FSharp Interpreters | medium | 61603 |
| `102469` | 8 | `T1059` Command and Scripting Interpreter | Use of FSharp Interpreters | medium | 61603 |
| `102470` | 8 | `T1059` Command and Scripting Interpreter | Potentially Suspicious NTFS Symlink Behavior Modification | medium | 61603 |
| `102471` | 8 | `T1059` Command and Scripting Interpreter | Potential Arbitrary Command Execution Via FTP.EXE | medium | 61603 |
| `102472` | 8 | `T1593.003` T1593.003 | Suspicious Git Clone | medium | 61603 |
| `102473` | 9 | - | Potentially Suspicious GoogleUpdate Child Process | high | 61603 |
| `102474` | 8 | - | File Decryption Using Gpg4win | medium | 61603 |
| `102475` | 8 | - | File Encryption Using Gpg4win | medium | 61603 |
| `102476` | 9 | - | File Encryption/Decryption Via Gpg4win From Suspicious Locations | high | 61603 |
| `102477` | 8 | - | Arbitrary Binary Execution Using GUP Utility | medium | 61603 |
| `102478` | 9 | `T1218.001` T1218.001 | Remote CHM File Download/Execution Via HH.EXE | high | 61603 |
| `102479` | 9 | `T1047` T1047 | HTML Help HH.EXE Suspicious Child Process | high | 61603 |
| `102480` | 9 | `T1047` T1047 | Suspicious HH.EXE Execution | high | 61603 |
| `102481` | 9 | `T1218.011` T1218.011 | HackTool - F-Secure C3 Load by Rundll32 | high | 61603 |
| `102482` | 13 | `T1059.003` T1059.003 | Operator Bloopers Cobalt Strike Commands | high | 61603 |
| `102483` | 13 | `T1059.003` T1059.003 | Operator Bloopers Cobalt Strike Modules | high | 61603 |
| `102484` | 13 | `T1218.011` T1218.011 | CobaltStrike Load by Rundll32 | high | 61603 |
| `102485` | 13 | `T1059` Command and Scripting Interpreter | Potential CobaltStrike Process Patterns | high | 61603 |
| `102486` | 13 | `T1059` Command and Scripting Interpreter | Potential CobaltStrike Process Patterns | high | 61603 |
| `102487` | 13 | `T1059` Command and Scripting Interpreter | Potential CobaltStrike Process Patterns | high | 61603 |
| `102488` | 13 | `T1059` Command and Scripting Interpreter | Potential CobaltStrike Process Patterns | high | 61603 |
| `102489` | 9 | `T1059.001` T1059.001 | HackTool - Covenant PowerShell Launcher | high | 61603 |
| `102490` | 9 | `T1059.001` T1059.001 | HackTool - Covenant PowerShell Launcher | high | 61603 |
| `102491` | 9 | `T1047` T1047 | HackTool - CrackMapExec Execution | high | 61603 |
| `102492` | 9 | `T1047` T1047 | HackTool - CrackMapExec Execution | high | 61603 |
| `102493` | 9 | `T1047` T1047 | HackTool - CrackMapExec Execution | high | 61603 |
| `102494` | 9 | `T1047` T1047 | HackTool - CrackMapExec Execution | high | 61603 |
| `102495` | 9 | `T1047` T1047 | HackTool - CrackMapExec Execution | high | 61603 |
| `102496` | 9 | `T1047` T1047 | HackTool - CrackMapExec Execution | high | 61603 |
| `102497` | 9 | `T1047` T1047 | HackTool - CrackMapExec Execution | high | 61603 |
| `102498` | 9 | `T1059.001` T1059.001 | HackTool - CrackMapExec PowerShell Obfuscation | high | 61603 |
| `102499` | 9 | `T1685` T1685 | Hacktool - EDR-Freeze Execution | high | 61603 |
| `102500` | 9 | `T1685` T1685 | Hacktool - EDR-Freeze Execution | high | 61603 |
| `102501` | 9 | `T1685` T1685 | HackTool - EDRSilencer Execution | high | 61603 |
| `102502` | 9 | `T1685` T1685 | HackTool - EDRSilencer Execution | high | 61603 |
| `102503` | 9 | `T1685` T1685 | HackTool - EDRSilencer Execution | high | 61603 |
| `102504` | 12 | `T1059.001` T1059.001 | HackTool - Empire PowerShell Launch Parameters | high | 61603 |
| `102505` | 9 | - | HackTool - GMER Rootkit Detector and Remover Execution | high | 61603 |
| `102506` | 9 | - | HackTool - GMER Rootkit Detector and Remover Execution | high | 61603 |
| `102507` | 9 | `T1047` T1047 | HackTool - Potential Impacket Lateral Movement Activity | high | 61603 |
| `102508` | 9 | `T1047` T1047 | HackTool - Potential Impacket Lateral Movement Activity | high | 61603 |
| `102509` | 9 | `T1027` Obfuscated Files or Information | Invoke-Obfuscation CLIP+ Launcher | high | 61603 |
| `102510` | 9 | `T1027` Obfuscated Files or Information | Invoke-Obfuscation Obfuscated IEX Invocation | high | 61603 |
| `102511` | 9 | `T1027` Obfuscated Files or Information | Invoke-Obfuscation Obfuscated IEX Invocation | high | 61603 |
| `102512` | 9 | `T1027` Obfuscated Files or Information | Invoke-Obfuscation Obfuscated IEX Invocation | high | 61603 |
| `102513` | 9 | `T1027` Obfuscated Files or Information | Invoke-Obfuscation Obfuscated IEX Invocation | high | 61603 |
| `102514` | 9 | `T1027` Obfuscated Files or Information | Invoke-Obfuscation Obfuscated IEX Invocation | high | 61603 |
| `102515` | 9 | `T1027` Obfuscated Files or Information | Invoke-Obfuscation Obfuscated IEX Invocation | high | 61603 |
| `102516` | 9 | `T1027` Obfuscated Files or Information | Invoke-Obfuscation Obfuscated IEX Invocation | high | 61603 |
| `102517` | 9 | `T1027` Obfuscated Files or Information | Invoke-Obfuscation STDIN+ Launcher | high | 61603 |
| `102518` | 9 | `T1027` Obfuscated Files or Information | Invoke-Obfuscation VAR+ Launcher | high | 61603 |
| `102519` | 8 | `T1027` Obfuscated Files or Information | Invoke-Obfuscation COMPRESS OBFUSCATION | medium | 61603 |
| `102520` | 9 | `T1027` Obfuscated Files or Information | Invoke-Obfuscation Via Stdin | high | 61603 |
| `102521` | 9 | `T1027` Obfuscated Files or Information | Invoke-Obfuscation Via Use Clip | high | 61603 |
| `102522` | 9 | `T1027` Obfuscated Files or Information | Invoke-Obfuscation Via Use MSHTA | high | 61603 |
| `102523` | 9 | `T1027` Obfuscated Files or Information | Invoke-Obfuscation VAR++ LAUNCHER OBFUSCATION | high | 61603 |
| `102524` | 8 | `T1059.003` T1059.003 | HackTool - Jlaive In-Memory Assembly Execution | medium | 61603 |
| `102525` | 9 | `T1059.003` T1059.003 | HackTool - Koadic Execution | high | 61603 |
| `102526` | 9 | `T1082` System Information Discovery | HackTool - PCHunter Execution | high | 61603 |
| `102527` | 9 | `T1082` System Information Discovery | HackTool - PCHunter Execution | high | 61603 |
| `102528` | 9 | `T1082` System Information Discovery | HackTool - PCHunter Execution | high | 61603 |
| `102529` | 9 | `T1082` System Information Discovery | HackTool - PCHunter Execution | high | 61603 |
| `102530` | 12 | `T1053.005` T1053.005 | HackTool - Default PowerSploit/Empire Scheduled Task Creation | high | 61603 |
| `102531` | 9 | `T1685` T1685 | HackTool - PowerTool Execution | high | 61603 |
| `102532` | 9 | `T1685` T1685 | HackTool - PowerTool Execution | high | 61603 |
| `102533` | 9 | `T1587` T1587 | HackTool - PurpleSharp Execution | high | 61603 |
| `102534` | 9 | `T1587` T1587 | HackTool - PurpleSharp Execution | high | 61603 |
| `102535` | 9 | `T1587` T1587 | HackTool - PurpleSharp Execution | high | 61603 |
| `102536` | 9 | `T1106` T1106 | HackTool - RedMimicry Winnti Playbook Execution | high | 61603 |
| `102537` | 9 | `T1685.001` T1685.001 | HackTool - SharpEvtMute Execution | high | 61603 |
| `102538` | 9 | `T1685.001` T1685.001 | HackTool - SharpEvtMute Execution | high | 61603 |
| `102539` | 9 | `T1685.001` T1685.001 | HackTool - SharpEvtMute Execution | high | 61603 |
| `102540` | 9 | `T1210` T1210 | HackTool - SharpWSUS/WSUSpendu Execution | high | 61603 |
| `102541` | 9 | `T1059` Command and Scripting Interpreter | HackTool - Sliver C2 Implant Activity Pattern | high | 61603 |
| `102542` | 9 | `T1059` Command and Scripting Interpreter | HackTool - Stracciatella Execution | high | 61603 |
| `102543` | 9 | `T1059` Command and Scripting Interpreter | HackTool - Stracciatella Execution | high | 61603 |
| `102544` | 9 | `T1059` Command and Scripting Interpreter | HackTool - Stracciatella Execution | high | 61603 |
| `102545` | 9 | `T1059` Command and Scripting Interpreter | HackTool - Stracciatella Execution | high | 61603 |
| `102546` | 8 | `T1218` T1218 | Suspicious ZipExec Execution | medium | 61603 |
| `102547` | 9 | `T1685` T1685 | Hypervisor-protected Code Integrity (HVCI) Related Registry Tamperi... | high | 61603 |
| `102548` | 8 | `T1036` T1036 | Potential Fake Instance Of Hxtsr.EXE Executed | medium | 61603 |
| `102549` | 8 | `T1564.001` T1564.001 | Use Icacls to Hide File to Everyone | medium | 61603 |
| `102550` | 9 | `T1218` T1218 | Self Extracting Package Creation Via Iexpress.EXE From Potentially ... | high | 61603 |
| `102551` | 9 | `T1685.001` T1685.001 | Disable Windows IIS HTTP Logging | high | 61603 |
| `102552` | 8 | - | Suspicious IIS URL GlobalRules Rewrite Via AppCmd | medium | 61603 |
| `102553` | 8 | `T1070` Indicator Removal | IIS WebServer Log Deletion via CommandLine Utilities | medium | 61603 |
| `102554` | 8 | `T1127` T1127 | C# IL Code Compilation Via Ilasm.EXE | medium | 61603 |
| `102555` | 9 | - | ImagingDevices Unusual Parent/Child Processes | high | 61603 |
| `102556` | 9 | - | ImagingDevices Unusual Parent/Child Processes | high | 61603 |
| `102557` | 9 | `T1218` T1218 | Arbitrary File Download Via IMEWDBLD.EXE | high | 61603 |
| `102558` | 8 | `T1218` T1218 | InfDefaultInstall.exe .inf Execution | medium | 61603 |
| `102559` | 8 | `T1218` T1218 | File Download Via InstallUtil.EXE | medium | 61603 |
| `102560` | 8 | - | Suspicious Execution of InstallUtil Without Log | medium | 61603 |
| `102561` | 8 | `T1203` T1203 | Java Running with Remote Debugging | medium | 61603 |
| `102562` | 9 | `T1127` T1127 | Kavremover Dropped Binary LOLBIN Usage | high | 61603 |
| `102563` | 8 | - | Computer Password Change Via Ksetup.EXE | medium | 61603 |
| `102564` | 8 | - | Logged-On User Password Change Via Ksetup.EXE | medium | 61603 |
| `102565` | 8 | `T1218` T1218 | Uncommon Link.EXE Parent Process | medium | 61603 |
| `102566` | 8 | - | Rebuild Performance Counter Values Via Lodctr.EXE | medium | 61603 |
| `102567` | 9 | `T1685` T1685 | Suspicious Windows Trace ETW Session Tamper Via Logman.EXE | high | 61603 |
| `102568` | 9 | `T1218` T1218 | Devtoolslauncher.exe Executes Specified Binary | high | 61603 |
| `102569` | 8 | `T1564.004` T1564.004 | Suspicious Diantz Alternate Data Stream Execution | medium | 61603 |
| `102570` | 8 | `T1564.004` T1564.004 | Suspicious Extrac32 Alternate Data Stream Execution | medium | 61603 |
| `102571` | 8 | `T1218` T1218 | Gpscript Execution | medium | 61603 |
| `102572` | 8 | `T1218` T1218 | Ie4uinit Lolbin Use From Invalid Path | medium | 61603 |
| `102573` | 8 | `T1216.001` T1216.001 | Launch-VsDevShell.PS1 Proxy Execution | medium | 61603 |
| `102574` | 9 | `T1216` T1216 | Potential Manage-bde.wsf Abuse To Proxy Execution | high | 61603 |
| `102575` | 9 | `T1218` T1218 | MpiExec Lolbin | high | 61603 |
| `102576` | 8 | `T1218` T1218 | Execute Files with Msdeploy.exe | medium | 61603 |
| `102577` | 8 | `T1059` Command and Scripting Interpreter | Use of OpenConsole | medium | 61603 |
| `102578` | 9 | `T1218` T1218 | OpenWith.exe Executes Specified Binary | high | 61603 |
| `102579` | 8 | `T1059` Command and Scripting Interpreter | Use of Pcalua For Execution | medium | 61603 |
| `102580` | 9 | `T1218` T1218 | Execute Pcwrun.EXE To Leverage Follina | high | 61603 |
| `102581` | 8 | `T1218.011` T1218.011 | Code Execution via Pcwutl.dll | medium | 61603 |
| `102582` | 8 | `T1059.001` T1059.001 | Execute Code with Pester.bat as Parent | medium | 61603 |
| `102583` | 8 | `T1059.001` T1059.001 | Execute Code with Pester.bat | medium | 61603 |
| `102584` | 8 | `T1216.001` T1216.001 | Pubprn.vbs Proxy Execution | medium | 61603 |
| `102585` | 8 | `T1218` T1218 | DLL Execution via Rasautou.exe | medium | 61603 |
| `102586` | 8 | `T1218` T1218 | REGISTER_APP.VBS Proxy Execution | medium | 61603 |
| `102587` | 8 | `T1127` T1127 | Use of Remote.exe | medium | 61603 |
| `102588` | 8 | `T1127` T1127 | Use of Remote.exe | medium | 61603 |
| `102589` | 8 | `T1218` T1218 | Lolbin Runexehelper Use As Proxy | medium | 61603 |
| `102590` | 8 | `T1059` Command and Scripting Interpreter | Suspicious Runscripthelper.exe | medium | 61603 |
| `102591` | 8 | `T1218` T1218 | Use of Scriptrunner.exe | medium | 61603 |
| `102592` | 8 | `T1218` T1218 | Use Of The SFTP.EXE Binary As A LOLBIN | medium | 61603 |
| `102593` | 8 | `T1218` T1218 | SyncAppvPublishingServer Execute Arbitrary PowerShell Code | medium | 61603 |
| `102594` | 8 | `T1218` T1218 | SyncAppvPublishingServer VBS Execute Arbitrary PowerShell Code | medium | 61603 |
| `102595` | 8 | `T1127` T1127 | Use of TTDInject.exe | medium | 61603 |
| `102596` | 8 | `T1127` T1127 | Use of TTDInject.exe | medium | 61603 |
| `102597` | 8 | `T1218` T1218 | Lolbin Unregmp2.exe Use As Proxy | medium | 61603 |
| `102598` | 8 | `T1216` T1216 | UtilityFunctions.ps1 Proxy Dll | medium | 61603 |
| `102599` | 9 | `T1027.004` T1027.004 | Visual Basic Command Line Compiler Usage | high | 61603 |
| `102600` | 8 | `T1218` T1218 | Use of VisualUiaVerifyNative.exe | medium | 61603 |
| `102601` | 8 | `T1218` T1218 | Use of VisualUiaVerifyNative.exe | medium | 61603 |
| `102602` | 8 | `T1127` T1127 | Use of VSIISExeLauncher.exe | medium | 61603 |
| `102603` | 8 | `T1127` T1127 | Use of Wfc.exe | medium | 61603 |
| `102604` | 8 | `T1127` T1127 | Use of Wfc.exe | medium | 61603 |
| `102605` | 8 | `T1218` T1218 | Potential Register_App.Vbs LOLScript Abuse | medium | 61603 |
| `102606` | 8 | `T1689` T1689 | LSA PPL Protection Setting Modification via CommandLine | medium | 61603 |
| `102607` | 8 | `T1127` T1127 | Potential Mftrace.EXE Abuse | medium | 61603 |
| `102608` | 9 | `T1021.003` T1021.003 | MMC20 Lateral Movement | high | 61603 |
| `102609` | 9 | `T1204.002` T1204.002 | MMC Executing Files with Reversed Extensions Using RTLO Abuse | high | 61603 |
| `102610` | 8 | `T1036` T1036 | CodePage Modification Via MODE.COM To Russian Language | medium | 61603 |
| `102611` | 9 | `T1218` T1218 | Potential Suspicious Mofcomp Execution | high | 61603 |
| `102612` | 9 | `T1685` T1685 | Windows Defender Definition Files Removed | high | 61603 |
| `102613` | 8 | - | Suspicious Msbuild Execution By Uncommon Parent Process | medium | 61603 |
| `102614` | 9 | `T1218` T1218 | MSDT Execution Via Answer File | high | 61603 |
| `102615` | 9 | `T1202` T1202 | Potential Arbitrary Command Execution Using Msdt.EXE | high | 61603 |
| `102616` | 8 | `T1202` T1202 | Suspicious Cabinet File Execution Via Msdt.EXE | medium | 61603 |
| `102617` | 9 | `T1036` T1036 | Suspicious MSDT Parent Process | high | 61603 |
| `102618` | 8 | `T1218` T1218 | Arbitrary File Download Via MSEDGE_PROXY.EXE | medium | 61603 |
| `102619` | 9 | `T1218.005` T1218.005 | Remotely Hosted HTA File Executed Via Mshta.EXE | high | 61603 |
| `102620` | 8 | `T1059` Command and Scripting Interpreter | Wscript Shell Run In CommandLine | medium | 61603 |
| `102621` | 9 | `T1218.005` T1218.005 | Suspicious JavaScript Execution Via Mshta.EXE | high | 61603 |
| `102622` | 9 | `T1218.005` T1218.005 | Potential LethalHTA Technique Execution | high | 61603 |
| `102623` | 9 | `T1218.005` T1218.005 | Suspicious MSHTA Child Process | high | 61603 |
| `102624` | 9 | `T1140` T1140 | MSHTA Execution with Suspicious File Extensions | high | 61603 |
| `102625` | 9 | `T1106` T1106 | Suspicious Mshta.EXE Execution Patterns | high | 61603 |
| `102626` | 8 | `T1218.007` T1218.007 | DllUnregisterServer Function Call Via Msiexec.EXE | medium | 61603 |
| `102627` | 8 | `T1218.007` T1218.007 | Suspicious MsiExec Embedding Parent | medium | 61603 |
| `102628` | 8 | `T1218.007` T1218.007 | Suspicious Msiexec Execute Arbitrary DLL | medium | 61603 |
| `102629` | 8 | `T1218.007` T1218.007 | Msiexec Quiet Installation | medium | 61603 |
| `102630` | 8 | `T1218.007` T1218.007 | Suspicious Msiexec Quiet Install From Remote Location | medium | 61603 |
| `102631` | 9 | `T1036.005` T1036.005 | Potential MsiExec Masquerading | high | 61603 |
| `102632` | 8 | `T1218` T1218 | Arbitrary File Download Via MSOHTMED.EXE | medium | 61603 |
| `102633` | 8 | `T1218` T1218 | Arbitrary File Download Via MSPUB.EXE | medium | 61603 |
| `102634` | 8 | `T1059.001` T1059.001 | Detection of PowerShell Execution via Sqlps.exe | medium | 61603 |
| `102635` | 8 | `T1059.001` T1059.001 | SQL Client Tools PowerShell Session Detection | medium | 61603 |
| `102636` | 8 | `T1220` T1220 | Msxsl.EXE Execution | medium | 61603 |
| `102637` | 9 | `T1220` T1220 | Remote XSL Execution Via Msxsl.EXE | high | 61603 |
| `102638` | 8 | `T1686.003` T1686.003 | New Firewall Rule Added Via Netsh.EXE | medium | 61603 |
| `102639` | 9 | `T1686.003` T1686.003 | Suspicious Program Location Whitelisted In Firewall Via Netsh.EXE | high | 61603 |
| `102640` | 9 | `T1686.003` T1686.003 | RDP Connection Allowed Via Netsh.EXE | high | 61603 |
| `102641` | 8 | `T1686.003` T1686.003 | Firewall Rule Deleted Via Netsh.EXE | medium | 61603 |
| `102642` | 8 | `T1686.003` T1686.003 | Firewall Disabled via Netsh.EXE | medium | 61603 |
| `102643` | 8 | `T1686.003` T1686.003 | Netsh Allow Group Policy on Microsoft Defender Firewall | medium | 61603 |
| `102644` | 8 | - | Firewall Rule Update Via Netsh.EXE | medium | 61603 |
| `102645` | 9 | `T1127` T1127 | Potential Arbitrary Code Execution Via Node.EXE | high | 61603 |
| `102646` | 8 | `T1127` T1127 | Node Process Executions | medium | 61603 |
| `102647` | 8 | - | Nslookup PowerShell Download Cradle - ProcessCreation | medium | 61603 |
| `102648` | 8 | `T1218.008` T1218.008 | Driver/DLL Installation Via Odbcconf.EXE | medium | 61603 |
| `102649` | 9 | `T1218.008` T1218.008 | Suspicious Driver/DLL Installation Via Odbcconf.EXE | high | 61603 |
| `102650` | 9 | `T1218.008` T1218.008 | Odbcconf.EXE Suspicious DLL Location | high | 61603 |
| `102651` | 8 | `T1218.008` T1218.008 | New DLL Registered Via Odbcconf.EXE | medium | 61603 |
| `102652` | 9 | `T1218.008` T1218.008 | Potentially Suspicious DLL Registered Via Odbcconf.EXE | high | 61603 |
| `102653` | 8 | `T1218.008` T1218.008 | Response File Execution Via Odbcconf.EXE | medium | 61603 |
| `102654` | 9 | `T1218.008` T1218.008 | Suspicious Response File Execution Via Odbcconf.EXE | high | 61603 |
| `102655` | 8 | `T1218.008` T1218.008 | Uncommon Child Process Spawned By Odbcconf.EXE | medium | 61603 |
| `102656` | 9 | `T1202` T1202 | Potential Arbitrary File Download Using Office Application | high | 61603 |
| `102657` | 9 | `T1202` T1202 | Potentially Suspicious Office Document Executed From Trusted Location | high | 61603 |
| `102658` | 9 | `T1218.001` T1218.001 | OneNote.EXE Execution of Malicious Embedded Scripts | high | 61603 |
| `102659` | 9 | `T1059` Command and Scripting Interpreter | Outlook EnableUnsafeClientMailRules Setting Enabled | high | 61603 |
| `102660` | 9 | `T1204.002` T1204.002 | Suspicious Outlook Child Process | high | 61603 |
| `102661` | 9 | `T1059` Command and Scripting Interpreter | Suspicious Remote Child Process From Outlook | high | 61603 |
| `102662` | 9 | `T1204.002` T1204.002 | Suspicious Binary In User Directory Spawned From Office Application | high | 61603 |
| `102663` | 9 | `T1047` T1047 | Suspicious Microsoft Office Child Process | high | 61603 |
| `102664` | 8 | `T1202` T1202 | Potential Arbitrary DLL Load Using Winword | medium | 61603 |
| `102665` | 8 | `T1218` T1218 | Potential Mpclient.DLL Sideloading Via OfflineScannerShell.EXE Exec... | medium | 61603 |
| `102666` | 8 | `T1072` T1072 | PDQ Deploy Remote Adminstartion Tool Execution | medium | 61603 |
| `102667` | 8 | `T1072` T1072 | PDQ Deploy Remote Adminstartion Tool Execution | medium | 61603 |
| `102668` | 8 | `T1072` T1072 | PDQ Deploy Remote Adminstartion Tool Execution | medium | 61603 |
| `102669` | 8 | `T1072` T1072 | PDQ Deploy Remote Adminstartion Tool Execution | medium | 61603 |
| `102670` | 8 | - | Potentially Suspicious Execution Of PDQDeployRunner | medium | 61603 |
| `102671` | 8 | `T1059` Command and Scripting Interpreter | Perl Inline Command Execution | medium | 61603 |
| `102672` | 8 | `T1059` Command and Scripting Interpreter | Php Inline Command Execution | medium | 61603 |
| `102673` | 9 | `T1140` T1140 | Ping Hex IP | high | 61603 |
| `102674` | 8 | - | Suspicious Powercfg Execution To Change Lock Screen Timeout | medium | 61603 |
| `102675` | 9 | - | AADInternals PowerShell Cmdlets Execution - ProccessCreation | high | 61603 |
| `102676` | 8 | - | Add Windows Capability Via PowerShell Cmdlet | medium | 61603 |
| `102677` | 9 | `T1685` T1685 | Potential AMSI Bypass Via .NET Reflection | high | 61603 |
| `102678` | 9 | `T1685` T1685 | Potential AMSI Bypass Via .NET Reflection | high | 61603 |
| `102679` | 8 | `T1685` T1685 | Potential AMSI Bypass Using NULL Bits | medium | 61603 |
| `102680` | 9 | `T1059.001` T1059.001 | Suspicious Encoded PowerShell Command Line | high | 61603 |
| `102681` | 9 | `T1059.001` T1059.001 | Suspicious PowerShell Encoded Command Patterns | high | 61603 |
| `102682` | 9 | - | Suspicious Obfuscated PowerShell Code | high | 61603 |
| `102683` | 9 | `T1140` T1140 | PowerShell Base64 Encoded FromBase64String Cmdlet | high | 61603 |
| `102684` | 9 | `T1140` T1140 | PowerShell Base64 Encoded FromBase64String Cmdlet | high | 61603 |
| `102685` | 9 | `T1059.001` T1059.001 | Malicious Base64 Encoded PowerShell Keywords in Command Lines | high | 61603 |
| `102686` | 9 | `T1059.001` T1059.001 | PowerShell Base64 Encoded IEX Cmdlet | high | 61603 |
| `102687` | 9 | `T1059.001` T1059.001 | PowerShell Base64 Encoded IEX Cmdlet | high | 61603 |
| `102688` | 9 | `T1059.001` T1059.001 | PowerShell Base64 Encoded Invoke Keyword | high | 61603 |
| `102689` | 9 | `T1685` T1685 | Powershell Base64 Encoded MpPreference Cmdlet | high | 61603 |
| `102690` | 9 | `T1685` T1685 | Powershell Base64 Encoded MpPreference Cmdlet | high | 61603 |
| `102691` | 9 | `T1059.001` T1059.001 | PowerShell Base64 Encoded Reflective Assembly Load | high | 61603 |
| `102692` | 9 | `T1059.001` T1059.001 | Suspicious Encoded And Obfuscated Reflection Assembly Load Function... | high | 61603 |
| `102693` | 9 | `T1059.001` T1059.001 | PowerShell Base64 Encoded WMI Classes | high | 61603 |
| `102694` | 8 | `T1216` T1216 | Potential Process Execution Proxy Via CL_Invocation.ps1 | medium | 61603 |
| `102695` | 8 | `T1216` T1216 | Assembly Loading Via CL_LoadAssembly.ps1 | medium | 61603 |
| `102696` | 8 | `T1216` T1216 | Potential Script Proxy Execution Via CL_Mutexverifiers.ps1 | medium | 61603 |
| `102697` | 8 | `T1027` Obfuscated Files or Information | ConvertTo-SecureString Cmdlet Usage Via CommandLine | medium | 61603 |
| `102698` | 9 | `T1027` Obfuscated Files or Information | Potential PowerShell Obfuscation Via Reversed Commands | high | 61603 |
| `102699` | 9 | `T1027` Obfuscated Files or Information | Potential PowerShell Command Line Obfuscation | high | 61603 |
| `102700` | 9 | `T1027.010` T1027.010 | Obfuscated PowerShell MSI Install via WindowsInstaller COM | high | 61603 |
| `102701` | 8 | `T1059.001` T1059.001 | PowerShell MSI Install via WindowsInstaller COM From Remote Location | medium | 61603 |
| `102702` | 9 | - | PowerShell Execution With Potential Decryption Capabilities | high | 61603 |
| `102703` | 9 | `T1685` T1685 | Powershell Defender Disable Scan Feature | high | 61603 |
| `102704` | 8 | `T1685` T1685 | Powershell Defender Exclusion | medium | 61603 |
| `102705` | 9 | `T1685` T1685 | Disable Windows Defender AV Security Monitoring | high | 61603 |
| `102706` | 8 | `T1685` T1685 | Windows Firewall Disabled via PowerShell | medium | 61603 |
| `102707` | 9 | `T1685` T1685 | Disabled IE Security Features | high | 61603 |
| `102708` | 9 | `T1685` T1685 | Disabled IE Security Features | high | 61603 |
| `102709` | 9 | `T1685` T1685 | Disabled IE Security Features | high | 61603 |
| `102710` | 8 | `T1059.001` T1059.001 | Potential PowerShell Downgrade Attack | medium | 61603 |
| `102711` | 9 | `T1059.001` T1059.001 | Obfuscated PowerShell OneLiner Execution | high | 61603 |
| `102712` | 9 | `T1059` Command and Scripting Interpreter | PowerShell Download and Execution Cradles | high | 61603 |
| `102713` | 8 | `T1059.001` T1059.001 | PowerShell Download Pattern | medium | 61603 |
| `102714` | 9 | - | Potentially Suspicious File Download From File Sharing Domain Via P... | high | 61603 |
| `102715` | 9 | `T1059.001` T1059.001 | DSInternals Suspicious PowerShell Cmdlets | high | 61603 |
| `102716` | 8 | - | Potential Suspicious Windows Feature Enabled - ProcCreation | medium | 61603 |
| `102717` | 8 | `T1059.001` T1059.001 | Suspicious Execution of Powershell with Base64 | medium | 61603 |
| `102718` | 8 | `T1059.001` T1059.001 | Powershell Inline Execution From A File | medium | 61603 |
| `102719` | 9 | `T1027` Obfuscated Files or Information | Base64 Encoded PowerShell Command Detected | high | 61603 |
| `102720` | 9 | `T1059.001` T1059.001 | Suspicious PowerShell IEX Execution Patterns | high | 61603 |
| `102721` | 9 | `T1553.004` T1553.004 | Root Certificate Installed From Susp Locations | high | 61603 |
| `102722` | 8 | `T1059.001` T1059.001 | Import PowerShell Modules From Suspicious Directories - ProcCreation | medium | 61603 |
| `102723` | 8 | - | Suspicious PowerShell Invocations - Specific - ProcessCreation | medium | 61603 |
| `102724` | 8 | - | Suspicious PowerShell Invocations - Specific - ProcessCreation | medium | 61603 |
| `102725` | 8 | - | Suspicious PowerShell Invocations - Specific - ProcessCreation | medium | 61603 |
| `102726` | 8 | - | Suspicious PowerShell Invocations - Specific - ProcessCreation | medium | 61603 |
| `102727` | 8 | - | Suspicious PowerShell Invocations - Specific - ProcessCreation | medium | 61603 |
| `102728` | 8 | - | Suspicious PowerShell Invocations - Specific - ProcessCreation | medium | 61603 |
| `102729` | 13 | `T1482` T1482 | Malicious PowerShell Commandlets - ProcessCreation | high | 61603 |
| `102730` | 9 | `T1059.001` T1059.001 | Potential PowerShell Obfuscation Via WCHAR/CHAR | high | 61603 |
| `102731` | 9 | `T1059.001` T1059.001 | Execution of Powershell Script in Public Folder | high | 61603 |
| `102732` | 9 | `T1218` T1218 | RemoteFXvGPUDisablement Abuse Via AtomicTestHarnesses | high | 61603 |
| `102733` | 9 | `T1685` T1685 | Tamper Windows Defender Remove-MpPreference | high | 61603 |
| `102734` | 9 | `T1059.001` T1059.001 | Potential Powershell ReverseShell Connection | high | 61603 |
| `102735` | 9 | `T1564.004` T1564.004 | Run PowerShell Script from ADS | high | 61603 |
| `102736` | 9 | `T1059` Command and Scripting Interpreter | Run PowerShell Script from Redirected Input Stream | high | 61603 |
| `102737` | 8 | `T1059.001` T1059.001 | Suspicious PowerShell Invocation From Script Engines | medium | 61603 |
| `102738` | 8 | `T1059.001` T1059.001 | Potentially Suspicious Powershell Script Execution From Temp Folder | medium | 61603 |
| `102739` | 9 | - | PowerShell Script Change Permission Via Set-Acl | high | 61603 |
| `102740` | 9 | - | PowerShell Set-Acl On Windows Folder | high | 61603 |
| `102741` | 8 | `T1059.001` T1059.001 | Change PowerShell Policies to an Insecure Level | medium | 61603 |
| `102742` | 8 | `T1685` T1685 | Service StartupType Change Via PowerShell Set-Service | medium | 61603 |
| `102743` | 9 | `T1059.001` T1059.001 | Exchange PowerShell Snap-Ins Usage | high | 61603 |
| `102744` | 9 | `T1059.001` T1059.001 | Suspicious PowerShell Download and Execute Pattern | high | 61603 |
| `102745` | 9 | `T1059.001` T1059.001 | Suspicious PowerShell Parameter Substring | high | 61603 |
| `102746` | 9 | `T1059.001` T1059.001 | Suspicious PowerShell Parent Process | high | 61603 |
| `102747` | 8 | `T1059.001` T1059.001 | PowerShell Script Run in AppData | medium | 61603 |
| `102748` | 9 | `T1027.009` T1027.009 | Powershell Token Obfuscation - Process Creation | high | 61603 |
| `102749` | 9 | `T1685` T1685 | Suspicious Uninstall of Windows Defender Feature via PowerShell | high | 61603 |
| `102750` | 9 | `T1059.001` T1059.001 | Net WebClient Casing Anomalies | high | 61603 |
| `102751` | 8 | `T1553.004` T1553.004 | Suspicious X509Enrollment - Process Creation | medium | 61603 |
| `102752` | 8 | `T1059.001` T1059.001 | Suspicious XOR Encoded PowerShell Command | medium | 61603 |
| `102753` | 8 | `T1218` T1218 | Arbitrary File Download Via PresentationHost.EXE | medium | 61603 |
| `102754` | 8 | `T1218` T1218 | XBAP Execution From Uncommon Locations Via PresentationHost.EXE | medium | 61603 |
| `102755` | 8 | `T1218` T1218 | Visual Studio NodejsTools PressAnyKey Arbitrary Binary Execution | medium | 61603 |
| `102756` | 8 | `T1218` T1218 | Abusing Print Executable | medium | 61603 |
| `102757` | 8 | `T1218` T1218 | File Download Using ProtocolHandler.exe | medium | 61603 |
| `102758` | 8 | `T1218` T1218 | Potential Provlaunch.EXE Binary Proxy Execution Abuse | medium | 61603 |
| `102759` | 9 | `T1218` T1218 | Suspicious Provlaunch.EXE Child Process | high | 61603 |
| `102760` | 8 | `T1564.003` T1564.003 | PUA - AdvancedRun Execution | medium | 61603 |
| `102761` | 8 | `T1564.003` T1564.003 | PUA - AdvancedRun Execution | medium | 61603 |
| `102762` | 8 | `T1564.003` T1564.003 | PUA - AdvancedRun Execution | medium | 61603 |
| `102763` | 9 | `T1685` T1685 | PUA - CleanWipe Execution | high | 61603 |
| `102764` | 9 | `T1685` T1685 | PUA - CleanWipe Execution | high | 61603 |
| `102765` | 9 | `T1685` T1685 | PUA - CleanWipe Execution | high | 61603 |
| `102766` | 9 | `T1685` T1685 | PUA - CleanWipe Execution | high | 61603 |
| `102767` | 9 | `T1587.001` T1587.001 | PUA - CsExec Execution | high | 61603 |
| `102768` | 9 | `T1587.001` T1587.001 | PUA - CsExec Execution | high | 61603 |
| `102769` | 9 | `T1027.005` T1027.005 | PUA - DefenderCheck Execution | high | 61603 |
| `102770` | 9 | `T1027.005` T1027.005 | PUA - DefenderCheck Execution | high | 61603 |
| `102771` | 8 | `T1569.002` T1569.002 | PUA - NirCmd Execution | medium | 61603 |
| `102772` | 8 | `T1569.002` T1569.002 | PUA - NirCmd Execution | medium | 61603 |
| `102773` | 8 | `T1569.002` T1569.002 | PUA - NirCmd Execution | medium | 61603 |
| `102774` | 9 | `T1569.002` T1569.002 | PUA - NirCmd Execution As LOCAL SYSTEM | high | 61603 |
| `102775` | 9 | `T1569.002` T1569.002 | PUA - NSudo Execution | high | 61603 |
| `102776` | 8 | `T1595` T1595 | PUA - PingCastle Execution | medium | 61603 |
| `102777` | 8 | `T1595` T1595 | PUA - PingCastle Execution | medium | 61603 |
| `102778` | 8 | `T1595` T1595 | PUA - PingCastle Execution | medium | 61603 |
| `102779` | 8 | `T1595` T1595 | PUA - PingCastle Execution | medium | 61603 |
| `102780` | 8 | `T1595` T1595 | PUA - PingCastle Execution | medium | 61603 |
| `102781` | 8 | `T1595` T1595 | PUA - PingCastle Execution | medium | 61603 |
| `102782` | 8 | `T1595` T1595 | PUA - PingCastle Execution | medium | 61603 |
| `102783` | 8 | `T1595` T1595 | PUA - PingCastle Execution | medium | 61603 |
| `102784` | 9 | `T1595` T1595 | PUA - PingCastle Execution From Potentially Suspicious Parent | high | 61603 |
| `102785` | 9 | `T1595` T1595 | PUA - PingCastle Execution From Potentially Suspicious Parent | high | 61603 |
| `102786` | 9 | `T1595` T1595 | PUA - PingCastle Execution From Potentially Suspicious Parent | high | 61603 |
| `102787` | 9 | `T1595` T1595 | PUA - PingCastle Execution From Potentially Suspicious Parent | high | 61603 |
| `102788` | 9 | `T1595` T1595 | PUA - PingCastle Execution From Potentially Suspicious Parent | high | 61603 |
| `102789` | 8 | `T1072` T1072 | PUA - Radmin Viewer Utility Execution | medium | 61603 |
| `102790` | 8 | `T1072` T1072 | PUA - Radmin Viewer Utility Execution | medium | 61603 |
| `102791` | 8 | `T1072` T1072 | PUA - Radmin Viewer Utility Execution | medium | 61603 |
| `102792` | 8 | `T1036.003` T1036.003 | PUA - Potential PE Metadata Tamper Using Rcedit | medium | 61603 |
| `102793` | 9 | `T1569.002` T1569.002 | PUA - RunXCmd Execution | high | 61603 |
| `102794` | 9 | `T1059` Command and Scripting Interpreter | PUA - Wsudo Suspicious Execution | high | 61603 |
| `102795` | 9 | `T1059` Command and Scripting Interpreter | PUA - Wsudo Suspicious Execution | high | 61603 |
| `102796` | 9 | `T1059` Command and Scripting Interpreter | PUA - Wsudo Suspicious Execution | high | 61603 |
| `102797` | 9 | `T1059` Command and Scripting Interpreter | PUA - Wsudo Suspicious Execution | high | 61603 |
| `102798` | 9 | `T1059` Command and Scripting Interpreter | PUA - Wsudo Suspicious Execution | high | 61603 |
| `102799` | 9 | `T1059.006` T1059.006 | Python One-Liners with Base64 Decoding | high | 61603 |
| `102800` | 8 | `T1059` Command and Scripting Interpreter | Python Inline Command Execution | medium | 61603 |
| `102801` | 9 | `T1059` Command and Scripting Interpreter | Python Spawning Pretty TTY on Windows | high | 61603 |
| `102802` | 8 | - | Query Usage To Exfil Data | medium | 61603 |
| `102803` | 9 | `T1059` Command and Scripting Interpreter | Suspicious Greedy Compression Using Rar.EXE | high | 61603 |
| `102804` | 9 | `T1059` Command and Scripting Interpreter | Suspicious Greedy Compression Using Rar.EXE | high | 61603 |
| `102805` | 9 | `T1059` Command and Scripting Interpreter | Suspicious Greedy Compression Using Rar.EXE | high | 61603 |
| `102806` | 8 | `T1059` Command and Scripting Interpreter | Suspicious RASdial Activity | medium | 61603 |
| `102807` | 9 | `T1685` T1685 | Add SafeBoot Keys Via Reg Utility | high | 61603 |
| `102808` | 8 | `T1685` T1685 | Suspicious Windows Defender Folder Exclusion Added Via Reg.EXE | medium | 61603 |
| `102809` | 9 | `T1070.003` T1070.003 | RunMRU Registry Key Deletion | high | 61603 |
| `102810` | 9 | `T1685` T1685 | SafeBoot Registry Key Deleted Via Reg.EXE | high | 61603 |
| `102811` | 9 | `T1685` T1685 | Service Registry Key Deleted Via Reg.EXE | high | 61603 |
| `102812` | 9 | `T1685` T1685 | Disabling Windows Defender WMI Autologger Session via Reg.exe | high | 61603 |
| `102813` | 9 | `T1685` T1685 | Security Service Disabled Via Reg.EXE | high | 61603 |
| `102814` | 9 | `T1685` T1685 | Disabled Volume Snapshots | high | 61603 |
| `102815` | 9 | `T1685` T1685 | Suspicious Windows Defender Registry Key Tampering Via Reg.EXE | high | 61603 |
| `102816` | 8 | `T1685` T1685 | Write Protect For Storage Disabled | medium | 61603 |
| `102817` | 8 | `T1218.009` T1218.009 | Potentially Suspicious Execution Of Regasm/Regsvcs With Uncommon Ex... | medium | 61603 |
| `102818` | 8 | `T1218.009` T1218.009 | Potentially Suspicious Execution Of Regasm/Regsvcs From Uncommon Lo... | medium | 61603 |
| `102819` | 9 | - | IE ZoneMap Setting Downgraded To MyComputer Zone For HTTP Protocols... | high | 61603 |
| `102820` | 9 | `T1685` T1685 | Python Function Execution Security Warning Disabled In Excel | high | 61603 |
| `102821` | 9 | `T1218` T1218 | Potential Provisioning Registry Key Abuse For Binary Proxy Execution | high | 61603 |
| `102822` | 9 | - | Potential PowerShell Execution Policy Tampering - ProcCreation | high | 61603 |
| `102823` | 8 | `T1564.002` T1564.002 | Hiding User Account Via SpecialAccounts Registry Key - CommandLine | medium | 61603 |
| `102824` | 8 | `T1218.010` T1218.010 | Potential Regsvr32 Commandline Flag Anomaly | medium | 61603 |
| `102825` | 9 | `T1218.010` T1218.010 | Potentially Suspicious Regsvr32 HTTP IP Pattern | high | 61603 |
| `102826` | 8 | `T1218.010` T1218.010 | Potentially Suspicious Regsvr32 HTTP/FTP Pattern | medium | 61603 |
| `102827` | 9 | `T1218.010` T1218.010 | Suspicious Regsvr32 Execution From Remote Share | high | 61603 |
| `102828` | 9 | `T1218.010` T1218.010 | Potentially Suspicious Child Process Of Regsvr32 | high | 61603 |
| `102829` | 8 | `T1218.010` T1218.010 | Regsvr32 Execution From Potential Suspicious Location | medium | 61603 |
| `102830` | 9 | `T1218.010` T1218.010 | Regsvr32 Execution From Highly Suspicious Location | high | 61603 |
| `102831` | 9 | `T1218.010` T1218.010 | Regsvr32 DLL Execution With Suspicious File Extension | high | 61603 |
| `102832` | 8 | `T1218.010` T1218.010 | Scripting/CommandLine Process Spawned Regsvr32 | medium | 61603 |
| `102833` | 8 | - | Remote Access Tool - AnyDesk Execution With Known Revoked Signing C... | medium | 61603 |
| `102834` | 8 | - | Remote Access Tool - NetSupport Execution From Unusual Location | medium | 61603 |
| `102835` | 8 | - | Remote Access Tool - RURAT Execution From Unusual Location | medium | 61603 |
| `102836` | 8 | - | Renamed AutoHotkey.EXE Execution | medium | 61603 |
| `102837` | 9 | `T1027` Obfuscated Files or Information | Renamed AutoIt Execution | high | 61603 |
| `102838` | 9 | `T1027` Obfuscated Files or Information | Renamed AutoIt Execution | high | 61603 |
| `102839` | 9 | `T1027` Obfuscated Files or Information | Renamed AutoIt Execution | high | 61603 |
| `102840` | 8 | `T1036.003` T1036.003 | Potential Defense Evasion Via Binary Rename | medium | 61603 |
| `102841` | 9 | `T1036.003` T1036.003 | Potential Defense Evasion Via Rename Of Highly Relevant Binaries | high | 61603 |
| `102842` | 8 | `T1553` T1553 | Renamed BOINC Client Execution | medium | 61603 |
| `102843` | 8 | `T1059` Command and Scripting Interpreter | Renamed CURL.EXE Execution | medium | 61603 |
| `102844` | 8 | `T1059` Command and Scripting Interpreter | Renamed FTP.EXE Execution | medium | 61603 |
| `102845` | 9 | `T1036.003` T1036.003 | Renamed Jusched.EXE Execution | high | 61603 |
| `102846` | 9 | `T1218` T1218 | Renamed MegaSync Execution | high | 61603 |
| `102847` | 9 | `T1036.003` T1036.003 | Renamed Msdt.EXE Execution | high | 61603 |
| `102848` | 8 | - | Renamed Microsoft Teams Execution | medium | 61603 |
| `102849` | 9 | - | Renamed NetSupport RAT Execution | high | 61603 |
| `102850` | 9 | `T1059` Command and Scripting Interpreter | Renamed NirCmd.EXE Execution | high | 61603 |
| `102851` | 9 | `T1036.003` T1036.003 | Renamed Office Binary Execution | high | 61603 |
| `102852` | 9 | `T1202` T1202 | Renamed PAExec Execution | high | 61603 |
| `102853` | 9 | `T1059` Command and Scripting Interpreter | Renamed PingCastle Binary Execution | high | 61603 |
| `102854` | 9 | `T1036` T1036 | Renamed Plink Execution | high | 61603 |
| `102855` | 8 | `T1218` T1218 | Visual Studio NodejsTools PressAnyKey Renamed Execution | medium | 61603 |
| `102856` | 9 | - | Potential Renamed Rundll32 Execution | high | 61603 |
| `102857` | 9 | `T1036.003` T1036.003 | Renamed Schtasks Execution | high | 61603 |
| `102858` | 9 | `T1588.002` T1588.002 | Renamed SysInternals DebugView Execution | high | 61603 |
| `102859` | 9 | `T1036.003` T1036.003 | Renamed ProcDump Execution | high | 61603 |
| `102860` | 9 | - | Renamed PsExec Service Execution | high | 61603 |
| `102861` | 8 | `T1059` Command and Scripting Interpreter | Ruby Inline Command Execution | medium | 61603 |
| `102862` | 9 | `T1564.004` T1564.004 | Potential Rundll32 Execution With DLL Stored In ADS | high | 61603 |
| `102863` | 9 | - | Suspicious Advpack Call Via Rundll32.EXE | high | 61603 |
| `102864` | 8 | `T1218.011` T1218.011 | Rundll32 InstallScreenSaver Execution | medium | 61603 |
| `102865` | 9 | - | Mshtml.DLL RunHTMLApplication Suspicious Usage | high | 61603 |
| `102866` | 9 | `T1202` T1202 | Rundll32 Execution Without CommandLine Parameters | high | 61603 |
| `102867` | 8 | `T1027.010` T1027.010 | Potential Obfuscated Ordinal Call Via Rundll32 | medium | 61603 |
| `102868` | 8 | - | Rundll32 Spawned Via Explorer.EXE | medium | 61603 |
| `102869` | 8 | `T1036` T1036 | Suspicious Process Start Locations | medium | 61603 |
| `102870` | 8 | `T1036` T1036 | Suspicious Process Start Locations | medium | 61603 |
| `102871` | 8 | `T1218.011` T1218.011 | Suspicious Rundll32 Setupapi.dll Activity | medium | 61603 |
| `102872` | 9 | `T1218.011` T1218.011 | Shell32 DLL Execution in Suspicious Directory | high | 61603 |
| `102873` | 8 | - | Potential ShellDispatch.DLL Functionality Abuse | medium | 61603 |
| `102874` | 9 | `T1218.011` T1218.011 | RunDLL32 Spawning Explorer | high | 61603 |
| `102875` | 8 | `T1218.011` T1218.011 | Potentially Suspicious Rundll32 Activity | medium | 61603 |
| `102876` | 9 | `T1218.011` T1218.011 | Suspicious Control Panel DLL Load | high | 61603 |
| `102877` | 9 | `T1218.011` T1218.011 | Suspicious Rundll32 Execution With Image Extension | high | 61603 |
| `102878` | 9 | - | Suspicious Usage Of ShellExec_RunDLL | high | 61603 |
| `102879` | 9 | `T1218.011` T1218.011 | Suspicious ShellExec_RunDLL Call Via Ordinal | high | 61603 |
| `102880` | 9 | `T1218.011` T1218.011 | Suspicious Rundll32 Activity Invoking Sys File | high | 61603 |
| `102881` | 8 | `T1218.011` T1218.011 | Potentially Suspicious Rundll32.EXE Execution of UDL File | medium | 61603 |
| `102882` | 9 | `T1021.002` T1021.002 | Rundll32 UNC Path Execution | high | 61603 |
| `102883` | 8 | `T1218.011` T1218.011 | Rundll32 Execution With Uncommon DLL Extension | medium | 61603 |
| `102884` | 8 | - | Suspicious Workstation Locking via Rundll32 | medium | 61603 |
| `102885` | 8 | `T1685` T1685 | Service StartupType Change Via Sc.EXE | medium | 61603 |
| `102886` | 9 | `T1053.005` T1053.005 | Uncommon One Time Only Scheduled Task At 00:00 | high | 61603 |
| `102887` | 9 | `T1047` T1047 | Script Event Consumer Spawning Process | high | 61603 |
| `102888` | 9 | `T1036` T1036 | Sdiagnhost Calling Suspicious Child Process | high | 61603 |
| `102889` | 9 | `T1218` T1218 | Uncommon Child Process Of Setres.EXE | high | 61603 |
| `102890` | 8 | `T1202` T1202 | Indirect Command Execution via SFTP ProxyCommand | medium | 61603 |
| `102891` | 8 | `T1216` T1216 | Uncommon Sigverif.EXE Child Process | medium | 61603 |
| `102892` | 8 | - | Uncommon Child Processes Of SndVol.exe | medium | 61603 |
| `102893` | 9 | `T1202` T1202 | Suspicious Splwow64 Without Params | high | 61603 |
| `102894` | 9 | `T1203` T1203 | Suspicious Spool Service Child Process | high | 61603 |
| `102895` | 8 | `T1218` T1218 | Arbitrary File Download Via Squirrel.EXE | medium | 61603 |
| `102896` | 8 | `T1218` T1218 | Process Proxy Execution Via Squirrel.EXE | medium | 61603 |
| `102897` | 8 | `T1218` T1218 | Program Executed Using Proxy/Local Command Via SSH.EXE | medium | 61603 |
| `102898` | 9 | `T1218` T1218 | Execution via stordiag.exe | high | 61603 |
| `102899` | 8 | - | Start of NT Virtual DOS Machine | medium | 61603 |
| `102900` | 8 | `T1564.004` T1564.004 | Execute From Alternate Data Streams | medium | 61603 |
| `102901` | 8 | - | Potentially Suspicious Windows App Activity | medium | 61603 |
| `102902` | 8 | `T1204` User Execution | Arbitrary Shell Command Execution Via Settingcontent-Ms | medium | 61603 |
| `102903` | 9 | `T1218.011` T1218.011 | Bad Opsec Defaults Sacrificial Processes With Improper Arguments | high | 61603 |
| `102904` | 9 | `T1218.011` T1218.011 | Bad Opsec Defaults Sacrificial Processes With Improper Arguments | high | 61603 |
| `102905` | 9 | `T1218.011` T1218.011 | Bad Opsec Defaults Sacrificial Processes With Improper Arguments | high | 61603 |
| `102906` | 9 | `T1218.011` T1218.011 | Bad Opsec Defaults Sacrificial Processes With Improper Arguments | high | 61603 |
| `102907` | 9 | `T1218.011` T1218.011 | Bad Opsec Defaults Sacrificial Processes With Improper Arguments | high | 61603 |
| `102908` | 8 | `T1204.002` T1204.002 | Potential Suspicious Browser Launch From Document Reader Process | medium | 61603 |
| `102909` | 8 | `T1140` T1140 | Potential Commandline Obfuscation Using Escape Characters | medium | 61603 |
| `102910` | 9 | `T1027` Obfuscated Files or Information | Potential CommandLine Obfuscation Using Unicode Characters From Sus... | high | 61603 |
| `102911` | 9 | `T1204.001` T1204.001 | Suspicious ClickFix/FileFix Execution Pattern | high | 61603 |
| `102912` | 9 | `T1204.004` T1204.004 | Suspicious Explorer Process with Whitespace Padding - ClickFix/FileFix | high | 61603 |
| `102913` | 8 | `T1059.003` T1059.003 | Suspicious Usage of For Loop with Recursive Directory Search in CMD | medium | 61603 |
| `102914` | 8 | `T1059.003` T1059.003 | Suspicious Usage of For Loop with Recursive Directory Search in CMD | medium | 61603 |
| `102915` | 8 | `T1036` T1036 | Potential Command Line Path Traversal Evasion Attempt | medium | 61603 |
| `102916` | 8 | `T1036` T1036 | Potential Command Line Path Traversal Evasion Attempt | medium | 61603 |
| `102917` | 8 | `T1036.003` T1036.003 | Suspicious Copy From or To System Directory | medium | 61603 |
| `102918` | 8 | `T1036.003` T1036.003 | Suspicious Copy From or To System Directory | medium | 61603 |
| `102919` | 8 | `T1036.003` T1036.003 | Suspicious Copy From or To System Directory | medium | 61603 |
| `102920` | 8 | `T1036.003` T1036.003 | Suspicious Copy From or To System Directory | medium | 61603 |
| `102921` | 9 | `T1036.003` T1036.003 | LOL-Binary Copied From System Directory | high | 61603 |
| `102922` | 9 | `T1036.003` T1036.003 | LOL-Binary Copied From System Directory | high | 61603 |
| `102923` | 9 | `T1036.003` T1036.003 | LOL-Binary Copied From System Directory | high | 61603 |
| `102924` | 9 | `T1036.003` T1036.003 | LOL-Binary Copied From System Directory | high | 61603 |
| `102925` | 9 | `T1059.001` T1059.001 | Potential Data Exfiltration Activity Via CommandLine Tools | high | 61603 |
| `102926` | 9 | `T1685` T1685 | Raccine Uninstall | high | 61603 |
| `102927` | 9 | `T1685` T1685 | Raccine Uninstall | high | 61603 |
| `102928` | 9 | `T1685` T1685 | Raccine Uninstall | high | 61603 |
| `102929` | 9 | `T1036.007` T1036.007 | Suspicious Parent Double Extension File Execution | high | 61603 |
| `102930` | 9 | `T1036.007` T1036.007 | Suspicious Parent Double Extension File Execution | high | 61603 |
| `102931` | 9 | - | DumpStack.log Defender Evasion | high | 61603 |
| `102932` | 9 | - | DumpStack.log Defender Evasion | high | 61603 |
| `102933` | 8 | - | Suspicious Electron Application Child Processes | medium | 61603 |
| `102934` | 8 | - | Potentially Suspicious Electron Application CommandLine | medium | 61603 |
| `102935` | 8 | `T1059.001` T1059.001 | Hidden Powershell in Link File Pattern | medium | 61603 |
| `102936` | 9 | - | Potential Defense Evasion Activity Via Emoji Usage In CommandLine - 1 | high | 61603 |
| `102937` | 9 | - | Potential Defense Evasion Activity Via Emoji Usage In CommandLine - 2 | high | 61603 |
| `102938` | 9 | - | Potential Defense Evasion Activity Via Emoji Usage In CommandLine - 3 | high | 61603 |
| `102939` | 9 | - | Potential Defense Evasion Activity Via Emoji Usage In CommandLine - 4 | high | 61603 |
| `102940` | 9 | `T1685` T1685 | ETW Logging Tamper In .NET Processes Via CommandLine | high | 61603 |
| `102941` | 9 | `T1070` Indicator Removal | ETW Trace Evasion Activity | high | 61603 |
| `102942` | 9 | `T1070` Indicator Removal | ETW Trace Evasion Activity | high | 61603 |
| `102943` | 9 | `T1070` Indicator Removal | ETW Trace Evasion Activity | high | 61603 |
| `102944` | 9 | `T1070` Indicator Removal | ETW Trace Evasion Activity | high | 61603 |
| `102945` | 9 | `T1070` Indicator Removal | ETW Trace Evasion Activity | high | 61603 |
| `102946` | 9 | `T1070` Indicator Removal | ETW Trace Evasion Activity | high | 61603 |
| `102947` | 9 | `T1070` Indicator Removal | ETW Trace Evasion Activity | high | 61603 |
| `102948` | 9 | `T1685.005` T1685.005 | Suspicious Eventlog Clearing or Configuration Change Activity | high | 61603 |
| `102949` | 9 | `T1564` T1564 | Potentially Suspicious Execution From Parent Process In Public Folder | high | 61603 |
| `102950` | 9 | `T1036` T1036 | Process Execution From A Potentially Suspicious Folder | high | 61603 |
| `102951` | 8 | `T1059.006` T1059.006 | Suspicious File Characteristics Due to Missing Fields | medium | 61603 |
| `102952` | 9 | `T1204.004` T1204.004 | Suspicious FileFix Execution Pattern | high | 61603 |
| `102953` | 8 | `T1564.004` T1564.004 | Potential Hidden Directory Creation Via NTFS INDEX_ALLOCATION Strea... | medium | 61603 |
| `102954` | 8 | `T1036` T1036 | Potential Homoglyph Attack Using Lookalike Characters | medium | 61603 |
| `102955` | 8 | `T1036` T1036 | Potential Homoglyph Attack Using Lookalike Characters | medium | 61603 |
| `102956` | 9 | - | Execution Of Non-Existing File | high | 61603 |
| `102957` | 9 | - | Base64 MZ Header In CommandLine | high | 61603 |
| `102958` | 8 | `T1059.007` T1059.007 | Potentially Suspicious Inline JavaScript Execution via NodeJS Binary | medium | 61603 |
| `102959` | 9 | `T1106` T1106 | Potential WinAPI Calls Via CommandLine | high | 61603 |
| `102960` | 8 | - | LOLBIN Execution From Abnormal Drive | medium | 61603 |
| `102961` | 8 | `T1218` T1218 | Potential File Download Via MS-AppInstaller Protocol Handler | medium | 61603 |
| `102962` | 8 | `T1059` Command and Scripting Interpreter | Suspicious Scan Loop Network | medium | 61603 |
| `102963` | 8 | - | Process Launched Without Image Name | medium | 61603 |
| `102964` | 8 | - | Execution of Suspicious File Type Extension | medium | 61603 |
| `102965` | 9 | - | Potentially Suspicious Call To Win32_NTEventlogFile Class | high | 61603 |
| `102966` | 8 | `T1564.004` T1564.004 | Use Short Name Path in Image | medium | 61603 |
| `102967` | 8 | `T1564.004` T1564.004 | Use NTFS Short Name in Command Line | medium | 61603 |
| `102968` | 8 | `T1564.004` T1564.004 | Use NTFS Short Name in Image | medium | 61603 |
| `102969` | 9 | `T1036` T1036 | Suspicious Process Parents | high | 61603 |
| `102970` | 9 | `T1218.011` T1218.011 | Potential PowerShell Execution Via DLL | high | 61603 |
| `102971` | 13 | `T1059` Command and Scripting Interpreter | Suspicious Program Names | high | 61603 |
| `102972` | 9 | `T1059` Command and Scripting Interpreter | Suspicious Program Names | high | 61603 |
| `102973` | 14 | `T1059` Command and Scripting Interpreter | Suspicious Program Names | high | 61603 |
| `102974` | 9 | `T1036.002` T1036.002 | Potential Defense Evasion Via Right-to-Left Override | high | 61603 |
| `102975` | 9 | `T1059` Command and Scripting Interpreter | Script Interpreter Execution From Suspicious Folder | high | 61603 |
| `102976` | 9 | `T1059` Command and Scripting Interpreter | Script Interpreter Execution From Suspicious Folder | high | 61603 |
| `102977` | 9 | `T1059` Command and Scripting Interpreter | Script Interpreter Execution From Suspicious Folder | high | 61603 |
| `102978` | 9 | `T1202` T1202 | Suspicious Service Binary Directory | high | 61603 |
| `102979` | 9 | `T1059.005` T1059.005 | Windows Shell/Scripting Processes Spawning Suspicious Programs | high | 61603 |
| `102980` | 12 | `T1036` T1036 | System File Execution Location Anomaly | high | 61603 |
| `102981` | 8 | `T1218` T1218 | Malicious PE Execution by Microsoft Visual Studio Debugger | medium | 61603 |
| `102982` | 8 | - | Weak or Abused Passwords In CLI | medium | 61603 |
| `102983` | 8 | `T1059.001` T1059.001 | Usage Of Web Request Commands And Cmdlets | medium | 61603 |
| `102984` | 9 | `T1218` T1218 | Execution via WorkFolders.exe | high | 61603 |
| `102985` | 9 | `T1036.005` T1036.005 | Suspicious Process Masquerading As SvcHost.EXE | high | 61603 |
| `102986` | 8 | `T1036.005` T1036.005 | Uncommon Svchost Parent Process | medium | 61603 |
| `102987` | 8 | - | Potential Memory Dumping Activity Via LiveKD | medium | 61603 |
| `102988` | 8 | - | Potential Memory Dumping Activity Via LiveKD | medium | 61603 |
| `102989` | 9 | - | Kernel Memory Dump Via LiveKD | high | 61603 |
| `102990` | 8 | `T1569` System Services | Psexec Execution | medium | 61603 |
| `102991` | 8 | `T1569` System Services | Psexec Execution | medium | 61603 |
| `102992` | 9 | `T1587.001` T1587.001 | PsExec/PAExec Escalation to LOCAL SYSTEM | high | 61603 |
| `102993` | 9 | `T1587.001` T1587.001 | Potential PsExec Remote Execution | high | 61603 |
| `102994` | 8 | - | PsExec Service Execution | medium | 61603 |
| `102995` | 8 | - | PsExec Service Execution | medium | 61603 |
| `102996` | 9 | - | PsExec Service Child Process Execution as LOCAL SYSTEM | high | 61603 |
| `102997` | 9 | `T1685` T1685 | Sysinternals PsSuspend Suspicious Execution | high | 61603 |
| `102998` | 9 | `T1587.001` T1587.001 | Potential Privilege Escalation To LOCAL SYSTEM | high | 61603 |
| `102999` | 8 | `T1685` T1685 | Sysmon Configuration Update | medium | 61603 |
| `103000` | 9 | `T1685` T1685 | Uninstall Sysinternals Sysmon | high | 61603 |
| `103001` | 8 | `T1218` T1218 | Potential Binary Impersonating Sysinternals Tools | medium | 61603 |
| `103002` | 8 | `T1218` T1218 | Potential Binary Impersonating Sysinternals Tools | medium | 61603 |
| `103003` | 8 | `T1059` Command and Scripting Interpreter | Sysprep on AppData Folder | medium | 61603 |
| `103004` | 9 | - | Potential Signing Bypass Via Windows Developer Features | high | 61603 |
| `103005` | 8 | `T1222.001` T1222.001 | Suspicious Recursive Takeown | medium | 61603 |
| `103006` | 9 | `T1685` T1685 | Taskkill Symantec Endpoint Protection | high | 61603 |
| `103007` | 9 | `T1036` T1036 | Taskmgr as LOCAL_SYSTEM | high | 61603 |
| `103008` | 8 | - | New Virtual Smart Card Created Via TpmVscMgr.EXE | medium | 61603 |
| `103009` | 8 | - | Potential RDP Session Hijacking Activity | medium | 61603 |
| `103010` | 9 | `T1548.002` T1548.002 | CMSTP UAC Bypass via COM Object Access | high | 61603 |
| `103011` | 9 | `T1548.002` T1548.002 | UAC Bypass Using IDiagnostic Profile | high | 61603 |
| `103012` | 9 | `T1685` T1685 | Uninstall Crowdstrike Falcon Sensor | high | 61603 |
| `103013` | 8 | `T1218` T1218 | Verclsid.exe Runs COM Object | medium | 61603 |
| `103014` | 8 | `T1059` Command and Scripting Interpreter | Potential Persistence Via VMwareToolBoxCmd.EXE VM State Change Script | medium | 61603 |
| `103015` | 9 | `T1059` Command and Scripting Interpreter | Suspicious Persistence Via VMwareToolBoxCmd.EXE VM State Change Script | high | 61603 |
| `103016` | 9 | `T1059` Command and Scripting Interpreter | VMToolsd Suspicious Child Process | high | 61603 |
| `103017` | 8 | `T1218` T1218 | Potentially Suspicious Child Process Of VsCode | medium | 61603 |
| `103018` | 8 | `T1218` T1218 | Potential Binary Proxy Execution Via VSDiagnostics.EXE | medium | 61603 |
| `103019` | 8 | `T1202` T1202 | Proxy Execution via Vshadow | medium | 61603 |
| `103020` | 8 | `T1218` T1218 | Suspicious Vsls-Agent Command With AgentExtensionPath Load | medium | 61603 |
| `103021` | 9 | `T1685` T1685 | Vulnerable Driver Blocklist Registry Tampering Via CommandLine | high | 61603 |
| `103022` | 9 | - | Wab Execution From Non Default Location | high | 61603 |
| `103023` | 9 | - | Wab/Wabmig Unusual Parent Or Child Processes | high | 61603 |
| `103024` | 9 | - | Wab/Wabmig Unusual Parent Or Child Processes | high | 61603 |
| `103025` | 8 | `T1059.001` T1059.001 | Potentially Suspicious WebDAV LNK Execution | medium | 61603 |
| `103026` | 8 | `T1036` T1036 | Potential ReflectDebugger Content Execution Via WerFault.EXE | medium | 61603 |
| `103027` | 9 | - | Suspicious Execution Location Of Wermgr.EXE | high | 61603 |
| `103028` | 9 | - | Suspicious File Download From IP Via Wget.EXE | high | 61603 |
| `103029` | 9 | - | Suspicious File Download From File Sharing Domain Via Wget.EXE | high | 61603 |
| `103030` | 9 | - | Suspicious File Download From IP Via Wget.EXE - Paths | high | 61603 |
| `103031` | 8 | - | Suspicious WindowsTerminal Child Processes | medium | 61603 |
| `103032` | 8 | `T1059` Command and Scripting Interpreter | Add New Download Source To Winget | medium | 61603 |
| `103033` | 9 | `T1059` Command and Scripting Interpreter | Add Insecure Download Source To Winget | high | 61603 |
| `103034` | 8 | `T1059` Command and Scripting Interpreter | Add Potential Suspicious New Download Source To Winget | medium | 61603 |
| `103035` | 8 | `T1059` Command and Scripting Interpreter | Install New Package Via Winget Local Manifest | medium | 61603 |
| `103036` | 8 | `T1203` T1203 | Potentially Suspicious Child Process Of WinRAR.EXE | medium | 61603 |
| `103037` | 8 | `T1216` T1216 | AWL Bypass with Winrm.vbs and Malicious WsmPty.xsl/WsmTxt.xsl | medium | 61603 |
| `103038` | 8 | `T1216` T1216 | Remote Code Execute via Winrm.vbs | medium | 61603 |
| `103039` | 8 | `T1059.001` T1059.001 | Remote PowerShell Session Host Process (WinRM) | medium | 61603 |
| `103040` | 8 | `T1059.001` T1059.001 | Remote PowerShell Session Host Process (WinRM) | medium | 61603 |
| `103041` | 8 | `T1218` T1218 | Wlrmdr.EXE Uncommon Argument Or Child Process | medium | 61603 |
| `103042` | 9 | `T1047` T1047 | Potential Windows Defender Tampering Via Wmic.EXE | high | 61603 |
| `103043` | 8 | `T1047` T1047 | New Process Created Via Wmic.EXE | medium | 61603 |
| `103044` | 8 | `T1047` T1047 | Hardware Model Reconnaissance Via Wmic.EXE | medium | 61603 |
| `103045` | 8 | `T1047` T1047 | Windows Hotfix Updates Reconnaissance Via Wmic.EXE | medium | 61603 |
| `103046` | 8 | `T1047` T1047 | Process Reconnaissance Via Wmic.EXE | medium | 61603 |
| `103047` | 8 | `T1047` T1047 | Potential Product Reconnaissance Via Wmic.EXE | medium | 61603 |
| `103048` | 8 | `T1047` T1047 | Potential Product Class Reconnaissance Via Wmic.EXE | medium | 61603 |
| `103049` | 8 | `T1047` T1047 | Service Reconnaissance Via Wmic.EXE | medium | 61603 |
| `103050` | 8 | `T1047` T1047 | Potential Unquoted Service Path Reconnaissance Via Wmic.EXE | medium | 61603 |
| `103051` | 8 | `T1047` T1047 | System Disk And Volume Reconnaissance Via Wmic.EXE | medium | 61603 |
| `103052` | 8 | `T1047` T1047 | WMIC Remote Command Execution | medium | 61603 |
| `103053` | 8 | `T1047` T1047 | Service Started/Stopped Via Wmic.EXE | medium | 61603 |
| `103054` | 8 | `T1047` T1047 | Service Startup Type Change Via Wmic.EXE | medium | 61603 |
| `103055` | 9 | `T1047` T1047 | Potential Remote SquiblyTwo Technique Execution | high | 61603 |
| `103056` | 9 | `T1204.002` T1204.002 | Suspicious WMIC Execution Via Office Process | high | 61603 |
| `103057` | 9 | `T1047` T1047 | Suspicious Process Created Via Wmic.EXE | high | 61603 |
| `103058` | 8 | `T1047` T1047 | Application Terminated Via Wmic.EXE | medium | 61603 |
| `103059` | 8 | `T1047` T1047 | Application Removed Via Wmic.EXE | medium | 61603 |
| `103060` | 9 | `T1685` T1685 | Potential Tampering With Security Products Via WMIC | high | 61603 |
| `103061` | 9 | `T1685` T1685 | Potential Tampering With Security Products Via WMIC | high | 61603 |
| `103062` | 9 | `T1685` T1685 | Potential Tampering With Security Products Via WMIC | high | 61603 |
| `103063` | 8 | `T1047` T1047 | XSL Script Execution Via WMIC.EXE | medium | 61603 |
| `103064` | 8 | `T1047` T1047 | WmiPrvSE Spawned A Process | medium | 61603 |
| `103065` | 8 | `T1047` T1047 | Potential WMI Lateral Movement WmiPrvSE Spawned PowerShell | medium | 61603 |
| `103066` | 9 | `T1047` T1047 | Suspicious WmiPrvSE Child Process | high | 61603 |
| `103067` | 8 | `T1059.005` T1059.005 | Potential Dropper Script Execution Via WScript/CScript/MSHTA | medium | 61603 |
| `103068` | 8 | - | Cscript/Wscript Potentially Suspicious Child Process | medium | 61603 |
| `103069` | 9 | `T1059.005` T1059.005 | Cscript/Wscript Uncommon Script Extension Execution | high | 61603 |
| `103070` | 8 | `T1218` T1218 | WSL Child Process Anomaly | medium | 61603 |
| `103071` | 9 | `T1059` Command and Scripting Interpreter | Installation of WSL Kali-Linux | high | 61603 |
| `103072` | 9 | `T1202` T1202 | WSL Kali-Linux Usage | high | 61603 |
| `103073` | 9 | `T1202` T1202 | WSL Kali-Linux Usage | high | 61603 |
| `103074` | 9 | `T1202` T1202 | WSL Kali-Linux Usage | high | 61603 |
| `103075` | 8 | `T1202` T1202 | Windows Binary Executed From WSL | medium | 61603 |
| `103076` | 9 | `T1218` T1218 | Proxy Execution Via Wuauclt.EXE | high | 61603 |
| `103077` | 9 | `T1036` T1036 | Suspicious Windows Update Agent Empty Cmdline | high | 61603 |
| `103078` | 9 | - | Cab File Extraction Via Wusa.EXE From Potentially Suspicious Paths | high | 61603 |
| `103079` | 9 | - | Wusa.EXE Executed By Parent Process Located In Suspicious Location | high | 61603 |
| `103080` | 8 | `T1218` T1218 | COM Object Execution via Xwizard.EXE | medium | 61603 |
| `103081` | 8 | - | Delete Defender Scan ShellEx Context Menu Registry Key | medium | 61614 |
| `103082` | 9 | `T1685` T1685 | Windows Credential Guard Related Registry Value Deleted - Registry | high | 61614 |
| `103083` | 9 | `T1685` T1685 | Folder Removed From Exploit Guard ProtectedFolders List - Registry | high | 61614 |
| `103084` | 9 | `T1685` T1685 | Removal Of AMSI Provider Registry Keys | high | 61614 |
| `103085` | 9 | `T1070.003` T1070.003 | RunMRU Registry Key Deletion - Registry | high | 61614 |
| `103086` | 8 | `T1685` T1685 | Removal Of Index Value to Hide Schedule Task - Registry | medium | 61614 |
| `103087` | 8 | `T1685` T1685 | Removal Of SD Value to Hide Schedule Task - Registry | medium | 61614 |
| `103088` | 9 | `T1218.003` T1218.003 | CMSTP Execution Registry Event | high | 61615 |
| `103089` | 9 | `T1685` T1685 | Windows Defender Threat Severity Default Action Modified | high | 61615 |
| `103090` | 9 | `T1608` T1608 | HybridConnectionManager Service Installation - Registry | high | 61615 |
| `103091` | 8 | `T1685` T1685 | Enable Remote Connection Between Anonymous Computer - AllowAnonymou... | medium | 61615 |
| `103092` | 9 | `T1564.001` T1564.001 | Registry Persistence via Service in Safe Mode | high | 61615 |
| `103093` | 9 | `T1685` T1685 | Potential AMSI COM Server Hijacking | high | 61615 |
| `103094` | 9 | `T1685` T1685 | AMSI Disabled via Registry Modification | high | 61615 |
| `103095` | 9 | `T1685` T1685 | Sysmon Driver Altitude Change | high | 61615 |
| `103096` | 9 | `T1685.001` T1685.001 | Change Winevt Channel Access Permission Via Registry | high | 61615 |
| `103097` | 9 | `T1685` T1685 | Windows Credential Guard Disabled - Registry | high | 61615 |
| `103098` | 9 | `T1202` T1202 | Custom File Open Handler Executes PowerShell | high | 61615 |
| `103099` | 8 | `T1685` T1685 | Windows Defender Exclusions Added - Registry | medium | 61615 |
| `103100` | 9 | `T1685` T1685 | Antivirus Filter Driver Disallowed On Dev Drive - Registry | high | 61615 |
| `103101` | 9 | `T1685` T1685 | Windows Hypervisor Enforced Code Integrity Disabled | high | 61615 |
| `103102` | 9 | `T1685` T1685 | Hypervisor Enforced Paging Translation Disabled | high | 61615 |
| `103103` | 8 | `T1070.005` T1070.005 | Disable Administrative Share Creation at Startup | medium | 61615 |
| `103104` | 9 | `T1685.001` T1685.001 | Potential AutoLogger Sessions Tampering | high | 61615 |
| `103105` | 8 | `T1686.003` T1686.003 | Disable Microsoft Defender Firewall via Registry | medium | 61615 |
| `103106` | 9 | - | Disable Macro Runtime Scan Scope | high | 61615 |
| `103107` | 8 | `T1685` T1685 | Disable Privacy Settings Experience in Registry | medium | 61615 |
| `103108` | 9 | `T1685` T1685 | Windows Defender Service Disabled - Registry | high | 61615 |
| `103109` | 8 | `T1686.003` T1686.003 | Disable Windows Firewall by Registry | medium | 61615 |
| `103110` | 9 | `T1685.001` T1685.001 | Disable Windows Event Logging Via Registry | high | 61615 |
| `103111` | 8 | `T1685` T1685 | Disable Exploit Guard Network Protection on Windows Defender | medium | 61615 |
| `103112` | 9 | `T1685` T1685 | Disabled Windows Defender Eventlog | high | 61615 |
| `103113` | 9 | `T1685` T1685 | Disable PUA Protection on Windows Defender | high | 61615 |
| `103114` | 8 | `T1685` T1685 | Disable Tamper Protection on Windows Defender | medium | 61615 |
| `103115` | 8 | `T1685` T1685 | Scripted Diagnostics Turn Off Check Enabled - Registry | medium | 61615 |
| `103116` | 9 | `T1685.001` T1685.001 | Potential EventLog File Location Tampering | high | 61615 |
| `103117` | 9 | `T1685` T1685 | Suspicious Application Allowed Through Exploit Guard | high | 61615 |
| `103118` | 9 | - | New File Association Using Exefile | high | 61615 |
| `103119` | 9 | `T1204.004` T1204.004 | FileFix - Command Evidence in TypedPaths | high | 61615 |
| `103120` | 8 | `T1564.001` T1564.001 | Displaying Hidden Files Feature Disabled | medium | 61615 |
| `103121` | 9 | `T1685` T1685 | Hide Schedule Task Via Index Value Tamper | high | 61615 |
| `103122` | 9 | - | Driver Added To Disallowed Images In HVCI - Registry | high | 61615 |
| `103123` | 9 | - | IE ZoneMap Setting Downgraded To MyComputer Zone For HTTP Protocols | high | 61615 |
| `103124` | 9 | `T1685` T1685 | Uncommon Extension In Keyboard Layout IME File Registry Value | high | 61615 |
| `103125` | 9 | `T1685` T1685 | Suspicious Path In Keyboard Layout IME File Registry Value | high | 61615 |
| `103126` | 8 | - | Internet Explorer DisableFirstRunCustomize Enabled | medium | 61615 |
| `103127` | 9 | `T1685` T1685 | Microsoft Office Protected View Disabled | high | 61615 |
| `103128` | 9 | `T1685` T1685 | Python Function Execution Security Warning Disabled In Excel - Regi... | high | 61615 |
| `103129` | 8 | `T1559.002` T1559.002 | Enable Microsoft Dynamic Data Exchange | medium | 61615 |
| `103130` | 8 | `T1559.002` T1559.002 | Enable Microsoft Dynamic Data Exchange | medium | 61615 |
| `103131` | 9 | `T1036.003` T1036.003 | Potential WerFault ReflectDebugger Registry Value Abuse | high | 61615 |
| `103132` | 9 | - | Potential Attachment Manager Settings Associations Tamper | high | 61615 |
| `103133` | 9 | - | Potential Attachment Manager Settings Attachments Tamper | high | 61615 |
| `103134` | 9 | `T1204.001` T1204.001 | Potential ClickFix Execution Pattern - Registry | high | 61615 |
| `103135` | 9 | `T1569.002` T1569.002 | PowerShell as a Service in Registry | high | 61615 |
| `103136` | 8 | - | Potential PowerShell Execution Policy Tampering | medium | 61615 |
| `103137` | 9 | `T1218` T1218 | Potential Provisioning Registry Key Abuse For Binary Proxy Executio... | high | 61615 |
| `103138` | 9 | `T1588.002` T1588.002 | Suspicious Execution Of Renamed Sysinternals Tools - Registry | high | 61615 |
| `103139` | 8 | `T1588.002` T1588.002 | PUA - Sysinternals Tools Execution - Registry | medium | 61615 |
| `103140` | 9 | `T1588.002` T1588.002 | Usage of Renamed Sysinternals Tools - RegistrySet | high | 61615 |
| `103141` | 9 | `T1059.001` T1059.001 | Potentially Suspicious Command Executed Via Run Dialog Box - Registry | high | 61615 |
| `103142` | 8 | `T1218.011` T1218.011 | ScreenSaver Registry Key Set | medium | 61615 |
| `103143` | 9 | `T1685` T1685 | Tamper With Sophos AV Registry Keys | high | 61615 |
| `103144` | 9 | `T1564.002` T1564.002 | Hiding User Account Via SpecialAccounts Registry Key | high | 61615 |
| `103145` | 8 | `T1588.002` T1588.002 | Suspicious Keyboard Layout Load | medium | 61615 |
| `103146` | 8 | `T1036.003` T1036.003 | Potential PendingFileRenameOperations Tampering | medium | 61615 |
| `103147` | 9 | `T1204.004` T1204.004 | Suspicious Space Characters in RunMRU Registry Path - ClickFix | high | 61615 |
| `103148` | 8 | `T1685` T1685 | Suspicious Service Installed | medium | 61615 |
| `103149` | 9 | `T1204.004` T1204.004 | Suspicious Space Characters in TypedPaths Registry Path - FileFix | high | 61615 |
| `103150` | 8 | `T1685` T1685 | WFP Filter Added via Registry | medium | 61615 |
| `103151` | 8 | - | Old TLS1.0/TLS1.1 Protocol Version Enabled | medium | 61615 |
| `103152` | 9 | - | Potential Signing Bypass Via Windows Developer Features - Registry | high | 61615 |
| `103153` | 9 | `T1685` T1685 | Windows Vulnerable Driver Blocklist Disabled | high | 61615 |
| `103154` | 9 | `T1218` T1218 | Execution DLL of Choice Using WAB.EXE | high | 61615 |
| `103155` | 9 | `T1685` T1685 | Disable Windows Defender Functionalities Via Registry Keys | high | 61615 |
| `103156` | 8 | - | Sysmon Configuration Change | medium | 60004 |
| `103157` | 9 | `T1564` T1564 | Sysmon Configuration Error | high | 60004 |
| `103158` | 9 | `T1564` T1564 | Sysmon Configuration Modification | high | 60004 |
| `103159` | 9 | - | Sysmon Blocked Executable | high | 60004 |
| `103160` | 9 | - | Sysmon Blocked File Shredding | high | 60004 |
| `103161` | 8 | - | Sysmon File Executable Creation Detected | medium | 60004 |
| `103162` | 9 | `T1059.005` T1059.005 | Suspicious Scripting in a WMI Consumer | high | 61621 |

### Persistence (TA0003) — 843 rules

| Rule ID | Level | Technique | Description | Confidence | Parent SID |
|---------|-------|-----------|-------------|------------|------------|
| `104000` | 9 | `T1547.001` T1547.001 | Registry persistence via currentversion\run | medium | 61615 |
| `104001` | 9 | `T1547.001` T1547.001 | Registry persistence via currentversion\run | medium | 61614 |
| `104002` | 9 | `T1547.001` T1547.001 | Registry persistence via currentversion\runonce | medium | 61615 |
| `104003` | 9 | `T1547.001` T1547.001 | Registry persistence via currentversion\runonce | medium | 61614 |
| `104004` | 9 | `T1547.004` T1547.004 | Registry persistence via userinit | medium | 61615 |
| `104005` | 9 | `T1546.003` T1546.003 | WMI event subscription (EventID 19) | medium | 61621 |
| `104006` | 9 | `T1546.003` T1546.003 | WMI event subscription (EventID 20) | medium | 61622 |
| `104007` | 9 | `T1546.003` T1546.003 | WMI event subscription (EventID 21) | medium | 61623 |
| `104008` | 9 | `T1136.001` T1136.001 | User account created | medium | 60100 |
| `104009` | 9 | `T1053.005` T1053.005 | Scheduled task created | medium | 60100 |
| `104010` | 7 | `T1098` T1098 | Member added to group | low | 60100 |
| `104011` | 9 | `T1547.004` T1547.004 | Registry persistence via winlogon\ | medium | 61615 |
| `104012` | 9 | `T1546.003` T1546.003 | WMI event subscription (EventID 20) | medium | 61622 |
| `104013` | 9 | `T1546.003` T1546.003 | WMI event subscription (EventID 21) | medium | 61623 |
| `104014` | 9 | `T1546.003` T1546.003 | WMI event subscription (EventID 19) | medium | 61621 |
| `104015` | 9 | `T1546.003` T1546.003 | WMI event subscription (EventID 20) | medium | 61622 |
| `104016` | 9 | `T1546.003` T1546.003 | WMI event subscription (EventID 21) | medium | 61623 |
| `104017` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104018` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104019` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104020` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104021` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104022` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104023` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104024` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104025` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104026` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104027` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104028` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104029` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104030` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104031` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104032` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104033` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104034` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104035` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104036` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104037` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104038` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104039` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104040` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104041` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104042` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104043` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104044` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104045` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104046` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104047` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104048` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104049` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104050` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104051` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104052` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104053` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104054` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104055` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104056` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104057` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104058` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104059` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104060` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104061` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104062` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104063` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104064` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104065` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104066` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104067` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104068` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104069` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104070` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104071` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104072` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104073` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104074` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104075` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104076` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104077` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104078` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104079` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104080` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104081` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104082` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104083` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104084` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104085` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104086` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104087` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104088` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104089` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104090` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104091` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104092` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104093` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104094` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104095` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104096` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104097` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104098` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104099` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104100` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104101` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104102` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104103` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104104` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104105` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104106` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104107` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104108` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104109` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104110` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104111` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104112` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104113` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104114` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104115` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104116` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104117` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104118` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104119` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104120` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104121` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104122` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104123` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104124` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104125` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104126` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104127` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104128` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104129` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104130` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104131` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104132` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104133` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104134` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104135` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104136` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104137` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104138` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104139` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104140` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104141` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104142` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104143` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104144` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104145` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104146` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104147` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104148` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104149` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104150` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104151` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104152` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104153` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104154` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104155` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104156` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104157` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104158` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104159` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104160` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104161` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104162` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104163` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104164` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104165` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104166` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104167` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104168` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104169` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104170` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104171` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104172` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104173` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104174` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104175` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104176` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104177` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104178` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104179` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104180` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104181` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104182` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104183` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104184` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104185` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104186` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104187` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104188` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104189` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104190` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104191` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104192` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104193` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104194` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104195` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104196` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104197` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104198` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104199` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104200` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104201` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104202` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104203` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104204` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104205` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104206` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104207` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104208` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104209` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104210` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104211` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104212` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104213` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104214` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104215` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104216` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104217` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104218` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104219` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104220` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104221` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104222` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104223` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104224` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104225` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104226` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104227` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104228` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104229` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104230` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104231` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104232` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104233` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104234` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104235` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104236` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104237` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104238` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104239` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104240` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104241` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104242` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104243` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104244` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104245` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104246` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104247` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104248` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104249` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104250` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104251` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104252` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104253` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104254` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104255` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104256` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104257` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104258` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104259` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104260` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104261` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104262` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104263` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104264` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104265` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104266` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104267` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104268` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104269` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104270` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104271` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104272` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104273` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104274` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104275` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104276` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104277` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104278` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104279` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104280` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104281` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104282` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104283` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104284` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104285` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104286` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104287` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104288` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104289` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104290` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104291` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104292` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104293` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104294` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104295` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104296` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104297` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104298` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104299` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104300` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104301` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104302` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104303` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104304` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104305` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104306` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104307` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104308` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104309` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104310` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104311` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104312` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104313` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104314` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104315` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104316` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104317` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104318` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104319` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104320` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104321` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104322` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104323` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104324` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104325` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104326` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104327` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104328` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104329` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104330` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104331` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104332` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104333` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104334` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104335` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104336` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104337` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104338` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104339` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104340` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104341` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104342` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104343` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104344` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104345` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104346` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104347` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104348` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104349` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104350` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104351` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104352` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104353` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104354` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104355` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104356` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104357` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104358` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104359` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104360` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104361` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104362` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104363` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104364` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104365` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104366` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104367` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104368` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104369` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104370` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104371` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104372` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104373` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104374` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104375` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104376` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104377` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104378` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104379` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104380` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104381` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104382` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104383` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104384` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104385` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104386` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104387` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104388` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104389` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104390` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104391` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104392` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104393` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104394` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104395` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104396` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104397` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104398` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104399` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104400` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104401` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104402` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104403` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104404` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104405` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104406` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104407` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104408` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104409` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104410` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104411` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104412` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104413` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104414` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104415` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104416` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104417` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104418` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104419` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104420` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104421` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104422` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104423` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104424` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104425` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104426` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104427` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104428` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104429` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104430` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104431` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104432` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104433` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104434` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104435` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104436` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104437` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104438` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104439` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104440` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104441` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104442` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104443` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104444` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104445` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104446` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104447` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104448` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104449` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104450` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104451` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104452` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104453` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104454` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104455` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104456` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104457` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104458` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104459` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104460` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104461` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104462` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104463` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104464` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104465` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104466` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104467` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104468` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104469` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104470` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104471` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104472` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104473` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104474` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104475` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104476` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104477` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104478` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104479` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104480` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104481` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104482` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104483` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104484` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104485` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104486` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104487` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104488` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104489` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104490` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104491` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104492` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104493` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104494` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104495` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104496` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104497` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104498` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104499` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104500` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104501` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104502` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104503` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104504` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104505` | 9 | `T1546.003` T1546.003 | WMI event subscription (EventID 20) | medium | 61622 |
| `104506` | 9 | `T1546.003` T1546.003 | WMI event subscription (EventID 19) | medium | 61621 |
| `104507` | 7 | `T1098` T1098 | Security group created | low | 60100 |
| `104508` | 7 | `T1098` T1098 | Security group changed | low | 60100 |
| `104509` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104510` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104511` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104512` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104513` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104514` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104515` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104516` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104517` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104518` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `104519` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `104520` | 10 | - | MSSQL Add Account To Sysadmin Role | high | 60003 |
| `104521` | 10 | - | MSSQL SPProcoption Set | high | 60003 |
| `104522` | 9 | `T1197` T1197 | BITS Transfer Job Downloading File Potential Suspicious Extension | medium | 60000 |
| `104523` | 10 | `T1197` T1197 | BITS Transfer Job Download From File Sharing Domains | high | 60000 |
| `104524` | 10 | `T1197` T1197 | BITS Transfer Job Download From Direct IP | high | 60000 |
| `104525` | 9 | `T1197` T1197 | BITS Transfer Job With Uncommon Or Suspicious Remote TLD | medium | 60000 |
| `104526` | 10 | `T1197` T1197 | BITS Transfer Job Download To Potential Suspicious Folder | high | 60000 |
| `104527` | 10 | `T1543` Create or Modify System Process | CodeIntegrity - Blocked Image/Driver Load For Policy Violation | high | 60000 |
| `104528` | 10 | `T1543` Create or Modify System Process | CodeIntegrity - Blocked Driver Load With Revoked Certificate | high | 60000 |
| `104529` | 9 | `T1685.001` T1685.001 | ETW Logging/Processing Option Disabled On IIS Server | medium | 60000 |
| `104530` | 10 | `T1685.001` T1685.001 | HTTP Logging Disabled On IIS Server | high | 60000 |
| `104531` | 9 | `T1685.001` T1685.001 | New Module Module Added To IIS Server | medium | 60000 |
| `104532` | 10 | `T1505.003` T1505.003 | Certificate Request Export to Exchange Webserver | high | 60000 |
| `104533` | 10 | `T1505.003` T1505.003 | Mailbox Export to Exchange Webserver | high | 60000 |
| `104534` | 10 | `T1505.003` T1505.003 | Exchange Set OabVirtualDirectory ExternalUrl Property | high | 60000 |
| `104535` | 10 | `T1505.002` T1505.002 | Failed MSExchange Transport Agent Installation | high | 60000 |
| `104536` | 13 | `T1021.002` T1021.002 | CobaltStrike Service Installations - Security | high | 60100 |
| `104537` | 10 | `T1112` T1112 | ETW Logging Disabled In .NET Processes - Registry | high | 60100 |
| `104538` | 10 | `T1112` T1112 | ETW Logging Disabled In .NET Processes - Registry | high | 60100 |
| `104539` | 10 | `T1136.001` T1136.001 | Hidden Local User Creation | high | 60100 |
| `104540` | 10 | `T1554` T1554 | HybridConnectionManager Service Installation | high | 60100 |
| `104541` | 10 | `T1685` T1685 | NetNTLM Downgrade Attack | high | 60100 |
| `104542` | 10 | `T1543` Create or Modify System Process | Service Installed By Unusual Client - Security | high | 60100 |
| `104543` | 9 | `T1134.005` T1134.005 | Addition of SID History to Active Directory Object | medium | 60100 |
| `104544` | 9 | `T1078` Valid Accounts | Account Tampering - Suspicious Failed Logon Reasons | medium | 60100 |
| `104545` | 9 | `T1484.001` T1484.001 | Startup/Logon Script Added to Group Policy Object | medium | 60100 |
| `104546` | 10 | `T1136.001` T1136.001 | Suspicious Windows ANONYMOUS LOGON Local Account Created | high | 60100 |
| `104547` | 10 | `T1556` T1556 | Possible Shadow Credentials Added | high | 60100 |
| `104548` | 10 | `T1112` T1112 | Sysmon Channel Reference Deletion | high | 60100 |
| `104549` | 10 | `T1112` T1112 | Sysmon Channel Reference Deletion | high | 60100 |
| `104550` | 9 | `T1546.003` T1546.003 | WMI Persistence - Security | medium | 60100 |
| `104551` | 10 | `T1554` T1554 | HybridConnectionManager Service Running | high | 60000 |
| `104552` | 13 | `T1021.002` T1021.002 | CobaltStrike Service Installations - System | high | 60106 |
| `104553` | 10 | `T1543` Create or Modify System Process | KrbRelayUp Service Installation | high | 60106 |
| `104554` | 10 | `T1543.003` T1543.003 | Moriya Rootkit - System | high | 60106 |
| `104555` | 9 | - | Anydesk Remote Access Software Service Installation | medium | 60106 |
| `104556` | 9 | - | NetSupport Manager Service Install | medium | 60106 |
| `104557` | 9 | `T1543.003` T1543.003 | New PDQDeploy Service - Server Side | medium | 60106 |
| `104558` | 9 | `T1543.003` T1543.003 | New PDQDeploy Service - Client Side | medium | 60106 |
| `104559` | 10 | `T1543.003` T1543.003 | ProcessHacker Privilege Elevation | high | 60106 |
| `104560` | 9 | - | Remote Utilities Host Service Install | medium | 60106 |
| `104561` | 10 | `T1543.003` T1543.003 | Sliver C2 Default Service Installation | high | 60106 |
| `104562` | 10 | `T1543` Create or Modify System Process | Service Installed By Unusual Client - System | high | 60106 |
| `104563` | 10 | `T1543.003` T1543.003 | Suspicious Service Installation | high | 60106 |
| `104564` | 9 | `T1543.003` T1543.003 | Uncommon Service Installation Image Path | medium | 60106 |
| `104565` | 10 | - | RTCore Suspicious Service Installation | high | 60106 |
| `104566` | 9 | `T1543.003` T1543.003 | Service Installation in Suspicious Folder | medium | 60106 |
| `104567` | 10 | `T1543.003` T1543.003 | Service Installation with Suspicious Folder Pattern | high | 60106 |
| `104568` | 10 | `T1543.003` T1543.003 | Suspicious Service Installation Script | high | 60106 |
| `104569` | 9 | `T1546.003` T1546.003 | WMI Persistence | medium | 61621 |
| `104570` | 10 | - | Potential Suspicious Winget Package Installation | high | 61617 |
| `104571` | 10 | `T1554` T1554 | DNS HybridConnectionManager Service Bus | high | 61624 |
| `104572` | 10 | `T1543.003` T1543.003 | Malicious Driver Load | high | 61608 |
| `104573` | 13 | `T1543.003` T1543.003 | Malicious Driver Load By Name | medium | 61608 |
| `104574` | 10 | `T1543` Create or Modify System Process | PUA - Process Hacker Driver Load | high | 61608 |
| `104575` | 10 | `T1543` Create or Modify System Process | PUA - Process Hacker Driver Load | high | 61608 |
| `104576` | 9 | `T1543` Create or Modify System Process | PUA - System Informer Driver Load | medium | 61608 |
| `104577` | 9 | `T1543` Create or Modify System Process | PUA - System Informer Driver Load | medium | 61608 |
| `104578` | 10 | `T1543.003` T1543.003 | Driver Load From A Temporary Directory | high | 61608 |
| `104579` | 10 | `T1543.003` T1543.003 | Vulnerable Driver Load | high | 61608 |
| `104580` | 10 | `T1543.003` T1543.003 | Vulnerable HackSys Extreme Vulnerable Driver Load | high | 61608 |
| `104581` | 10 | `T1543.003` T1543.003 | Vulnerable HackSys Extreme Vulnerable Driver Load | high | 61608 |
| `104582` | 10 | `T1543.003` T1543.003 | Vulnerable WinRing0 Driver Load | high | 61608 |
| `104583` | 10 | `T1543.003` T1543.003 | Vulnerable WinRing0 Driver Load | high | 61608 |
| `104584` | 10 | `T1133` T1133 | Unusual File Modification by dns.exe | high | 61604 |
| `104585` | 10 | `T1133` T1133 | Unusual File Deletion by Dns.exe | high | 61625 |
| `104586` | 9 | `T1574.001` T1574.001 | Creation Of Non-Existent System DLL | medium | 61613 |
| `104587` | 10 | `T1574.001` T1574.001 | DLL Search Order Hijackig Via Additional Space in Path | high | 61613 |
| `104588` | 9 | - | Potential Persistence Attempt Via ErrorHandler.Cmd | medium | 61613 |
| `104589` | 10 | `T1505.003` T1505.003 | Suspicious ASPX File Drop by Exchange | high | 61613 |
| `104590` | 9 | `T1190` Exploit Public-Facing Application | Suspicious File Drop by Exchange | medium | 61613 |
| `104591` | 10 | `T1574.001` T1574.001 | HackTool - Powerup Write Hijack DLL | high | 61613 |
| `104592` | 10 | `T1574.001` T1574.001 | Malicious DLL File Dropped in the Teams or OneDrive Folder | high | 61613 |
| `104593` | 9 | - | Potential Persistence Via Notepad++ Plugins | medium | 61613 |
| `104594` | 10 | `T1137.006` T1137.006 | Potential Persistence Via Microsoft Office Add-In | high | 61613 |
| `104595` | 10 | `T1137.006` T1137.006 | Potential Persistence Via Microsoft Office Add-In | high | 61613 |
| `104596` | 10 | `T1137.006` T1137.006 | Potential Persistence Via Microsoft Office Add-In | high | 61613 |
| `104597` | 10 | `T1137.006` T1137.006 | Potential Persistence Via Microsoft Office Add-In | high | 61613 |
| `104598` | 10 | `T1137.003` T1137.003 | Potential Persistence Via Outlook Form | high | 61613 |
| `104599` | 10 | `T1137` T1137 | Potential Persistence Via Microsoft Office Startup Folder | high | 61613 |
| `104600` | 9 | - | Potential Binary Or Script Dropper Via PowerShell | medium | 61613 |
| `104601` | 9 | - | Potential Suspicious PowerShell Module File Created | medium | 61613 |
| `104602` | 9 | - | PowerShell Module File Created By Non-PowerShell Process | medium | 61613 |
| `104603` | 9 | `T1505.003` T1505.003 | Suspicious File Write to Webapps Root Directory | medium | 61613 |
| `104604` | 9 | `T1546.013` T1546.013 | PowerShell Profile Modification | medium | 61613 |
| `104605` | 10 | - | Suspicious File Creation Activity From Fake Recycle.Bin Folder | high | 61613 |
| `104606` | 10 | - | Suspicious File Creation Activity From Fake Recycle.Bin Folder | high | 61613 |
| `104607` | 9 | `T1546.013` T1546.013 | VsCode Powershell Profile Modification | medium | 61613 |
| `104608` | 10 | `T1068` Exploitation for Privilege Escalation | Process Explorer Driver Creation By Non-Sysinternals Binary | high | 61613 |
| `104609` | 9 | `T1068` Exploitation for Privilege Escalation | Process Monitor Driver Creation By Non-Sysinternals Binary | medium | 61613 |
| `104610` | 10 | - | Potential Privilege Escalation Attempt Via .Exe.Local Technique | high | 61613 |
| `104611` | 9 | `T1505.003` T1505.003 | Potential Webshell Creation On Static Website | medium | 61613 |
| `104612` | 10 | `T1542.001` T1542.001 | UEFI Persistence Via Wpbbin - FileCreation | high | 61613 |
| `104613` | 9 | `T1574.001` T1574.001 | Potential Antivirus Software DLL Sideloading | medium | 61609 |
| `104614` | 10 | `T1574.001` T1574.001 | Potential appverifUI.DLL Sideloading | high | 61609 |
| `104615` | 9 | `T1574.001` T1574.001 | Potential AVKkid.DLL Sideloading | medium | 61609 |
| `104616` | 9 | `T1574.001` T1574.001 | Potential CCleanerDU.DLL Sideloading | medium | 61609 |
| `104617` | 9 | `T1574.001` T1574.001 | Potential CCleanerReactivator.DLL Sideloading | medium | 61609 |
| `104618` | 9 | `T1574.001` T1574.001 | Potential Chrome Frame Helper DLL Sideloading | medium | 61609 |
| `104619` | 9 | `T1574.001` T1574.001 | Potential DLL Sideloading Via ClassicExplorer32.dll | medium | 61609 |
| `104620` | 10 | `T1574.001` T1574.001 | Potential DLL Sideloading Via comctl32.dll | high | 61609 |
| `104621` | 10 | `T1574.001` T1574.001 | System Control Panel Item Loaded From Uncommon Location | high | 61609 |
| `104622` | 9 | `T1574.001` T1574.001 | Potential DLL Sideloading Of DBGCORE.DLL | medium | 61609 |
| `104623` | 9 | `T1574.001` T1574.001 | Potential DLL Sideloading Of DBGHELP.DLL | medium | 61609 |
| `104624` | 10 | `T1574.001` T1574.001 | Potential EACore.DLL Sideloading | high | 61609 |
| `104625` | 10 | `T1574.001` T1574.001 | Potential Edputil.DLL Sideloading | high | 61609 |
| `104626` | 10 | `T1574.001` T1574.001 | Potential System DLL Sideloading From Non System Locations | high | 61609 |
| `104627` | 9 | `T1574.001` T1574.001 | Potential Goopdate.DLL Sideloading | medium | 61609 |
| `104628` | 9 | `T1574.001` T1574.001 | Potential DLL Sideloading Of Libcurl.DLL Via GUP.EXE | medium | 61609 |
| `104629` | 10 | `T1574.001` T1574.001 | Potential Iviewers.DLL Sideloading | high | 61609 |
| `104630` | 10 | `T1574.001` T1574.001 | Potential JLI.dll Side-Loading | high | 61609 |
| `104631` | 9 | `T1574.001` T1574.001 | Potential DLL Sideloading Via JsSchHlp | medium | 61609 |
| `104632` | 10 | `T1574.001` T1574.001 | Potential DLL Sideloading Of KeyScramblerIE.DLL Via KeyScrambler.EXE | high | 61609 |
| `104633` | 9 | `T1574.001` T1574.001 | Potential Libvlc.DLL Sideloading | medium | 61609 |
| `104634` | 9 | `T1574.001` T1574.001 | Potential Mfdetours.DLL Sideloading | medium | 61609 |
| `104635` | 10 | `T1574.001` T1574.001 | Unsigned Mfdetours.DLL Sideloading | high | 61609 |
| `104636` | 10 | `T1574.001` T1574.001 | Potential DLL Sideloading Of Non-Existent DLLs From System Folders | high | 61609 |
| `104637` | 10 | `T1574.001` T1574.001 | Microsoft Office DLL Sideload | high | 61609 |
| `104638` | 10 | `T1574.001` T1574.001 | Potential Rcdll.DLL Sideloading | high | 61609 |
| `104639` | 9 | `T1574.001` T1574.001 | Potential RjvPlatform.DLL Sideloading From Default Location | medium | 61609 |
| `104640` | 10 | `T1574.001` T1574.001 | Potential RjvPlatform.DLL Sideloading From Non-Default Location | high | 61609 |
| `104641` | 9 | `T1574.001` T1574.001 | Potential RoboForm.DLL Sideloading | medium | 61609 |
| `104642` | 10 | `T1574.001` T1574.001 | DLL Sideloading Of ShellChromeAPI.DLL | high | 61609 |
| `104643` | 9 | `T1574.001` T1574.001 | Potential ShellDispatch.DLL Sideloading | medium | 61609 |
| `104644` | 10 | `T1574.001` T1574.001 | Potential SmadHook.DLL Sideloading | high | 61609 |
| `104645` | 9 | `T1574.001` T1574.001 | Potential SolidPDFCreator.DLL Sideloading | medium | 61609 |
| `104646` | 9 | `T1574.001` T1574.001 | Third Party Software DLL Sideloading | medium | 61609 |
| `104647` | 10 | `T1574.001` T1574.001 | Potential Vcruntime140 DLL Sideloading | high | 61609 |
| `104648` | 9 | `T1574.001` T1574.001 | Potential Vivaldi_elf.DLL Sideloading | medium | 61609 |
| `104649` | 9 | `T1574.001` T1574.001 | VMGuestLib DLL Sideload | medium | 61609 |
| `104650` | 9 | `T1574.001` T1574.001 | VMMap Signed Dbghelp.DLL Potential Sideloading | medium | 61609 |
| `104651` | 10 | `T1574.001` T1574.001 | VMMap Unsigned Dbghelp.DLL Potential Sideloading | high | 61609 |
| `104652` | 10 | `T1574.001` T1574.001 | Potential Waveedit.DLL Sideloading | high | 61609 |
| `104653` | 9 | `T1574.001` T1574.001 | Potential Wazuh Security Platform DLL Sideloading | medium | 61609 |
| `104654` | 9 | `T1574.001` T1574.001 | Potential WWlib.DLL Sideloading | medium | 61609 |
| `104655` | 10 | `T1548.002` T1548.002 | UAC Bypass With Fake DLL | high | 61609 |
| `104656` | 10 | `T1574.007` T1574.007 | Trusted Path Bypass via Windows Directory Spoofing | high | 61609 |
| `104657` | 9 | `T1219.002` T1219.002 | Remote Access Tool - AnyDesk Incoming Connection | medium | 61605 |
| `104658` | 10 | `T1571` T1571 | Potentially Suspicious Malware Callback Communication | high | 61605 |
| `104659` | 9 | `T1571` T1571 | Communication To Uncommon Destination Ports | medium | 61605 |
| `104660` | 10 | `T1556.002` T1556.002 | Powershell Install a DLL in System Directory | high | 91801 |
| `104661` | 9 | `T1136.002` T1136.002 | Manipulation of User Computer or Group Security Principals Across AD | medium | 91801 |
| `104662` | 9 | - | Unsigned AppX Installation Attempt Using Add-AppxPackage - PsScript | medium | 91801 |
| `104663` | 10 | `T1137.006` T1137.006 | Code Executed Via Office Add-in XLL File | high | 91801 |
| `104664` | 10 | `T1059.001` T1059.001 | PowerShell Web Access Installation - PsScript | high | 91801 |
| `104665` | 10 | `T1059.001` T1059.001 | PowerShell Web Access Installation - PsScript | high | 91801 |
| `104666` | 10 | `T1059.001` T1059.001 | PowerShell Web Access Installation - PsScript | high | 91801 |
| `104667` | 10 | - | Potential Persistence Via Security Descriptors - ScriptBlock | high | 91801 |
| `104668` | 10 | `T1574.011` T1574.011 | Suspicious Service DACL Modification Via Set-Service Cmdlet - PS | high | 91801 |
| `104669` | 9 | `T1546.013` T1546.013 | Potential Persistence Via PowerShell User Profile Using Add-Content | medium | 91801 |
| `104670` | 10 | `T1574.011` T1574.011 | Abuse of Service Permissions to Hide Services Via Set-Service - PS | high | 91801 |
| `104671` | 9 | `T1112` T1112 | Registry Modification Attempt Via VBScript - PowerShell | medium | 91801 |
| `104672` | 9 | `T1546.003` T1546.003 | Powershell WMI Persistence | medium | 91801 |
| `104673` | 10 | `T1053.002` T1053.002 | Interactive AT Job | high | 61603 |
| `104674` | 9 | `T1070` Indicator Removal | Potential Ransomware or Unauthorized MBR Tampering Via Bcdedit.EXE | medium | 61603 |
| `104675` | 9 | `T1197` T1197 | File Download Via Bitsadmin | medium | 61603 |
| `104676` | 10 | `T1197` T1197 | Suspicious Download From Direct IP Via Bitsadmin | high | 61603 |
| `104677` | 10 | `T1197` T1197 | Suspicious Download From File-Sharing Website Via Bitsadmin | high | 61603 |
| `104678` | 10 | `T1197` T1197 | File With Suspicious Extension Downloaded Via Bitsadmin | high | 61603 |
| `104679` | 10 | `T1197` T1197 | File Download Via Bitsadmin To A Suspicious Target Folder | high | 61603 |
| `104680` | 9 | `T1197` T1197 | Monitoring For Persistence Via BITS | medium | 61603 |
| `104681` | 9 | `T1176.001` T1176.001 | Chromium Browser Instance Executed With Custom Extension | medium | 61603 |
| `104682` | 10 | `T1176.001` T1176.001 | Suspicious Chromium Browser Instance Executed With Custom Extension | high | 61603 |
| `104683` | 10 | `T1546.008` T1546.008 | Persistence Via Sticky Key Backdoor | high | 61603 |
| `104684` | 10 | `T1543.003` T1543.003 | Devcon Execution Disabling VMware VMCI Device | high | 61603 |
| `104685` | 10 | `T1133` T1133 | Unusual Child Process of dns.exe | high | 61603 |
| `104686` | 10 | `T1685.001` T1685.001 | Security Event Logging Disabled via MiniNt Registry Key - Process | high | 61603 |
| `104687` | 10 | `T1615` T1615 | HackTool - SharpUp PrivEsc Tool Execution | high | 61603 |
| `104688` | 10 | `T1615` T1615 | HackTool - SharpUp PrivEsc Tool Execution | high | 61603 |
| `104689` | 10 | `T1615` T1615 | HackTool - SharpUp PrivEsc Tool Execution | high | 61603 |
| `104690` | 9 | `T1505.003` T1505.003 | IIS Native-Code Module Command Line Installation | medium | 61603 |
| `104691` | 10 | `T1505.004` T1505.004 | Suspicious IIS Module Registration | high | 61603 |
| `104692` | 9 | `T1203` T1203 | Potentially Suspicious Child Process of KeyScrambler.exe | medium | 61603 |
| `104693` | 9 | `T1136.001` T1136.001 | New User Created Via Net.EXE | medium | 61603 |
| `104694` | 10 | `T1136.001` T1136.001 | New User Created Via Net.EXE With Never Expire Option | high | 61603 |
| `104695` | 10 | `T1574.011` T1574.011 | Abuse of Service Permissions to Hide Services Via Set-Service | high | 61603 |
| `104696` | 9 | - | Unsigned AppX Installation Attempt Using Add-AppxPackage | medium | 61603 |
| `104697` | 9 | `T1505.002` T1505.002 | MSExchange Transport Agent Installation | medium | 61603 |
| `104698` | 10 | `T1543.003` T1543.003 | PUA - Kernel Driver Utility (KDU) Execution | high | 61603 |
| `104699` | 9 | `T1082` System Information Discovery | PUA - System Informer Execution | medium | 61603 |
| `104700` | 9 | `T1082` System Information Discovery | PUA - System Informer Execution | medium | 61603 |
| `104701` | 9 | `T1082` System Information Discovery | PUA - System Informer Execution | medium | 61603 |
| `104702` | 9 | `T1082` System Information Discovery | PUA - System Informer Execution | medium | 61603 |
| `104703` | 9 | `T1082` System Information Discovery | PUA - System Informer Execution | medium | 61603 |
| `104704` | 9 | `T1556.002` T1556.002 | Dropping Of Password Filter DLL | medium | 61603 |
| `104705` | 9 | `T1112` T1112 | Potentially Suspicious Desktop Background Change Using Reg.EXE | medium | 61603 |
| `104706` | 9 | `T1112` T1112 | Potential Suspicious Registry File Imported Via Reg.EXE | medium | 61603 |
| `104707` | 10 | `T1112` T1112 | RestrictedAdminMode Registry Value Tampering - ProcCreation | high | 61603 |
| `104708` | 10 | `T1112` T1112 | Enable LM Hash Storage - ProcCreation | high | 61603 |
| `104709` | 10 | `T1021.001` T1021.001 | Potential Tampering With RDP Related Registry Keys Via Reg.EXE | high | 61603 |
| `104710` | 9 | `T1546.002` T1546.002 | Suspicious ScreenSave Change by Reg.exe | medium | 61603 |
| `104711` | 10 | `T1112` T1112 | Reg Add Suspicious Paths | high | 61603 |
| `104712` | 9 | `T1112` T1112 | Imports Registry Key From a File | medium | 61603 |
| `104713` | 10 | `T1112` T1112 | Imports Registry Key From an ADS | high | 61603 |
| `104714` | 10 | `T1112` T1112 | Suspicious Registry Modification From ADS Via Regini.EXE | high | 61603 |
| `104715` | 10 | `T1546.008` T1546.008 | Suspicious Debugger Registration Cmdline | high | 61603 |
| `104716` | 10 | `T1574.011` T1574.011 | Potential Privilege Escalation via Service Permissions Weakness | high | 61603 |
| `104717` | 9 | - | Persistence Via TypedPaths - CommandLine | medium | 61603 |
| `104718` | 9 | `T1133` T1133 | Remote Access Tool - ScreenConnect Installation Execution | medium | 61603 |
| `104719` | 10 | `T1112` T1112 | ShimCache Flush | high | 61603 |
| `104720` | 10 | `T1574.011` T1574.011 | Possible Privilege Escalation via Weak Service Permissions | high | 61603 |
| `104721` | 9 | `T1543.003` T1543.003 | New Kernel Driver Via SC.EXE | medium | 61603 |
| `104722` | 10 | `T1574.011` T1574.011 | Service DACL Abuse To Hide Services Via Sc.EXE | high | 61603 |
| `104723` | 9 | `T1574.011` T1574.011 | Service Security Descriptor Tampering Via Sc.EXE | medium | 61603 |
| `104724` | 10 | `T1543.003` T1543.003 | Suspicious Service Path Modification | high | 61603 |
| `104725` | 9 | `T1546.011` T1546.011 | Potential Shim Database Persistence via Sdbinst.EXE | medium | 61603 |
| `104726` | 9 | `T1546.011` T1546.011 | Uncommon Extension Shim Database Installation Via Sdbinst.EXE | medium | 61603 |
| `104727` | 9 | `T1211` T1211 | Writing Of Malicious Files To The Fonts Folder | medium | 61603 |
| `104728` | 10 | `T1112` T1112 | Non-privileged Usage of Reg or Powershell | high | 61603 |
| `104729` | 10 | - | Suspicious Process Execution From Fake Recycle.Bin Folder | high | 61603 |
| `104730` | 10 | `T1543.003` T1543.003 | Suspicious New Service Creation | high | 61603 |
| `104731` | 10 | `T1543.003` T1543.003 | Suspicious New Service Creation | high | 61603 |
| `104732` | 10 | `T1547.001` T1547.001 | User Shell Folders Registry Modification via CommandLine | high | 61603 |
| `104733` | 9 | `T1112` T1112 | Registry Modification Attempt Via VBScript | medium | 61603 |
| `104734` | 9 | `T1112` T1112 | Suspicious VBoxDrvInst.exe Parameters | medium | 61603 |
| `104735` | 10 | `T1505.003` T1505.003 | Chopper Webshell Process Pattern | high | 61603 |
| `104736` | 10 | `T1505.003` T1505.003 | Webshell Hacking Activity Patterns | high | 61603 |
| `104737` | 10 | `T1505.003` T1505.003 | Webshell Hacking Activity Patterns | high | 61603 |
| `104738` | 10 | `T1505.003` T1505.003 | Webshell Hacking Activity Patterns | high | 61603 |
| `104739` | 10 | `T1505.003` T1505.003 | Webshell Detection With Command Line Keywords | high | 61603 |
| `104740` | 10 | `T1505.003` T1505.003 | Webshell Detection With Command Line Keywords | high | 61603 |
| `104741` | 10 | `T1505.003` T1505.003 | Webshell Detection With Command Line Keywords | high | 61603 |
| `104742` | 10 | `T1505.003` T1505.003 | Suspicious Process By Web Server Process | high | 61603 |
| `104743` | 10 | `T1505.003` T1505.003 | Suspicious Process By Web Server Process | high | 61603 |
| `104744` | 10 | `T1505.003` T1505.003 | Suspicious Process By Web Server Process | high | 61603 |
| `104745` | 10 | `T1505.003` T1505.003 | Webshell Tool Reconnaissance Activity | high | 61603 |
| `104746` | 10 | `T1505.003` T1505.003 | Webshell Tool Reconnaissance Activity | high | 61603 |
| `104747` | 10 | `T1505.003` T1505.003 | Webshell Tool Reconnaissance Activity | high | 61603 |
| `104748` | 9 | `T1546.003` T1546.003 | WMI Persistence - Script Event Consumer | medium | 61603 |
| `104749` | 9 | `T1047` T1047 | Registry Manipulation via WMI Stdregprov | medium | 61603 |
| `104750` | 10 | `T1542.001` T1542.001 | UEFI Persistence Via Wpbbin - ProcessCreation | high | 61603 |
| `104751` | 9 | - | Potential Persistence Via Disk Cleanup Handler - Registry | medium | 61614 |
| `104752` | 10 | `T1070` Indicator Removal | Terminal Server Client Connection History Cleared - Registry | high | 61614 |
| `104753` | 10 | `T1070` Indicator Removal | Terminal Server Client Connection History Cleared - Registry | high | 61614 |
| `104754` | 9 | `T1112` T1112 | Removal of Potential COM Hijacking Registry Keys | medium | 61614 |
| `104755` | 12 | `T1136.001` T1136.001 | Creation of a Local Hidden User Account by Registry | high | 61615 |
| `104756` | 10 | `T1685.001` T1685.001 | Disable Security Events Logging Adding Reg Key MiniNt | high | 61615 |
| `104757` | 10 | `T1685.001` T1685.001 | Disable Security Events Logging Adding Reg Key MiniNt | high | 61615 |
| `104758` | 10 | `T1112` T1112 | Wdigest CredGuard Registry Modification | high | 61615 |
| `104759` | 10 | `T1112` T1112 | Registry Entries For Azorult Malware | high | 61615 |
| `104760` | 10 | `T1112` T1112 | Potential Qakbot Registry Activity | high | 61615 |
| `104761` | 9 | `T1546.002` T1546.002 | Path To Screensaver Binary Modified | medium | 61615 |
| `104762` | 10 | `T1685` T1685 | NetNTLM Downgrade Attack - Registry | high | 61615 |
| `104763` | 9 | `T1137.002` T1137.002 | Office Application Startup - Office Test | medium | 61615 |
| `104764` | 10 | `T1112` T1112 | RedMimicry Winnti Playbook Registry Manipulation | high | 61615 |
| `104765` | 9 | `T1112` T1112 | Run Once Task Configuration in Registry | medium | 61615 |
| `104766` | 10 | `T1548.002` T1548.002 | Shell Open Registry Keys Manipulation | high | 61615 |
| `104767` | 9 | `T1112` T1112 | Registry Tampering by Potentially Suspicious Processes | medium | 61615 |
| `104768` | 9 | - | Add Debugger Entry To AeDebug For Persistence | medium | 61615 |
| `104769` | 9 | `T1112` T1112 | Allow RDP Remote Assistance Feature | medium | 61615 |
| `104770` | 9 | `T1112` T1112 | New BgInfo.EXE Custom DB Path Registry Configuration | medium | 61615 |
| `104771` | 9 | `T1112` T1112 | New BgInfo.EXE Custom VBScript Registry Configuration | medium | 61615 |
| `104772` | 9 | `T1112` T1112 | New BgInfo.EXE Custom WMI Query Registry Configuration | medium | 61615 |
| `104773` | 9 | `T1137` T1137 | IE Change Domain Zone | medium | 61615 |
| `104774` | 9 | `T1112` T1112 | ClickOnce Trust Prompt Tampering | medium | 61615 |
| `104775` | 13 | `T1021.002` T1021.002 | Potential CobaltStrike Service Installations - Registry | high | 61615 |
| `104776` | 10 | `T1546` T1546 | COM Hijack via Sdclt | high | 61615 |
| `104777` | 9 | `T1564` T1564 | CrashControl CrashDump Disabled | medium | 61615 |
| `104778` | 10 | `T1685.001` T1685.001 | Security Event Logging Disabled via MiniNt Registry Key - Registry Set | high | 61615 |
| `104779` | 10 | `T1112` T1112 | Service Binary in Suspicious Folder | high | 61615 |
| `104780` | 10 | `T1112` T1112 | Service Binary in Suspicious Folder | high | 61615 |
| `104781` | 9 | `T1112` T1112 | Potentially Suspicious Desktop Background Change Via Registry | medium | 61615 |
| `104782` | 9 | `T1112` T1112 | Disable Internal Tools or Feature in Registry | medium | 61615 |
| `104783` | 9 | `T1112` T1112 | Disable Internal Tools or Feature in Registry | medium | 61615 |
| `104784` | 9 | `T1112` T1112 | Disable Windows Security Center Notifications | medium | 61615 |
| `104785` | 9 | `T1112` T1112 | Add DisallowRun Execution to Registry | medium | 61615 |
| `104786` | 9 | - | Persistence Via Disk Cleanup Handler - Autorun | medium | 61615 |
| `104787` | 9 | `T1140` T1140 | DNS-over-HTTPS Enabled by Registry | medium | 61615 |
| `104788` | 9 | `T1140` T1140 | DNS-over-HTTPS Enabled by Registry | medium | 61615 |
| `104789` | 9 | `T1140` T1140 | DNS-over-HTTPS Enabled by Registry | medium | 61615 |
| `104790` | 10 | `T1112` T1112 | ETW Logging Disabled In .NET Processes - Sysmon Registry | high | 61615 |
| `104791` | 10 | `T1112` T1112 | ETW Logging Disabled In .NET Processes - Sysmon Registry | high | 61615 |
| `104792` | 9 | `T1574.012` T1574.012 | Enabling COR Profiler Environment Variables | medium | 61615 |
| `104793` | 9 | `T1574.012` T1574.012 | Enabling COR Profiler Environment Variables | medium | 61615 |
| `104794` | 10 | `T1112` T1112 | Change User Account Associated with the FAX Service | high | 61615 |
| `104795` | 10 | `T1112` T1112 | Change the Fax Dll | high | 61615 |
| `104796` | 10 | - | Add Debugger Entry To Hangs Key For Persistence | high | 61615 |
| `104797` | 10 | - | Persistence Via Hhctrl.ocx | high | 61615 |
| `104798` | 9 | `T1137` T1137 | Registry Modification to Hidden File Extension | medium | 61615 |
| `104799` | 9 | `T1137` T1137 | Registry Modification to Hidden File Extension | medium | 61615 |
| `104800` | 9 | `T1112` T1112 | Registry Hide Function from User | medium | 61615 |
| `104801` | 9 | `T1112` T1112 | Registry Hide Function from User | medium | 61615 |
| `104802` | 10 | `T1112` T1112 | RestrictedAdminMode Registry Value Tampering | high | 61615 |
| `104803` | 10 | `T1112` T1112 | NET NGenAssemblyUsageLog Registry Key Tamper | high | 61615 |
| `104804` | 10 | `T1112` T1112 | Trust Access Disable For VBApplications | high | 61615 |
| `104805` | 10 | `T1112` T1112 | Outlook EnableUnsafeClientMailRules Setting Enabled - Registry | high | 61615 |
| `104806` | 9 | `T1137` T1137 | Outlook Security Settings Updated - Registry | medium | 61615 |
| `104807` | 10 | `T1112` T1112 | Macro Enabled In A Potentially Suspicious Document | high | 61615 |
| `104808` | 10 | `T1112` T1112 | Uncommon Microsoft Office Trusted Location Added | high | 61615 |
| `104809` | 10 | `T1112` T1112 | Office Macros Warning Disabled | high | 61615 |
| `104810` | 9 | - | Potential Persistence Via New AMSI Providers - Registry | medium | 61615 |
| `104811` | 10 | - | Potential Persistence Via AutodialDLL | high | 61615 |
| `104812` | 10 | - | Potential Persistence Via CHM Helper DLL | high | 61615 |
| `104813` | 9 | `T1112` T1112 | Potential Persistence Via Custom Protocol Handler | medium | 61615 |
| `104814` | 9 | `T1112` T1112 | Potential Persistence Via Event Viewer Events.asp | medium | 61615 |
| `104815` | 9 | - | Register New IFiltre For Persistence | medium | 61615 |
| `104816` | 9 | - | Register New IFiltre For Persistence | medium | 61615 |
| `104817` | 10 | - | Potential Persistence Via LSA Extensions | high | 61615 |
| `104818` | 10 | - | Potential Persistence Via Mpnotify | high | 61615 |
| `104819` | 10 | - | Potential Persistence Via MyComputer Registry Keys | high | 61615 |
| `104820` | 10 | - | Potential Persistence Via DLLPathOverride | high | 61615 |
| `104821` | 9 | `T1137.006` T1137.006 | Potential Persistence Via Visual Studio Tools for Office | medium | 61615 |
| `104822` | 10 | `T1112` T1112 | Potential Persistence Via Outlook Home Page | high | 61615 |
| `104823` | 10 | `T1112` T1112 | Potential Persistence Via Outlook Today Page | high | 61615 |
| `104824` | 10 | - | Potential Persistence Via TypedPaths | high | 61615 |
| `104825` | 10 | `T1137.006` T1137.006 | Potential Persistence Via Excel Add-in - Registry | high | 61615 |
| `104826` | 10 | `T1112` T1112 | Registry Modification for OCI DLL Redirection | high | 61615 |
| `104827` | 10 | `T1564.001` T1564.001 | PowerShell Logging Disabled Via Registry Key Tampering | high | 61615 |
| `104828` | 9 | - | Potential SentinelOne Shell Context Menu Scan Command Tampering | medium | 61615 |
| `104829` | 9 | `T1543.003` T1543.003 | ServiceDll Hijack | medium | 61615 |
| `104830` | 9 | `T1112` T1112 | Registry Explorer Policy Modification | medium | 61615 |
| `104831` | 9 | `T1553.003` T1553.003 | Persistence Via New SIP Provider | medium | 61615 |
| `104832` | 9 | `T1112` T1112 | Activate Suppression of Windows Security Center Notifications | medium | 61615 |
| `104833` | 10 | `T1574` T1574 | Suspicious Printer Driver Empty Manufacturer | high | 61615 |
| `104834` | 10 | `T1547.001` T1547.001 | Modify User Shell Folders Startup Value | high | 61615 |
| `104835` | 10 | - | Suspicious Environment Variable Has Been Registered | high | 61615 |
| `104836` | 10 | `T1112` T1112 | Enable LM Hash Storage | high | 61615 |
| `104837` | 9 | `T1112` T1112 | RDP Sensitive Settings Changed to Zero | medium | 61615 |
| `104838` | 10 | `T1112` T1112 | RDP Sensitive Settings Changed | high | 61615 |
| `104839` | 10 | `T1547.003` T1547.003 | New TimeProviders Registered With Uncommon DLL Name | high | 61615 |
| `104840` | 10 | `T1112` T1112 | Wdigest Enable UseLogonCredential | high | 61615 |
| `104841` | 9 | - | Enable Local Manifest Installation With Winget | medium | 61615 |
| `104842` | 9 | `T1112` T1112 | Winlogon AllowMultipleTSSessions Enable | medium | 61615 |

### Privilege Escalation (TA0004) — 383 rules

| Rule ID | Level | Technique | Description | Confidence | Parent SID |
|---------|-------|-----------|-------------|------------|------------|
| `106000` | 8 | `T1078` Valid Accounts | Special privilege assignment | low | 60100 |
| `106001` | 11 | - | CodeIntegrity - Disallowed File For Protected Processes Has Been Bl... | high | 60000 |
| `106002` | 11 | - | CodeIntegrity - Revoked Kernel Driver Loaded | high | 60000 |
| `106003` | 11 | - | CodeIntegrity - Blocked Image Load With Revoked Certificate | high | 60000 |
| `106004` | 11 | - | CodeIntegrity - Revoked Image Loaded | high | 60000 |
| `106005` | 11 | - | CodeIntegrity - Unsigned Kernel Module Loaded | high | 60000 |
| `106006` | 11 | - | CodeIntegrity - Unsigned Image Loaded | high | 60000 |
| `106007` | 11 | - | CodeIntegrity - Unmet WHQL Requirements For Loaded Kernel Module | high | 60000 |
| `106008` | 11 | `T1574.001` T1574.001 | DNS Server Error Failed Loading the ServerLevelPluginDLL | high | 60000 |
| `106009` | 10 | `T1134.001` T1134.001 | Potential Access Token Abuse | medium | 60100 |
| `106010` | 11 | - | DiagTrackEoP Default Login Username | high | 60100 |
| `106011` | 10 | `T1133` T1133 | External Remote RDP Logon from Public IP | medium | 60100 |
| `106012` | 11 | `T1133` T1133 | External Remote SMB Logon from Public IP | high | 60100 |
| `106013` | 10 | `T1078` Valid Accounts | Failed Logon From Public IP | medium | 60100 |
| `106014` | 11 | `T1548` Abuse Elevation Control Mechanism | Potential Privilege Escalation via Local Kerberos Relay over LDAP | high | 60100 |
| `106015` | 11 | `T1098` T1098 | Powerview Add-DomainObjectAcl DCSync AD Extend Right | high | 60100 |
| `106016` | 11 | - | ADCS Certificate Template Configuration Vulnerability with Risky EKU | high | 60100 |
| `106017` | 11 | `T1098` T1098 | Enabled User Right in AD to Control User Objects | high | 60100 |
| `106018` | 11 | `T1098` T1098 | Active Directory User Backdoors | high | 60100 |
| `106019` | 10 | `T1053.002` T1053.002 | Remote Task Creation via ATSVC Named Pipe | medium | 60100 |
| `106020` | 10 | `T1484.001` T1484.001 | Windows Default Domain GPO Modification | medium | 60100 |
| `106021` | 11 | `T1053.005` T1053.005 | Persistence and Execution at Scale via GPO Scheduled Task | high | 60100 |
| `106022` | 11 | `T1053.005` T1053.005 | Persistence and Execution at Scale via GPO Scheduled Task | high | 60100 |
| `106023` | 11 | `T1134` Access Token Manipulation | HackTool - NoFilter Execution | high | 60100 |
| `106024` | 11 | `T1134` Access Token Manipulation | HackTool - NoFilter Execution | high | 60100 |
| `106025` | 14 | `T1134.001` T1134.001 | Meterpreter or Cobalt Strike Getsystem Service Installation - Security | high | 60100 |
| `106026` | 10 | `T1547.009` T1547.009 | Windows Network Access Suspicious desktop.ini Action | medium | 60100 |
| `106027` | 10 | `T1548` Abuse Elevation Control Mechanism | SCM Database Privileged Operation | medium | 60100 |
| `106028` | 10 | `T1543.003` T1543.003 | Remote Access Tool Services Have Been Installed - Security | medium | 60100 |
| `106029` | 10 | `T1098` T1098 | A New Trust Was Created To A Domain | medium | 60100 |
| `106030` | 11 | `T1098` T1098 | Password Change on Directory Service Restore Mode (DSRM) Account | high | 60100 |
| `106031` | 10 | `T1484.001` T1484.001 | Group Policy Abuse for Privilege Addition | medium | 60100 |
| `106032` | 10 | `T1078` Valid Accounts | Suspicious Remote Logon with Explicit Credentials | medium | 60100 |
| `106033` | 11 | `T1574.001` T1574.001 | Microsoft Defender Blocked from Loading Unsigned DLL | high | 60000 |
| `106034` | 11 | `T1574.001` T1574.001 | Unsigned Binary Loaded From Suspicious Location | high | 60000 |
| `106035` | 11 | `T1574.001` T1574.001 | DHCP Server Loaded the CallOut DLL | high | 60106 |
| `106036` | 11 | `T1574.001` T1574.001 | DHCP Server Error Failed Loading the CallOut DLL | high | 60106 |
| `106037` | 10 | - | Certificate Use With No Strong Mapping | medium | 60106 |
| `106038` | 11 | `T1548` Abuse Elevation Control Mechanism | Vulnerable Netlogon Secure Channel Connection Allowed | high | 60106 |
| `106039` | 14 | `T1134.001` T1134.001 | Meterpreter or Cobalt Strike Getsystem Service Installation - System | high | 60106 |
| `106040` | 10 | `T1543.003` T1543.003 | Remote Access Tool Services Have Been Installed - System | medium | 60106 |
| `106041` | 10 | `T1053.005` T1053.005 | Scheduled Task Executed From A Suspicious Location | medium | 60000 |
| `106042` | 10 | `T1053.005` T1053.005 | Scheduled Task Executed Uncommon LOLBIN | medium | 60000 |
| `106043` | 11 | `T1055.012` T1055.012 | HackTool - CACTUSTORCH Remote Thread Creation | high | 61610 |
| `106044` | 13 | `T1055.001` T1055.001 | HackTool - Potential CobaltStrike Process Injection | high | 61610 |
| `106045` | 11 | `T1055` Process Injection | Rare Remote Thread Creation By Uncommon Source Image | high | 61610 |
| `106046` | 10 | `T1055` Process Injection | Remote Thread Creation By Uncommon Source Image | medium | 61610 |
| `106047` | 10 | `T1055.003` T1055.003 | Remote Thread Creation In Uncommon Target Image | medium | 61610 |
| `106048` | 10 | `T1547.009` T1547.009 | New Custom Shim Database Created | medium | 61613 |
| `106049` | 10 | `T1546.002` T1546.002 | Suspicious Screensaver Binary File Creation | medium | 61613 |
| `106050` | 11 | `T1547.009` T1547.009 | Creation Exe for Service with Unquoted Path | high | 61613 |
| `106051` | 10 | `T1547.009` T1547.009 | Desktop.INI Created by Uncommon Process | medium | 61613 |
| `106052` | 10 | `T1566` Phishing | Potential Initial Access via DLL Search Order Hijacking | medium | 61613 |
| `106053` | 11 | `T1547.001` T1547.001 | File Creation In Suspicious Directory By Msdt.EXE | high | 61613 |
| `106054` | 10 | `T1137` T1137 | New Outlook Macro Created | medium | 61613 |
| `106055` | 11 | `T1137` T1137 | Suspicious Outlook Macro Created | high | 61613 |
| `106056` | 11 | `T1547.001` T1547.001 | Potential Startup Shortcut Persistence Via PowerShell.EXE | high | 61613 |
| `106057` | 11 | `T1547` Boot or Logon Autostart Execution | Potential RipZip Attack on Startup Folder | high | 61613 |
| `106058` | 10 | `T1547.001` T1547.001 | Startup Folder File Write | medium | 61613 |
| `106059` | 10 | `T1055` Process Injection | Created Files by Microsoft Sync Center | medium | 61613 |
| `106060` | 11 | `T1546` T1546 | Suspicious Get-Variable.exe Creation | high | 61613 |
| `106061` | 11 | `T1204.002` T1204.002 | Suspicious Startup Folder Persistence | high | 61613 |
| `106062` | 11 | `T1053` Scheduled Task/Job | Suspicious Scheduled Task Write to System32 Tasks | high | 61613 |
| `106063` | 10 | `T1547.015` T1547.015 | Windows Terminal Profile Settings Modification By Uncommon Process | medium | 61613 |
| `106064` | 11 | - | LiveKD Kernel Memory Dump File Created | high | 61613 |
| `106065` | 10 | - | LiveKD Driver Creation | medium | 61613 |
| `106066` | 11 | - | LiveKD Driver Creation By Uncommon Process | high | 61613 |
| `106067` | 11 | `T1548.002` T1548.002 | UAC Bypass Using Consent and Comctl32 - File | high | 61613 |
| `106068` | 11 | `T1548.002` T1548.002 | UAC Bypass Using .NET Code Profiler on MMC | high | 61613 |
| `106069` | 11 | - | UAC Bypass Using EventVwr | high | 61613 |
| `106070` | 11 | `T1548.002` T1548.002 | UAC Bypass Using IEInstal - File | high | 61613 |
| `106071` | 11 | `T1548.002` T1548.002 | UAC Bypass Using MSConfig Token Modification - File | high | 61613 |
| `106072` | 11 | `T1548.002` T1548.002 | UAC Bypass Using NTFS Reparse Point - File | high | 61613 |
| `106073` | 11 | `T1548.002` T1548.002 | UAC Bypass Abusing Winsat Path Parsing - File | high | 61613 |
| `106074` | 11 | `T1548.002` T1548.002 | UAC Bypass Using Windows Media Player - File | high | 61613 |
| `106075` | 11 | `T1548.002` T1548.002 | UAC Bypass Using Windows Media Player - File | high | 61613 |
| `106076` | 10 | `T1574.001` T1574.001 | Creation of WerFault.exe/Wer.dll in Unusual Folder | medium | 61613 |
| `106077` | 11 | `T1547.001` T1547.001 | WinRAR Creating Files in Startup Locations | high | 61613 |
| `106078` | 11 | `T1546.003` T1546.003 | WMI Persistence - Script Event Consumer File Write | high | 61613 |
| `106079` | 10 | `T1546.002` T1546.002 | Writing Local Admin Share | medium | 61613 |
| `106080` | 11 | `T1574.001` T1574.001 | Aruba Network Service Potential DLL Sideloading | high | 61609 |
| `106081` | 10 | `T1218` T1218 | Potential DLL Sideloading Using Coregen.exe | medium | 61609 |
| `106082` | 10 | `T1574.001` T1574.001 | Potential DLL Sideloading Of DbgModel.DLL | medium | 61609 |
| `106083` | 10 | `T1574.001` T1574.001 | Potential DLL Sideloading Of MpSvc.DLL | medium | 61609 |
| `106084` | 10 | `T1574.001` T1574.001 | Potential DLL Sideloading Of MsCorSvc.DLL | medium | 61609 |
| `106085` | 10 | `T1574.001` T1574.001 | Potential Python DLL SideLoading | medium | 61609 |
| `106086` | 11 | `T1574.001` T1574.001 | Fax Service DLL Search Order Hijack | high | 61609 |
| `106087` | 11 | `T1574.001` T1574.001 | Potential DLL Sideloading Via VMware Xfer | high | 61609 |
| `106088` | 11 | `T1574.001` T1574.001 | Potential Mpclient.DLL Sideloading | high | 61609 |
| `106089` | 10 | `T1574.001` T1574.001 | Unsigned Module Loaded by ClickOnce Application | medium | 61609 |
| `106090` | 11 | `T1574.001` T1574.001 | Suspicious Unsigned Thor Scanner Execution | high | 61609 |
| `106091` | 11 | `T1548.002` T1548.002 | UAC Bypass Using Iscsicpl - ImageLoad | high | 61609 |
| `106092` | 11 | `T1546.003` T1546.003 | WMI Persistence - Command Line Event Consumer | high | 61609 |
| `106093` | 11 | `T1055` Process Injection | Network Connection Initiated Via Notepad.EXE | high | 61605 |
| `106094` | 10 | `T1055` Process Injection | Microsoft Sync Center Suspicious Network Connections | medium | 61605 |
| `106095` | 13 | `T1055` Process Injection | CobaltStrike Named Pipe | high | 61619 |
| `106096` | 13 | `T1055` Process Injection | CobaltStrike Named Pipe | high | 61619 |
| `106097` | 13 | `T1055` Process Injection | CobaltStrike Named Pipe | high | 61619 |
| `106098` | 13 | `T1055` Process Injection | CobaltStrike Named Pipe | high | 61619 |
| `106099` | 13 | `T1055` Process Injection | CobaltStrike Named Pipe | high | 61619 |
| `106100` | 13 | `T1055` Process Injection | CobaltStrike Named Pipe | high | 61619 |
| `106101` | 13 | `T1055` Process Injection | CobaltStrike Named Pipe | high | 61619 |
| `106102` | 13 | `T1055` Process Injection | CobaltStrike Named Pipe | high | 61619 |
| `106103` | 13 | `T1055` Process Injection | CobaltStrike Named Pipe | high | 61619 |
| `106104` | 13 | `T1055` Process Injection | CobaltStrike Named Pipe | high | 61619 |
| `106105` | 13 | `T1055` Process Injection | CobaltStrike Named Pipe | high | 61619 |
| `106106` | 13 | `T1055` Process Injection | CobaltStrike Named Pipe Pattern Regex | high | 61619 |
| `106107` | 13 | `T1055` Process Injection | CobaltStrike Named Pipe Pattern Regex | high | 61619 |
| `106108` | 13 | `T1055` Process Injection | CobaltStrike Named Pipe Pattern Regex | high | 61619 |
| `106109` | 13 | `T1055` Process Injection | CobaltStrike Named Pipe Pattern Regex | high | 61619 |
| `106110` | 13 | `T1055` Process Injection | CobaltStrike Named Pipe Pattern Regex | high | 61619 |
| `106111` | 13 | `T1055` Process Injection | CobaltStrike Named Pipe Pattern Regex | high | 61619 |
| `106112` | 13 | `T1055` Process Injection | CobaltStrike Named Pipe Pattern Regex | high | 61619 |
| `106113` | 13 | `T1055` Process Injection | CobaltStrike Named Pipe Pattern Regex | high | 61619 |
| `106114` | 13 | `T1055` Process Injection | CobaltStrike Named Pipe Pattern Regex | high | 61619 |
| `106115` | 13 | `T1055` Process Injection | CobaltStrike Named Pipe Pattern Regex | high | 61619 |
| `106116` | 13 | `T1055` Process Injection | CobaltStrike Named Pipe Pattern Regex | high | 61619 |
| `106117` | 13 | `T1055` Process Injection | CobaltStrike Named Pipe Pattern Regex | high | 61619 |
| `106118` | 13 | `T1055` Process Injection | CobaltStrike Named Pipe Pattern Regex | high | 61619 |
| `106119` | 13 | `T1055` Process Injection | CobaltStrike Named Pipe Pattern Regex | high | 61619 |
| `106120` | 13 | `T1055` Process Injection | CobaltStrike Named Pipe Pattern Regex | high | 61619 |
| `106121` | 13 | `T1055` Process Injection | CobaltStrike Named Pipe Pattern Regex | high | 61619 |
| `106122` | 13 | `T1055` Process Injection | CobaltStrike Named Pipe Pattern Regex | high | 61619 |
| `106123` | 13 | `T1055` Process Injection | CobaltStrike Named Pipe Pattern Regex | high | 61619 |
| `106124` | 13 | `T1055` Process Injection | CobaltStrike Named Pipe Pattern Regex | high | 61619 |
| `106125` | 13 | `T1055` Process Injection | CobaltStrike Named Pipe Patterns | high | 61619 |
| `106126` | 13 | `T1055` Process Injection | CobaltStrike Named Pipe Patterns | high | 61619 |
| `106127` | 13 | `T1055` Process Injection | CobaltStrike Named Pipe Patterns | high | 61619 |
| `106128` | 11 | `T1055` Process Injection | HackTool - CoercedPotato Named Pipe Creation | high | 61619 |
| `106129` | 11 | - | HackTool - DiagTrackEoP Default Named Pipe | high | 61619 |
| `106130` | 11 | `T1055` Process Injection | HackTool - EfsPotato Named Pipe Creation | high | 61619 |
| `106131` | 11 | `T1528` T1528 | HackTool - Koh Default Named Pipe | high | 61619 |
| `106132` | 12 | `T1055` Process Injection | Malicious Named Pipe Created | high | 61619 |
| `106133` | 10 | `T1078` Valid Accounts | Suspicious Computer Machine Password by PowerShell | medium | 91801 |
| `106134` | 10 | `T1053.005` T1053.005 | Powershell Create Scheduled Task | medium | 91801 |
| `106135` | 10 | `T1053.005` T1053.005 | Powershell Create Scheduled Task | medium | 91801 |
| `106136` | 10 | `T1574.012` T1574.012 | Registry-Free Process Scope COR_PROFILER | medium | 91801 |
| `106137` | 10 | `T1078.002` T1078.002 | DMSA Service Account Created in Specific OUs - PowerShell | medium | 91801 |
| `106138` | 10 | `T1574.011` T1574.011 | Service Registry Permissions Weakness Check | medium | 91801 |
| `106139` | 10 | `T1098` T1098 | Powershell LocalAccount Manipulation | medium | 91801 |
| `106140` | 10 | `T1484.001` T1484.001 | Modify Group Policy Settings - ScriptBlockLogging | medium | 91801 |
| `106141` | 11 | `T1055` Process Injection | PowerShell ShellCode | high | 91801 |
| `106142` | 10 | `T1546.015` T1546.015 | Suspicious GetTypeFromCLSID ShellExecute | medium | 91801 |
| `106143` | 10 | `T1547.004` T1547.004 | Winlogon Helper DLL | medium | 91801 |
| `106144` | 11 | `T1548` Abuse Elevation Control Mechanism | Credential Dumping Attempt Via Svchost | high | 61612 |
| `106145` | 10 | `T1548.002` T1548.002 | Function Call From Undocumented COM Interface EditionUpgradeManager | medium | 61612 |
| `106146` | 11 | `T1548.002` T1548.002 | UAC Bypass Using WOW64 Logger DLL Hijack | high | 61612 |
| `106147` | 11 | `T1547.001` T1547.001 | Suspicious Autorun Registry Modified via WMI | high | 61603 |
| `106148` | 11 | `T1546.001` T1546.001 | Change Default File Association To Executable Via Assoc | high | 61603 |
| `106149` | 11 | `T1546.008` T1546.008 | Potential Privilege Escalation Using Symlink Between Osk and Cmd | high | 61603 |
| `106150` | 11 | `T1546.008` T1546.008 | Sticky Key Like Backdoor Execution | high | 61603 |
| `106151` | 11 | `T1218.002` T1218.002 | Control Panel Items | high | 61603 |
| `106152` | 10 | `T1078.002` T1078.002 | New DMSA Service Account Created in Specific OUs | medium | 61603 |
| `106153` | 11 | `T1055.001` T1055.001 | ManageEngine Endpoint Central Dctask64.EXE Potential Abuse | high | 61603 |
| `106154` | 10 | `T1574.001` T1574.001 | Potential DLL Sideloading Via DeviceEnroller.EXE | medium | 61603 |
| `106155` | 11 | `T1548.002` T1548.002 | PowerShell Web Access Feature Enabled Via DISM | high | 61603 |
| `106156` | 11 | `T1574.001` T1574.001 | DLL Sideloading by VMware Xfer Utility | high | 61603 |
| `106157` | 11 | `T1055` Process Injection | Dllhost.EXE Execution Anomaly | high | 61603 |
| `106158` | 11 | `T1574.001` T1574.001 | New DNS ServerLevelPluginDll Installed Via Dnscmd.EXE | high | 61603 |
| `106159` | 11 | `T1548.002` T1548.002 | Potentially Suspicious Event Viewer Child Process | high | 61603 |
| `106160` | 11 | `T1548.002` T1548.002 | Explorer NOUACCHECK Flag | high | 61603 |
| `106161` | 11 | `T1574.001` T1574.001 | Suspicious GUP Usage | high | 61603 |
| `106162` | 11 | `T1055` Process Injection | HackTool - CoercedPotato Execution | high | 61603 |
| `106163` | 11 | `T1055` Process Injection | HackTool - CoercedPotato Execution | high | 61603 |
| `106164` | 11 | `T1055` Process Injection | HackTool - CoercedPotato Execution | high | 61603 |
| `106165` | 11 | `T1047` T1047 | HackTool - CrackMapExec Execution Patterns | high | 61603 |
| `106166` | 11 | `T1055` Process Injection | HackTool - DInjector PowerShell Cradle Execution | high | 61603 |
| `106167` | 12 | `T1548.002` T1548.002 | HackTool - Empire PowerShell UAC Bypass | high | 61603 |
| `106168` | 11 | `T1055.012` T1055.012 | HackTool - HollowReaper Execution | high | 61603 |
| `106169` | 10 | `T1134.001` T1134.001 | HackTool - Impersonate Execution | medium | 61603 |
| `106170` | 11 | - | HackTool - LocalPotato Execution | high | 61603 |
| `106171` | 11 | - | HackTool - LocalPotato Execution | high | 61603 |
| `106172` | 11 | - | HackTool - LocalPotato Execution | high | 61603 |
| `106173` | 14 | `T1134.001` T1134.001 | Potential Meterpreter/CobaltStrike Activity | high | 61603 |
| `106174` | 11 | `T1134.004` T1134.004 | HackTool - PPID Spoofing SelectMyParent Tool Execution | high | 61603 |
| `106175` | 11 | `T1134.004` T1134.004 | HackTool - PPID Spoofing SelectMyParent Tool Execution | high | 61603 |
| `106176` | 11 | `T1134.004` T1134.004 | HackTool - PPID Spoofing SelectMyParent Tool Execution | high | 61603 |
| `106177` | 11 | `T1134.004` T1134.004 | HackTool - PPID Spoofing SelectMyParent Tool Execution | high | 61603 |
| `106178` | 11 | `T1134.004` T1134.004 | HackTool - PPID Spoofing SelectMyParent Tool Execution | high | 61603 |
| `106179` | 11 | `T1134.001` T1134.001 | HackTool - SharpDPAPI Execution | high | 61603 |
| `106180` | 11 | `T1134.001` T1134.001 | HackTool - SharpImpersonation Execution | high | 61603 |
| `106181` | 11 | `T1134.001` T1134.001 | HackTool - SharpImpersonation Execution | high | 61603 |
| `106182` | 11 | `T1134.001` T1134.001 | HackTool - SharpImpersonation Execution | high | 61603 |
| `106183` | 11 | `T1134.001` T1134.001 | HackTool - SharpImpersonation Execution | high | 61603 |
| `106184` | 11 | `T1134.001` T1134.001 | HackTool - SharpImpersonation Execution | high | 61603 |
| `106185` | 11 | `T1053` Scheduled Task/Job | HackTool - SharPersist Execution | high | 61603 |
| `106186` | 11 | `T1053` Scheduled Task/Job | HackTool - SharPersist Execution | high | 61603 |
| `106187` | 11 | `T1053` Scheduled Task/Job | HackTool - SharPersist Execution | high | 61603 |
| `106188` | 11 | `T1053` Scheduled Task/Job | HackTool - SharPersist Execution | high | 61603 |
| `106189` | 11 | `T1053` Scheduled Task/Job | HackTool - SharPersist Execution | high | 61603 |
| `106190` | 11 | `T1053` Scheduled Task/Job | HackTool - SharPersist Execution | high | 61603 |
| `106191` | 11 | `T1068` Exploitation for Privilege Escalation | HKTL - SharpSuccessor Privilege Escalation Tool Execution | high | 61603 |
| `106192` | 11 | `T1068` Exploitation for Privilege Escalation | HKTL - SharpSuccessor Privilege Escalation Tool Execution | high | 61603 |
| `106193` | 11 | `T1068` Exploitation for Privilege Escalation | HKTL - SharpSuccessor Privilege Escalation Tool Execution | high | 61603 |
| `106194` | 11 | `T1068` Exploitation for Privilege Escalation | HKTL - SharpSuccessor Privilege Escalation Tool Execution | high | 61603 |
| `106195` | 11 | `T1068` Exploitation for Privilege Escalation | HackTool - SysmonEOP Execution | high | 61603 |
| `106196` | 11 | `T1068` Exploitation for Privilege Escalation | HackTool - SysmonEOP Execution | high | 61603 |
| `106197` | 11 | `T1548.002` T1548.002 | HackTool - UACMe Akagi Execution | high | 61603 |
| `106198` | 11 | `T1548.002` T1548.002 | HackTool - UACMe Akagi Execution | high | 61603 |
| `106199` | 11 | `T1548.002` T1548.002 | HackTool - UACMe Akagi Execution | high | 61603 |
| `106200` | 11 | `T1548.002` T1548.002 | HackTool - UACMe Akagi Execution | high | 61603 |
| `106201` | 11 | `T1548.002` T1548.002 | HackTool - UACMe Akagi Execution | high | 61603 |
| `106202` | 11 | `T1548.002` T1548.002 | HackTool - UACMe Akagi Execution | high | 61603 |
| `106203` | 11 | `T1082` System Information Discovery | HackTool - winPEAS Execution | high | 61603 |
| `106204` | 11 | `T1082` System Information Discovery | HackTool - winPEAS Execution | high | 61603 |
| `106205` | 11 | `T1082` System Information Discovery | HackTool - winPEAS Execution | high | 61603 |
| `106206` | 11 | `T1082` System Information Discovery | HackTool - winPEAS Execution | high | 61603 |
| `106207` | 11 | `T1082` System Information Discovery | HackTool - winPEAS Execution | high | 61603 |
| `106208` | 11 | `T1082` System Information Discovery | HackTool - winPEAS Execution | high | 61603 |
| `106209` | 10 | - | Windows Kernel Debugger Execution | medium | 61603 |
| `106210` | 10 | - | Windows Kernel Debugger Execution | medium | 61603 |
| `106211` | 11 | `T1055.001` T1055.001 | Mavinject Inject DLL Into Running Process | high | 61603 |
| `106212` | 11 | `T1574.008` T1574.008 | Using SettingSyncHost.exe as LOLBin | high | 61603 |
| `106213` | 10 | `T1547` Boot or Logon Autostart Execution | Suspicious Driver Install by pnputil.exe | medium | 61603 |
| `106214` | 11 | `T1547` Boot or Logon Autostart Execution | Suspicious GrpConv Execution | high | 61603 |
| `106215` | 10 | `T1055.001` T1055.001 | Potential DLL Injection Or Execution Using Tracker.exe | medium | 61603 |
| `106216` | 10 | `T1484.001` T1484.001 | Windows Default Domain GPO Modification via GPME | medium | 61603 |
| `106217` | 11 | `T1574.001` T1574.001 | Potential Mpclient.DLL Sideloading Via Defender Binaries | high | 61603 |
| `106218` | 11 | `T1055` Process Injection | Potential Process Injection Via Msra.EXE | high | 61603 |
| `106219` | 10 | `T1546.007` T1546.007 | Potential Persistence Via Netsh Helper DLL | medium | 61603 |
| `106220` | 11 | `T1543.003` T1543.003 | Suspicious Service DACL Modification Via Set-Service Cmdlet | high | 61603 |
| `106221` | 11 | `T1134.002` T1134.002 | PUA - AdvancedRun Suspicious Execution | high | 61603 |
| `106222` | 10 | `T1547.001` T1547.001 | Potential Persistence Attempt Via Run Keys Using Reg.EXE | medium | 61603 |
| `106223` | 10 | `T1547.001` T1547.001 | Direct Autorun Keys Modification | medium | 61603 |
| `106224` | 10 | `T1484.001` T1484.001 | Modify Group Policy Settings | medium | 61603 |
| `106225` | 10 | `T1574.011` T1574.011 | Changing Existing Service ImagePath Value Via Reg.EXE | medium | 61603 |
| `106226` | 11 | `T1548` Abuse Elevation Control Mechanism | Regedit as Trusted Installer | high | 61603 |
| `106227` | 10 | `T1574` T1574 | DLL Execution Via Register-cimprovider.exe | medium | 61603 |
| `106228` | 11 | `T1037.001` T1037.001 | Potential Persistence Via Logon Scripts - CommandLine | high | 61603 |
| `106229` | 10 | `T1574` T1574 | Regsvr32 DLL Execution With Uncommon Extension | medium | 61603 |
| `106230` | 11 | `T1036` T1036 | Renamed ZOHO Dctask64 Execution | high | 61603 |
| `106231` | 11 | `T1055.001` T1055.001 | Renamed Mavinject.EXE Execution | high | 61603 |
| `106232` | 11 | `T1574.001` T1574.001 | Renamed Vmnat.exe Execution | high | 61603 |
| `106233` | 11 | `T1055` Process Injection | Suspicious Rundll32 Invoking Inline VBScript | high | 61603 |
| `106234` | 11 | `T1212` T1212 | Suspicious NTLM Authentication on the Printer Spooler Service | high | 61603 |
| `106235` | 11 | `T1546.015` T1546.015 | Rundll32 Registered COM Objects | high | 61603 |
| `106236` | 11 | `T1543.003` T1543.003 | Allow Service Access Using Security Descriptor Tampering Via Sc.EXE | high | 61603 |
| `106237` | 11 | `T1543.003` T1543.003 | Deny Service Access Using Security Descriptor Tampering Via Sc.EXE | high | 61603 |
| `106238` | 10 | `T1543.003` T1543.003 | Potential Persistence Attempt Via Existing Service Tampering | medium | 61603 |
| `106239` | 11 | `T1053.005` T1053.005 | Suspicious Schtasks Execution AppData Folder | high | 61603 |
| `106240` | 11 | `T1053.005` T1053.005 | Suspicious Modification Of Scheduled Tasks | high | 61603 |
| `106241` | 11 | `T1053.005` T1053.005 | Suspicious Scheduled Task Creation Involving Temp Folder | high | 61603 |
| `106242` | 10 | `T1053.005` T1053.005 | Scheduled Task Creation with Curl and PowerShell Execution Combo | medium | 61603 |
| `106243` | 10 | `T1053.005` T1053.005 | Schedule Task Creation From Env Variable Or Potentially Suspicious ... | medium | 61603 |
| `106244` | 11 | `T1053.005` T1053.005 | Schtasks From Suspicious Folders | high | 61603 |
| `106245` | 10 | `T1053.005` T1053.005 | Suspicious Scheduled Task Name As GUID | medium | 61603 |
| `106246` | 11 | `T1053.005` T1053.005 | Potential SSH Tunnel Persistence Install Using A Scheduled Task | high | 61603 |
| `106247` | 10 | `T1053.005` T1053.005 | Potential Persistence Via Microsoft Compatibility Appraiser | medium | 61603 |
| `106248` | 11 | `T1053.005` T1053.005 | Potential Persistence Via Powershell Search Order Hijacking - Task | high | 61603 |
| `106249` | 10 | `T1053.005` T1053.005 | Scheduled Task Executing Payload from Registry | medium | 61603 |
| `106250` | 11 | `T1053.005` T1053.005 | Scheduled Task Executing Encoded Payload from Registry | high | 61603 |
| `106251` | 11 | `T1053.005` T1053.005 | Suspicious Schtasks Schedule Types | high | 61603 |
| `106252` | 10 | `T1053.005` T1053.005 | Suspicious Schtasks Schedule Type With High Privileges | medium | 61603 |
| `106253` | 10 | `T1036.005` T1036.005 | Suspicious Scheduled Task Creation via Masqueraded XML File | medium | 61603 |
| `106254` | 11 | `T1053.005` T1053.005 | Suspicious Command Patterns In Scheduled Task Creation | high | 61603 |
| `106255` | 11 | `T1053.005` T1053.005 | Schtasks Creation Or Modification With SYSTEM Privileges | high | 61603 |
| `106256` | 12 | `T1053.005` T1053.005 | Scheduled Task Creation Masquerading as System Processes | high | 61603 |
| `106257` | 10 | `T1548.002` T1548.002 | Sdclt Child Processes | medium | 61603 |
| `106258` | 10 | `T1574.005` T1574.005 | Setup16.EXE Execution With Custom .Lst File | medium | 61603 |
| `106259` | 12 | `T1548` Abuse Elevation Control Mechanism | Abused Debug Privilege by Arbitrary Parent Processes | high | 61603 |
| `106260` | 10 | `T1098` T1098 | User Added to Local Administrators Group | medium | 61603 |
| `106261` | 11 | `T1098` T1098 | User Added To Highly Privileged Group | high | 61603 |
| `106262` | 10 | `T1548.002` T1548.002 | Always Install Elevated Windows Installer | medium | 61603 |
| `106263` | 10 | `T1548.002` T1548.002 | Always Install Elevated Windows Installer | medium | 61603 |
| `106264` | 11 | `T1134.002` T1134.002 | Suspicious Child Process Created as System | high | 61603 |
| `106265` | 10 | `T1548.002` T1548.002 | Always Install Elevated MSI Spawned Cmd And Powershell | medium | 61603 |
| `106266` | 10 | `T1059` Command and Scripting Interpreter | Elevated System Shell Spawned From Uncommon Parent Location | medium | 61603 |
| `106267` | 10 | - | Suspicious RunAs-Like Flag Combination | medium | 61603 |
| `106268` | 10 | `T1548.002` T1548.002 | Registry Modification of MS-settings Protocol Handler | medium | 61603 |
| `106269` | 10 | `T1055` Process Injection | Process Creation Using Sysnative Folder | medium | 61603 |
| `106270` | 11 | `T1574.001` T1574.001 | Tasks Folder Evasion | high | 61603 |
| `106271` | 10 | `T1055` Process Injection | Suspicious Userinit Child Process | medium | 61603 |
| `106272` | 11 | `T1055` Process Injection | Suspect Svchost Activity | high | 61603 |
| `106273` | 11 | `T1036.005` T1036.005 | Uncommon Svchost Command Line Parameter | high | 61603 |
| `106274` | 10 | `T1543.003` T1543.003 | Sysinternals PsService Execution | medium | 61603 |
| `106275` | 10 | `T1543.003` T1543.003 | Sysinternals PsService Execution | medium | 61603 |
| `106276` | 10 | `T1543.003` T1543.003 | Sysinternals PsSuspend Execution | medium | 61603 |
| `106277` | 10 | `T1543.003` T1543.003 | Sysinternals PsSuspend Execution | medium | 61603 |
| `106278` | 11 | `T1548.002` T1548.002 | UAC Bypass Using ChangePK and SLUI | high | 61603 |
| `106279` | 11 | `T1548.002` T1548.002 | UAC Bypass Using Disk Cleanup | high | 61603 |
| `106280` | 11 | `T1548.002` T1548.002 | Bypass UAC via CMSTP | high | 61603 |
| `106281` | 11 | `T1548.002` T1548.002 | UAC Bypass Tools Using ComputerDefaults | high | 61603 |
| `106282` | 11 | `T1548.002` T1548.002 | UAC Bypass Using Consent and Comctl32 - Process | high | 61603 |
| `106283` | 11 | `T1548.002` T1548.002 | UAC Bypass Using DismHost | high | 61603 |
| `106284` | 11 | - | UAC Bypass Using Event Viewer RecentViews | high | 61603 |
| `106285` | 11 | `T1548.002` T1548.002 | Bypass UAC via Fodhelper.exe | high | 61603 |
| `106286` | 10 | `T1548` Abuse Elevation Control Mechanism | UAC Bypass via Windows Firewall Snap-In Hijack | medium | 61603 |
| `106287` | 11 | `T1548.002` T1548.002 | UAC Bypass via ICMLuaUtil | high | 61603 |
| `106288` | 11 | `T1548.002` T1548.002 | UAC Bypass Using IEInstal - Process | high | 61603 |
| `106289` | 11 | `T1548.002` T1548.002 | UAC Bypass Using MSConfig Token Modification - Process | high | 61603 |
| `106290` | 11 | `T1548.002` T1548.002 | UAC Bypass Using NTFS Reparse Point - Process | high | 61603 |
| `106291` | 11 | `T1548.002` T1548.002 | UAC Bypass Using NTFS Reparse Point - Process | high | 61603 |
| `106292` | 11 | `T1548.002` T1548.002 | UAC Bypass Using PkgMgr and DISM | high | 61603 |
| `106293` | 10 | `T1548.002` T1548.002 | Potential UAC Bypass Via Sdclt.EXE | medium | 61603 |
| `106294` | 11 | `T1548.002` T1548.002 | TrustedPath UAC Bypass Pattern | high | 61603 |
| `106295` | 11 | `T1548.002` T1548.002 | UAC Bypass Abusing Winsat Path Parsing - Process | high | 61603 |
| `106296` | 11 | `T1548.002` T1548.002 | UAC Bypass Using Windows Media Player - Process | high | 61603 |
| `106297` | 11 | `T1548.002` T1548.002 | UAC Bypass Using Windows Media Player - Process | high | 61603 |
| `106298` | 11 | `T1548.002` T1548.002 | Bypass UAC via WSReset.exe | high | 61603 |
| `106299` | 11 | `T1548.002` T1548.002 | UAC Bypass WSReset | high | 61603 |
| `106300` | 11 | `T1037.001` T1037.001 | Uncommon Userinit Child Process | high | 61603 |
| `106301` | 11 | `T1055` Process Injection | Suspicious Child Process Of Wermgr.EXE | high | 61603 |
| `106302` | 11 | `T1033` T1033 | Whoami.EXE Execution From Privileged Process | high | 61603 |
| `106303` | 11 | `T1033` T1033 | Security Privileges Enumeration Via Whoami.EXE | high | 61603 |
| `106304` | 11 | `T1546.003` T1546.003 | WMI Backdoor Exchange Transport Agent | high | 61603 |
| `106305` | 10 | `T1047` T1047 | Password Set to Never Expire via WMI | medium | 61603 |
| `106306` | 11 | `T1546.003` T1546.003 | New ActiveScriptEventConsumer Created Via Wmic.EXE | high | 61603 |
| `106307` | 11 | `T1574.001` T1574.001 | Xwizard.EXE Execution From Non-Default Location | high | 61603 |
| `106308` | 10 | `T1055.012` T1055.012 | Potential Process Hollowing Activity | medium | 61627 |
| `106309` | 11 | `T1548.002` T1548.002 | UAC Bypass Via Wsreset | high | 61615 |
| `106310` | 11 | `T1547.001` T1547.001 | Narrator's Feedback-Hub Persistence | high | 61615 |
| `106311` | 11 | `T1547.001` T1547.001 | Narrator's Feedback-Hub Persistence | high | 61615 |
| `106312` | 10 | `T1546.009` T1546.009 | New DLL Added to AppCertDlls Registry Key | medium | 61615 |
| `106313` | 10 | `T1546.009` T1546.009 | New DLL Added to AppCertDlls Registry Key | medium | 61615 |
| `106314` | 10 | `T1546.010` T1546.010 | New DLL Added to AppInit_DLLs Registry Key | medium | 61615 |
| `106315` | 11 | `T1547` Boot or Logon Autostart Execution | Registry Persistence Mechanisms in Recycle Bin | high | 61615 |
| `106316` | 11 | `T1547` Boot or Logon Autostart Execution | Registry Persistence Mechanisms in Recycle Bin | high | 61615 |
| `106317` | 11 | `T1547` Boot or Logon Autostart Execution | WINEKEY Registry Modification | high | 61615 |
| `106318` | 11 | `T1547.005` T1547.005 | Security Support Provider (SSP) Added to LSA Configuration | high | 61615 |
| `106319` | 11 | `T1546.008` T1546.008 | Sticky Key Like Backdoor Usage - Registry | high | 61615 |
| `106320` | 10 | `T1218` T1218 | Atbroker Registry Change | medium | 61615 |
| `106321` | 11 | `T1547.001` T1547.001 | Suspicious Run Key from Download | high | 61615 |
| `106322` | 12 | `T1547.008` T1547.008 | DLL Load via LSASS | high | 61615 |
| `106323` | 10 | `T1547.010` T1547.010 | Add Port Monitor Persistence in Registry | medium | 61615 |
| `106324` | 10 | `T1547.001` T1547.001 | Classes Autorun Keys Modification | medium | 61615 |
| `106325` | 10 | `T1547.001` T1547.001 | Common Autorun Keys Modification | medium | 61615 |
| `106326` | 10 | `T1547.001` T1547.001 | CurrentControlSet Autorun Keys Modification | medium | 61615 |
| `106327` | 10 | `T1547.001` T1547.001 | CurrentVersion Autorun Keys Modification | medium | 61615 |
| `106328` | 10 | `T1547.001` T1547.001 | CurrentVersion NT Autorun Keys Modification | medium | 61615 |
| `106329` | 10 | `T1547.001` T1547.001 | Internet Explorer Autorun Keys Modification | medium | 61615 |
| `106330` | 10 | `T1547.001` T1547.001 | Office Autorun Keys Modification | medium | 61615 |
| `106331` | 10 | `T1547.001` T1547.001 | Session Manager Autorun Keys Modification | medium | 61615 |
| `106332` | 10 | `T1547.001` T1547.001 | System Scripts Autorun Keys Modification | medium | 61615 |
| `106333` | 10 | `T1547.001` T1547.001 | WinSock2 Autorun Keys Modification | medium | 61615 |
| `106334` | 10 | `T1547.001` T1547.001 | Wow6432Node CurrentVersion Autorun Keys Modification | medium | 61615 |
| `106335` | 10 | `T1547.001` T1547.001 | Wow6432Node Classes Autorun Keys Modification | medium | 61615 |
| `106336` | 10 | `T1547.001` T1547.001 | Wow6432Node Windows NT CurrentVersion Autorun Keys Modification | medium | 61615 |
| `106337` | 11 | `T1548.002` T1548.002 | Bypass UAC Using DelegateExecute | high | 61615 |
| `106338` | 11 | `T1547.010` T1547.010 | Bypass UAC Using Event Viewer | high | 61615 |
| `106339` | 11 | `T1548.002` T1548.002 | Bypass UAC Using SilentCleanup Task | high | 61615 |
| `106340` | 11 | `T1547.010` T1547.010 | Default RDP Port Changed to Non Standard Port | high | 61615 |
| `106341` | 10 | `T1574` T1574 | Potential Registry Persistence Attempt Via DbgManagedDebugger | medium | 61615 |
| `106342` | 11 | `T1574.001` T1574.001 | DHCP Callout DLL Installation | high | 61615 |
| `106343` | 11 | `T1547.001` T1547.001 | Windows Event Log Access Tampering Via Registry | high | 61615 |
| `106344` | 11 | `T1547.001` T1547.001 | Windows Event Log Access Tampering Via Registry | high | 61615 |
| `106345` | 11 | `T1574.001` T1574.001 | New DNS ServerLevelPluginDll Installed | high | 61615 |
| `106346` | 11 | `T1546.007` T1546.007 | New Netsh Helper DLL Registered From A Suspicious Location | high | 61615 |
| `106347` | 10 | `T1546.007` T1546.007 | Potential Persistence Via Netsh Helper DLL - Registry | medium | 61615 |
| `106348` | 11 | `T1137` T1137 | Potential Persistence Via Outlook LoadMacroProviderOnBoot Setting | high | 61615 |
| `106349` | 11 | `T1137` T1137 | Outlook Macro Execution Without Warning Setting Enabled | high | 61615 |
| `106350` | 10 | `T1546.011` T1546.011 | Potential Persistence Via AppCompat RegisterAppRestart Layer | medium | 61615 |
| `106351` | 11 | `T1546.012` T1546.012 | Potential Persistence Via App Paths Default Property | high | 61615 |
| `106352` | 10 | `T1546.015` T1546.015 | Potential Persistence Using DebugPath | medium | 61615 |
| `106353` | 10 | `T1546.015` T1546.015 | Potential Persistence Using DebugPath | medium | 61615 |
| `106354` | 11 | `T1546.015` T1546.015 | COM Object Hijacking Via Modification Of Default System CLSID Defau... | high | 61615 |
| `106355` | 10 | `T1546.015` T1546.015 | Potential COM Object Hijacking Via TreatAs Subkey - Registry | medium | 61615 |
| `106356` | 11 | `T1546.015` T1546.015 | Potential PSFactoryBuffer COM Hijacking | high | 61615 |
| `106357` | 11 | `T1546.012` T1546.012 | Potential Persistence Via GlobalFlags | high | 61615 |
| `106358` | 11 | `T1546.012` T1546.012 | Potential Persistence Via GlobalFlags | high | 61615 |
| `106359` | 10 | `T1037.001` T1037.001 | Potential Persistence Via Logon Scripts - Registry | medium | 61615 |
| `106360` | 10 | `T1546.015` T1546.015 | Potential Persistence Via Scrobj.dll COM Hijacking | medium | 61615 |
| `106361` | 10 | `T1546.011` T1546.011 | Potential Persistence Via Shim Database Modification | medium | 61615 |
| `106362` | 11 | `T1546.011` T1546.011 | Suspicious Shim Database Patching Activity | high | 61615 |
| `106363` | 11 | `T1546.011` T1546.011 | Potential Persistence Via Shim Database In Uncommon Location | high | 61615 |
| `106364` | 10 | `T1547.001` T1547.001 | Suspicious PowerShell In Registry Run Keys | medium | 61615 |
| `106365` | 11 | `T1547.001` T1547.001 | Registry Persistence via Explorer Run Key | high | 61615 |
| `106366` | 11 | `T1547.001` T1547.001 | New RUN Key Pointing to Suspicious Folder | high | 61615 |
| `106367` | 10 | `T1548.002` T1548.002 | Suspicious Shell Open Command Registry Modification | medium | 61615 |
| `106368` | 11 | `T1053` Scheduled Task/Job | Scheduled TaskCache Change by Uncommon Program | high | 61615 |
| `106369` | 11 | `T1053.005` T1053.005 | Potential Registry Persistence Attempt Via Windows Telemetry | high | 61615 |
| `106370` | 10 | `T1546.015` T1546.015 | COM Hijacking via TreatAs | medium | 61615 |
| `106371` | 11 | `T1548.002` T1548.002 | UAC Bypass via Event Viewer | high | 61615 |
| `106372` | 11 | `T1548.002` T1548.002 | UAC Bypass via Sdclt | high | 61615 |
| `106373` | 11 | `T1548.002` T1548.002 | UAC Bypass via Sdclt | high | 61615 |
| `106374` | 11 | `T1548.002` T1548.002 | UAC Bypass Abusing Winsat Path Parsing - Registry | high | 61615 |
| `106375` | 11 | `T1548.002` T1548.002 | UAC Bypass Using Windows Media Player - Registry | high | 61615 |
| `106376` | 10 | `T1548.002` T1548.002 | UAC Disabled | medium | 61615 |
| `106377` | 10 | `T1548.002` T1548.002 | UAC Notification Disabled | medium | 61615 |
| `106378` | 10 | `T1548.002` T1548.002 | UAC Secure Desktop Prompt Disabled | medium | 61615 |
| `106379` | 11 | `T1547.001` T1547.001 | VBScript Payload Stored in Registry | high | 61615 |
| `106380` | 11 | `T1547.004` T1547.004 | Winlogon Notify Key Logon Persistence | high | 61615 |
| `106381` | 10 | `T1546.003` T1546.003 | WMI Event Subscription | medium | 61621 |
| `106382` | 11 | `T1047` T1047 | Suspicious Encoded Scripts in a WMI Consumer | high | 61621 |

### Defense Evasion (TA0005) — 35 rules

| Rule ID | Level | Technique | Description | Confidence | Parent SID |
|---------|-------|-----------|-------------|------------|------------|
| `108000` | 9 | `T1574.002` T1574.002 | DLL loaded from suspicious path | medium | 61609 |
| `108001` | 10 | `T1218.011` T1218.011 | Suspicious process: rundll32 | high | 61603 |
| `108002` | 9 | `T1218.011` T1218.011 | File created by rundll32 | medium | 61613 |
| `108003` | 9 | `T1574.002` T1574.002 | DLL loaded from suspicious path | medium | 61609 |
| `108004` | 10 | `T1197` T1197 | Suspicious process: bitsadmin | high | 61603 |
| `108005` | 10 | `T1218.010` T1218.010 | Suspicious process: regsvr32 | high | 61603 |
| `108006` | 10 | `T1218.010` T1218.010 | DLL sideloading by regsvr32 | high | 61609 |
| `108007` | 10 | `T1218.010` T1218.010 | Network connection by regsvr32 | high | 61605 |
| `108008` | 10 | `T1140` T1140 | Suspicious process: certutil | high | 61603 |
| `108009` | 9 | `T1140` T1140 | File created by certutil | medium | 61613 |
| `108010` | 10 | `T1218.004` T1218.004 | Suspicious process: installutil | high | 61603 |
| `108011` | 10 | `T1218.005` T1218.005 | Suspicious process: mshta | high | 61603 |
| `108012` | 10 | `T1218.005` T1218.005 | DLL sideloading by mshta | high | 61609 |
| `108013` | 10 | `T1218.005` T1218.005 | Network connection by mshta | high | 61605 |
| `108014` | 10 | `T1218.005` T1218.005 | Network connection by mshta | high | 61605 |
| `108015` | 10 | `T1218.003` T1218.003 | Suspicious process: cmstp | high | 61603 |
| `108016` | 10 | `T1218.011` T1218.011 | DLL sideloading by rundll32 | high | 61609 |
| `108017` | 10 | `T1218.011` T1218.011 | Network connection by rundll32 | high | 61605 |
| `108018` | 10 | `T1140` T1140 | Network connection by certutil | high | 61605 |
| `108019` | 9 | `T1574.002` T1574.002 | DLL loaded from suspicious path | medium | 61609 |
| `108020` | 10 | `T1218.011` T1218.011 | Network connection by rundll32 | high | 61605 |
| `108021` | 9 | `T1574.002` T1574.002 | DLL loaded from suspicious path | medium | 61609 |
| `108022` | 9 | `T1112` T1112 | Registry persistence via shell | medium | 61615 |
| `108023` | 9 | `T1112` T1112 | Registry persistence via shell | medium | 61614 |
| `108024` | 10 | `T1218.007` T1218.007 | DLL sideloading by msiexec | high | 61609 |
| `108025` | 10 | `T1218.011` T1218.011 | Network connection by rundll32 | high | 61605 |
| `108026` | 10 | `T1218.010` T1218.010 | Network connection by regsvr32 | high | 61605 |
| `108027` | 10 | `T1218.005` T1218.005 | Network connection by mshta | high | 61605 |
| `108028` | 10 | `T1218.005` T1218.005 | Network connection by mshta | high | 61605 |
| `108029` | 9 | `T1574.002` T1574.002 | DLL loaded from suspicious path | medium | 61609 |
| `108030` | 9 | `T1036` T1036 | Account renamed | medium | 60100 |
| `108031` | 9 | `T1562.001` T1562.001 | Suspicious PowerShell: set-mppreference -disablerealtimemonitoring | medium | 91801 |
| `108032` | 9 | `T1112` T1112 | Registry persistence via currentversion\explorer\shell | medium | 61614 |
| `108033` | 9 | `T1027` Obfuscated Files or Information | Suspicious PowerShell: invoke-obfuscation | medium | 91801 |
| `108034` | 10 | `T1218.004` T1218.004 | DLL sideloading by installutil | high | 61609 |

### Credential Access (TA0006) — 295 rules

| Rule ID | Level | Technique | Description | Confidence | Parent SID |
|---------|-------|-----------|-------------|------------|------------|
| `110000` | 11 | `T1003.002` T1003.002 | Suspicious command: reg save | medium | 61603 |
| `110001` | 12 | `T1003.001` T1003.001 | LSASS memory access | high | 61612 |
| `110002` | 12 | `T1003.001` T1003.001 | Suspicious process: procdump | high | 61603 |
| `110003` | 11 | `T1003.001` T1003.001 | Suspicious command: procdump | medium | 61603 |
| `110004` | 11 | `T1003.003` T1003.003 | Suspicious command: ntdsutil | medium | 61603 |
| `110005` | 9 | `T1110` Brute Force | Failed logon attempt | low | 60100 |
| `110006` | 12 | `T1003.001` T1003.001 | Remote thread injection into LSASS | high | 61610 |
| `110007` | 12 | `T1003.001` T1003.001 | LSASS memory access | high | 61612 |
| `110008` | 11 | `T1003.001` T1003.001 | Suspicious PowerShell: minidump | medium | 91801 |
| `110009` | 12 | `T1003.001` T1003.001 | LSASS memory access | high | 61612 |
| `110010` | 12 | `T1003.001` T1003.001 | LSASS memory access | high | 61612 |
| `110011` | 12 | `T1003.001` T1003.001 | LSASS memory access | high | 61612 |
| `110012` | 11 | `T1003.001` T1003.001 | File created by procdump | medium | 61613 |
| `110013` | 11 | `T1003.001` T1003.001 | Suspicious command: dumpert | medium | 61603 |
| `110014` | 11 | `T1003.001` T1003.001 | Suspicious command: comsvcs.dll | medium | 61603 |
| `110015` | 11 | `T1003.001` T1003.001 | Suspicious command: minidump | medium | 61603 |
| `110016` | 12 | `T1003.001` T1003.001 | LSASS memory access | high | 61612 |
| `110017` | 12 | `T1003.001` T1003.001 | LSASS memory access | high | 61612 |
| `110018` | 13 | `T1003` OS Credential Dumping | Suspicious service: mimikatz driver (mimidrv) | high | 60106 |
| `110019` | 13 | `T1003` OS Credential Dumping | PowerShell module: invoke-mimikatz | medium | 91801 |
| `110020` | 13 | `T1003.001` T1003.001 | PowerShell module: sekurlsa:: | medium | 91801 |
| `110021` | 13 | `T1003` OS Credential Dumping | Suspicious process: mimikatz | high | 61603 |
| `110022` | 11 | `T1003.001` T1003.001 | Suspicious PowerShell: comsvcs.dll | medium | 91801 |
| `110023` | 13 | `T1003` OS Credential Dumping | Suspicious PowerShell: invoke-mimikatz | medium | 91801 |
| `110024` | 12 | `T1003.001` T1003.001 | LSASS Process Crashed - Application | high | 60003 |
| `110025` | 11 | `T1003.003` T1003.003 | Ntdsutil Abuse | medium | 60003 |
| `110026` | 11 | `T1110` Brute Force | MSSQL Server Failed Logon From External Network | medium | 60003 |
| `110027` | 11 | `T1649` T1649 | Certificate Private Key Acquired | medium | 60000 |
| `110028` | 11 | `T1649` T1649 | Certificate Exported From Local Certificate Store | medium | 60000 |
| `110029` | 11 | - | Standard User In High Privileged Group | medium | 60000 |
| `110030` | 11 | `T1110` Brute Force | NTLM Brute Force | medium | 60000 |
| `110031` | 12 | `T1003.006` T1003.006 | Active Directory Replication from Non Machine Account | high | 60100 |
| `110032` | 13 | `T1003.006` T1003.006 | Mimikatz DC Sync | high | 60100 |
| `110033` | 12 | `T1003.004` T1003.004 | DPAPI Domain Backup Key Extraction | high | 60100 |
| `110034` | 11 | `T1003.004` T1003.004 | DPAPI Domain Master Key Backup Attempt | medium | 60100 |
| `110035` | 12 | `T1003.002` T1003.002 | Possible Impacket SecretDump Remote Activity | high | 60100 |
| `110036` | 11 | `T1558.003` T1558.003 | Kerberoasting Activity - Initial Query | medium | 60100 |
| `110037` | 12 | `T1003.001` T1003.001 | LSASS Access From Non System Account | medium | 60100 |
| `110038` | 12 | `T1003.001` T1003.001 | Credential Dumping Tools Service Execution - Security | high | 60100 |
| `110039` | 12 | `T1003` OS Credential Dumping | WCE wceaux.dll Access | high | 60100 |
| `110040` | 12 | `T1187` T1187 | Possible PetitPotam Coerce Authentication Attempt | high | 60100 |
| `110041` | 12 | `T1187` T1187 | PetitPotam Suspicious Kerberos TGT Request | high | 60100 |
| `110042` | 11 | `T1207` T1207 | Possible DC Shadow Attack | medium | 60100 |
| `110043` | 11 | `T1207` T1207 | Possible DC Shadow Attack | medium | 60100 |
| `110044` | 12 | `T1558` Steal or Forge Kerberos Tickets | Replay Attack Detected | high | 60100 |
| `110045` | 11 | `T1003` OS Credential Dumping | File Access Of Signal Desktop Sensitive Data | medium | 60100 |
| `110046` | 12 | `T1212` T1212 | Kerberos Manipulation | high | 60100 |
| `110047` | 12 | `T1003.001` T1003.001 | Password Dumper Activity on LSASS | high | 60100 |
| `110048` | 12 | `T1003.001` T1003.001 | Potentially Suspicious AccessMask Requested From LSASS | medium | 60100 |
| `110049` | 12 | `T1003.001` T1003.001 | Potentially Suspicious AccessMask Requested From LSASS | medium | 60100 |
| `110050` | 11 | `T1558.003` T1558.003 | Suspicious Kerberos RC4 Ticket Encryption | medium | 60100 |
| `110051` | 12 | `T1528` T1528 | Suspicious Teams Application Related ObjectAcess Event | high | 60100 |
| `110052` | 12 | `T1003.002` T1003.002 | Transferring Files with Credential Data via Network Shares | medium | 60100 |
| `110053` | 12 | `T1558.003` T1558.003 | User Couldn't Call a Privileged Service 'LsaRegisterLogonProcess' | high | 60100 |
| `110054` | 11 | `T1110.001` T1110.001 | Suspicious Rejected SMB Guest Logon From IP | medium | 60000 |
| `110055` | 12 | `T1003.002` T1003.002 | Critical Hive In Suspicious Location Access Bits Cleared | high | 60106 |
| `110056` | 11 | `T1003.002` T1003.002 | Crash Dump Created By Operating System | medium | 60106 |
| `110057` | 12 | `T1003.001` T1003.001 | Credential Dumping Tools Service Execution - System | high | 60106 |
| `110058` | 12 | `T1003.001` T1003.001 | LSASS Access Detected via Attack Surface Reduction | high | 60005 |
| `110059` | 12 | `T1555.005` T1555.005 | Remote Thread Created In KeePass.EXE | high | 61610 |
| `110060` | 12 | - | Remote Thread Creation In Mstsc.Exe From Suspicious Location | high | 61610 |
| `110061` | 12 | `T1003.001` T1003.001 | Potential Credential Dumping Attempt Via PowerShell Remote Thread | high | 61610 |
| `110062` | 12 | `T1003.001` T1003.001 | Password Dumper Remote Thread in LSASS | high | 61610 |
| `110063` | 12 | `T1599.001` T1599.001 | WinDivert Driver Load | high | 61608 |
| `110064` | 12 | `T1599.001` T1599.001 | WinDivert Driver Load | high | 61608 |
| `110065` | 11 | `T1003` OS Credential Dumping | Credential Manager Access By Uncommon Applications | medium | 61613 |
| `110066` | 11 | `T1555.004` T1555.004 | Access To Windows Credential History File By Uncommon Applications | medium | 61613 |
| `110067` | 11 | `T1003` OS Credential Dumping | Access To Crypto Currency Wallets By Uncommon Applications | medium | 61613 |
| `110068` | 11 | `T1555.004` T1555.004 | Access To Windows DPAPI Master Keys By Uncommon Applications | medium | 61613 |
| `110069` | 11 | `T1552.006` T1552.006 | Access To Potentially Sensitive Sysvol Files By Uncommon Applications | medium | 61613 |
| `110070` | 11 | `T1528` T1528 | Microsoft Teams Sensitive File Access By Uncommon Applications | medium | 61613 |
| `110071` | 12 | `T1003.001` T1003.001 | Cred Dump Tools Dropped Files | high | 61613 |
| `110072` | 12 | `T1003.001` T1003.001 | Cred Dump Tools Dropped Files | high | 61613 |
| `110073` | 12 | `T1003.001` T1003.001 | HackTool - CrackMapExec File Indicators | high | 61613 |
| `110074` | 12 | `T1003.001` T1003.001 | HackTool - Dumpert Process Dumper Default File | high | 61613 |
| `110075` | 12 | `T1552.001` T1552.001 | HackTool - Typical HiveNightmare SAM File Export | high | 61613 |
| `110076` | 12 | `T1552.001` T1552.001 | HackTool - Typical HiveNightmare SAM File Export | high | 61613 |
| `110077` | 13 | `T1558` Steal or Forge Kerberos Tickets | HackTool - Mimikatz Kirbi File Creation | high | 61613 |
| `110078` | 12 | - | HackTool - NPPSpy Hacktool Usage | high | 61613 |
| `110079` | 12 | `T1003.002` T1003.002 | HackTool - QuarksPwDump Dump File | high | 61613 |
| `110080` | 12 | `T1003` OS Credential Dumping | HackTool - Potential Remote Credential Dumping Activity Via CrackMa... | high | 61613 |
| `110081` | 12 | `T1003.001` T1003.001 | HackTool - SafetyKatz Dump Indicator | high | 61613 |
| `110082` | 12 | `T1003.001` T1003.001 | HackTool - Impacket File Indicators | high | 61613 |
| `110083` | 12 | `T1003.001` T1003.001 | LSASS Process Memory Dump Files | high | 61613 |
| `110084` | 12 | `T1003.001` T1003.001 | LSASS Process Memory Dump Files | high | 61613 |
| `110085` | 12 | `T1003.001` T1003.001 | LSASS Process Memory Dump Files | high | 61613 |
| `110086` | 12 | `T1003.001` T1003.001 | LSASS Process Memory Dump Files | high | 61613 |
| `110087` | 12 | `T1003.001` T1003.001 | LSASS Process Memory Dump Files | high | 61613 |
| `110088` | 12 | `T1003.001` T1003.001 | LSASS Process Dump Artefact In CrashDumps Folder | high | 61613 |
| `110089` | 12 | `T1003.001` T1003.001 | WerFault LSASS Process Memory Dump | high | 61613 |
| `110090` | 12 | `T1003.003` T1003.003 | NTDS.DIT Creation By Uncommon Parent Process | high | 61613 |
| `110091` | 12 | `T1003.002` T1003.002 | NTDS.DIT Creation By Uncommon Process | high | 61613 |
| `110092` | 12 | `T1003.003` T1003.003 | NTDS Exfiltration Filename Patterns | high | 61613 |
| `110093` | 12 | `T1003.002` T1003.002 | Potential SAM Database Dump | high | 61613 |
| `110094` | 12 | `T1003.002` T1003.002 | Potential SAM Database Dump | high | 61613 |
| `110095` | 12 | `T1555` T1555 | DPAPI Backup Keys And Certificate Export Activity IOC | high | 61613 |
| `110096` | 12 | `T1003.001` T1003.001 | LSASS Process Memory Dump Creation Via Taskmgr.EXE | high | 61613 |
| `110097` | 12 | `T1003.001` T1003.001 | Suspicious Renamed Comsvcs DLL Loaded By Rundll32 | high | 61609 |
| `110098` | 11 | `T1056.002` T1056.002 | CredUI.DLL Loaded By Uncommon Process | medium | 61609 |
| `110099` | 12 | `T1003.001` T1003.001 | Suspicious Unsigned Dbghelp/Dbgcore DLL Loaded | high | 61609 |
| `110100` | 12 | `T1218` T1218 | Time Travel Debugging Utility Usage - Image | high | 61609 |
| `110101` | 12 | `T1003.001` T1003.001 | Unsigned Image Loaded Into LSASS Process | medium | 61609 |
| `110102` | 12 | `T1003` OS Credential Dumping | Suspicious Loading of Dbgcore/Dbghelp DLLs from Uncommon Location | high | 61609 |
| `110103` | 11 | `T1558` Steal or Forge Kerberos Tickets | Uncommon Outbound Kerberos Connection | medium | 61605 |
| `110104` | 13 | `T1003.001` T1003.001 | HackTool - Credential Dumping Tools Named Pipe Created | high | 61619 |
| `110105` | 12 | `T1003.003` T1003.003 | Suspicious Get-ADDBAccount Usage | high | 91801 |
| `110106` | 11 | `T1555.003` T1555.003 | Access to Browser Login Data | medium | 91801 |
| `110107` | 12 | `T1003.003` T1003.003 | Create Volume Shadow Copy with Powershell | high | 91801 |
| `110108` | 11 | `T1555` T1555 | Dump Credentials from Windows Credential Manager With PowerShell | medium | 91801 |
| `110109` | 11 | `T1555` T1555 | Dump Credentials from Windows Credential Manager With PowerShell | medium | 91801 |
| `110110` | 11 | `T1555` T1555 | Dump Credentials from Windows Credential Manager With PowerShell | medium | 91801 |
| `110111` | 11 | `T1555` T1555 | Enumerate Credentials from Windows Credential Manager With PowerShell | medium | 91801 |
| `110112` | 11 | `T1552.004` T1552.004 | Certificate Exported Via PowerShell - ScriptBlock | medium | 91801 |
| `110113` | 11 | `T1003.006` T1003.006 | Suspicious Get-ADReplAccount | medium | 91801 |
| `110114` | 12 | `T1003` OS Credential Dumping | HackTool - Rubeus Execution - ScriptBlock | high | 91801 |
| `110115` | 12 | `T1046` T1046 | HackTool - WinPwn Execution - ScriptBlock | high | 91801 |
| `110116` | 11 | `T1056.001` T1056.001 | Powershell Keylogging | medium | 91801 |
| `110117` | 11 | `T1056.001` T1056.001 | Powershell Keylogging | medium | 91801 |
| `110118` | 12 | `T1003` OS Credential Dumping | Live Memory Dump Using Powershell | high | 91801 |
| `110119` | 11 | `T1040` T1040 | Potential Packet Capture Activity Via Start-NetEventSession - Scrip... | medium | 91801 |
| `110120` | 13 | `T1003` OS Credential Dumping | Potential Invoke-Mimikatz PowerShell Script | high | 91801 |
| `110121` | 13 | `T1003` OS Credential Dumping | Potential Invoke-Mimikatz PowerShell Script | high | 91801 |
| `110122` | 13 | `T1003` OS Credential Dumping | Potential Invoke-Mimikatz PowerShell Script | high | 91801 |
| `110123` | 12 | `T1059.001` T1059.001 | PowerShell Credential Prompt | high | 91801 |
| `110124` | 12 | `T1558.003` T1558.003 | Suspicious Kerberos Ticket Request via PowerShell Script - ScriptBlock | high | 91801 |
| `110125` | 11 | `T1552.001` T1552.001 | Extracting Information with PowerShell | medium | 91801 |
| `110126` | 12 | `T1003.001` T1003.001 | PowerShell Get-Process LSASS in ScriptBlock | high | 91801 |
| `110127` | 12 | - | Veeam Backup Servers Credential Dumping Script Execution | high | 91801 |
| `110128` | 13 | `T1003.001` T1003.001 | HackTool - Generic Process Access | high | 61612 |
| `110129` | 12 | `T1003.001` T1003.001 | HackTool - Generic Process Access | high | 61612 |
| `110130` | 12 | `T1003.001` T1003.001 | Lsass Memory Dump via Comsvcs DLL | high | 61612 |
| `110131` | 12 | `T1003.001` T1003.001 | LSASS Memory Access by Tool With Dump Keyword In Name | high | 61612 |
| `110132` | 12 | `T1003.001` T1003.001 | Potential Credential Dumping Activity Via LSASS | medium | 61612 |
| `110133` | 12 | `T1003.001` T1003.001 | Credential Dumping Activity By Python Based Tool | high | 61612 |
| `110134` | 12 | `T1003.001` T1003.001 | Remote LSASS Process Access Through Windows Remote Management | high | 61612 |
| `110135` | 12 | `T1003.001` T1003.001 | Suspicious LSASS Access Via MalSecLogon | high | 61612 |
| `110136` | 12 | `T1003.001` T1003.001 | Potentially Suspicious GrantedAccess Flags On LSASS | medium | 61612 |
| `110137` | 12 | `T1003.001` T1003.001 | Credential Dumping Attempt Via WerFault | high | 61612 |
| `110138` | 12 | `T1003.001` T1003.001 | LSASS Access From Potentially White-Listed Processes | high | 61612 |
| `110139` | 12 | `T1003.001` T1003.001 | Suspicious Process Access to LSASS with Dbgcore/Dbghelp DLLs | high | 61612 |
| `110140` | 12 | `T1185` T1185 | Potential Data Stealing Via Chromium Headless Debugging | high | 61603 |
| `110141` | 11 | `T1185` T1185 | Browser Started with Remote Debugging | medium | 61603 |
| `110142` | 11 | `T1185` T1185 | Browser Started with Remote Debugging | medium | 61603 |
| `110143` | 12 | `T1218.011` T1218.011 | Process Access via TrolleyExpress Exclusion | high | 61603 |
| `110144` | 12 | - | Copy .DMP/.DUMP Files From Remote Share Via Cmd.EXE | high | 61603 |
| `110145` | 12 | `T1003.002` T1003.002 | VolumeShadowCopy Symlink Creation Via Mklink | high | 61603 |
| `110146` | 11 | `T1003.005` T1003.005 | New Generic Credentials Added Via Cmdkey.EXE | medium | 61603 |
| `110147` | 12 | `T1003.005` T1003.005 | Potential Reconnaissance For Cached Credentials Via Cmdkey.EXE | high | 61603 |
| `110148` | 12 | `T1036` T1036 | CreateDump Process Dump | high | 61603 |
| `110149` | 12 | `T1003.001` T1003.001 | Potential Windows Defender AV Bypass Via Dump64.EXE Rename | high | 61603 |
| `110150` | 11 | `T1036` T1036 | DumpMinitool Execution | medium | 61603 |
| `110151` | 12 | `T1036` T1036 | Suspicious DumpMinitool Execution | high | 61603 |
| `110152` | 11 | `T1003` OS Credential Dumping | Esentutl Gather Credentials | medium | 61603 |
| `110153` | 12 | `T1003.002` T1003.002 | Copying Sensitive Files with Credential Data | high | 61603 |
| `110154` | 11 | `T1218` T1218 | Remote File Download Via Findstr.EXE | medium | 61603 |
| `110155` | 12 | `T1552.006` T1552.006 | Findstr GPP Passwords | high | 61603 |
| `110156` | 12 | `T1552.006` T1552.006 | LSASS Process Reconnaissance Via Findstr.EXE | high | 61603 |
| `110157` | 11 | `T1552.006` T1552.006 | Permission Misconfiguration Reconnaissance Via Findstr.EXE | medium | 61603 |
| `110158` | 12 | `T1003.001` T1003.001 | HackTool - CrackMapExec Process Patterns | high | 61603 |
| `110159` | 12 | `T1003.001` T1003.001 | HackTool - CrackMapExec Process Patterns | high | 61603 |
| `110160` | 12 | `T1003.001` T1003.001 | HackTool - CrackMapExec Process Patterns | high | 61603 |
| `110161` | 12 | `T1003.001` T1003.001 | HackTool - CreateMiniDump Execution | high | 61603 |
| `110162` | 12 | `T1003.001` T1003.001 | HackTool - CreateMiniDump Execution | high | 61603 |
| `110163` | 12 | `T1003.001` T1003.001 | HackTool - Doppelanger LSASS Dumper Execution | high | 61603 |
| `110164` | 12 | `T1003.001` T1003.001 | HackTool - Doppelanger LSASS Dumper Execution | high | 61603 |
| `110165` | 12 | `T1003.001` T1003.001 | HackTool - Dumpert Process Dumper Execution | high | 61603 |
| `110166` | 12 | `T1003.001` T1003.001 | HackTool - Dumpert Process Dumper Execution | high | 61603 |
| `110167` | 12 | `T1588.002` T1588.002 | Hacktool Execution - Imphash | high | 61603 |
| `110168` | 12 | `T1588.002` T1588.002 | Hacktool Execution - PE Metadata | high | 61603 |
| `110169` | 12 | `T1003.001` T1003.001 | HackTool - HandleKatz LSASS Dumper Execution | high | 61603 |
| `110170` | 12 | `T1003.001` T1003.001 | HackTool - HandleKatz LSASS Dumper Execution | high | 61603 |
| `110171` | 12 | `T1003.001` T1003.001 | HackTool - HandleKatz LSASS Dumper Execution | high | 61603 |
| `110172` | 12 | `T1110.002` T1110.002 | HackTool - Hashcat Password Cracker Execution | high | 61603 |
| `110173` | 12 | `T1110.002` T1110.002 | HackTool - Hashcat Password Cracker Execution | high | 61603 |
| `110174` | 12 | `T1110` Brute Force | HackTool - Hydra Password Bruteforce Execution | high | 61603 |
| `110175` | 12 | `T1003.001` T1003.001 | HackTool - Inveigh Execution | high | 61603 |
| `110176` | 12 | `T1003.001` T1003.001 | HackTool - Inveigh Execution | high | 61603 |
| `110177` | 12 | `T1003.001` T1003.001 | HackTool - Inveigh Execution | high | 61603 |
| `110178` | 12 | `T1003.001` T1003.001 | HackTool - Inveigh Execution | high | 61603 |
| `110179` | 12 | `T1558.003` T1558.003 | HackTool - KrbRelay Execution | high | 61603 |
| `110180` | 12 | `T1558.003` T1558.003 | HackTool - KrbRelay Execution | high | 61603 |
| `110181` | 12 | `T1558.003` T1558.003 | HackTool - KrbRelay Execution | high | 61603 |
| `110182` | 12 | `T1558.003` T1558.003 | HackTool - KrbRelay Execution | high | 61603 |
| `110183` | 12 | `T1558.003` T1558.003 | HackTool - KrbRelay Execution | high | 61603 |
| `110184` | 12 | `T1558.003` T1558.003 | HackTool - RemoteKrbRelay Execution | high | 61603 |
| `110185` | 12 | `T1558.003` T1558.003 | HackTool - KrbRelayUp Execution | high | 61603 |
| `110186` | 12 | `T1558.003` T1558.003 | HackTool - KrbRelayUp Execution | high | 61603 |
| `110187` | 12 | `T1558.003` T1558.003 | HackTool - KrbRelayUp Execution | high | 61603 |
| `110188` | 12 | `T1558.003` T1558.003 | HackTool - KrbRelayUp Execution | high | 61603 |
| `110189` | 12 | `T1558.003` T1558.003 | HackTool - KrbRelayUp Execution | high | 61603 |
| `110190` | 11 | - | HackTool - LaZagne Execution | medium | 61603 |
| `110191` | 11 | - | HackTool - LaZagne Execution | medium | 61603 |
| `110192` | 13 | `T1003.001` T1003.001 | HackTool - Mimikatz Execution | high | 61603 |
| `110193` | 13 | `T1003.001` T1003.001 | HackTool - Mimikatz Execution | high | 61603 |
| `110194` | 13 | `T1003.001` T1003.001 | HackTool - Mimikatz Execution | high | 61603 |
| `110195` | 12 | `T1003.002` T1003.002 | HackTool - Pypykatz Credentials Dumping Activity | high | 61603 |
| `110196` | 12 | `T1003.002` T1003.002 | HackTool - Quarks PwDump Execution | high | 61603 |
| `110197` | 12 | `T1003.002` T1003.002 | HackTool - Quarks PwDump Execution | high | 61603 |
| `110198` | 12 | `T1003` OS Credential Dumping | HackTool - Rubeus Execution | high | 61603 |
| `110199` | 12 | `T1003` OS Credential Dumping | HackTool - Rubeus Execution | high | 61603 |
| `110200` | 12 | `T1003` OS Credential Dumping | HackTool - Rubeus Execution | high | 61603 |
| `110201` | 12 | `T1003` OS Credential Dumping | HackTool - Rubeus Execution | high | 61603 |
| `110202` | 12 | `T1003.001` T1003.001 | HackTool - SafetyKatz Execution | high | 61603 |
| `110203` | 12 | `T1003.001` T1003.001 | HackTool - SafetyKatz Execution | high | 61603 |
| `110204` | 12 | `T1003.001` T1003.001 | HackTool - SafetyKatz Execution | high | 61603 |
| `110205` | 12 | `T1555` T1555 | HackTool - SecurityXploded Execution | high | 61603 |
| `110206` | 12 | `T1555` T1555 | HackTool - SecurityXploded Execution | high | 61603 |
| `110207` | 12 | `T1555` T1555 | HackTool - SecurityXploded Execution | high | 61603 |
| `110208` | 12 | `T1003.001` T1003.001 | HackTool - Windows Credential Editor (WCE) Execution | high | 61603 |
| `110209` | 12 | `T1003.001` T1003.001 | HackTool - Windows Credential Editor (WCE) Execution | high | 61603 |
| `110210` | 12 | `T1046` T1046 | HackTool - WinPwn Execution | high | 61603 |
| `110211` | 12 | `T1003.001` T1003.001 | HackTool - WSASS Execution | high | 61603 |
| `110212` | 12 | `T1003.001` T1003.001 | HackTool - WSASS Execution | high | 61603 |
| `110213` | 12 | `T1003.001` T1003.001 | HackTool - WSASS Execution | high | 61603 |
| `110214` | 12 | `T1036` T1036 | HackTool - XORDump Execution | high | 61603 |
| `110215` | 12 | `T1036` T1036 | HackTool - XORDump Execution | high | 61603 |
| `110216` | 12 | `T1003` OS Credential Dumping | Microsoft IIS Service Account Password Dumped | high | 61603 |
| `110217` | 12 | `T1003` OS Credential Dumping | Microsoft IIS Connection Strings Decryption | high | 61603 |
| `110218` | 11 | `T1003.001` T1003.001 | Dumping Process via Sqldumper.exe | medium | 61603 |
| `110219` | 12 | `T1218` T1218 | Time Travel Debugging Utility Usage | high | 61603 |
| `110220` | 12 | `T1003` OS Credential Dumping | Potential Credential Dumping Via LSASS Process Clone | high | 61603 |
| `110221` | 11 | `T1003.003` T1003.003 | Suspicious Usage Of Active Directory Diagnostic Tool (ntdsutil.exe) | medium | 61603 |
| `110222` | 11 | `T1003.003` T1003.003 | Invocation of Active Directory Diagnostic Tool (ntdsutil.exe) | medium | 61603 |
| `110223` | 11 | `T1552.001` T1552.001 | Potential PowerShell Console History Access Attempt via History File | medium | 61603 |
| `110224` | 11 | `T1552.004` T1552.004 | Certificate Exported Via PowerShell | medium | 61603 |
| `110225` | 12 | `T1552.004` T1552.004 | PowerShell Get-Process LSASS | high | 61603 |
| `110226` | 12 | `T1558.003` T1558.003 | Suspicious Kerberos Ticket Request via CLI | high | 61603 |
| `110227` | 12 | `T1003.002` T1003.002 | PowerShell SAM Copy | high | 61603 |
| `110228` | 12 | `T1003.003` T1003.003 | Sensitive File Dump Via Print.EXE | high | 61603 |
| `110229` | 12 | `T1003.003` T1003.003 | PUA - DIT Snapshot Viewer | high | 61603 |
| `110230` | 12 | `T1003.003` T1003.003 | PUA - DIT Snapshot Viewer | high | 61603 |
| `110231` | 12 | `T1003` OS Credential Dumping | PUA - Memory Dump Mount Via MemProcFS | high | 61603 |
| `110232` | 11 | `T1056.002` T1056.002 | PUA - Mouse Lock Execution | medium | 61603 |
| `110233` | 11 | `T1056.002` T1056.002 | PUA - Mouse Lock Execution | medium | 61603 |
| `110234` | 11 | `T1056.002` T1056.002 | PUA - Mouse Lock Execution | medium | 61603 |
| `110235` | 11 | `T1555.003` T1555.003 | PUA - WebBrowserPassView Execution | medium | 61603 |
| `110236` | 11 | `T1555.003` T1555.003 | PUA - WebBrowserPassView Execution | medium | 61603 |
| `110237` | 12 | `T1003.001` T1003.001 | Process Memory Dump via RdrLeakDiag.EXE | high | 61603 |
| `110238` | 12 | `T1003.002` T1003.002 | Dumping of Sensitive Hives Via Reg.EXE | high | 61603 |
| `110239` | 11 | `T1552.002` T1552.002 | Enumeration for Credentials in Registry | medium | 61603 |
| `110240` | 11 | `T1552.002` T1552.002 | Enumeration for 3rd Party Creds From CLI | medium | 61603 |
| `110241` | 12 | `T1552.002` T1552.002 | Registry Export of Third-Party Credentials | high | 61603 |
| `110242` | 12 | `T1003` OS Credential Dumping | Potential Credential Dumping Attempt Using New NetworkProvider - CLI | high | 61603 |
| `110243` | 12 | `T1528` T1528 | Renamed BrowserCore.EXE Execution | high | 61603 |
| `110244` | 12 | `T1036` T1036 | Renamed CreateDump Utility Execution | high | 61603 |
| `110245` | 12 | `T1036` T1036 | Renamed CreateDump Utility Execution | high | 61603 |
| `110246` | 12 | `T1036` T1036 | Renamed CreateDump Utility Execution | high | 61603 |
| `110247` | 11 | `T1003` OS Credential Dumping | Capture Credentials with Rpcping.exe | medium | 61603 |
| `110248` | 12 | `T1555.004` T1555.004 | Suspicious Key Manager Access | high | 61603 |
| `110249` | 12 | `T1036` T1036 | Process Memory Dump Via Comsvcs.DLL | high | 61603 |
| `110250` | 12 | `T1555` T1555 | Suspicious Serv-U Process Pattern | high | 61603 |
| `110251` | 11 | `T1558.003` T1558.003 | Potential SPN Enumeration Via Setspn.EXE | medium | 61603 |
| `110252` | 12 | `T1539` T1539 | SQLite Chromium Profile Data DB Access | high | 61603 |
| `110253` | 12 | `T1539` T1539 | SQLite Firefox Profile Data DB Access | high | 61603 |
| `110254` | 11 | `T1555.003` T1555.003 | Potential Browser Data Stealing | medium | 61603 |
| `110255` | 11 | `T1552` T1552 | Potentially Suspicious EventLog Recon Activity Using Log Query Util... | medium | 61603 |
| `110256` | 11 | `T1552` T1552 | Potentially Suspicious EventLog Recon Activity Using Log Query Util... | medium | 61603 |
| `110257` | 11 | `T1528` T1528 | Potentially Suspicious JWT Token Search Via CLI | medium | 61603 |
| `110258` | 12 | `T1003.001` T1003.001 | LSASS Dump Keyword In CommandLine | high | 61603 |
| `110259` | 12 | `T1003.001` T1003.001 | LSASS Dump Keyword In CommandLine | high | 61603 |
| `110260` | 12 | `T1003.001` T1003.001 | LSASS Dump Keyword In CommandLine | high | 61603 |
| `110261` | 12 | `T1003.001` T1003.001 | LSASS Dump Keyword In CommandLine | high | 61603 |
| `110262` | 11 | `T1040` T1040 | Potential Network Sniffing Activity Using Network Tools | medium | 61603 |
| `110263` | 11 | `T1040` T1040 | Potential Network Sniffing Activity Using Network Tools | medium | 61603 |
| `110264` | 12 | `T1003.003` T1003.003 | Suspicious Process Patterns NTDS.DIT Exfil | high | 61603 |
| `110265` | 12 | `T1003.003` T1003.003 | Suspicious Process Patterns NTDS.DIT Exfil | high | 61603 |
| `110266` | 12 | `T1003.003` T1003.003 | Suspicious Process Patterns NTDS.DIT Exfil | high | 61603 |
| `110267` | 12 | `T1003.003` T1003.003 | Suspicious Process Patterns NTDS.DIT Exfil | high | 61603 |
| `110268` | 12 | `T1003.003` T1003.003 | Suspicious Process Patterns NTDS.DIT Exfil | high | 61603 |
| `110269` | 12 | `T1003.003` T1003.003 | Suspicious Process Patterns NTDS.DIT Exfil | high | 61603 |
| `110270` | 12 | `T1003.003` T1003.003 | Suspicious Process Patterns NTDS.DIT Exfil | high | 61603 |
| `110271` | 11 | `T1552.004` T1552.004 | Private Keys Reconnaissance Via CommandLine Tools | medium | 61603 |
| `110272` | 12 | `T1552` T1552 | Script Interpreter Spawning Credential Scanner - Windows | high | 61603 |
| `110273` | 11 | `T1003` OS Credential Dumping | Shadow Copies Creation Using Operating Systems Utilities | medium | 61603 |
| `110274` | 12 | `T1134` Access Token Manipulation | Suspicious SYSTEM User Process Creation | high | 61603 |
| `110275` | 11 | `T1552.006` T1552.006 | Suspicious SYSVOL Domain Group Policy Access | medium | 61603 |
| `110276` | 11 | `T1036` T1036 | Procdump Execution | medium | 61603 |
| `110277` | 12 | `T1036` T1036 | Potential SysInternals ProcDump Evasion | high | 61603 |
| `110278` | 12 | `T1036` T1036 | Potential SysInternals ProcDump Evasion | high | 61603 |
| `110279` | 12 | `T1036` T1036 | Potential SysInternals ProcDump Evasion | high | 61603 |
| `110280` | 12 | `T1036` T1036 | Potential LSASS Process Dump Via Procdump | high | 61603 |
| `110281` | 11 | `T1003` OS Credential Dumping | Loaded Module Enumeration Via Tasklist.EXE | medium | 61603 |
| `110282` | 11 | `T1528` T1528 | Potentially Suspicious Command Targeting Teams Sensitive Files | medium | 61603 |
| `110283` | 11 | `T1555.004` T1555.004 | Windows Credential Manager Access via VaultCmd | medium | 61603 |
| `110284` | 12 | `T1003.003` T1003.003 | Sensitive File Dump Via Wbadmin.EXE | high | 61603 |
| `110285` | 12 | `T1003.003` T1003.003 | Sensitive File Recovery From Backup Via Wbadmin.EXE | high | 61603 |
| `110286` | 12 | `T1003.001` T1003.001 | Potential Credential Dumping Via WER | high | 61603 |
| `110287` | 12 | `T1685` T1685 | PPL Tampering Via WerFaultSecure | high | 61603 |
| `110288` | 12 | `T1003.002` T1003.002 | Esentutl Volume Shadow Copy Service Keys | high | 61615 |
| `110289` | 12 | `T1003.001` T1003.001 | Windows Credential Editor Registry | high | 61615 |
| `110290` | 12 | `T1003.001` T1003.001 | Potential Credential Dumping Via LSASS SilentProcessExit Technique | high | 61615 |
| `110291` | 12 | `T1556` T1556 | Directory Service Restore Mode(DSRM) Registry Value Tampering | high | 61615 |
| `110292` | 12 | `T1003.001` T1003.001 | Lsass Full Dump Request Via DumpType Registry Settings | high | 61615 |
| `110293` | 11 | `T1003` OS Credential Dumping | Potential Credential Dumping Attempt Using New NetworkProvider - REG | medium | 61615 |
| `110294` | 12 | `T1003` OS Credential Dumping | Potentially Suspicious ODBC Driver Registered | high | 61615 |

### Discovery (TA0007) — 137 rules

| Rule ID | Level | Technique | Description | Confidence | Parent SID |
|---------|-------|-----------|-------------|------------|------------|
| `112000` | 6 | `T1087.001` T1087.001 | Suspicious command: net user | medium | 61603 |
| `112001` | 6 | `T1069.002` T1069.002 | Potential Active Directory Reconnaissance/Enumeration Via LDAP | medium | 60000 |
| `112002` | 6 | `T1012` T1012 | Azure AD Health Monitoring Agent Registry Keys Access | medium | 60100 |
| `112003` | 6 | `T1012` T1012 | Azure AD Health Service Agents Registry Keys Access | medium | 60100 |
| `112004` | 7 | `T1087.002` T1087.002 | AD Privileged Users or Groups Reconnaissance | high | 60100 |
| `112005` | 6 | `T1087.002` T1087.002 | Potential AD User Enumeration From Non-Machine Account | medium | 60100 |
| `112006` | 7 | `T1087` Account Discovery | Hacktool Ruler | high | 60100 |
| `112007` | 6 | `T1201` T1201 | Password Policy Enumerated | medium | 60100 |
| `112008` | 6 | `T1040` T1040 | Windows Pcap Drivers | medium | 60100 |
| `112009` | 7 | `T1012` T1012 | SAM Registry Hive Handle Request | high | 60100 |
| `112010` | 6 | `T1010` T1010 | SCM Database Handle Failure | medium | 60100 |
| `112011` | 7 | `T1087.002` T1087.002 | Reconnaissance Activity | high | 60100 |
| `112012` | 7 | `T1012` T1012 | SysKey Registry Keys Access | high | 60100 |
| `112013` | 6 | `T1046` T1046 | Advanced IP Scanner - File Event | medium | 61613 |
| `112014` | 11 | `T1087.001` T1087.001 | BloodHound Collection Files | high | 61613 |
| `112015` | 6 | - | GatherNetworkInfo.VBS Reconnaissance Script Output | medium | 61613 |
| `112016` | 6 | `T1087.002` T1087.002 | ADExplorer Writing Complete AD Snapshot Into .dat File | medium | 61613 |
| `112017` | 6 | `T1087` Account Discovery | Uncommon Connection to Active Directory Web Services | medium | 61605 |
| `112018` | 6 | `T1016` T1016 | Suspicious Network Connection to IP Lookup Service APIs | medium | 61605 |
| `112019` | 6 | `T1046` T1046 | Python Initiated Connection | medium | 61605 |
| `112020` | 6 | - | Potential Active Directory Enumeration Using AD Module - PsModule | medium | 91801 |
| `112021` | 6 | - | Potential Active Directory Enumeration Using AD Module - PsScript | medium | 91801 |
| `112022` | 6 | - | Potential Active Directory Enumeration Using AD Module - PsScript | medium | 91801 |
| `112023` | 7 | `T1059.001` T1059.001 | PowerShell ADRecon Execution | high | 91801 |
| `112024` | 6 | `T1033` T1033 | Get-ADUser Enumeration Using UserAccountControl Flags | medium | 91801 |
| `112025` | 6 | `T1033` T1033 | Computer Discovery And Export Via Get-ADComputer Cmdlet - PowerShell | medium | 91801 |
| `112026` | 6 | `T1497.001` T1497.001 | Powershell Detect Virtualization Environment | medium | 91801 |
| `112027` | 6 | `T1018` T1018 | DirectorySearcher Powershell Exploitation | medium | 91801 |
| `112028` | 6 | `T1518.001` T1518.001 | Security Software Discovery Via Powershell Script | medium | 91801 |
| `112029` | 6 | - | PowerShell Hotfix Enumeration | medium | 91801 |
| `112030` | 6 | `T1018` T1018 | Potential Unconstrained Delegation Discovery Via Get-ADComputer - S... | medium | 91801 |
| `112031` | 6 | `T1083` File and Directory Discovery | Powershell Sensitive File Discovery | medium | 91801 |
| `112032` | 6 | `T1518` T1518 | Detected Windows Software Discovery - PowerShell | medium | 91801 |
| `112033` | 6 | `T1083` File and Directory Discovery | Powershell Directory Enumeration | medium | 91801 |
| `112034` | 6 | `T1033` T1033 | User Discovery And Export Via Get-ADUser Cmdlet - PowerShell | medium | 91801 |
| `112035` | 6 | `T1614.001` T1614.001 | Console CodePage Lookup Via CHCP | medium | 61603 |
| `112036` | 6 | - | Potential Discovery Activity Via Dnscmd.EXE | medium | 61603 |
| `112037` | 7 | - | Potential Recon Activity Using DriverQuery.EXE | high | 61603 |
| `112038` | 6 | - | DriverQuery.EXE Execution | medium | 61603 |
| `112039` | 6 | `T1482` T1482 | Domain Trust Discovery Via Dsquery | medium | 61603 |
| `112040` | 7 | `T1082` System Information Discovery | Suspicious Kernel Dump Using Dtrace | high | 61603 |
| `112041` | 7 | `T1082` System Information Discovery | Suspicious Kernel Dump Using Dtrace | high | 61603 |
| `112042` | 7 | `T1135` T1135 | File Explorer Folder Opened Using Explorer Folder Shortcut Via Shell | high | 61603 |
| `112043` | 6 | `T1057` T1057 | Recon Command Output Piped To Findstr.EXE | medium | 61603 |
| `112044` | 6 | `T1518.001` T1518.001 | Security Tools Keyword Lookup Via Findstr.EXE | medium | 61603 |
| `112045` | 7 | `T1518.001` T1518.001 | Sysmon Discovery Via Default Driver Altitude Using Findstr.EXE | high | 61603 |
| `112046` | 6 | `T1615` T1615 | Gpresult Display Group Policy Information | medium | 61603 |
| `112047` | 11 | `T1087.001` T1087.001 | HackTool - Bloodhound/Sharphound Execution | high | 61603 |
| `112048` | 11 | `T1087.001` T1087.001 | HackTool - Bloodhound/Sharphound Execution | high | 61603 |
| `112049` | 11 | `T1087.001` T1087.001 | HackTool - Bloodhound/Sharphound Execution | high | 61603 |
| `112050` | 11 | `T1087.001` T1087.001 | HackTool - Bloodhound/Sharphound Execution | high | 61603 |
| `112051` | 11 | `T1087.001` T1087.001 | HackTool - Bloodhound/Sharphound Execution | high | 61603 |
| `112052` | 11 | `T1087.001` T1087.001 | HackTool - Bloodhound/Sharphound Execution | high | 61603 |
| `112053` | 11 | `T1087.001` T1087.001 | HackTool - Bloodhound/Sharphound Execution | high | 61603 |
| `112054` | 7 | `T1649` T1649 | HackTool - Certify Execution | high | 61603 |
| `112055` | 11 | `T1649` T1649 | HackTool - Certipy Execution | high | 61603 |
| `112056` | 7 | `T1018` T1018 | HackTool - NetExec Execution | high | 61603 |
| `112057` | 6 | - | HackTool - SharpLDAPmonitor Execution | medium | 61603 |
| `112058` | 6 | - | HackTool - SharpLDAPmonitor Execution | medium | 61603 |
| `112059` | 6 | - | HackTool - SharpLDAPmonitor Execution | medium | 61603 |
| `112060` | 7 | `T1033` T1033 | HackTool - SharpLdapWhoami Execution | high | 61603 |
| `112061` | 7 | `T1033` T1033 | HackTool - SharpLdapWhoami Execution | high | 61603 |
| `112062` | 7 | `T1033` T1033 | HackTool - SharpLdapWhoami Execution | high | 61603 |
| `112063` | 7 | `T1033` T1033 | HackTool - SharpLdapWhoami Execution | high | 61603 |
| `112064` | 7 | `T1049` T1049 | HackTool - SharpView Execution | high | 61603 |
| `112065` | 7 | `T1049` T1049 | HackTool - SharpView Execution | high | 61603 |
| `112066` | 7 | `T1049` T1049 | HackTool - SharpView Execution | high | 61603 |
| `112067` | 7 | `T1087` Account Discovery | HackTool - SOAPHound Execution | high | 61603 |
| `112068` | 7 | `T1482` T1482 | HackTool - TruffleSnout Execution | high | 61603 |
| `112069` | 7 | `T1482` T1482 | HackTool - TruffleSnout Execution | high | 61603 |
| `112070` | 6 | `T1615` T1615 | Potential Reconnaissance Activity Via GatherNetworkInfo.VBS | medium | 61603 |
| `112071` | 6 | `T1087.001` T1087.001 | Suspicious Group And Account Reconnaissance Activity Using Net.EXE | medium | 61603 |
| `112072` | 6 | `T1040` T1040 | New Network Trace Capture Started Via Netsh.EXE | medium | 61603 |
| `112073` | 6 | `T1040` T1040 | Harvesting Of Wifi Credentials Via Netsh.EXE | medium | 61603 |
| `112074` | 6 | `T1016` T1016 | Potential Recon Activity Via Nltest.EXE | medium | 61603 |
| `112075` | 7 | `T1087` Account Discovery | Network Reconnaissance Activity | high | 61603 |
| `112076` | 6 | `T1040` T1040 | PktMon.EXE Execution | medium | 61603 |
| `112077` | 6 | `T1040` T1040 | PktMon.EXE Execution | medium | 61603 |
| `112078` | 6 | - | Potential Active Directory Enumeration Using AD Module - ProcCreation | medium | 61603 |
| `112079` | 6 | `T1033` T1033 | Computer Discovery And Export Via Get-ADComputer Cmdlet | medium | 61603 |
| `112080` | 6 | `T1087.001` T1087.001 | Suspicious Reconnaissance Activity Using Get-LocalGroupMember Cmdlet | medium | 61603 |
| `112081` | 6 | `T1033` T1033 | User Discovery And Export Via Get-ADUser Cmdlet | medium | 61603 |
| `112082` | 7 | `T1087.002` T1087.002 | PUA - Suspicious ActiveDirectory Enumeration Via AdFind.EXE | high | 61603 |
| `112083` | 7 | `T1087.002` T1087.002 | PUA - Suspicious ActiveDirectory Enumeration Via AdFind.EXE | high | 61603 |
| `112084` | 7 | `T1087.002` T1087.002 | PUA - Suspicious ActiveDirectory Enumeration Via AdFind.EXE | high | 61603 |
| `112085` | 6 | `T1087.002` T1087.002 | PUA - AdFind.EXE Execution | medium | 61603 |
| `112086` | 6 | `T1087.002` T1087.002 | PUA - AdFind.EXE Execution | medium | 61603 |
| `112087` | 6 | `T1087.002` T1087.002 | PUA - AdFind.EXE Execution | medium | 61603 |
| `112088` | 7 | `T1018` T1018 | PUA - AdFind Suspicious Execution | high | 61603 |
| `112089` | 6 | `T1046` T1046 | PUA - Advanced IP Scanner Execution | medium | 61603 |
| `112090` | 6 | `T1046` T1046 | PUA - Advanced IP Scanner Execution | medium | 61603 |
| `112091` | 6 | `T1046` T1046 | PUA - Advanced IP Scanner Execution | medium | 61603 |
| `112092` | 6 | `T1046` T1046 | PUA - Advanced IP Scanner Execution | medium | 61603 |
| `112093` | 6 | `T1046` T1046 | PUA - Advanced Port Scanner Execution | medium | 61603 |
| `112094` | 6 | `T1046` T1046 | PUA - Advanced Port Scanner Execution | medium | 61603 |
| `112095` | 6 | `T1046` T1046 | PUA - Advanced Port Scanner Execution | medium | 61603 |
| `112096` | 6 | `T1046` T1046 | PUA - Advanced Port Scanner Execution | medium | 61603 |
| `112097` | 7 | `T1590.001` T1590.001 | PUA - Crassus Execution | high | 61603 |
| `112098` | 7 | `T1590.001` T1590.001 | PUA - Crassus Execution | high | 61603 |
| `112099` | 7 | `T1590.001` T1590.001 | PUA - Crassus Execution | high | 61603 |
| `112100` | 6 | `T1046` T1046 | PUA - SoftPerfect Netscan Execution | medium | 61603 |
| `112101` | 6 | `T1046` T1046 | PUA - SoftPerfect Netscan Execution | medium | 61603 |
| `112102` | 6 | `T1046` T1046 | PUA - SoftPerfect Netscan Execution | medium | 61603 |
| `112103` | 6 | `T1046` T1046 | PUA - NimScan Execution | medium | 61603 |
| `112104` | 6 | `T1046` T1046 | PUA - NimScan Execution | medium | 61603 |
| `112105` | 6 | `T1046` T1046 | PUA - Nmap/Zenmap Execution | medium | 61603 |
| `112106` | 6 | `T1046` T1046 | PUA - Nmap/Zenmap Execution | medium | 61603 |
| `112107` | 6 | `T1622` T1622 | PUA - Process Hacker Execution | medium | 61603 |
| `112108` | 6 | `T1622` T1622 | PUA - Process Hacker Execution | medium | 61603 |
| `112109` | 6 | `T1622` T1622 | PUA - Process Hacker Execution | medium | 61603 |
| `112110` | 6 | `T1622` T1622 | PUA - Process Hacker Execution | medium | 61603 |
| `112111` | 6 | `T1622` T1622 | PUA - Process Hacker Execution | medium | 61603 |
| `112112` | 6 | `T1622` T1622 | PUA - Process Hacker Execution | medium | 61603 |
| `112113` | 7 | `T1526` T1526 | PUA - Seatbelt Execution | high | 61603 |
| `112114` | 6 | `T1083` File and Directory Discovery | PUA - TruffleHog Execution | medium | 61603 |
| `112115` | 6 | `T1012` T1012 | Potential Configuration And Service Reconnaissance Via Reg.EXE | medium | 61603 |
| `112116` | 6 | `T1518` T1518 | Detected Windows Software Discovery | medium | 61603 |
| `112117` | 6 | `T1614.001` T1614.001 | System Language Discovery via Reg.Exe | medium | 61603 |
| `112118` | 7 | `T1018` T1018 | Renamed AdFind Execution | high | 61603 |
| `112119` | 7 | `T1018` T1018 | Renamed AdFind Execution | high | 61603 |
| `112120` | 7 | `T1018` T1018 | Renamed AdFind Execution | high | 61603 |
| `112121` | 7 | `T1033` T1033 | Renamed Whoami Execution | high | 61603 |
| `112122` | 7 | `T1615` T1615 | Suspicious Reconnaissance Activity Via GatherNetworkInfo.VBS | high | 61603 |
| `112123` | 6 | - | Obfuscated IP Download Activity | medium | 61603 |
| `112124` | 6 | - | Obfuscated IP Via CLI | medium | 61603 |
| `112125` | 7 | `T1033` T1033 | WhoAmI as Parameter | high | 61603 |
| `112126` | 6 | `T1069.001` T1069.001 | Permission Check Via Accesschk.EXE | medium | 61603 |
| `112127` | 6 | `T1087.002` T1087.002 | Active Directory Database Snapshot Via ADExplorer | medium | 61603 |
| `112128` | 7 | `T1087.002` T1087.002 | Suspicious Active Directory Database Snapshot Via ADExplorer | high | 61603 |
| `112129` | 6 | `T1087` Account Discovery | Suspicious Use of PsLogList | medium | 61603 |
| `112130` | 7 | `T1124` T1124 | Use of W32tm as Timer | high | 61603 |
| `112131` | 6 | `T1033` T1033 | Enumerate All Information With Whoami.EXE | medium | 61603 |
| `112132` | 6 | `T1033` T1033 | Group Membership Reconnaissance Via Whoami.EXE | medium | 61603 |
| `112133` | 6 | `T1033` T1033 | Whoami.EXE Execution With Output Option | medium | 61603 |
| `112134` | 6 | `T1033` T1033 | Whoami.EXE Execution Anomaly | medium | 61603 |
| `112135` | 6 | `T1047` T1047 | Computer System Reconnaissance Via Wmic.EXE | medium | 61603 |
| `112136` | 6 | `T1082` System Information Discovery | Uncommon System Information Discovery Via Wmic.EXE | medium | 61603 |

### Lateral Movement (TA0008) — 77 rules

| Rule ID | Level | Technique | Description | Confidence | Parent SID |
|---------|-------|-----------|-------------|------------|------------|
| `114000` | 8 | `T1078` Valid Accounts | Explicit credential logon | low | 60100 |
| `114001` | 8 | `T1021.001` T1021.001 | Remote logon (type 3) | low | 60100 |
| `114002` | 8 | `T1021.001` T1021.001 | Remote logon (type 10) | low | 60100 |
| `114003` | 11 | `T1021.002` T1021.002 | Suspicious named pipe: \ntsvcs | high | 61620 |
| `114004` | 11 | `T1021.002` T1021.002 | Suspicious named pipe: \scerpc | high | 61620 |
| `114005` | 11 | `T1021.002` T1021.002 | Suspicious process: psexesvc | high | 61603 |
| `114006` | 11 | `T1021.002` T1021.002 | Suspicious process: psexec | high | 61603 |
| `114007` | 11 | `T1021.002` T1021.002 | Suspicious named pipe: \psexe | high | 61619 |
| `114008` | 11 | `T1021.002` T1021.002 | Suspicious named pipe: \psexe | high | 61620 |
| `114009` | 10 | `T1021.002` T1021.002 | File created by psexec | medium | 61613 |
| `114010` | 10 | `T1021.002` T1021.002 | DNS query by psexec | medium | 61624 |
| `114011` | 11 | `T1021.002` T1021.002 | Suspicious service: PSEXESVC | high | 60106 |
| `114012` | 11 | `T1072` T1072 | Restricted Software Access By SRP | high | 60003 |
| `114013` | 10 | `T1021.004` T1021.004 | OpenSSH Server Listening On Socket | medium | 60000 |
| `114014` | 11 | `T1550.002` T1550.002 | Successful Overpass the Hash Attempt | high | 60100 |
| `114015` | 10 | `T1550.002` T1550.002 | Pass the Hash Activity 2 | medium | 60100 |
| `114016` | 10 | `T1550.002` T1550.002 | Pass the Hash Activity 2 | medium | 60100 |
| `114017` | 11 | `T1021.001` T1021.001 | RDP Login from Localhost | high | 60100 |
| `114018` | 10 | `T1021.002` T1021.002 | DCERPC SMB Spoolss Named Pipe | medium | 60100 |
| `114019` | 11 | `T1021.002` T1021.002 | DCOM InternetExplorer.Application Iertutil DLL Hijack - Security | high | 60100 |
| `114020` | 11 | `T1021.002` T1021.002 | Impacket PsExec Execution | high | 60100 |
| `114021` | 11 | `T1021.002` T1021.002 | First Time Seen Remote Named Pipe | high | 60100 |
| `114022` | 11 | `T1021.002` T1021.002 | Metasploit SMB Authentication | high | 60100 |
| `114023` | 11 | `T1021.002` T1021.002 | Metasploit SMB Authentication | high | 60100 |
| `114024` | 11 | `T1021.002` T1021.002 | Metasploit Or Impacket Service Installation Via SMB PsExec | high | 60100 |
| `114025` | 10 | `T1021.001` T1021.001 | Denied Access To Remote Desktop | medium | 60100 |
| `114026` | 11 | `T1021.002` T1021.002 | Protected Storage Service Access | high | 60100 |
| `114027` | 11 | `T1558.003` T1558.003 | Register new Logon Process by Rubeus | high | 60100 |
| `114028` | 11 | `T1021.002` T1021.002 | SMB Create Remote File Admin Share | high | 60100 |
| `114029` | 10 | `T1558.003` T1558.003 | Uncommon Outbound Kerberos Connection - Security | medium | 60100 |
| `114030` | 11 | `T1021.002` T1021.002 | Suspicious PsExec Execution | high | 60100 |
| `114031` | 10 | `T1021.002` T1021.002 | Remote Service Activity via SVCCTL Named Pipe | medium | 60100 |
| `114032` | 10 | `T1021.002` T1021.002 | Unsigned or Unencrypted SMB Connection to Share Established | medium | 60000 |
| `114033` | 10 | `T1550.002` T1550.002 | NTLMv1 Logon Between Client and Server | medium | 60106 |
| `114034` | 11 | `T1210` T1210 | Zerologon Exploitation Using Well-known Tools | high | 60106 |
| `114035` | 11 | `T1021.002` T1021.002 | smbexec.py Service Installation | high | 60106 |
| `114036` | 11 | `T1021.002` T1021.002 | Potential DCOM InternetExplorer.Application DLL Hijack | high | 61613 |
| `114037` | 11 | `T1136.002` T1136.002 | PSEXEC Remote Execution File Artefact | high | 61613 |
| `114038` | 11 | `T1047` T1047 | Wmiexec Default Output File | high | 61613 |
| `114039` | 11 | `T1047` T1047 | Wmiexec Default Output File | high | 61613 |
| `114040` | 11 | `T1047` T1047 | Wmiexec Default Output File | high | 61613 |
| `114041` | 11 | `T1021.002` T1021.002 | Potential DCOM InternetExplorer.Application DLL Hijack - Image Load | high | 61609 |
| `114042` | 10 | `T1546.003` T1546.003 | WMI ActiveScriptEventConsumers Activity Via Scrcons.EXE DLL Load | medium | 61609 |
| `114043` | 11 | `T1218` T1218 | BaaUpdate.exe Suspicious DLL Load | high | 61609 |
| `114044` | 11 | `T1021.001` T1021.001 | Outbound RDP Connections Over Non-Standard Tools | high | 61605 |
| `114045` | 10 | `T1021.002` T1021.002 | PUA - CSExec Default Named Pipe | medium | 61619 |
| `114046` | 10 | `T1021.002` T1021.002 | PUA - RemCom Default Named Pipe | medium | 61619 |
| `114047` | 11 | - | HackTool - Evil-WinRm Execution - PowerShell Module | high | 91801 |
| `114048` | 10 | `T1021.006` T1021.006 | Enable Windows Remote Management | medium | 91801 |
| `114049` | 10 | `T1021.006` T1021.006 | Execute Invoke-command on Remote Host | medium | 91801 |
| `114050` | 10 | `T1021.002` T1021.002 | Suspicious New-PSDrive to Admin Share | medium | 91801 |
| `114051` | 11 | `T1218` T1218 | Suspicious BitLocker Access Agent Update Utility Execution | high | 61603 |
| `114052` | 10 | `T1072` T1072 | Suspicious Csi.exe Usage | medium | 61603 |
| `114053` | 10 | `T1021.006` T1021.006 | HackTool - WinRM Access Via Evil-WinRM | medium | 61603 |
| `114054` | 11 | `T1021.002` T1021.002 | HackTool - SharpMove Tool Execution | high | 61603 |
| `114055` | 11 | - | HackTool - Wmiexec Default Powershell Command | high | 61603 |
| `114056` | 10 | `T1210` T1210 | Suspicious SysAidServer Child | medium | 61603 |
| `114057` | 11 | `T1021.003` T1021.003 | MMC Spawning Windows Shell | high | 61603 |
| `114058` | 11 | `T1563.002` T1563.002 | Potential MSTSC Shadowing Activity | high | 61603 |
| `114059` | 10 | `T1021.001` T1021.001 | New Remote Desktop Connection Initiated Via Mstsc.EXE | medium | 61603 |
| `114060` | 11 | - | Mstsc.EXE Execution From Uncommon Parent | high | 61603 |
| `114061` | 10 | `T1021.002` T1021.002 | Windows Admin Share Mount Via Net.EXE | medium | 61603 |
| `114062` | 11 | `T1021.002` T1021.002 | Windows Internet Hosted WebDav Share Mount Via Net.EXE | high | 61603 |
| `114063` | 10 | `T1090` T1090 | New Port Forwarding Rule Added Via Netsh.EXE | medium | 61603 |
| `114064` | 11 | `T1090` T1090 | RDP Port Forwarding Rule Added Via Netsh.EXE | high | 61603 |
| `114065` | 11 | `T1021.003` T1021.003 | Potential Excel.EXE DCOM Lateral Movement Via ActivateMicrosoftApp | high | 61603 |
| `114066` | 10 | `T1021.001` T1021.001 | RDP Enable or Disable via Win32_TerminalServiceSetting WMI Class | medium | 61603 |
| `114067` | 11 | `T1021.002` T1021.002 | Rundll32 Execution Without Parameters | high | 61603 |
| `114068` | 11 | `T1021.003` T1021.003 | Suspicious Speech Runtime Binary Child Process | high | 61603 |
| `114069` | 10 | `T1039` T1039 | Copy From Or To Admin Share Or Sysvol Folder | medium | 61603 |
| `114070` | 11 | `T1021` Remote Services | Privilege Escalation via Named Pipe Impersonation | high | 61603 |
| `114071` | 10 | `T1021` Remote Services | Potential Remote Desktop Tunneling | medium | 61603 |
| `114072` | 11 | `T1563.002` T1563.002 | Suspicious RDP Redirect Using TSCON | high | 61603 |
| `114073` | 11 | `T1021.005` T1021.005 | Suspicious UltraVNC Execution | high | 61603 |
| `114074` | 11 | `T1021.006` T1021.006 | Winrs Local Command Execution | high | 61603 |
| `114075` | 10 | `T1021.006` T1021.006 | Potential Lateral Movement via Windows Remote Shell | medium | 61603 |
| `114076` | 10 | `T1090` T1090 | New PortProxy Registry Entry Added | medium | 61615 |

### Collection (TA0009) — 51 rules

| Rule ID | Level | Technique | Description | Confidence | Parent SID |
|---------|-------|-----------|-------------|------------|------------|
| `116000` | 8 | `T1557.001` T1557.001 | RottenPotato Like Attack Pattern | high | 60100 |
| `116001` | 7 | `T1123` T1123 | Processes Accessing the Microphone and Webcam | medium | 60100 |
| `116002` | 8 | `T1557.003` T1557.003 | Potential Kerberos Coercion by Spoofing SPNs via DNS Manipulation | high | 60100 |
| `116003` | 8 | `T1557.003` T1557.003 | Potential Kerberos Coercion by Spoofing SPNs via DNS Manipulation | high | 60100 |
| `116004` | 7 | `T1039` T1039 | Suspicious Access to Sensitive File Extensions | medium | 60100 |
| `116005` | 8 | `T1557.001` T1557.001 | Local Privilege Escalation Indicator TabTip | high | 60106 |
| `116006` | 7 | `T1195.002` T1195.002 | Notepad++ Updater DNS Query to Uncommon Domains | medium | 61624 |
| `116007` | 8 | `T1557.001` T1557.001 | Suspicious DNS Query Indicating Kerberos Coercion via DNS Object SP... | high | 61624 |
| `116008` | 8 | `T1195.002` T1195.002 | Uncommon File Created by Notepad++ Updater Gup.EXE | high | 61613 |
| `116009` | 7 | `T1005` T1005 | ADFS Database Named Pipe Connection By Uncommon Tool | medium | 61619 |
| `116010` | 7 | `T1074.001` T1074.001 | Zip A Folder With PowerShell For Staging In Temp - PowerShell | medium | 91801 |
| `116011` | 7 | `T1115` T1115 | PowerShell Get Clipboard | medium | 91801 |
| `116012` | 7 | `T1074.001` T1074.001 | Zip A Folder With PowerShell For Staging In Temp  - PowerShell Module | medium | 91801 |
| `116013` | 7 | `T1119` T1119 | Automated Collection Command PowerShell | medium | 91801 |
| `116014` | 7 | `T1113` T1113 | Windows Screen Capture with CopyFromScreen | medium | 91801 |
| `116015` | 7 | `T1056.001` T1056.001 | Potential Keylogger Activity | medium | 91801 |
| `116016` | 7 | `T1114.001` T1114.001 | Powershell Local Email Collection | medium | 91801 |
| `116017` | 7 | `T1119` T1119 | Recon Information for Export with PowerShell | medium | 91801 |
| `116018` | 7 | `T1074.001` T1074.001 | Zip A Folder With PowerShell For Staging In Temp - PowerShell Script | medium | 91801 |
| `116019` | 7 | `T1560.001` T1560.001 | 7Zip Compressing Dump Files | medium | 61603 |
| `116020` | 7 | `T1560.001` T1560.001 | Compress Data and Lock With Password for Exfiltration With 7-ZIP | medium | 61603 |
| `116021` | 7 | `T1005` T1005 | Esentutl Steals Browser Information | medium | 61603 |
| `116022` | 8 | `T1195.002` T1195.002 | Suspicious Child Process of Notepad++ Updater - GUP.Exe | high | 61603 |
| `116023` | 8 | `T1557.001` T1557.001 | HackTool - ADCSPwn Execution | high | 61603 |
| `116024` | 8 | `T1557.001` T1557.001 | HackTool - Impacket Tools Execution | high | 61603 |
| `116025` | 13 | `T1557.001` T1557.001 | HackTool - Impacket Tools Execution | high | 61603 |
| `116026` | 8 | `T1557.001` T1557.001 | Potential SMB Relay Attack Tool Execution | high | 61603 |
| `116027` | 8 | `T1557.001` T1557.001 | Potential SMB Relay Attack Tool Execution | high | 61603 |
| `116028` | 8 | `T1557.001` T1557.001 | Potential SMB Relay Attack Tool Execution | high | 61603 |
| `116029` | 8 | `T1557.001` T1557.001 | Attempts of Kerberos Coercion Via DNS SPN Spoofing | high | 61603 |
| `116030` | 8 | `T1560.001` T1560.001 | Suspicious Manipulation Of Default Accounts Via Net.EXE | high | 61603 |
| `116031` | 7 | `T1123` T1123 | Audio Capture via PowerShell | medium | 61603 |
| `116032` | 7 | `T1115` T1115 | PowerShell Get-Clipboard Cmdlet Via CLI | medium | 61603 |
| `116033` | 7 | `T1074.001` T1074.001 | Folder Compress To Potentially Suspicious Output Via Compress-Archi... | medium | 61603 |
| `116034` | 7 | `T1113` T1113 | Screen Capture Activity Via Psr.EXE | medium | 61603 |
| `116035` | 8 | `T1560.001` T1560.001 | Rar Usage with Password and Compression Level | high | 61603 |
| `116036` | 7 | `T1113` T1113 | Windows Recall Feature Enabled Via Reg.EXE | medium | 61603 |
| `116037` | 7 | - | Renamed Remote Utilities RAT (RURAT) Execution | medium | 61603 |
| `116038` | 7 | `T1685.001` T1685.001 | Potential Suspicious Activity Using SeCEdit | medium | 61603 |
| `116039` | 7 | `T1123` T1123 | Audio Capture via SoundRecorder | medium | 61603 |
| `116040` | 7 | `T1005` T1005 | Veeam Backup Database Suspicious Query | medium | 61603 |
| `116041` | 8 | `T1005` T1005 | VeeamBackup Database Credentials Dump Via Sqlcmd.EXE | high | 61603 |
| `116042` | 7 | `T1119` T1119 | Automated Collection Command Prompt | medium | 61603 |
| `116043` | 7 | `T1119` T1119 | Recon Information for Export with Command Prompt | medium | 61603 |
| `116044` | 7 | `T1560.001` T1560.001 | Winrar Compressing Dump Files | medium | 61603 |
| `116045` | 7 | `T1560.001` T1560.001 | WinRAR Execution in Non-Standard Folder | medium | 61603 |
| `116046` | 7 | `T1560.001` T1560.001 | Compress Data and Lock With Password for Exfiltration With WINZIP | medium | 61603 |
| `116047` | 7 | `T1113` T1113 | Windows Recall Feature Enabled - DisableAIDataAnalysis Value Deleted | medium | 61614 |
| `116048` | 8 | `T1125` T1125 | Suspicious Camera and Microphone Access | high | 61615 |
| `116049` | 7 | `T1113` T1113 | Periodic Backup For System Registry Hives Enabled | medium | 61615 |
| `116050` | 7 | `T1113` T1113 | Windows Recall Feature Enabled - Registry | medium | 61615 |

### Command and Control (TA0011) — 193 rules

| Rule ID | Level | Technique | Description | Confidence | Parent SID |
|---------|-------|-----------|-------------|------------|------------|
| `118000` | 9 | `T1105` Ingress Tool Transfer | Executable dropped in downloads | medium | 61613 |
| `118001` | 9 | `T1105` Ingress Tool Transfer | Executable dropped in appdata | medium | 61613 |
| `118002` | 9 | `T1105` Ingress Tool Transfer | Executable dropped in temp | medium | 61613 |
| `118003` | 9 | `T1105` Ingress Tool Transfer | Executable dropped in programdata | medium | 61613 |
| `118004` | 9 | `T1105` Ingress Tool Transfer | Executable dropped in public | medium | 61613 |
| `118005` | 10 | `T1219.002` T1219.002 | Atera Agent Installation | high | 60003 |
| `118006` | 13 | `T1071.004` T1071.004 | Suspicious Cobalt Strike DNS Beaconing - DNS Client | high | 60000 |
| `118007` | 9 | - | DNS Query To Put.io - DNS Client | medium | 60000 |
| `118008` | 10 | `T1090.003` T1090.003 | Query Tor Onion Address - DNS Client | high | 60000 |
| `118009` | 9 | `T1219.002` T1219.002 | Potential Remote Desktop Connection to Non-Domain Host | medium | 60000 |
| `118010` | 10 | `T1090.001` T1090.001 | RDP over Reverse SSH Tunnel WFP | high | 60100 |
| `118011` | 10 | `T1001.003` T1001.003 | Suspicious LDAP-Attributes Used | high | 60100 |
| `118012` | 10 | `T1027` Obfuscated Files or Information | Password Protected ZIP File Opened (Suspicious Filenames) | high | 60100 |
| `118013` | 9 | `T1219.002` T1219.002 | Mesh Agent Service Installation | medium | 60106 |
| `118014` | 9 | `T1219.002` T1219.002 | TacticalRMM Service Installation | medium | 60106 |
| `118015` | 10 | `T1090` T1090 | Ngrok Usage with Remote Desktop Service | high | 60000 |
| `118016` | 9 | `T1105` Ingress Tool Transfer | AppX Package Installation Attempts Via AppInstaller.EXE | medium | 61624 |
| `118017` | 9 | `T1071.001` T1071.001 | Cloudflared Tunnels Related DNS Requests | medium | 61624 |
| `118018` | 9 | `T1071.004` T1071.004 | DNS Query To Common Malware Hosting and Shortener Services | medium | 61624 |
| `118019` | 9 | `T1071.001` T1071.001 | DNS Query To Devtunnels Domain | medium | 61624 |
| `118020` | 9 | `T1219.002` T1219.002 | DNS Query To AzureWebsites.NET By Non-Browser Process | medium | 61624 |
| `118021` | 10 | `T1071.004` T1071.004 | DNS Query by Finger Utility | high | 61624 |
| `118022` | 13 | `T1071.004` T1071.004 | Suspicious Cobalt Strike DNS Beaconing - Sysmon | high | 61624 |
| `118023` | 13 | `T1071.004` T1071.004 | Suspicious Cobalt Strike DNS Beaconing - Sysmon | high | 61624 |
| `118024` | 9 | `T1219.002` T1219.002 | DNS Query To Remote Access Software Domain From Non-Browser App | medium | 61624 |
| `118025` | 9 | `T1219.002` T1219.002 | DNS Query To Remote Access Software Domain From Non-Browser App | medium | 61624 |
| `118026` | 9 | `T1219.002` T1219.002 | TeamViewer Domain Query By Non-TeamViewer Application | medium | 61624 |
| `118027` | 10 | `T1090.003` T1090.003 | DNS Query Tor .Onion Address - Sysmon | high | 61624 |
| `118028` | 9 | `T1071.001` T1071.001 | DNS Query To Visual Studio Code Tunnels Domain | medium | 61624 |
| `118029` | 9 | `T1001.003` T1001.003 | ADSI-Cache File Creation By Uncommon Tool | medium | 61613 |
| `118030` | 9 | `T1219.002` T1219.002 | Anydesk Temporary Artefact | medium | 61613 |
| `118031` | 10 | `T1219.002` T1219.002 | Suspicious Binary Writes Via AnyDesk | high | 61613 |
| `118032` | 10 | `T1127` T1127 | Suspicious File Created by ArcSOC.exe | high | 61613 |
| `118033` | 9 | `T1105` Ingress Tool Transfer | Potentially Suspicious File Creation by OpenEDR's ITSMService | medium | 61613 |
| `118034` | 9 | `T1219.002` T1219.002 | GoToAssist Temporary Installation Artefact | medium | 61613 |
| `118035` | 10 | `T1219.002` T1219.002 | HackTool - Inveigh Execution Artefacts | high | 61613 |
| `118036` | 10 | `T1219.002` T1219.002 | HackTool - RemoteKrbRelay SMB Relay Secrets Dump Module Indicators | high | 61613 |
| `118037` | 9 | `T1219.002` T1219.002 | Installation of TeamViewer Desktop | medium | 61613 |
| `118038` | 9 | `T1219.002` T1219.002 | ScreenConnect Temporary Installation Artefact | medium | 61613 |
| `118039` | 10 | `T1105` Ingress Tool Transfer | Suspicious Desktopimgdownldr Target File | high | 61613 |
| `118040` | 10 | `T1218` T1218 | Legitimate Application Writing Files In Uncommon Location | high | 61613 |
| `118041` | 9 | `T1219.002` T1219.002 | TeamViewer Remote Session | medium | 61613 |
| `118042` | 9 | `T1219.002` T1219.002 | TeamViewer Remote Session | medium | 61613 |
| `118043` | 10 | `T1219.002` T1219.002 | Hijack Legit RDP Session to Move Laterally | high | 61613 |
| `118044` | 9 | - | Visual Studio Code Tunnel Remote File Creation | medium | 61613 |
| `118045` | 10 | - | Renamed VsCode Code Tunnel Execution - File Indicator | high | 61613 |
| `118046` | 10 | `T1071` Application Layer Protocol | HackTool - SILENTTRINITY Stager DLL Load | high | 61609 |
| `118047` | 10 | `T1105` Ingress Tool Transfer | Uncommon Network Connection Initiated By Certutil.EXE | high | 61605 |
| `118048` | 9 | `T1102` T1102 | Network Connection Initiated To AzureWebsites.NET By Non-Browser Pr... | medium | 61605 |
| `118049` | 10 | `T1102` T1102 | New Connection Initiated To Potential Dead Drop Resolver Domain | high | 61605 |
| `118050` | 10 | `T1105` Ingress Tool Transfer | Suspicious Dropbox API Usage | high | 61605 |
| `118051` | 9 | `T1102` T1102 | Suspicious Non-Browser Network Communication With Google API | medium | 61605 |
| `118052` | 10 | `T1572` T1572 | Communication To LocaltoNet Tunneling Service Initiated | high | 61605 |
| `118053` | 9 | `T1041` T1041 | Network Communication Initiated To Portmap.IO Domain | medium | 61605 |
| `118054` | 9 | `T1102` T1102 | Suspicious Non-Browser Network Communication With Telegram API | medium | 61605 |
| `118055` | 10 | `T1071.004` T1071.004 | Network Connection Initiated via Finger.EXE | high | 61605 |
| `118056` | 10 | `T1105` Ingress Tool Transfer | Network Connection Initiated By IMEWDBLD.EXE | high | 61605 |
| `118057` | 9 | - | Office Application Initiated Network Connection Over Uncommon Ports | medium | 61605 |
| `118058` | 10 | `T1572` T1572 | RDP Over Reverse SSH Tunnel | high | 61605 |
| `118059` | 10 | `T1572` T1572 | RDP to HTTP or HTTPS Target Ports | high | 61605 |
| `118060` | 10 | `T1105` Ingress Tool Transfer | Network Communication Initiated To File Sharing Domains From Proces... | high | 61605 |
| `118061` | 10 | `T1105` Ingress Tool Transfer | Network Connection Initiated From Process Located In Potentially Su... | high | 61605 |
| `118062` | 9 | - | Suspicious Wordpad Outbound Connections | medium | 61605 |
| `118063` | 9 | `T1105` Ingress Tool Transfer | Local Network Connection Initiated By Script Interpreter | medium | 61605 |
| `118064` | 10 | `T1105` Ingress Tool Transfer | Outbound Network Connection Initiated By Script Interpreter | high | 61605 |
| `118065` | 9 | `T1095` T1095 | Netcat The Powershell Version | medium | 91801 |
| `118066` | 9 | `T1105` Ingress Tool Transfer | Potential COM Objects Download Cradles Usage - PS Script | medium | 91801 |
| `118067` | 9 | `T1132.001` T1132.001 | Suspicious FromBase64String Usage On Gzip Archive - Ps Script | medium | 91801 |
| `118068` | 9 | `T1071.001` T1071.001 | Change User Agents with WebRequest | medium | 91801 |
| `118069` | 9 | `T1090` T1090 | Suspicious TCP Tunnel Via PowerShell Script | medium | 91801 |
| `118070` | 9 | `T1571` T1571 | Testing Usage of Uncommonly Used Port | medium | 91801 |
| `118071` | 10 | `T1105` Ingress Tool Transfer | File Download with Headless Browser | high | 61603 |
| `118072` | 9 | `T1105` Ingress Tool Transfer | File Download From Browser Process Via Inline URL | medium | 61603 |
| `118073` | 10 | `T1090.003` T1090.003 | Tor Client/Browser Execution | high | 61603 |
| `118074` | 10 | `T1090.003` T1090.003 | Tor Client/Browser Execution | high | 61603 |
| `118075` | 10 | `T1090.003` T1090.003 | Tor Client/Browser Execution | high | 61603 |
| `118076` | 9 | `T1105` Ingress Tool Transfer | File Download via CertOC.EXE | medium | 61603 |
| `118077` | 10 | `T1105` Ingress Tool Transfer | File Download From IP Based URL Via CertOC.EXE | high | 61603 |
| `118078` | 10 | `T1105` Ingress Tool Transfer | Suspicious CertReq Command to Download | high | 61603 |
| `118079` | 9 | `T1027` Obfuscated Files or Information | Suspicious Download Via Certutil.EXE | medium | 61603 |
| `118080` | 10 | `T1027` Obfuscated Files or Information | Suspicious File Downloaded From Direct IP Via Certutil.EXE | high | 61603 |
| `118081` | 10 | `T1027` Obfuscated Files or Information | Suspicious File Downloaded From File-Sharing Website Via Certutil.EXE | high | 61603 |
| `118082` | 9 | `T1090.001` T1090.001 | Cloudflared Portable Execution | medium | 61603 |
| `118083` | 9 | `T1090.001` T1090.001 | Cloudflared Quick Tunnel Execution | medium | 61603 |
| `118084` | 9 | `T1102` T1102 | Cloudflared Tunnel Connections Cleanup | medium | 61603 |
| `118085` | 9 | `T1102` T1102 | Cloudflared Tunnel Execution | medium | 61603 |
| `118086` | 10 | `T1218` T1218 | Curl Download And Execute Combination | high | 61603 |
| `118087` | 9 | `T1105` Ingress Tool Transfer | Potential Download/Upload Activity Using Type Command | medium | 61603 |
| `118088` | 9 | `T1105` Ingress Tool Transfer | Potential Download/Upload Activity Using Type Command | medium | 61603 |
| `118089` | 10 | `T1105` Ingress Tool Transfer | Suspicious Curl.EXE Download | high | 61603 |
| `118090` | 9 | `T1105` Ingress Tool Transfer | Remote File Download Via Desktopimgdownldr Utility | medium | 61603 |
| `118091` | 10 | `T1105` Ingress Tool Transfer | Suspicious Desktopimgdownldr Command | high | 61603 |
| `118092` | 10 | `T1105` Ingress Tool Transfer | Finger.EXE Execution | high | 61603 |
| `118093` | 10 | `T1105` Ingress Tool Transfer | Finger.EXE Execution | high | 61603 |
| `118094` | 9 | `T1105` Ingress Tool Transfer | Arbitrary File Download Via GfxDownloadWrapper.EXE | medium | 61603 |
| `118095` | 9 | `T1102.002` T1102.002 | Github Self-Hosted Runner Execution | medium | 61603 |
| `118096` | 10 | `T1105` Ingress Tool Transfer | File Download Using Notepad++ GUP Utility | high | 61603 |
| `118097` | 10 | `T1090` T1090 | HackTool - Htran/NATBypass Execution | high | 61603 |
| `118098` | 10 | `T1090` T1090 | HackTool - Htran/NATBypass Execution | high | 61603 |
| `118099` | 10 | `T1090.001` T1090.001 | HackTool - SharpChisel Execution | high | 61603 |
| `118100` | 10 | `T1090.001` T1090.001 | HackTool - SharpChisel Execution | high | 61603 |
| `118101` | 10 | `T1071` Application Layer Protocol | HackTool - SILENTTRINITY Stager Execution | high | 61603 |
| `118102` | 10 | `T1105` Ingress Tool Transfer | File Download And Execution Via IEExec.EXE | high | 61603 |
| `118103` | 10 | `T1102` T1102 | Suspicious Child Process Of Manage Engine ServiceDesk | high | 61603 |
| `118104` | 9 | `T1218` T1218 | Import LDAP Data Interchange Format File Via Ldifde.EXE | medium | 61603 |
| `118105` | 9 | `T1105` Ingress Tool Transfer | Suspicious Diantz Download and Compress Into a CAB File | medium | 61603 |
| `118106` | 9 | `T1105` Ingress Tool Transfer | Suspicious Extrac32 Execution | medium | 61603 |
| `118107` | 10 | `T1105` Ingress Tool Transfer | PrintBrm ZIP Creation of Extraction | high | 61603 |
| `118108` | 9 | `T1105` Ingress Tool Transfer | Replace.exe Usage | medium | 61603 |
| `118109` | 10 | `T1218` T1218 | File Download Via Windows Defender MpCmpRun.EXE | high | 61603 |
| `118110` | 9 | `T1218.007` T1218.007 | MsiExec Web Install | medium | 61603 |
| `118111` | 10 | `T1219.002` T1219.002 | Suspicious Mstsc.EXE Execution With Local RDP File | high | 61603 |
| `118112` | 10 | `T1572` T1572 | Suspicious Plink Port Forwarding | high | 61603 |
| `118113` | 10 | `T1572` T1572 | Potential RDP Tunneling Via Plink | high | 61603 |
| `118114` | 9 | `T1132.001` T1132.001 | Gzip Archive Decode Via PowerShell | medium | 61603 |
| `118115` | 9 | `T1105` Ingress Tool Transfer | Potential COM Objects Download Cradles Usage - Process Creation | medium | 61603 |
| `118116` | 9 | `T1059.001` T1059.001 | Potential DLL File Download Via PowerShell Invoke-WebRequest | medium | 61603 |
| `118117` | 9 | `T1132.001` T1132.001 | Suspicious FromBase64String Usage On Gzip Archive - Process Creation | medium | 61603 |
| `118118` | 9 | `T1105` Ingress Tool Transfer | Suspicious Invoke-WebRequest Execution With DirectIP | medium | 61603 |
| `118119` | 10 | `T1105` Ingress Tool Transfer | Suspicious Invoke-WebRequest Execution | high | 61603 |
| `118120` | 10 | `T1572` T1572 | PUA - 3Proxy Execution | high | 61603 |
| `118121` | 10 | `T1572` T1572 | PUA - 3Proxy Execution | high | 61603 |
| `118122` | 10 | `T1572` T1572 | PUA - 3Proxy Execution | high | 61603 |
| `118123` | 10 | `T1090.001` T1090.001 | PUA - Chisel Tunneling Tool Execution | high | 61603 |
| `118124` | 10 | `T1090` T1090 | PUA - Fast Reverse Proxy (FRP) Execution | high | 61603 |
| `118125` | 10 | `T1090` T1090 | PUA - Fast Reverse Proxy (FRP) Execution | high | 61603 |
| `118126` | 10 | `T1090` T1090 | PUA - Fast Reverse Proxy (FRP) Execution | high | 61603 |
| `118127` | 10 | `T1090` T1090 | PUA- IOX Tunneling Tool Execution | high | 61603 |
| `118128` | 10 | `T1090` T1090 | PUA- IOX Tunneling Tool Execution | high | 61603 |
| `118129` | 10 | `T1090` T1090 | PUA- IOX Tunneling Tool Execution | high | 61603 |
| `118130` | 10 | `T1095` T1095 | PUA - Netcat Suspicious Execution | high | 61603 |
| `118131` | 10 | `T1095` T1095 | PUA - Netcat Suspicious Execution | high | 61603 |
| `118132` | 10 | `T1572` T1572 | PUA - Ngrok Execution | high | 61603 |
| `118133` | 10 | `T1572` T1572 | PUA - Ngrok Execution | high | 61603 |
| `118134` | 10 | `T1572` T1572 | PUA - Ngrok Execution | high | 61603 |
| `118135` | 10 | `T1572` T1572 | PUA - Ngrok Execution | high | 61603 |
| `118136` | 10 | `T1105` Ingress Tool Transfer | PUA - Nimgrab Execution | high | 61603 |
| `118137` | 10 | `T1105` Ingress Tool Transfer | PUA - Nimgrab Execution | high | 61603 |
| `118138` | 10 | `T1090` T1090 | PUA - NPS Tunneling Tool Execution | high | 61603 |
| `118139` | 10 | `T1090` T1090 | PUA - NPS Tunneling Tool Execution | high | 61603 |
| `118140` | 10 | `T1090` T1090 | PUA - NPS Tunneling Tool Execution | high | 61603 |
| `118141` | 10 | `T1090` T1090 | PUA - NPS Tunneling Tool Execution | high | 61603 |
| `118142` | 9 | `T1090` T1090 | Potentially Suspicious Usage Of Qemu | medium | 61603 |
| `118143` | 9 | `T1219.002` T1219.002 | Remote Access Tool - AnyDesk Execution | medium | 61603 |
| `118144` | 9 | `T1219.002` T1219.002 | Remote Access Tool - AnyDesk Execution | medium | 61603 |
| `118145` | 9 | `T1219.002` T1219.002 | Remote Access Tool - AnyDesk Execution | medium | 61603 |
| `118146` | 9 | `T1219.002` T1219.002 | Remote Access Tool - AnyDesk Execution | medium | 61603 |
| `118147` | 9 | `T1219.002` T1219.002 | Remote Access Tool - AnyDesk Piped Password Via CLI | medium | 61603 |
| `118148` | 10 | `T1219.002` T1219.002 | Remote Access Tool - AnyDesk Silent Installation | high | 61603 |
| `118149` | 10 | `T1219.002` T1219.002 | Remote Access Tool - Anydesk Execution From Suspicious Folder | high | 61603 |
| `118150` | 9 | `T1219.002` T1219.002 | Remote Access Tool - GoToAssist Execution | medium | 61603 |
| `118151` | 9 | `T1219.002` T1219.002 | Remote Access Tool - GoToAssist Execution | medium | 61603 |
| `118152` | 9 | `T1219.002` T1219.002 | Remote Access Tool - GoToAssist Execution | medium | 61603 |
| `118153` | 9 | `T1219.002` T1219.002 | Remote Access Tool - LogMeIn Execution | medium | 61603 |
| `118154` | 9 | `T1219.002` T1219.002 | Remote Access Tool - LogMeIn Execution | medium | 61603 |
| `118155` | 9 | `T1219.002` T1219.002 | Remote Access Tool - LogMeIn Execution | medium | 61603 |
| `118156` | 9 | `T1219.002` T1219.002 | Remote Access Tool - Potential MeshAgent Execution - Windows | medium | 61603 |
| `118157` | 9 | `T1219.002` T1219.002 | Remote Access Tool - MeshAgent Command Execution via MeshCentral | medium | 61603 |
| `118158` | 9 | `T1219.002` T1219.002 | Remote Access Tool - NetSupport Execution | medium | 61603 |
| `118159` | 9 | `T1219.002` T1219.002 | Remote Access Tool - NetSupport Execution | medium | 61603 |
| `118160` | 9 | `T1219.002` T1219.002 | Remote Access Tool - NetSupport Execution | medium | 61603 |
| `118161` | 9 | `T1219.002` T1219.002 | Remote Access Tool - NetSupport Execution | medium | 61603 |
| `118162` | 10 | `T1219.002` T1219.002 | Remote Access Tool - Renamed MeshAgent Execution - Windows | high | 61603 |
| `118163` | 9 | `T1219.002` T1219.002 | Remote Access Tool - ScreenConnect Execution | medium | 61603 |
| `118164` | 9 | `T1219.002` T1219.002 | Remote Access Tool - ScreenConnect Execution | medium | 61603 |
| `118165` | 9 | `T1219.002` T1219.002 | Remote Access Tool - ScreenConnect Execution | medium | 61603 |
| `118166` | 9 | `T1219.002` T1219.002 | Remote Access Tool - ScreenConnect Potential Suspicious Remote Comm... | medium | 61603 |
| `118167` | 9 | `T1219.002` T1219.002 | Remote Access Tool - Simple Help Execution | medium | 61603 |
| `118168` | 9 | `T1219` T1219 | Remote Access Tool - TacticalRMM Agent Registration to Potentially ... | medium | 61603 |
| `118169` | 9 | `T1219.002` T1219.002 | Remote Access Tool - UltraViewer Execution | medium | 61603 |
| `118170` | 9 | `T1219.002` T1219.002 | Remote Access Tool - UltraViewer Execution | medium | 61603 |
| `118171` | 9 | `T1219.002` T1219.002 | Remote Access Tool - UltraViewer Execution | medium | 61603 |
| `118172` | 10 | `T1090.001` T1090.001 | Renamed Cloudflared.EXE Execution | high | 61603 |
| `118173` | 10 | `T1090.001` T1090.001 | Renamed Cloudflared.EXE Execution | high | 61603 |
| `118174` | 10 | `T1090.001` T1090.001 | Renamed Cloudflared.EXE Execution | high | 61603 |
| `118175` | 10 | `T1090.001` T1090.001 | Renamed Cloudflared.EXE Execution | high | 61603 |
| `118176` | 9 | `T1572` T1572 | Port Forwarding Activity Via SSH.EXE | medium | 61603 |
| `118177` | 10 | `T1572` T1572 | Potential RDP Tunneling Via SSH | high | 61603 |
| `118178` | 9 | `T1219.002` T1219.002 | Potential Amazon SSM Agent Hijacking | medium | 61603 |
| `118179` | 10 | `T1105` Ingress Tool Transfer | Suspicious Download from Office Domain | high | 61603 |
| `118180` | 10 | `T1219` T1219 | Suspicious Velociraptor Child Process | high | 61603 |
| `118181` | 10 | `T1219.002` T1219.002 | Suspicious TSCON Start as SYSTEM | high | 61603 |
| `118182` | 9 | `T1219.002` T1219.002 | Use of UltraVNC Remote Access Software | medium | 61603 |
| `118183` | 9 | `T1219.002` T1219.002 | Use of UltraVNC Remote Access Software | medium | 61603 |
| `118184` | 9 | `T1219.002` T1219.002 | Use of UltraVNC Remote Access Software | medium | 61603 |
| `118185` | 9 | `T1219.002` T1219.002 | Use of UltraVNC Remote Access Software | medium | 61603 |
| `118186` | 9 | `T1071.001` T1071.001 | Visual Studio Code Tunnel Execution | medium | 61603 |
| `118187` | 9 | `T1071.001` T1071.001 | Visual Studio Code Tunnel Execution | medium | 61603 |
| `118188` | 9 | `T1071.001` T1071.001 | Visual Studio Code Tunnel Execution | medium | 61603 |
| `118189` | 9 | `T1071.001` T1071.001 | Visual Studio Code Tunnel Shell Execution | medium | 61603 |
| `118190` | 10 | `T1071.001` T1071.001 | Renamed Visual Studio Code Tunnel Execution | high | 61603 |
| `118191` | 9 | `T1071.001` T1071.001 | Visual Studio Code Tunnel Service Installation | medium | 61603 |
| `118192` | 10 | `T1105` Ingress Tool Transfer | Lolbas OneDriveStandaloneUpdater.exe Proxy Download | high | 61615 |

### Exfiltration (TA0010) — 36 rules

| Rule ID | Level | Technique | Description | Confidence | Parent SID |
|---------|-------|-----------|-------------|------------|------------|
| `120000` | 12 | `T1485` Data Destruction | MSSQL Destructive Query | medium | 60003 |
| `120001` | 13 | `T1567.002` T1567.002 | DNS Query for Anonfiles.com Domain - DNS Client | high | 60000 |
| `120002` | 12 | `T1567.002` T1567.002 | DNS Query To MEGA Hosting Website - DNS Client | medium | 60000 |
| `120003` | 12 | `T1048` T1048 | Tap Driver Installation | medium | 60106 |
| `120004` | 13 | `T1567.002` T1567.002 | DNS Query for Anonfiles.com Domain - Sysmon | high | 61624 |
| `120005` | 12 | `T1567.002` T1567.002 | DNS Query To MEGA Hosting Website | medium | 61624 |
| `120006` | 12 | `T1567.002` T1567.002 | Rclone Config File Creation | medium | 61613 |
| `120007` | 12 | `T1567` T1567 | Network Connection Initiated To BTunnels Domains | medium | 61605 |
| `120008` | 12 | `T1567` T1567 | Network Connection Initiated To Cloudflared Tunnels Domains | medium | 61605 |
| `120009` | 12 | `T1567.001` T1567.001 | Network Connection Initiated To DevTunnels Domain | medium | 61605 |
| `120010` | 13 | `T1567` T1567 | Process Initiated Network Connection To Ngrok Domain | high | 61605 |
| `120011` | 13 | `T1567` T1567 | Communication To Ngrok Tunneling Service Initiated | high | 61605 |
| `120012` | 12 | `T1567` T1567 | Network Connection Initiated To Visual Studio Code Tunnels Domain | medium | 61605 |
| `120013` | 12 | `T1048.003` T1048.003 | Suspicious Outbound SMTP Connections | medium | 61605 |
| `120014` | 12 | - | Potential Data Exfiltration Via Audio File | medium | 91801 |
| `120015` | 12 | `T1048.003` T1048.003 | PowerShell ICMP Exfiltration | medium | 91801 |
| `120016` | 13 | `T1048` T1048 | Powershell DNSExfiltration | high | 91801 |
| `120017` | 13 | - | Suspicious PowerShell Mailbox Export to Share - PS | high | 91801 |
| `120018` | 12 | `T1020` T1020 | PowerShell Script With File Hostname Resolving Capabilities | medium | 91801 |
| `120019` | 12 | `T1567` T1567 | Arbitrary File Download Via ConfigSecurityPolicy.EXE | medium | 61603 |
| `120020` | 12 | `T1087.002` T1087.002 | Active Directory Structure Export Via Csvde.EXE | medium | 61603 |
| `120021` | 13 | `T1048.001` T1048.001 | DNS Exfiltration and Tunneling Tools Execution | high | 61603 |
| `120022` | 13 | `T1048.001` T1048.001 | DNS Exfiltration and Tunneling Tools Execution | high | 61603 |
| `120023` | 12 | - | Active Directory Structure Export Via Ldifde.EXE | medium | 61603 |
| `120024` | 12 | `T1567` T1567 | LOLBAS Data Exfiltration by DataSvcUtil.exe | medium | 61603 |
| `120025` | 13 | - | Email Exifiltration Via Powershell | high | 61603 |
| `120026` | 13 | - | Suspicious PowerShell Mailbox Export to Share | high | 61603 |
| `120027` | 13 | `T1567.002` T1567.002 | PUA - Rclone Execution | high | 61603 |
| `120028` | 13 | `T1048` T1048 | PUA - Restic Backup Tool Execution | high | 61603 |
| `120029` | 13 | `T1048` T1048 | PUA - Restic Backup Tool Execution | high | 61603 |
| `120030` | 13 | `T1048` T1048 | PUA - Restic Backup Tool Execution | high | 61603 |
| `120031` | 13 | `T1012` T1012 | Exports Critical Registry Keys To a File | high | 61603 |
| `120032` | 12 | `T1048.003` T1048.003 | WebDav Client Execution Via Rundll32.EXE | medium | 61603 |
| `120033` | 13 | `T1048.003` T1048.003 | Suspicious WebDav Client Execution Via Rundll32.EXE | high | 61603 |
| `120034` | 13 | `T1048` T1048 | Suspicious Redirection to Local Admin Share | high | 61603 |
| `120035` | 12 | `T1048` T1048 | Tap Installer Execution | medium | 61603 |

### Impact (TA0040) — 44 rules

| Rule ID | Level | Technique | Description | Confidence | Parent SID |
|---------|-------|-----------|-------------|------------|------------|
| `122000` | 13 | `T1490` T1490 | Suspicious command: shadow copy | medium | 61603 |
| `122001` | 13 | `T1489` Service Stop | Suspicious PowerShell: stop-service | medium | 91801 |
| `122002` | 13 | `T1070.004` T1070.004 | Potential Secure Deletion with SDelete | medium | 60100 |
| `122003` | 13 | `T1557` T1557 | ISATAP Router Address Was Set | medium | 60106 |
| `122004` | 14 | `T1499.001` T1499.001 | NTFS Vulnerability Exploitation | high | 60106 |
| `122005` | 14 | `T1489` Service Stop | Important Scheduled Task Deleted or Disabled | high | 60000 |
| `122006` | 13 | `T1490` T1490 | Backup Files Deleted | medium | 61625 |
| `122007` | 13 | `T1486` Data Encrypted for Impact | Suspicious Appended Extension | medium | 61613 |
| `122008` | 14 | `T1486` Data Encrypted for Impact | Load Of RstrtMgr.DLL By A Suspicious Process | high | 61609 |
| `122009` | 14 | `T1490` T1490 | Suspicious Volume Shadow Copy VSS_PS.dll Load | high | 61609 |
| `122010` | 14 | `T1490` T1490 | Suspicious Volume Shadow Copy Vssapi.dll Load | high | 61609 |
| `122011` | 13 | `T1490` T1490 | Potentially Suspicious Volume Shadow Copy Vsstrace.dll Load | medium | 61609 |
| `122012` | 14 | `T1496` T1496 | Network Communication With Crypto Mining Pool | high | 61605 |
| `122013` | 14 | `T1490` T1490 | Delete Volume Shadow Copies Via WMI With PowerShell | high | 91801 |
| `122014` | 14 | `T1565` T1565 | Powershell Add Name Resolution Policy Table Rule | high | 91801 |
| `122015` | 13 | `T1531` T1531 | Remove Account From Domain Admin Group | medium | 91801 |
| `122016` | 14 | `T1490` T1490 | Deletion of Volume Shadow Copies via WMI with PowerShell - PS Script | high | 91801 |
| `122017` | 14 | `T1490` T1490 | Boot Configuration Tampering Via Bcdedit.EXE | high | 61603 |
| `122018` | 13 | `T1485` Data Destruction | Deleted Data Overwritten Via Cipher.EXE | medium | 61603 |
| `122019` | 14 | `T1490` T1490 | Copy From VolumeShadowCopy Via Cmd.EXE | high | 61603 |
| `122020` | 14 | `T1070` Indicator Removal | Fsutil Suspicious Invocation | high | 61603 |
| `122021` | 13 | `T1486` Data Encrypted for Impact | Portable Gpg.EXE Execution | medium | 61603 |
| `122022` | 14 | `T1490` T1490 | Deletion of Volume Shadow Copies via WMI with PowerShell | high | 61603 |
| `122023` | 13 | `T1490` T1490 | Windows Recovery Environment Disabled Via Reagentc | medium | 61603 |
| `122024` | 14 | `T1486` Data Encrypted for Impact | Suspicious Reg Add BitLocker | high | 61603 |
| `122025` | 14 | `T1490` T1490 | System Restore Registry Modification via CommandLine | high | 61603 |
| `122026` | 14 | `T1486` Data Encrypted for Impact | Renamed Gpg.EXE Execution | high | 61603 |
| `122027` | 14 | `T1485` Data Destruction | Renamed Sysinternals Sdelete Execution | high | 61603 |
| `122028` | 14 | `T1489` Service Stop | Delete Important Scheduled Task | high | 61603 |
| `122029` | 14 | `T1489` Service Stop | Delete All Scheduled Tasks | high | 61603 |
| `122030` | 14 | `T1489` Service Stop | Disable Important Scheduled Task | high | 61603 |
| `122031` | 13 | `T1529` T1529 | Suspicious Execution of Shutdown | medium | 61603 |
| `122032` | 13 | `T1529` T1529 | Suspicious Execution of Shutdown to Log Out | medium | 61603 |
| `122033` | 14 | `T1496` T1496 | Potential Crypto Mining Activity | high | 61603 |
| `122034` | 14 | `T1490` T1490 | Sensitive File Access Via Volume Shadow Copy Backup | high | 61603 |
| `122035` | 14 | `T1489` Service Stop | Suspicious Windows Service Tampering | high | 61603 |
| `122036` | 14 | `T1070` Indicator Removal | Shadow Copies Deletion Using Operating Systems Utilities | high | 61603 |
| `122037` | 14 | `T1485` Data Destruction | Potential File Overwrite Via Sysinternals SDelete | high | 61603 |
| `122038` | 14 | `T1490` T1490 | All Backups Deleted Via Wbadmin.EXE | high | 61603 |
| `122039` | 13 | `T1490` T1490 | Windows Backup Deleted Via Wbadmin.EXE | medium | 61603 |
| `122040` | 13 | `T1490` T1490 | File Recovery From Backup Via Wbadmin.EXE | medium | 61603 |
| `122041` | 14 | `T1490` T1490 | Registry Disable System Restore | high | 61615 |
| `122042` | 13 | `T1490` T1490 | New Root or CA or AuthRoot Certificate to Store | medium | 61615 |
| `122043` | 14 | `T1491.001` T1491.001 | Potential Ransomware Activity Using LegalNotice Message | high | 61615 |

## Exported Rule Files

Rules are exported in three parallel views. Each view contains the same rules, organized differently:

### `database/rules/by_tactic/`
_One XML file per MITRE ATT&CK tactic. Best for broad deployment._

| File | Rules |
|------|-------|
| `collection.xml` | 51 |
| `command_and_control.xml` | 188 |
| `credential_access.xml` | 271 |
| `defense_evasion.xml` | 35 |
| `discovery.xml` | 136 |
| `execution.xml` | 1144 |
| `exfiltration.xml` | 36 |
| `impact.xml` | 42 |
| `initial_access.xml` | 32 |
| `lateral_movement.xml` | 65 |
| `persistence.xml` | 323 |
| `privilege_escalation.xml` | 382 |

### `database/rules/by_technique/`
_One XML file per MITRE technique. Best for selective/granular deployment._

| File | Rules |
|------|-------|
| `T1001.003_unknown.xml` | 2 |
| `T1003.001_unknown.xml` | 80 |
| `T1003.002_unknown.xml` | 16 |
| `T1003.003_unknown.xml` | 19 |
| `T1003.004_unknown.xml` | 2 |
| `T1003.005_unknown.xml` | 2 |
| `T1003.006_unknown.xml` | 3 |
| `T1003_credential_dumping.xml` | 26 |
| `T1005_data_from_local_system.xml` | 4 |
| `T1010_unknown.xml` | 1 |
| `T1012_unknown.xml` | 6 |
| `T1016_unknown.xml` | 2 |
| `T1018_unknown.xml` | 7 |
| `T1020_unknown.xml` | 1 |
| `T1021.001_unknown.xml` | 6 |
| `T1021.002_unknown.xml` | 29 |
| `T1021.003_unknown.xml` | 4 |
| `T1021.004_unknown.xml` | 1 |
| `T1021.005_unknown.xml` | 1 |
| `T1021.006_unknown.xml` | 5 |
| `T1021_remote_services.xml` | 2 |
| `T1027.004_unknown.xml` | 2 |
| `T1027.005_unknown.xml` | 2 |
| `T1027.009_unknown.xml` | 1 |
| `T1027.010_unknown.xml` | 2 |
| `T1027_obfuscated_files.xml` | 79 |
| `T1033_unknown.xml` | 17 |
| `T1036.002_unknown.xml` | 2 |
| `T1036.003_unknown.xml` | 19 |
| `T1036.005_unknown.xml` | 8 |
| `T1036.007_unknown.xml` | 5 |
| `T1036_unknown.xml` | 44 |
| `T1037.001_unknown.xml` | 3 |
| `T1039_data_from_network_shared.xml` | 2 |
| `T1040_unknown.xml` | 8 |
| `T1041_exfil_over_c2.xml` | 1 |
| `T1046_unknown.xml` | 19 |
| `T1047_unknown.xml` | 49 |
| `T1048.001_unknown.xml` | 2 |
| `T1048.003_unknown.xml` | 4 |
| `T1048_exfil_over_alt_protocol.xml` | 8 |
| `T1049_unknown.xml` | 3 |
| `T1053.002_unknown.xml` | 2 |
| `T1053.005_unknown.xml` | 29 |
| `T1053_scheduled_task.xml` | 8 |
| `T1055.001_unknown.xml` | 5 |
| `T1055.003_unknown.xml` | 1 |
| `T1055.012_unknown.xml` | 3 |
| `T1055_process_injection.xml` | 54 |
| `T1056.001_unknown.xml` | 3 |
| `T1056.002_unknown.xml` | 4 |
| `T1057_unknown.xml` | 1 |
| `T1059.001_unknown.xml` | 110 |
| `T1059.003_unknown.xml` | 12 |
| `T1059.005_unknown.xml` | 11 |
| `T1059.006_unknown.xml` | 2 |
| `T1059.007_unknown.xml` | 1 |
| `T1059_command_scripting.xml` | 70 |
| `T1068_exploitation_for_privesc.xml` | 8 |
| `T1069.001_unknown.xml` | 1 |
| `T1069.002_unknown.xml` | 1 |
| `T1070.003_unknown.xml` | 8 |
| `T1070.004_unknown.xml` | 8 |
| `T1070.005_unknown.xml` | 2 |
| `T1070.006_unknown.xml` | 1 |
| `T1070_indicator_removal.xml` | 25 |
| `T1071.001_unknown.xml` | 11 |
| `T1071.004_unknown.xml` | 6 |
| `T1071_application_layer_protocol.xml` | 2 |
| `T1072_unknown.xml` | 9 |
| `T1074.001_unknown.xml` | 4 |
| `T1078.002_unknown.xml` | 2 |
| `T1078_valid_accounts.xml` | 7 |
| `T1082_system_info_discovery.xml` | 18 |
| `T1083_file_directory_discovery.xml` | 3 |
| `T1087.001_unknown.xml` | 10 |
| `T1087.002_unknown.xml` | 13 |
| `T1087_account_discovery.xml` | 5 |
| `T1090.001_unknown.xml` | 10 |
| `T1090.003_unknown.xml` | 5 |
| `T1090_unknown.xml` | 18 |
| `T1095_unknown.xml` | 3 |
| `T1098_unknown.xml` | 8 |
| `T1102.002_unknown.xml` | 1 |
| `T1102_unknown.xml` | 7 |
| `T1105_ingress_tool_transfer.xml` | 37 |
| `T1106_unknown.xml` | 7 |
| `T1110.001_unknown.xml` | 1 |
| `T1110.002_unknown.xml` | 2 |
| `T1110_brute_force.xml` | 3 |
| `T1112_unknown.xml` | 61 |
| `T1113_unknown.xml` | 6 |
| `T1114.001_unknown.xml` | 1 |
| `T1115_unknown.xml` | 2 |
| `T1119_unknown.xml` | 4 |
| `T1123_unknown.xml` | 3 |
| `T1124_unknown.xml` | 1 |
| `T1125_unknown.xml` | 1 |
| `T1127.001_unknown.xml` | 1 |
| `T1127_unknown.xml` | 18 |
| `T1129_unknown.xml` | 1 |
| `T1132.001_unknown.xml` | 3 |
| `T1133_unknown.xml` | 8 |
| `T1134.001_unknown.xml` | 11 |
| `T1134.002_unknown.xml` | 2 |
| `T1134.004_unknown.xml` | 5 |
| `T1134.005_unknown.xml` | 1 |
| `T1134_access_token_manipulation.xml` | 3 |
| `T1135_unknown.xml` | 1 |
| `T1136.001_unknown.xml` | 5 |
| `T1136.002_unknown.xml` | 2 |
| `T1137.002_unknown.xml` | 1 |
| `T1137.003_unknown.xml` | 1 |
| `T1137.006_unknown.xml` | 7 |
| `T1137_unknown.xml` | 9 |
| `T1140_unknown.xml` | 8 |
| `T1176.001_unknown.xml` | 2 |
| `T1185_unknown.xml` | 3 |
| `T1187_unknown.xml` | 2 |
| `T1190_exploit_public_app.xml` | 6 |
| `T1195.002_unknown.xml` | 3 |
| `T1195_unknown.xml` | 1 |
| `T1197_unknown.xml` | 11 |
| `T1200_unknown.xml` | 1 |
| `T1201_unknown.xml` | 1 |
| `T1202_unknown.xml` | 22 |
| `T1203_unknown.xml` | 7 |
| `T1204.001_unknown.xml` | 2 |
| `T1204.002_unknown.xml` | 19 |
| `T1204.004_unknown.xml` | 5 |
| `T1204_user_execution.xml` | 2 |
| `T1207_unknown.xml` | 2 |
| `T1210_unknown.xml` | 3 |
| `T1211_unknown.xml` | 3 |
| `T1212_unknown.xml` | 2 |
| `T1216.001_unknown.xml` | 2 |
| `T1216_unknown.xml` | 10 |
| `T1218.001_unknown.xml` | 2 |
| `T1218.002_unknown.xml` | 1 |
| `T1218.003_unknown.xml` | 5 |
| `T1218.004_unknown.xml` | 2 |
| `T1218.005_unknown.xml` | 4 |
| `T1218.007_unknown.xml` | 7 |
| `T1218.008_unknown.xml` | 8 |
| `T1218.009_unknown.xml` | 3 |
| `T1218.010_unknown.xml` | 9 |
| `T1218.011_unknown.xml` | 27 |
| `T1218_unknown.xml` | 113 |
| `T1219.002_unknown.xml` | 54 |
| `T1219_unknown.xml` | 2 |
| `T1220_unknown.xml` | 3 |
| `T1222.001_unknown.xml` | 2 |
| `T1222_unknown.xml` | 1 |
| `T1482_unknown.xml` | 6 |
| `T1484.001_unknown.xml` | 6 |
| `T1485_data_destruction.xml` | 4 |
| `T1486_data_encrypted_for_impact.xml` | 5 |
| `T1489_service_stop.xml` | 5 |
| `T1490_unknown.xml` | 17 |
| `T1491.001_unknown.xml` | 1 |
| `T1496_unknown.xml` | 2 |
| `T1497.001_unknown.xml` | 1 |
| `T1499.001_unknown.xml` | 1 |
| `T1505.002_unknown.xml` | 2 |
| `T1505.003_unknown.xml` | 21 |
| `T1505.004_unknown.xml` | 1 |
| `T1518.001_unknown.xml` | 3 |
| `T1518_unknown.xml` | 2 |
| `T1526_unknown.xml` | 1 |
| `T1528_unknown.xml` | 6 |
| `T1529_unknown.xml` | 2 |
| `T1531_unknown.xml` | 1 |
| `T1539_unknown.xml` | 2 |
| `T1542.001_unknown.xml` | 2 |
| `T1543.003_unknown.xml` | 35 |
| `T1543_create_modify_service.xml` | 9 |
| `T1546.001_unknown.xml` | 1 |
| `T1546.002_unknown.xml` | 4 |
| `T1546.003_unknown.xml` | 10 |
| `T1546.007_unknown.xml` | 3 |
| `T1546.008_unknown.xml` | 5 |
| `T1546.009_unknown.xml` | 2 |
| `T1546.010_unknown.xml` | 1 |
| `T1546.011_unknown.xml` | 6 |
| `T1546.012_unknown.xml` | 3 |
| `T1546.013_unknown.xml` | 3 |
| `T1546.015_unknown.xml` | 9 |
| `T1546_unknown.xml` | 2 |
| `T1547.001_unknown.xml` | 31 |
| `T1547.003_unknown.xml` | 1 |
| `T1547.004_unknown.xml` | 2 |
| `T1547.005_unknown.xml` | 1 |
| `T1547.008_unknown.xml` | 1 |
| `T1547.009_unknown.xml` | 4 |
| `T1547.010_unknown.xml` | 3 |
| `T1547.015_unknown.xml` | 1 |
| `T1547_boot_autostart.xml` | 6 |
| `T1548.002_unknown.xml` | 63 |
| `T1548_abuse_elevation.xml` | 7 |
| `T1550.002_unknown.xml` | 4 |
| `T1552.001_unknown.xml` | 4 |
| `T1552.002_unknown.xml` | 3 |
| `T1552.004_unknown.xml` | 4 |
| `T1552.006_unknown.xml` | 5 |
| `T1552_unknown.xml` | 3 |
| `T1553.003_unknown.xml` | 1 |
| `T1553.004_unknown.xml` | 7 |
| `T1553.005_unknown.xml` | 2 |
| `T1553_unknown.xml` | 1 |
| `T1554_unknown.xml` | 3 |
| `T1555.003_unknown.xml` | 4 |
| `T1555.004_unknown.xml` | 4 |
| `T1555.005_unknown.xml` | 1 |
| `T1555_unknown.xml` | 9 |
| `T1556.002_unknown.xml` | 2 |
| `T1556_unknown.xml` | 2 |
| `T1557.001_unknown.xml` | 10 |
| `T1557.003_unknown.xml` | 2 |
| `T1557_unknown.xml` | 1 |
| `T1558.003_unknown.xml` | 19 |
| `T1558_steal_kerberos_ticket.xml` | 3 |
| `T1559.001_unknown.xml` | 2 |
| `T1559.002_unknown.xml` | 2 |
| `T1560.001_unknown.xml` | 7 |
| `T1562.001_unknown.xml` | 1 |
| `T1563.002_unknown.xml` | 2 |
| `T1564.001_unknown.xml` | 6 |
| `T1564.002_unknown.xml` | 2 |
| `T1564.003_unknown.xml` | 5 |
| `T1564.004_unknown.xml` | 18 |
| `T1564.006_unknown.xml` | 1 |
| `T1564_unknown.xml` | 6 |
| `T1565_unknown.xml` | 1 |
| `T1566.001_unknown.xml` | 10 |
| `T1566_phishing.xml` | 3 |
| `T1567.001_unknown.xml` | 1 |
| `T1567.002_unknown.xml` | 6 |
| `T1567_exfil_over_web_service.xml` | 7 |
| `T1569.002_unknown.xml` | 18 |
| `T1569_system_services.xml` | 2 |
| `T1571_unknown.xml` | 3 |
| `T1572_unknown.xml` | 14 |
| `T1574.001_unknown.xml` | 72 |
| `T1574.002_unknown.xml` | 5 |
| `T1574.005_unknown.xml` | 1 |
| `T1574.007_unknown.xml` | 1 |
| `T1574.008_unknown.xml` | 1 |
| `T1574.011_unknown.xml` | 9 |
| `T1574.012_unknown.xml` | 3 |
| `T1574_unknown.xml` | 4 |
| `T1587.001_unknown.xml` | 8 |
| `T1587_unknown.xml` | 3 |
| `T1588.002_unknown.xml` | 7 |
| `T1590.001_unknown.xml` | 3 |
| `T1590.002_unknown.xml` | 1 |
| `T1590_unknown.xml` | 1 |
| `T1593.003_unknown.xml` | 1 |
| `T1595_unknown.xml` | 13 |
| `T1599.001_unknown.xml` | 2 |
| `T1608_unknown.xml` | 1 |
| `T1614.001_unknown.xml` | 2 |
| `T1615_unknown.xml` | 6 |
| `T1620_unknown.xml` | 1 |
| `T1622_unknown.xml` | 6 |
| `T1649_unknown.xml` | 4 |
| `T1685.001_unknown.xml` | 25 |
| `T1685.005_unknown.xml` | 8 |
| `T1685_unknown.xml` | 122 |
| `T1686.003_unknown.xml` | 14 |
| `T1689_unknown.xml` | 1 |
| `unknown_collection.xml` | 1 |
| `unknown_command_and_control.xml` | 5 |
| `unknown_credential_access.xml` | 7 |
| `unknown_discovery.xml` | 14 |
| `unknown_execution.xml` | 160 |
| `unknown_exfiltration.xml` | 5 |
| `unknown_initial_access.xml` | 4 |
| `unknown_lateral_movement.xml` | 3 |
| `unknown_persistence.xml` | 38 |
| `unknown_privilege_escalation.xml` | 22 |

### `database/rules/by_source/`
_Grouped by Windows event source (Sysmon, Security, PowerShell, System). Aligns with Wazuh decoder structure._

| File | Rules |
|------|-------|
| `application.xml` | 58 |
| `powershell.xml` | 208 |
| `security.xml` | 145 |
| `sysmon.xml` | 2169 |
| `system.xml` | 90 |

## Deployment to Wazuh

Copy the desired view's XML files to your Wazuh manager:

```bash
# Option A: Deploy by tactic (recommended)
sudo cp database/rules/by_tactic/*.xml /var/ossec/etc/rules/

# Option B: Deploy by source (matches Wazuh decoder structure)
sudo cp database/rules/by_source/*.xml /var/ossec/etc/rules/

# Restart Wazuh manager to load new rules
sudo systemctl restart wazuh-manager

# Verify rules loaded
sudo /var/ossec/bin/wazuh-logtest
```
