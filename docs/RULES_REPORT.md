# Wazuh Rule Database Report

> Generated: 2026-07-20 06:28 UTC
> Pipeline version: 1.0.0

## Overview

| Metric | Value |
|--------|-------|
| Total rules generated | **3215** |
| EVTX files processed | 2294 |
| EVTX sources used | 1 |
| MITRE tactics covered | 12 / 12 |
| MITRE techniques covered | 270 |
| Rule ID range | 100000 - 119999 |

## Alert Level Distribution

| Level | Wazuh Severity | Count | Percentage |
|-------|----------------|-------|------------|
| 6 | Low relevance | 88 | 2.7% █ |
| 7 | Bad word matching | 76 | 2.4% █ |
| 8 | First time seen | 542 | 16.9% ████████ |
| 9 | Error from invalid source | 1369 | 42.6% █████████████████████ |
| 10 | Multiple user-generated errors | 447 | 13.9% ██████ |
| 11 | Integrity checking warning | 343 | 10.7% █████ |
| 12 | High importance event | 232 | 7.2% ███ |
| 13 | Unusual error (high importance) | 86 | 2.7% █ |
| 14 | High importance security event | 32 | 1.0%  |

## Detection Confidence Distribution

| Confidence | Count | Description |
|------------|-------|-------------|
| high | 1525 | Exact tool/process name match |
| medium | 1682 | Command-line pattern or behavioral indicator |
| low | 8 | Heuristic / generic event |

## Rules by MITRE ATT&CK Tactic

### Initial Access (TA0001) — 32 rules

| Rule ID | Level | Technique | Description | Confidence | Parent SID |
|---------|-------|-----------|-------------|------------|------------|
| `113000` | 8 | `T1200` T1200 | Device Installation Blocked | medium | 60100 |
| `113001` | 8 | `T1566.001` T1566.001 | ISO Image Mounted | medium | 60100 |
| `113002` | 9 | `T1078` Valid Accounts | Win Susp Computer Name Containing Samtheadmin | high | 60100 |
| `113003` | 9 | `T1078` Valid Accounts | Win Susp Computer Name Containing Samtheadmin | high | 60100 |
| `113004` | 9 | `T1027` Obfuscated Files or Information | Password Protected ZIP File Opened (Email Attachment) | high | 60100 |
| `113005` | 8 | `T1078` Valid Accounts | User Added to Local Administrator Group | medium | 60100 |
| `113006` | 9 | `T1566.001` T1566.001 | ISO File Created Within Temp Folders | high | 61613 |
| `113007` | 9 | `T1566.001` T1566.001 | ISO File Created Within Temp Folders | high | 61613 |
| `113008` | 8 | `T1566.001` T1566.001 | ISO or Image Mount Indicator in Recent Files | medium | 61613 |
| `113009` | 9 | `T1195` T1195 | Octopus Scanner Malware | high | 61613 |
| `113010` | 9 | `T1566.001` T1566.001 | Office Macro File Creation From Suspicious Process | high | 61613 |
| `113011` | 9 | `T1566.001` T1566.001 | Suspicious File Created in Outlook Temporary Directory | high | 61613 |
| `113012` | 9 | `T1190` Exploit Public-Facing Application | Suspicious MSExchangeMailboxReplication ASPX Write | high | 61613 |
| `113013` | 9 | `T1190` Exploit Public-Facing Application | Suspicious File Write to SharePoint Layouts Directory | high | 61613 |
| `113014` | 9 | `T1566.001` T1566.001 | Suspicious HWP Sub Processes | high | 61603 |
| `113015` | 9 | - | Suspicious Shells Spawn by Java Utility Keytool | high | 61603 |
| `113016` | 9 | - | Suspicious Processes Spawned by Java.EXE | high | 61603 |
| `113017` | 8 | - | Shell Process Spawned by Java.EXE | medium | 61603 |
| `113018` | 9 | `T1505.003` T1505.003 | Suspicious Child Process Of SQL Server | high | 61603 |
| `113019` | 9 | - | Suspicious Child Process Of Veeam Dabatase | high | 61603 |
| `113020` | 8 | `T1021.002` T1021.002 | Password Provided In Command Line Of Net.EXE | medium | 61603 |
| `113021` | 9 | `T1566` Phishing | Suspicious Microsoft OneNote Child Process | high | 61603 |
| `113022` | 9 | `T1566.001` T1566.001 | Suspicious Execution From Outlook Temporary Folder | high | 61603 |
| `113023` | 9 | `T1190` Exploit Public-Facing Application | Remote Access Tool - ScreenConnect Server Web Shell Execution | high | 61603 |
| `113024` | 9 | `T1133` T1133 | User Added to Remote Desktop Users Group | high | 61603 |
| `113025` | 9 | `T1566` Phishing | Phishing Pattern ISO in Archive | high | 61603 |
| `113026` | 9 | `T1566.001` T1566.001 | Suspicious Double Extension File Execution | high | 61603 |
| `113027` | 9 | `T1204.002` T1204.002 | Suspicious LNK Command-Line Padding with Whitespace Characters | high | 61603 |
| `113028` | 9 | `T1190` Exploit Public-Facing Application | Terminal Service Process Spawn | high | 61603 |
| `113029` | 9 | `T1190` Exploit Public-Facing Application | Suspicious Processes Spawned by WinRM | high | 61603 |
| `113030` | 8 | `T1566.001` T1566.001 | Windows Registry Trust Record Modification | medium | 61615 |
| `113031` | 9 | `T1133` T1133 | Running Chrome VPN Extensions via the Registry 2 VPN Extension | high | 61615 |

### Execution (TA0002) — 1118 rules

| Rule ID | Level | Technique | Description | Confidence | Parent SID |
|---------|-------|-----------|-------------|------------|------------|
| `100000` | 9 | `T1047` T1047 | Suspicious process: wmic | high | 61603 |
| `100001` | 9 | `T1047` T1047 | Suspicious process: wmic | high | 61603 |
| `100002` | 8 | `T1059.001` T1059.001 | Suspicious command: iex( | medium | 61603 |
| `100003` | 8 | `T1047` T1047 | File created by wmic | medium | 61613 |
| `100004` | 9 | `T1047` T1047 | Network connection by wmic | high | 61605 |
| `100005` | 8 | `T1059.001` T1059.001 | Suspicious command: -nop  | medium | 61603 |
| `100006` | 9 | `T1047` T1047 | DLL sideloading by wmic | high | 61609 |
| `100007` | 9 | `T1047` T1047 | Network connection by wmic | high | 61605 |
| `100008` | 8 | `T1059.001` T1059.001 | Suspicious command: bypass | medium | 61603 |
| `100009` | 8 | `T1059.001` T1059.001 | Suspicious command: -w hidden | medium | 61603 |
| `100010` | 8 | `T1059.001` T1059.001 | Suspicious PowerShell: downloadstring | medium | 91801 |
| `100011` | 8 | `T1059.001` T1059.001 | Suspicious PowerShell: iex( | medium | 91801 |
| `100012` | 8 | `T1059.001` T1059.001 | PowerShell module: downloadstring | medium | 91801 |
| `100013` | 8 | `T1059.001` T1059.001 | PowerShell module: iex( | medium | 91801 |
| `100014` | 8 | `T1059.001` T1059.001 | PowerShell module: invoke-expression | medium | 91801 |
| `100015` | 8 | `T1059.001` T1059.001 | Suspicious PowerShell: bypass | medium | 91801 |
| `100016` | 8 | `T1047` T1047 | Suspicious PowerShell: invoke-wmimethod | medium | 91801 |
| `100017` | 8 | `T1059.001` T1059.001 | Suspicious PowerShell: invoke-expression | medium | 91801 |
| `100018` | 8 | `T1059.001` T1059.001 | Suspicious PowerShell: invoke-webrequest | medium | 91801 |
| `100019` | 8 | `T1059.001` T1059.001 | Suspicious PowerShell: -nop  | medium | 91801 |
| `100020` | 9 | `T1588` T1588 | Relevant Anti-Virus Signature Keywords In Application Log | high | 60003 |
| `100021` | 9 | `T1211` T1211 | Microsoft Malware Protection Engine Crash | high | 60003 |
| `100022` | 8 | - | Dump Ntds.dit To Suspicious Location | medium | 60003 |
| `100023` | 9 | `T1203` T1203 | Audit CVE Event | high | 60003 |
| `100024` | 8 | `T1070.004` T1070.004 | Backup Catalog Deleted | medium | 60003 |
| `100025` | 8 | - | MSI Installation From Suspicious Locations | medium | 60003 |
| `100026` | 8 | `T1218` T1218 | MSI Installation From Web | medium | 60003 |
| `100027` | 9 | - | MSSQL Disable Audit Settings | high | 60003 |
| `100028` | 9 | - | MSSQL XPCmdshell Suspicious Execution | high | 60003 |
| `100029` | 9 | - | MSSQL XPCmdshell Option Change | high | 60003 |
| `100030` | 9 | `T1211` T1211 | Microsoft Malware Protection Engine Crash - WER | high | 60003 |
| `100031` | 8 | `T1204.002` T1204.002 | AppLocker Prevented Application or Script from Running | medium | 60000 |
| `100032` | 8 | - | Deployment AppX Package Was Blocked By AppLocker | medium | 60000 |
| `100033` | 9 | - | Remote AppX Package Downloaded from File Sharing or CDN Domain | high | 60000 |
| `100034` | 8 | - | AppX Package Deployment Failed Due to Signing Requirements | medium | 60000 |
| `100035` | 9 | - | AppX Located in Known Staging Directory Added to Deployment Pipeline | high | 60000 |
| `100036` | 8 | - | Potential Malicious AppX Package Installation Attempts | medium | 60000 |
| `100037` | 8 | - | Deployment Of The AppX Package Was Blocked By The Policy | medium | 60000 |
| `100038` | 8 | - | AppX Located in Uncommon Directory Added to Deployment Pipeline | medium | 60000 |
| `100039` | 8 | `T1204.002` T1204.002 | Windows AppX Deployment Full Trust Package Installation | medium | 60000 |
| `100040` | 8 | `T1204.002` T1204.002 | Windows AppX Deployment Unsigned Package Installation | medium | 60000 |
| `100041` | 8 | - | Suspicious Digital Signature Of AppX Package | medium | 60000 |
| `100042` | 9 | - | Loading Diagcab Package From Remote Path | high | 60000 |
| `100043` | 8 | `T1590.002` T1590.002 | Failed DNS Zone Transfer | medium | 60000 |
| `100044` | 8 | `T1686.003` T1686.003 | Uncommon New Firewall Rule Added In Windows Firewall Exception List | medium | 60016 |
| `100045` | 9 | `T1686.003` T1686.003 | New Firewall Rule Added In Windows Firewall Exception List For Pote... | high | 60016 |
| `100046` | 8 | `T1686.003` T1686.003 | New Firewall Rule Added In Windows Firewall Exception List Via WmiP... | medium | 60016 |
| `100047` | 9 | `T1686.003` T1686.003 | All Rules Have Been Deleted From The Windows Firewall Configuration | high | 60016 |
| `100048` | 8 | `T1686.003` T1686.003 | A Rule Has Been Deleted From The Windows Firewall Exception List | medium | 60016 |
| `100049` | 9 | `T1587.001` T1587.001 | ProxyLogon MSExchange OabVirtualDirectory | high | 60000 |
| `100050` | 9 | `T1070` Indicator Removal | Remove Exported Mailbox from Exchange Webserver | high | 60000 |
| `100051` | 9 | `T1685` T1685 | Windows Filtering Platform Blocked Connection From EDR Agent Binary | high | 60100 |
| `100052` | 9 | `T1222.001` T1222.001 | AD Object WriteDAC Access | high | 60100 |
| `100053` | 9 | `T1685` T1685 | Weak Encryption Enabled and Kerberoast | high | 60100 |
| `100054` | 9 | `T1685.005` T1685.005 | Security Eventlog Cleared | high | 60100 |
| `100055` | 9 | `T1685.005` T1685.005 | Security Eventlog Cleared | high | 60100 |
| `100056` | 9 | `T1685.001` T1685.001 | Important Windows Event Auditing Disabled | high | 60100 |
| `100057` | 9 | `T1685.001` T1685.001 | Important Windows Event Auditing Disabled | high | 60100 |
| `100058` | 9 | `T1685` T1685 | HackTool - EDRSilencer Execution - Filter Added | high | 60100 |
| `100059` | 9 | `T1027` Obfuscated Files or Information | Invoke-Obfuscation CLIP+ Launcher - Security | high | 60100 |
| `100061` | 9 | `T1027` Obfuscated Files or Information | Invoke-Obfuscation STDIN+ Launcher - Security | high | 60100 |
| `100062` | 9 | `T1027` Obfuscated Files or Information | Invoke-Obfuscation VAR+ Launcher - Security | high | 60100 |
| `100063` | 8 | `T1027` Obfuscated Files or Information | Invoke-Obfuscation COMPRESS OBFUSCATION - Security | medium | 60100 |
| `100064` | 8 | `T1027` Obfuscated Files or Information | Invoke-Obfuscation RUNDLL LAUNCHER - Security | medium | 60100 |
| `100065` | 9 | `T1027` Obfuscated Files or Information | Invoke-Obfuscation Via Stdin - Security | high | 60100 |
| `100066` | 9 | `T1027` Obfuscated Files or Information | Invoke-Obfuscation Via Use Clip - Security | high | 60100 |
| `100067` | 9 | `T1027` Obfuscated Files or Information | Invoke-Obfuscation Via Use MSHTA - Security | high | 60100 |
| `100068` | 9 | `T1027` Obfuscated Files or Information | Invoke-Obfuscation Via Use Rundll32 - Security | high | 60100 |
| `100069` | 9 | `T1027` Obfuscated Files or Information | Invoke-Obfuscation VAR++ LAUNCHER OBFUSCATION - Security | high | 60100 |
| `100070` | 8 | - | Potential AS-REP Roasting via Kerberos TGT Requests | medium | 60100 |
| `100071` | 8 | `T1036` T1036 | New or Renamed User Account with '$' Character | medium | 60100 |
| `100072` | 8 | `T1036` T1036 | New or Renamed User Account with '$' Character | medium | 60100 |
| `100073` | 9 | `T1569.002` T1569.002 | PowerShell Scripts Installed as Services - Security | high | 60100 |
| `100074` | 9 | `T1059.001` T1059.001 | Remote PowerShell Sessions Network Connections (WinRM) | high | 60100 |
| `100075` | 8 | `T1027` Obfuscated Files or Information | Password Protected ZIP File Opened | medium | 60100 |
| `100076` | 9 | `T1053.005` T1053.005 | Suspicious Scheduled Task Creation | high | 60100 |
| `100077` | 9 | `T1053.005` T1053.005 | Important Scheduled Task Deleted/Disabled | high | 60100 |
| `100078` | 9 | `T1053.005` T1053.005 | Suspicious Scheduled Task Update | high | 60100 |
| `100079` | 8 | `T1685` T1685 | Potential Privileged System Service Operation - SeLoadDriverPrivilege | medium | 60100 |
| `100080` | 8 | `T1685` T1685 | Windows Defender Exclusion List Modified | medium | 60100 |
| `100081` | 8 | `T1685` T1685 | Windows Defender Exclusion Registry Key - Write Access Requested | medium | 60100 |
| `100082` | 9 | `T1047` T1047 | T1047 Wmiprvse Wbemcomn DLL Hijack | high | 60100 |
| `100083` | 8 | - | Suspicious Application Installed | medium | 60000 |
| `100084` | 8 | - | Suspicious Application Installed | medium | 60000 |
| `100085` | 9 | `T1685` T1685 | Sysmon Application Crashed | high | 60002 |
| `100086` | 8 | `T1685.005` T1685.005 | Eventlog Cleared | medium | 60002 |
| `100087` | 9 | `T1685.005` T1685.005 | Important Windows Eventlog Cleared | high | 60002 |
| `100088` | 8 | `T1685` T1685 | Windows Defender Threat Detection Service Disabled | medium | 60002 |
| `100089` | 9 | `T1027` Obfuscated Files or Information | Invoke-Obfuscation CLIP+ Launcher - System | high | 60002 |
| `100091` | 9 | `T1027` Obfuscated Files or Information | Invoke-Obfuscation STDIN+ Launcher - System | high | 60002 |
| `100092` | 9 | `T1027` Obfuscated Files or Information | Invoke-Obfuscation VAR+ Launcher - System | high | 60002 |
| `100093` | 8 | `T1027` Obfuscated Files or Information | Invoke-Obfuscation COMPRESS OBFUSCATION - System | medium | 60002 |
| `100094` | 8 | `T1027` Obfuscated Files or Information | Invoke-Obfuscation RUNDLL LAUNCHER - System | medium | 60002 |
| `100095` | 9 | `T1027` Obfuscated Files or Information | Invoke-Obfuscation Via Stdin - System | high | 60002 |
| `100096` | 9 | `T1027` Obfuscated Files or Information | Invoke-Obfuscation Via Use Clip - System | high | 60002 |
| `100097` | 9 | `T1027` Obfuscated Files or Information | Invoke-Obfuscation Via Use MSHTA - System | high | 60002 |
| `100098` | 9 | `T1027` Obfuscated Files or Information | Invoke-Obfuscation Via Use Rundll32 - System | high | 60002 |
| `100099` | 9 | `T1027` Obfuscated Files or Information | Invoke-Obfuscation VAR++ LAUNCHER OBFUSCATION - System | high | 60002 |
| `100100` | 9 | `T1569.002` T1569.002 | PowerShell Scripts Installed as Services | high | 60002 |
| `100101` | 8 | `T1569.002` T1569.002 | CSExec Service Installation | medium | 60002 |
| `100102` | 9 | `T1569.002` T1569.002 | HackTool Service Registration or Execution | high | 60002 |
| `100103` | 8 | `T1569.002` T1569.002 | PAExec Service Installation | medium | 60002 |
| `100104` | 8 | `T1569.002` T1569.002 | RemCom Service Installation | medium | 60002 |
| `100105` | 8 | `T1569.002` T1569.002 | PsExec Service Installation | medium | 60002 |
| `100106` | 9 | - | Important Windows Service Terminated With Error | high | 60002 |
| `100107` | 9 | - | Important Windows Service Terminated Unexpectedly | high | 60002 |
| `100108` | 9 | `T1685` T1685 | Windows Defender Grace Period Expired | high | 60005 |
| `100109` | 9 | `T1047` T1047 | PSExec and WMI Process Creations Block | high | 60005 |
| `100110` | 8 | `T1685` T1685 | Windows Defender Exclusions Added | medium | 60005 |
| `100111` | 9 | `T1685` T1685 | Windows Defender Exploit Guard Tamper | high | 60005 |
| `100112` | 9 | `T1685` T1685 | Windows Defender Malware And PUA Scanning Disabled | high | 60005 |
| `100113` | 9 | `T1059` Command and Scripting Interpreter | Windows Defender AMSI Trigger Detected | high | 60005 |
| `100114` | 9 | `T1685` T1685 | Windows Defender Real-time Protection Disabled | high | 60005 |
| `100115` | 8 | `T1685` T1685 | Windows Defender Real-Time Protection Failure/Restart | medium | 60005 |
| `100116` | 9 | `T1685` T1685 | Win Defender Restored Quarantine File | high | 60005 |
| `100117` | 9 | `T1685` T1685 | Windows Defender Configuration Changes | high | 60005 |
| `100118` | 9 | `T1685` T1685 | Microsoft Defender Tamper Protection Trigger | high | 60005 |
| `100119` | 9 | `T1059` Command and Scripting Interpreter | Windows Defender Threat Detected | high | 60005 |
| `100120` | 9 | `T1685` T1685 | Windows Defender Virus Scanning Feature Disabled | high | 60005 |
| `100121` | 8 | `T1218.011` T1218.011 | Remote Thread Creation Via PowerShell In Uncommon Target | medium | 61610 |
| `100122` | 9 | `T1127` T1127 | Remote Thread Creation Ttdinject.exe Proxy | high | 61610 |
| `100123` | 8 | `T1564.004` T1564.004 | Hidden Executable In NTFS Alternate Data Stream | medium | 61617 |
| `100124` | 8 | - | Creation Of a Suspicious ADS File Outside a Browser Download | medium | 61617 |
| `100125` | 9 | `T1564.004` T1564.004 | Suspicious File Download From File Sharing Websites -  File Stream | high | 61617 |
| `100126` | 8 | `T1564.004` T1564.004 | Unusual File Download From File Sharing Websites - File Stream | medium | 61617 |
| `100127` | 9 | `T1564.004` T1564.004 | HackTool Named File Stream Created | high | 61617 |
| `100128` | 9 | `T1564.004` T1564.004 | Exports Registry Key To an Alternate Data Stream | high | 61617 |
| `100130` | 9 | - | Potentially Suspicious File Download From ZIP TLD | high | 61617 |
| `100131` | 8 | `T1559.001` T1559.001 | DNS Query Request By Regsvr32.EXE | medium | 61624 |
| `100132` | 8 | `T1590` T1590 | Suspicious DNS Query for IP Lookup Service APIs | medium | 61624 |
| `100133` | 8 | `T1070` Indicator Removal | EventLog EVTX File Deleted | medium | 61625 |
| `100134` | 9 | `T1070` Indicator Removal | Exchange PowerShell Cmdlet History Deleted | high | 61625 |
| `100135` | 8 | `T1070` Indicator Removal | IIS WebServer Access Logs Deleted | medium | 61625 |
| `100136` | 8 | - | Process Deletion of Its Own Executable | medium | 61625 |
| `100137` | 8 | `T1070` Indicator Removal | PowerShell Console History Logs Deleted | medium | 61625 |
| `100138` | 9 | `T1070.004` T1070.004 | Prefetch File Deleted | high | 61625 |
| `100139` | 8 | `T1070` Indicator Removal | Tomcat WebServer Logs Deleted | medium | 61625 |
| `100140` | 8 | `T1070.004` T1070.004 | File Deleted Via Sysinternals SDelete | medium | 61625 |
| `100141` | 8 | `T1070.004` T1070.004 | ADS Zone.Identifier Deleted By Uncommon Application | medium | 61625 |
| `100142` | 8 | - | Assembly DLL Creation Via AspNetCompiler | medium | 61613 |
| `100143` | 8 | `T1685.001` T1685.001 | EVTX Created In Uncommon Location | medium | 61613 |
| `100144` | 8 | `T1036.005` T1036.005 | Files With System DLL Name In Unsuspected Locations | medium | 61613 |
| `100145` | 12 | `T1036.005` T1036.005 | Files With System Process Name In Unsuspected Locations | medium | 61613 |
| `100146` | 9 | `T1059.005` T1059.005 | WScript or CScript Dropper - File | high | 61613 |
| `100147` | 8 | `T1569.002` T1569.002 | CSExec Service File Creation | medium | 61613 |
| `100148` | 8 | - | Potentially Suspicious DMP/HDMP File Creation | medium | 61613 |
| `100149` | 9 | `T1021.002` T1021.002 | HackTool - NetExec File Indicators | high | 61613 |
| `100150` | 9 | `T1021.002` T1021.002 | HackTool - NetExec File Indicators | high | 61613 |
| `100151` | 9 | `T1059.005` T1059.005 | Adwind RAT / JRAT File Artifact | high | 61613 |
| `100152` | 9 | `T1059.005` T1059.005 | Adwind RAT / JRAT File Artifact | high | 61613 |
| `100153` | 9 | - | Uncommon File Creation By Mysql Daemon Process | high | 61613 |
| `100154` | 9 | `T1218` T1218 | Suspicious DotNET CLR Usage Log Artifact | high | 61613 |
| `100155` | 9 | - | Suspicious File Creation In Uncommon AppData Folder | high | 61613 |
| `100156` | 8 | `T1218.011` T1218.011 | SCR File Write Event | medium | 61613 |
| `100157` | 8 | - | OneNote Attachment File Dropped In Suspicious Location | medium | 61613 |
| `100158` | 9 | - | Suspicious File Created Via OneNote Application | high | 61613 |
| `100159` | 8 | - | Publisher Attachment File Dropped In Suspicious Location | medium | 61613 |
| `100160` | 9 | `T1204.002` T1204.002 | File With Uncommon Extension Created By An Office Application | high | 61613 |
| `100161` | 9 | `T1587.001` T1587.001 | Uncommon File Created In Office Startup Folder | high | 61613 |
| `100162` | 9 | `T1059` Command and Scripting Interpreter | PCRE.NET Package Temp Files | high | 61613 |
| `100163` | 8 | `T1059` Command and Scripting Interpreter | Suspicious File Created In PerfLogs | medium | 61613 |
| `100164` | 13 | `T1059.001` T1059.001 | Malicious PowerShell Scripts - FileCreation | high | 61613 |
| `100165` | 9 | `T1059.001` T1059.001 | Malicious PowerShell Scripts - FileCreation | high | 61613 |
| `100166` | 8 | - | PSScriptPolicyTest Creation By Uncommon Process | medium | 61613 |
| `100167` | 9 | - | .RDP File Created By Uncommon Application | high | 61613 |
| `100168` | 9 | `T1027` Obfuscated Files or Information | Potential Winnti Dropper Activity | high | 61613 |
| `100169` | 9 | - | PDF File Created By RegEdit.EXE | high | 61613 |
| `100170` | 8 | `T1569.002` T1569.002 | RemCom Service File Creation | medium | 61613 |
| `100171` | 8 | `T1218` T1218 | Self Extraction Directive File Created In Potentially Suspicious Lo... | medium | 61613 |
| `100172` | 9 | `T1059` Command and Scripting Interpreter | Windows Shell/Scripting Application File Write to Suspicious Folder | high | 61613 |
| `100173` | 9 | `T1059` Command and Scripting Interpreter | Windows Shell/Scripting Application File Write to Suspicious Folder | high | 61613 |
| `100174` | 12 | `T1036` T1036 | Windows Binaries Write Suspicious Extensions | high | 61613 |
| `100175` | 9 | `T1036` T1036 | Windows Binaries Write Suspicious Extensions | high | 61613 |
| `100176` | 9 | `T1564` T1564 | Suspicious Creation with Colorcpl | high | 61613 |
| `100177` | 8 | `T1036.005` T1036.005 | Suspicious Files in Default GPO Folder | medium | 61613 |
| `100178` | 8 | - | Creation of a Diagcab | medium | 61613 |
| `100179` | 9 | `T1036.007` T1036.007 | Suspicious Double Extension Files | high | 61613 |
| `100180` | 9 | `T1036.007` T1036.007 | Suspicious Double Extension Files | high | 61613 |
| `100181` | 9 | `T1564` T1564 | Suspicious Executable File Creation | high | 61613 |
| `100182` | 8 | `T1564.004` T1564.004 | Potential Hidden Directory Creation Via NTFS INDEX_ALLOCATION Stream | medium | 61613 |
| `100183` | 8 | `T1036` T1036 | Potential Homoglyph Attack Using Lookalike Characters in Filename | medium | 61613 |
| `100184` | 8 | `T1036` T1036 | Potential Homoglyph Attack Using Lookalike Characters in Filename | medium | 61613 |
| `100185` | 9 | `T1218` T1218 | Legitimate Application Dropped Archive | high | 61613 |
| `100186` | 9 | `T1218` T1218 | Legitimate Application Dropped Executable | high | 61613 |
| `100187` | 9 | `T1218` T1218 | Legitimate Application Dropped Script | high | 61613 |
| `100188` | 8 | `T1036.007` T1036.007 | Suspicious LNK Double Extension File Created | medium | 61613 |
| `100189` | 8 | `T1685` T1685 | Suspicious PROCEXP152.sys File Created In TMP | medium | 61613 |
| `100190` | 9 | `T1204` User Execution | Suspicious Binaries and Scripts in Public Folder | high | 61613 |
| `100191` | 9 | `T1036.002` T1036.002 | Potential File Extension Spoofing Using Right-to-Left Override | high | 61613 |
| `100192` | 8 | - | Drop Binaries Into Spool Drivers Color Folder | medium | 61613 |
| `100193` | 9 | `T1059.001` T1059.001 | Suspicious Interactive PowerShell as SYSTEM | high | 61613 |
| `100194` | 8 | - | Potentially Suspicious WDAC Policy File Creation | medium | 61613 |
| `100195` | 8 | - | WinSxS Executable File Creation By Non-System Process | medium | 61613 |
| `100196` | 9 | `T1548.002` T1548.002 | UAC Bypass Using IDiagnostic Profile - File | high | 61613 |
| `100197` | 8 | `T1587.001` T1587.001 | VHD Image Download Via Browser | medium | 61613 |
| `100198` | 8 | `T1216` T1216 | AWL Bypass with Winrm.vbs and Malicious WsmPty.xsl/WsmTxt.xsl - File | medium | 61613 |
| `100199` | 9 | `T1047` T1047 | Wmiprvse Wbemcomn DLL Hijack - File | high | 61613 |
| `100200` | 8 | `T1218` T1218 | Potentially Suspicious Self Extraction Directive File Created | medium | 61613 |
| `100201` | 8 | `T1059` Command and Scripting Interpreter | Clfs.SYS Loaded By Process Located In a Potential Suspicious Location | medium | 61609 |
| `100202` | 9 | `T1218.003` T1218.003 | DLL Loaded From Suspicious Location Via Cmspt.EXE | high | 61609 |
| `100203` | 8 | - | Amsi.DLL Loaded Via LOLBIN Process | medium | 61609 |
| `100204` | 9 | `T1059` Command and Scripting Interpreter | PCRE.NET Package Image Load | high | 61609 |
| `100205` | 9 | `T1202` T1202 | Diagnostic Library Sdiageng.DLL Loaded By Msdt.EXE | high | 61609 |
| `100206` | 8 | `T1059.001` T1059.001 | PowerShell Core DLL Loaded By Non PowerShell Process | medium | 61609 |
| `100207` | 8 | `T1129` T1129 | Unsigned .node File Loaded | medium | 61609 |
| `100208` | 9 | `T1685.001` T1685.001 | HackTool - SharpEvtMute DLL Load | high | 61609 |
| `100209` | 8 | `T1204.002` T1204.002 | DotNET Assembly DLL Loaded Via Office Application | medium | 61609 |
| `100210` | 8 | `T1204.002` T1204.002 | CLR DLL Loaded Via Office Applications | medium | 61609 |
| `100211` | 9 | `T1204.002` T1204.002 | GAC DLL Loaded Via Office Applications | high | 61609 |
| `100212` | 8 | `T1204.002` T1204.002 | Microsoft Excel Add-In Loaded From Uncommon Location | medium | 61609 |
| `100213` | 8 | `T1204.002` T1204.002 | Microsoft VBA For Outlook Addin Loaded Via Outlook | medium | 61609 |
| `100214` | 8 | - | PowerShell Core DLL Loaded Via Office Application | medium | 61609 |
| `100215` | 9 | `T1204.002` T1204.002 | VBA DLL Loaded Via Office Application | high | 61609 |
| `100216` | 8 | `T1204.002` T1204.002 | Remote DLL Load Via Rundll32.EXE | medium | 61609 |
| `100217` | 9 | `T1059` Command and Scripting Interpreter | Abusable DLL Potential Sideloading From Suspicious Location | high | 61609 |
| `100218` | 8 | `T1070` Indicator Removal | DLL Load By System Process From Suspicious Locations | medium | 61609 |
| `100219` | 9 | `T1055` Process Injection | DotNet CLR DLL Loaded By Scripting Applications | high | 61609 |
| `100220` | 8 | `T1218.011` T1218.011 | Unsigned DLL Loaded by Windows Utility | medium | 61609 |
| `100221` | 8 | `T1059.005` T1059.005 | MMC Loading Script Engines DLLs | medium | 61609 |
| `100222` | 8 | `T1220` T1220 | WMIC Loading Scripting Libraries | medium | 61609 |
| `100223` | 9 | `T1047` T1047 | Wmiprvse Wbemcomn DLL Hijack | high | 61609 |
| `100224` | 8 | `T1059.001` T1059.001 | Suspicious WSMAN Provider Image Loads | medium | 61609 |
| `100225` | 9 | `T1218` T1218 | Network Connection Initiated By AddinUtil.EXE | high | 61605 |
| `100226` | 9 | `T1218.003` T1218.003 | Outbound Network Connection Initiated By Cmstp.EXE | high | 61605 |
| `100227` | 9 | `T1071.001` T1071.001 | Outbound Network Connection Initiated By Microsoft Dialer | high | 61605 |
| `100228` | 9 | `T1203` T1203 | Network Connection Initiated By Eqnedt32.EXE | high | 61605 |
| `100229` | 8 | `T1203` T1203 | Office Application Initiated Network Connection To Non-Local IP | medium | 61605 |
| `100230` | 8 | `T1218.009` T1218.009 | RegAsm.EXE Initiating Network Connection To Public IP | medium | 61605 |
| `100231` | 8 | `T1559.001` T1559.001 | Network Connection Initiated By Regsvr32.EXE | medium | 61605 |
| `100232` | 8 | `T1218.011` T1218.011 | Rundll32 Internet Connection | medium | 61605 |
| `100233` | 9 | `T1127.001` T1127.001 | Silenttrinity Stager Msbuild Activity | high | 61605 |
| `100234` | 9 | - | Suspicious Network Connection Binary No CommandLine | high | 61605 |
| `100235` | 9 | `T1059.001` T1059.001 | Potential Remote PowerShell Session Initiated | high | 61605 |
| `100236` | 8 | `T1218.011` T1218.011 | Outbound Network Connection To Public IP Via Winlogon | medium | 61605 |
| `100237` | 8 | `T1218` T1218 | Potentially Suspicious Wuauclt Network Connection | medium | 61605 |
| `100238` | 8 | `T1059.001` T1059.001 | Alternate PowerShell Hosts Pipe | medium | 61619 |
| `100239` | 8 | `T1569.002` T1569.002 | PUA - PAExec Default Named Pipe | medium | 61619 |
| `100240` | 8 | `T1047` T1047 | WMI Event Consumer Created Named Pipe | medium | 61619 |
| `100241` | 8 | `T1569.002` T1569.002 | PsExec Tool Execution From Suspicious Locations - PipeName | medium | 61619 |
| `100242` | 8 | `T1059.001` T1059.001 | Nslookup PowerShell Download Cradle | medium | 91801 |
| `100243` | 8 | `T1059.001` T1059.001 | PowerShell Downgrade Attack - PowerShell | medium | 91801 |
| `100244` | 9 | `T1059.001` T1059.001 | PowerShell Called from an Executable Version Mismatch | high | 91801 |
| `100245` | 9 | `T1218` T1218 | Potential RemoteFXvGPUDisablement.EXE Abuse | high | 91801 |
| `100246` | 9 | `T1685` T1685 | Tamper Windows Defender - PSClassic | high | 91801 |
| `100247` | 8 | `T1059.001` T1059.001 | Suspicious Non PowerShell WSMAN COM Provider | medium | 91801 |
| `100248` | 8 | `T1059.001` T1059.001 | Alternate PowerShell Hosts - PowerShell Module | medium | 91801 |
| `100249` | 9 | `T1059.001` T1059.001 | Bad Opsec Powershell Code Artifacts | high | 91801 |
| `100250` | 8 | `T1070.003` T1070.003 | Clear PowerShell History - PowerShell Module | medium | 91801 |
| `100251` | 8 | `T1070.003` T1070.003 | Clear PowerShell History - PowerShell Module | medium | 91801 |
| `100252` | 13 | `T1059.001` T1059.001 | Malicious PowerShell Scripts - PoshModule | high | 91801 |
| `100253` | 9 | `T1059.001` T1059.001 | Malicious PowerShell Scripts - PoshModule | high | 91801 |
| `100258` | 8 | `T1027` Obfuscated Files or Information | Invoke-Obfuscation COMPRESS OBFUSCATION - PowerShell Module | medium | 91801 |
| `100259` | 8 | `T1027` Obfuscated Files or Information | Invoke-Obfuscation RUNDLL LAUNCHER - PowerShell Module | medium | 91801 |
| `100262` | 9 | `T1027` Obfuscated Files or Information | Invoke-Obfuscation Via Use MSHTA - PowerShell Module | high | 91801 |
| `100263` | 9 | `T1027` Obfuscated Files or Information | Invoke-Obfuscation Via Use Rundll32 - PowerShell Module | high | 91801 |
| `100265` | 13 | `T1482` T1482 | Malicious PowerShell Commandlets - PoshModule | high | 91801 |
| `100266` | 9 | `T1059.001` T1059.001 | Remote PowerShell Session (PS Module) | high | 91801 |
| `100267` | 9 | `T1218` T1218 | Potential RemoteFXvGPUDisablement.EXE Abuse - PowerShell Module | high | 91801 |
| `100268` | 8 | `T1059.001` T1059.001 | Suspicious PowerShell Download - PoshModule | medium | 91801 |
| `100269` | 9 | `T1059.001` T1059.001 | Suspicious PowerShell Invocations - Generic - PowerShell Module | high | 91801 |
| `100270` | 9 | `T1059.001` T1059.001 | Suspicious PowerShell Invocations - Specific - PowerShell Module | high | 91801 |
| `100271` | 9 | `T1059.001` T1059.001 | Suspicious PowerShell Invocations - Specific - PowerShell Module | high | 91801 |
| `100272` | 9 | `T1059.001` T1059.001 | Suspicious PowerShell Invocations - Specific - PowerShell Module | high | 91801 |
| `100273` | 9 | `T1059.001` T1059.001 | Suspicious PowerShell Invocations - Specific - PowerShell Module | high | 91801 |
| `100274` | 9 | `T1059.001` T1059.001 | Suspicious PowerShell Invocations - Specific - PowerShell Module | high | 91801 |
| `100275` | 9 | `T1059.001` T1059.001 | Suspicious PowerShell Invocations - Specific - PowerShell Module | high | 91801 |
| `100276` | 8 | `T1218` T1218 | SyncAppvPublishingServer Bypass Powershell Restriction - PS Module | medium | 91801 |
| `100277` | 9 | - | AADInternals PowerShell Cmdlets Execution - PsScript | high | 91801 |
| `100278` | 8 | - | Add Windows Capability Via PowerShell Script | medium | 91801 |
| `100279` | 9 | `T1685` T1685 | AMSI Bypass Pattern Assembly GetType | high | 91801 |
| `100280` | 8 | `T1685` T1685 | Potential AMSI Bypass Script Using NULL Bits | medium | 91801 |
| `100281` | 9 | `T1059.001` T1059.001 | Silence.EDA Detection | high | 91801 |
| `100282` | 8 | `T1070.003` T1070.003 | Clear PowerShell History - PowerShell | medium | 91801 |
| `100283` | 8 | `T1070.003` T1070.003 | Clear PowerShell History - PowerShell | medium | 91801 |
| `100284` | 9 | `T1070` Indicator Removal | Clearing Windows Console History | high | 91801 |
| `100285` | 8 | `T1059.001` T1059.001 | PowerShell Create Local User | medium | 91801 |
| `100286` | 9 | `T1070.003` T1070.003 | Disable Powershell Command History | high | 91801 |
| `100287` | 9 | `T1685` T1685 | Disable-WindowsOptionalFeature Command PowerShell | high | 91801 |
| `100288` | 8 | `T1620` T1620 | Potential In-Memory Execution Using Reflection.Assembly | medium | 91801 |
| `100289` | 9 | `T1059.001` T1059.001 | DSInternals Suspicious PowerShell Cmdlets - ScriptBlock | high | 91801 |
| `100290` | 8 | - | Potential Suspicious Windows Feature Enabled | medium | 91801 |
| `100291` | 9 | `T1070` Indicator Removal | Disable of ETW Trace - Powershell | high | 91801 |
| `100292` | 9 | `T1070` Indicator Removal | Disable of ETW Trace - Powershell | high | 91801 |
| `100293` | 8 | `T1059.001` T1059.001 | Import PowerShell Modules From Suspicious Directories | medium | 91801 |
| `100298` | 8 | `T1027` Obfuscated Files or Information | Invoke-Obfuscation COMPRESS OBFUSCATION - PowerShell | medium | 91801 |
| `100299` | 8 | `T1027` Obfuscated Files or Information | Invoke-Obfuscation RUNDLL LAUNCHER - PowerShell | medium | 91801 |
| `100302` | 9 | `T1027` Obfuscated Files or Information | Invoke-Obfuscation Via Use MSHTA - PowerShell | high | 91801 |
| `100303` | 9 | `T1027` Obfuscated Files or Information | Invoke-Obfuscation Via Use Rundll32 - PowerShell | high | 91801 |
| `100305` | 13 | `T1482` T1482 | Malicious PowerShell Commandlets - ScriptBlock | high | 91801 |
| `100306` | 13 | `T1059.001` T1059.001 | Malicious PowerShell Keywords | medium | 91801 |
| `100307` | 8 | `T1059.001` T1059.001 | Powershell MsXml COM Object | medium | 91801 |
| `100308` | 13 | `T1059.001` T1059.001 | Malicious Nishang PowerShell Commandlets | high | 91801 |
| `100309` | 9 | `T1564.004` T1564.004 | NTFS Alternate Data Stream | high | 91801 |
| `100310` | 9 | `T1059.001` T1059.001 | PowerView PowerShell Cmdlets - ScriptBlock | high | 91801 |
| `100311` | 9 | `T1059.001` T1059.001 | PSAsyncShell - Asynchronous TCP Reverse Shell | high | 91801 |
| `100312` | 9 | `T1059.001` T1059.001 | PowerShell PSAttack | high | 91801 |
| `100313` | 8 | `T1059.001` T1059.001 | PowerShell Remote Session Creation | medium | 91801 |
| `100314` | 9 | `T1218` T1218 | Potential RemoteFXvGPUDisablement.EXE Abuse - PowerShell ScriptBlock | high | 91801 |
| `100315` | 8 | `T1553.004` T1553.004 | Root Certificate Installed - PowerShell | medium | 91801 |
| `100316` | 8 | `T1553.004` T1553.004 | Root Certificate Installed - PowerShell | medium | 91801 |
| `100317` | 8 | `T1553.005` T1553.005 | Suspicious Invoke-Item From Mount-DiskImage | medium | 91801 |
| `100318` | 9 | `T1222` T1222 | PowerShell Set-Acl On Windows Folder - PsScript | high | 91801 |
| `100319` | 8 | `T1059.001` T1059.001 | Change PowerShell Policies to an Insecure Level - PowerShell | medium | 91801 |
| `100320` | 9 | `T1059.001` T1059.001 | Malicious ShellIntel PowerShell Commandlets | high | 91801 |
| `100321` | 8 | `T1564.004` T1564.004 | Powershell Store File In Alternate Data Stream | medium | 91801 |
| `100322` | 8 | `T1685.005` T1685.005 | Suspicious Eventlog Clear | medium | 91801 |
| `100323` | 8 | `T1685.005` T1685.005 | Suspicious Eventlog Clear | medium | 91801 |
| `100324` | 8 | `T1685.005` T1685.005 | Suspicious Eventlog Clear | medium | 91801 |
| `100325` | 8 | `T1059.001` T1059.001 | Suspicious PowerShell Download - Powershell Script | medium | 91801 |
| `100326` | 8 | `T1059.003` T1059.003 | Powershell Execute Batch Script | medium | 91801 |
| `100327` | 8 | `T1202` T1202 | Troubleshooting Pack Cmdlet Execution | medium | 91801 |
| `100328` | 8 | `T1564.006` T1564.006 | Suspicious Hyper-V Cmdlets | medium | 91801 |
| `100329` | 9 | `T1059.001` T1059.001 | Suspicious PowerShell Invocations - Generic | high | 91801 |
| `100330` | 9 | `T1059.001` T1059.001 | Suspicious PowerShell Invocations - Specific | high | 91801 |
| `100331` | 9 | `T1059.001` T1059.001 | Suspicious PowerShell Invocations - Specific | high | 91801 |
| `100332` | 9 | `T1059.001` T1059.001 | Suspicious PowerShell Invocations - Specific | high | 91801 |
| `100333` | 9 | `T1059.001` T1059.001 | Suspicious PowerShell Invocations - Specific | high | 91801 |
| `100334` | 9 | `T1059.001` T1059.001 | Suspicious PowerShell Invocations - Specific | high | 91801 |
| `100335` | 9 | `T1059.001` T1059.001 | Suspicious PowerShell Invocations - Specific | high | 91801 |
| `100336` | 8 | `T1070.003` T1070.003 | Suspicious IO.FileStream | medium | 91801 |
| `100337` | 8 | `T1059.001` T1059.001 | Potential Suspicious PowerShell Keywords | medium | 91801 |
| `100338` | 8 | `T1070.005` T1070.005 | PowerShell Deleted Mounted Share | medium | 91801 |
| `100339` | 8 | `T1036.003` T1036.003 | Suspicious Start-Process PassThru | medium | 91801 |
| `100340` | 8 | `T1553.005` T1553.005 | Suspicious Unblock-File | medium | 91801 |
| `100341` | 8 | `T1564.003` T1564.003 | Suspicious PowerShell WindowStyle Option | medium | 91801 |
| `100342` | 8 | - | PowerShell Write-EventLog Usage | medium | 91801 |
| `100343` | 8 | `T1218` T1218 | SyncAppvPublishingServer Execution to Bypass Powershell Restriction | medium | 91801 |
| `100344` | 9 | `T1685` T1685 | Tamper Windows Defender Remove-MpPreference - ScriptBlockLogging | high | 91801 |
| `100345` | 9 | `T1685` T1685 | Tamper Windows Defender - ScriptBlockLogging | high | 91801 |
| `100346` | 8 | `T1070.006` T1070.006 | Powershell Timestomp | medium | 91801 |
| `100347` | 8 | `T1059.001` T1059.001 | Usage Of Web Request Commands And Cmdlets - ScriptBlock | medium | 91801 |
| `100348` | 8 | - | Potentially Suspicious Call To Win32_NTEventlogFile Class - PSScript | medium | 91801 |
| `100349` | 8 | `T1218.007` T1218.007 | PowerShell WMI Win32_Product Install MSI | medium | 91801 |
| `100350` | 9 | `T1059.001` T1059.001 | Potential WinAPI Calls Via PowerShell Scripts | high | 91801 |
| `100351` | 9 | `T1059.001` T1059.001 | Potential WinAPI Calls Via PowerShell Scripts | high | 91801 |
| `100352` | 9 | `T1059.001` T1059.001 | Potential WinAPI Calls Via PowerShell Scripts | high | 91801 |
| `100353` | 9 | `T1059.001` T1059.001 | Potential WinAPI Calls Via PowerShell Scripts | high | 91801 |
| `100354` | 8 | `T1685` T1685 | Windows Defender Exclusions Added - PowerShell | medium | 91801 |
| `100355` | 8 | `T1686.003` T1686.003 | Windows Firewall Profile Disabled | medium | 91801 |
| `100356` | 8 | `T1047` T1047 | WMIC Unquoted Services Path Lookup - PowerShell | medium | 91801 |
| `100357` | 9 | `T1047` T1047 | WMImplant Hack Tool | high | 91801 |
| `100358` | 8 | `T1553.004` T1553.004 | Suspicious X509Enrollment - Ps Script | medium | 91801 |
| `100359` | 8 | `T1059.001` T1059.001 | Powershell XML Execute Command | medium | 91801 |
| `100360` | 9 | `T1218.003` T1218.003 | CMSTP Execution Process Access | high | 61612 |
| `100362` | 12 | `T1106` T1106 | HackTool - HandleKatz Duplicating LSASS Handle | high | 61612 |
| `100363` | 9 | `T1204.002` T1204.002 | HackTool - LittleCorporal Generated Maldoc Injection | high | 61612 |
| `100364` | 9 | `T1685.001` T1685.001 | HackTool - SysmonEnte Execution | high | 61612 |
| `100365` | 8 | `T1106` T1106 | Potential Direct Syscall of NtOpenProcess | medium | 61612 |
| `100366` | 9 | `T1685.001` T1685.001 | Suspicious Svchost Process Access | high | 61612 |
| `100367` | 9 | `T1685` T1685 | Suspicious Process Access of MsMpEng by WerFaultSecure - EDR-Freeze | high | 61612 |
| `100368` | 8 | - | Potential DLL Injection Via AccCheckConsole | medium | 61603 |
| `100369` | 9 | `T1218` T1218 | Suspicious AddinUtil.EXE CommandLine Execution | high | 61603 |
| `100370` | 8 | `T1218` T1218 | Uncommon Child Process Of AddinUtil.EXE | medium | 61603 |
| `100371` | 8 | `T1218` T1218 | Uncommon AddinUtil.EXE CommandLine Execution | medium | 61603 |
| `100372` | 8 | `T1218` T1218 | AddinUtil.EXE Execution From Uncommon Directory | medium | 61603 |
| `100373` | 9 | `T1003.001` T1003.001 | Potential Adplus.EXE Abuse | high | 61603 |
| `100374` | 8 | `T1218` T1218 | AgentExecutor PowerShell Execution | medium | 61603 |
| `100375` | 9 | `T1218` T1218 | Suspicious AgentExecutor PowerShell Execution | high | 61603 |
| `100376` | 9 | `T1685` T1685 | Windows AMSI Related Registry Tampering Via CommandLine | high | 61603 |
| `100377` | 8 | `T1218` T1218 | Uncommon Child Process Of Appvlp.EXE | medium | 61603 |
| `100378` | 9 | `T1059` Command and Scripting Interpreter | Suspicious ArcSOC.exe Child Process | high | 61603 |
| `100379` | 8 | `T1127` T1127 | AspNetCompiler Execution | medium | 61603 |
| `100380` | 9 | `T1127` T1127 | Suspicious Child Process of AspNetCompiler | high | 61603 |
| `100381` | 9 | `T1127` T1127 | Potentially Suspicious ASP.NET Compilation Via AspNetCompiler | high | 61603 |
| `100382` | 8 | `T1218` T1218 | Uncommon  Assistive Technology Applications Execution Via AtBroker.EXE | medium | 61603 |
| `100383` | 8 | `T1564.001` T1564.001 | Hiding Files with Attrib.exe | medium | 61603 |
| `100384` | 9 | `T1564.001` T1564.001 | Set Suspicious Files as System Files Using Attrib.EXE | high | 61603 |
| `100385` | 9 | `T1685.001` T1685.001 | Audit Policy Tampering Via NT Resource Kit Auditpol | high | 61603 |
| `100386` | 9 | `T1685.001` T1685.001 | Audit Policy Tampering Via Auditpol | high | 61603 |
| `100387` | 9 | `T1685.001` T1685.001 | Windows EventLog Autologger Session Registry Modification Via Comma... | high | 61603 |
| `100388` | 8 | `T1202` T1202 | Indirect Inline Command Execution Via Bash.EXE | medium | 61603 |
| `100389` | 8 | `T1202` T1202 | Indirect Command Execution From Script File Via Bash.EXE | medium | 61603 |
| `100390` | 8 | `T1048` T1048 | Data Export From MSSQL Table Via BCP.EXE | medium | 61603 |
| `100391` | 9 | `T1059.005` T1059.005 | Suspicious Child Process Of BgInfo.EXE | high | 61603 |
| `100392` | 8 | `T1059.005` T1059.005 | Uncommon Child Process Of BgInfo.EXE | medium | 61603 |
| `100393` | 9 | - | Chromium Browser Headless Execution To Mockbin Like Site | high | 61603 |
| `100394` | 9 | `T1036` T1036 | Suspicious Calculator Usage | high | 61603 |
| `100395` | 8 | `T1106` T1106 | Potential Binary Proxy Execution Via Cdb.EXE | medium | 61603 |
| `100396` | 8 | `T1553.004` T1553.004 | New Root Certificate Installed Via CertMgr.EXE | medium | 61603 |
| `100397` | 8 | `T1218` T1218 | DLL Loaded via CertOC.EXE | medium | 61603 |
| `100398` | 9 | `T1218` T1218 | Suspicious DLL Loaded via CertOC.EXE | high | 61603 |
| `100399` | 8 | `T1553.004` T1553.004 | New Root Certificate Installed Via Certutil.EXE | medium | 61603 |
| `100402` | 9 | `T1027` Obfuscated Files or Information | Suspicious File Encoded To Base64 Via Certutil.EXE | high | 61603 |
| `100403` | 9 | `T1027` Obfuscated Files or Information | File In Suspicious Location Encoded To Base64 Via Certutil.EXE | high | 61603 |
| `100405` | 9 | `T1218` T1218 | Potential NTLM Coercion Via Certutil.EXE | high | 61603 |
| `100406` | 8 | `T1036` T1036 | Suspicious CodePage Switch Via CHCP | medium | 61603 |
| `100407` | 8 | `T1070.004` T1070.004 | Greedy File Deletion Using Del | medium | 61603 |
| `100408` | 8 | `T1059` Command and Scripting Interpreter | Potential Dosfuscation Activity | medium | 61603 |
| `100409` | 8 | `T1059.003` T1059.003 | Command Line Execution with Suspicious URL and AppData Strings | medium | 61603 |
| `100410` | 8 | `T1564.003` T1564.003 | Cmd Launched with Hidden Start Flags to Suspicious Targets | medium | 61603 |
| `100411` | 9 | `T1059.001` T1059.001 | Suspicious File Execution From Internet Hosted WebDav Share | high | 61603 |
| `100412` | 9 | `T1059.001` T1059.001 | Cmd.EXE Missing Space Characters Execution Anomaly | high | 61603 |
| `100413` | 9 | `T1059.001` T1059.001 | Cmd.EXE Missing Space Characters Execution Anomaly | high | 61603 |
| `100414` | 9 | `T1059.001` T1059.001 | Cmd.EXE Missing Space Characters Execution Anomaly | high | 61603 |
| `100415` | 9 | - | NtdllPipe Like Activity Execution | high | 61603 |
| `100416` | 9 | `T1059.003` T1059.003 | Potential CommandLine Path Traversal Via Cmd.EXE | high | 61603 |
| `100417` | 8 | `T1070.004` T1070.004 | Potentially Suspicious Ping/Copy Command Combination | medium | 61603 |
| `100418` | 9 | `T1070.004` T1070.004 | Suspicious Ping/Del Command Combination | high | 61603 |
| `100419` | 8 | `T1218` T1218 | Potentially Suspicious CMD Shell Output Redirect | medium | 61603 |
| `100420` | 8 | `T1059.003` T1059.003 | Read Contents From Stdin Via Cmd.EXE | medium | 61603 |
| `100421` | 12 | `T1059` Command and Scripting Interpreter | Unusual Parent Process For Cmd.EXE | medium | 61603 |
| `100422` | 8 | `T1218` T1218 | Potential Arbitrary File Download Via Cmdl32.EXE | medium | 61603 |
| `100423` | 9 | `T1218.003` T1218.003 | CMSTP Execution Process Creation | high | 61603 |
| `100424` | 8 | `T1059.003` T1059.003 | OpenEDR Spawning Command Shell | medium | 61603 |
| `100425` | 8 | `T1059.001` T1059.001 | Powershell Executed From Headless ConHost Process | medium | 61603 |
| `100426` | 9 | `T1059.003` T1059.003 | Conhost.exe CommandLine Path Traversal | high | 61603 |
| `100427` | 8 | `T1202` T1202 | Uncommon Child Process Of Conhost.EXE | medium | 61603 |
| `100428` | 9 | `T1202` T1202 | Potentially Suspicious Child Processes Spawned by ConHost | high | 61603 |
| `100429` | 12 | `T1059` Command and Scripting Interpreter | Conhost Spawned By Uncommon Parent Process | medium | 61603 |
| `100430` | 9 | `T1685` T1685 | Windows Credential Guard Registry Tampering Via CommandLine | high | 61603 |
| `100431` | 8 | `T1027.004` T1027.004 | Dynamic .NET Compilation Via Csc.EXE | medium | 61603 |
| `100432` | 9 | `T1059.005` T1059.005 | Csc.EXE Execution Form Potentially Suspicious Parent | high | 61603 |
| `100433` | 9 | `T1127` T1127 | Suspicious Use of CSharp Interactive Console | high | 61603 |
| `100434` | 8 | - | Potential Cookies Session Hijacking | medium | 61603 |
| `100435` | 8 | - | Curl Web Request With Potential Custom User-Agent | medium | 61603 |
| `100438` | 9 | - | Suspicious File Download From File Sharing Domain Via Curl.EXE | high | 61603 |
| `100439` | 8 | - | Insecure Transfer Via Curl.EXE | medium | 61603 |
| `100440` | 8 | - | Insecure Proxy/DOH Transfer Via Curl.EXE | medium | 61603 |
| `100441` | 8 | - | Local File Read Using Curl.EXE | medium | 61603 |
| `100442` | 9 | `T1216` T1216 | Suspicious CustomShellHost Execution | high | 61603 |
| `100443` | 8 | `T1218` T1218 | Uncommon Child Process Of Defaultpack.EXE | medium | 61603 |
| `100444` | 9 | `T1685` T1685 | PowerShell Defender Threat Severity Default Action Set to 'Allow' o... | high | 61603 |
| `100445` | 9 | `T1685` T1685 | Windows Defender Context Menu Removed | high | 61603 |
| `100446` | 8 | `T1218` T1218 | DeviceCredentialDeployment Execution | medium | 61603 |
| `100447` | 8 | `T1218` T1218 | Arbitrary MSI Download Via Devinit.EXE | medium | 61603 |
| `100448` | 8 | - | Potentially Suspicious Child Process Of ClickOnce Application | medium | 61603 |
| `100449` | 8 | `T1218` T1218 | Potentially Suspicious Child Process Of DiskShadow.EXE | medium | 61603 |
| `100451` | 8 | `T1218` T1218 | Diskshadow Script Mode - Execution From Potential Suspicious Location | medium | 61603 |
| `100452` | 8 | `T1685` T1685 | Dism Remove Online Package | medium | 61603 |
| `100453` | 8 | `T1685` T1685 | Dism Remove Online Package | medium | 61603 |
| `100454` | 8 | `T1218` T1218 | Potential Application Whitelisting Bypass via Dnx.EXE | medium | 61603 |
| `100455` | 8 | `T1218` T1218 | Arbitrary DLL or Csproj Code Execution Via Dotnet.EXE | medium | 61603 |
| `100456` | 8 | `T1218` T1218 | Binary Proxy Execution Via Dotnet-Trace.EXE | medium | 61603 |
| `100457` | 8 | `T1218` T1218 | Process Memory Dump Via Dotnet-Dump | medium | 61603 |
| `100458` | 8 | `T1218` T1218 | Potentially Over Permissive Permissions Granted Using Dsacls.EXE | medium | 61603 |
| `100459` | 8 | `T1218` T1218 | Potential Password Spraying Attempt Using Dsacls.EXE | medium | 61603 |
| `100460` | 8 | `T1218` T1218 | New Capture Session Launched Via DXCap.EXE | medium | 61603 |
| `100461` | 8 | `T1218` T1218 | Potentially Suspicious Cabinet File Expansion | medium | 61603 |
| `100462` | 8 | `T1036` T1036 | Explorer Process Tree Break | medium | 61603 |
| `100463` | 8 | `T1036` T1036 | Explorer Process Tree Break | medium | 61603 |
| `100464` | 8 | `T1036` T1036 | Findstr Launching .lnk File | medium | 61603 |
| `100465` | 8 | `T1070` Indicator Removal | Filter Driver Unloaded Via Fltmc.EXE | medium | 61603 |
| `100466` | 9 | `T1070` Indicator Removal | Sysmon Driver Unloaded Via Fltmc.EXE | high | 61603 |
| `100467` | 9 | `T1036` T1036 | Forfiles.EXE Child Process Masquerading | high | 61603 |
| `100468` | 8 | `T1059` Command and Scripting Interpreter | Forfiles Command Execution | medium | 61603 |
| `100469` | 9 | - | Uncommon FileSystem Load Attempt By Format.com | high | 61603 |
| `100470` | 8 | `T1059` Command and Scripting Interpreter | Use of FSharp Interpreters | medium | 61603 |
| `100471` | 8 | `T1059` Command and Scripting Interpreter | Use of FSharp Interpreters | medium | 61603 |
| `100472` | 8 | `T1059` Command and Scripting Interpreter | Potentially Suspicious NTFS Symlink Behavior Modification | medium | 61603 |
| `100474` | 8 | `T1593.003` T1593.003 | Suspicious Git Clone | medium | 61603 |
| `100475` | 9 | - | Potentially Suspicious GoogleUpdate Child Process | high | 61603 |
| `100476` | 8 | - | File Decryption Using Gpg4win | medium | 61603 |
| `100477` | 8 | - | File Encryption Using Gpg4win | medium | 61603 |
| `100478` | 9 | - | File Encryption/Decryption Via Gpg4win From Suspicious Locations | high | 61603 |
| `100479` | 8 | - | Arbitrary Binary Execution Using GUP Utility | medium | 61603 |
| `100480` | 9 | `T1218.001` T1218.001 | Remote CHM File Download/Execution Via HH.EXE | high | 61603 |
| `100481` | 9 | `T1047` T1047 | HTML Help HH.EXE Suspicious Child Process | high | 61603 |
| `100482` | 9 | `T1047` T1047 | Suspicious HH.EXE Execution | high | 61603 |
| `100483` | 9 | `T1218.011` T1218.011 | HackTool - F-Secure C3 Load by Rundll32 | high | 61603 |
| `100484` | 13 | `T1059.003` T1059.003 | Operator Bloopers Cobalt Strike Commands | high | 61603 |
| `100485` | 13 | `T1059.003` T1059.003 | Operator Bloopers Cobalt Strike Modules | high | 61603 |
| `100486` | 13 | `T1218.011` T1218.011 | CobaltStrike Load by Rundll32 | high | 61603 |
| `100487` | 13 | `T1059` Command and Scripting Interpreter | Potential CobaltStrike Process Patterns | high | 61603 |
| `100488` | 13 | `T1059` Command and Scripting Interpreter | Potential CobaltStrike Process Patterns | high | 61603 |
| `100489` | 13 | `T1059` Command and Scripting Interpreter | Potential CobaltStrike Process Patterns | high | 61603 |
| `100490` | 13 | `T1059` Command and Scripting Interpreter | Potential CobaltStrike Process Patterns | high | 61603 |
| `100491` | 9 | `T1059.001` T1059.001 | HackTool - Covenant PowerShell Launcher | high | 61603 |
| `100492` | 9 | `T1059.001` T1059.001 | HackTool - Covenant PowerShell Launcher | high | 61603 |
| `100493` | 9 | `T1047` T1047 | HackTool - CrackMapExec Execution | high | 61603 |
| `100494` | 9 | `T1047` T1047 | HackTool - CrackMapExec Execution | high | 61603 |
| `100495` | 9 | `T1047` T1047 | HackTool - CrackMapExec Execution | high | 61603 |
| `100496` | 9 | `T1047` T1047 | HackTool - CrackMapExec Execution | high | 61603 |
| `100497` | 9 | `T1047` T1047 | HackTool - CrackMapExec Execution | high | 61603 |
| `100498` | 9 | `T1047` T1047 | HackTool - CrackMapExec Execution | high | 61603 |
| `100499` | 9 | `T1047` T1047 | HackTool - CrackMapExec Execution | high | 61603 |
| `100500` | 9 | `T1059.001` T1059.001 | HackTool - CrackMapExec PowerShell Obfuscation | high | 61603 |
| `100501` | 9 | `T1685` T1685 | Hacktool - EDR-Freeze Execution | high | 61603 |
| `100502` | 9 | `T1685` T1685 | Hacktool - EDR-Freeze Execution | high | 61603 |
| `100503` | 9 | `T1685` T1685 | HackTool - EDRSilencer Execution | high | 61603 |
| `100504` | 9 | `T1685` T1685 | HackTool - EDRSilencer Execution | high | 61603 |
| `100505` | 9 | `T1685` T1685 | HackTool - EDRSilencer Execution | high | 61603 |
| `100506` | 12 | `T1059.001` T1059.001 | HackTool - Empire PowerShell Launch Parameters | high | 61603 |
| `100507` | 9 | - | HackTool - GMER Rootkit Detector and Remover Execution | high | 61603 |
| `100508` | 9 | - | HackTool - GMER Rootkit Detector and Remover Execution | high | 61603 |
| `100509` | 9 | `T1047` T1047 | HackTool - Potential Impacket Lateral Movement Activity | high | 61603 |
| `100510` | 9 | `T1047` T1047 | HackTool - Potential Impacket Lateral Movement Activity | high | 61603 |
| `100511` | 9 | `T1027` Obfuscated Files or Information | Invoke-Obfuscation CLIP+ Launcher | high | 61603 |
| `100516` | 9 | `T1027` Obfuscated Files or Information | Invoke-Obfuscation Obfuscated IEX Invocation | high | 61603 |
| `100517` | 9 | `T1027` Obfuscated Files or Information | Invoke-Obfuscation Obfuscated IEX Invocation | high | 61603 |
| `100518` | 9 | `T1027` Obfuscated Files or Information | Invoke-Obfuscation Obfuscated IEX Invocation | high | 61603 |
| `100521` | 8 | `T1027` Obfuscated Files or Information | Invoke-Obfuscation COMPRESS OBFUSCATION | medium | 61603 |
| `100524` | 9 | `T1027` Obfuscated Files or Information | Invoke-Obfuscation Via Use MSHTA | high | 61603 |
| `100525` | 9 | `T1027` Obfuscated Files or Information | Invoke-Obfuscation VAR++ LAUNCHER OBFUSCATION | high | 61603 |
| `100526` | 8 | `T1059.003` T1059.003 | HackTool - Jlaive In-Memory Assembly Execution | medium | 61603 |
| `100527` | 9 | `T1059.003` T1059.003 | HackTool - Koadic Execution | high | 61603 |
| `100528` | 9 | `T1082` System Information Discovery | HackTool - PCHunter Execution | high | 61603 |
| `100529` | 9 | `T1082` System Information Discovery | HackTool - PCHunter Execution | high | 61603 |
| `100530` | 9 | `T1082` System Information Discovery | HackTool - PCHunter Execution | high | 61603 |
| `100531` | 9 | `T1082` System Information Discovery | HackTool - PCHunter Execution | high | 61603 |
| `100532` | 12 | `T1053.005` T1053.005 | HackTool - Default PowerSploit/Empire Scheduled Task Creation | high | 61603 |
| `100533` | 9 | `T1685` T1685 | HackTool - PowerTool Execution | high | 61603 |
| `100534` | 9 | `T1685` T1685 | HackTool - PowerTool Execution | high | 61603 |
| `100535` | 9 | `T1587` T1587 | HackTool - PurpleSharp Execution | high | 61603 |
| `100536` | 9 | `T1587` T1587 | HackTool - PurpleSharp Execution | high | 61603 |
| `100537` | 9 | `T1587` T1587 | HackTool - PurpleSharp Execution | high | 61603 |
| `100538` | 9 | `T1106` T1106 | HackTool - RedMimicry Winnti Playbook Execution | high | 61603 |
| `100539` | 9 | `T1685.001` T1685.001 | HackTool - SharpEvtMute Execution | high | 61603 |
| `100540` | 9 | `T1685.001` T1685.001 | HackTool - SharpEvtMute Execution | high | 61603 |
| `100541` | 9 | `T1685.001` T1685.001 | HackTool - SharpEvtMute Execution | high | 61603 |
| `100542` | 9 | `T1210` T1210 | HackTool - SharpWSUS/WSUSpendu Execution | high | 61603 |
| `100543` | 9 | `T1059` Command and Scripting Interpreter | HackTool - Sliver C2 Implant Activity Pattern | high | 61603 |
| `100544` | 9 | `T1059` Command and Scripting Interpreter | HackTool - Stracciatella Execution | high | 61603 |
| `100545` | 9 | `T1059` Command and Scripting Interpreter | HackTool - Stracciatella Execution | high | 61603 |
| `100546` | 9 | `T1059` Command and Scripting Interpreter | HackTool - Stracciatella Execution | high | 61603 |
| `100547` | 9 | `T1059` Command and Scripting Interpreter | HackTool - Stracciatella Execution | high | 61603 |
| `100548` | 8 | `T1218` T1218 | Suspicious ZipExec Execution | medium | 61603 |
| `100549` | 9 | `T1685` T1685 | Hypervisor-protected Code Integrity (HVCI) Related Registry Tamperi... | high | 61603 |
| `100550` | 8 | `T1036` T1036 | Potential Fake Instance Of Hxtsr.EXE Executed | medium | 61603 |
| `100551` | 8 | `T1564.001` T1564.001 | Use Icacls to Hide File to Everyone | medium | 61603 |
| `100552` | 9 | `T1218` T1218 | Self Extracting Package Creation Via Iexpress.EXE From Potentially ... | high | 61603 |
| `100553` | 9 | `T1685.001` T1685.001 | Disable Windows IIS HTTP Logging | high | 61603 |
| `100554` | 8 | - | Suspicious IIS URL GlobalRules Rewrite Via AppCmd | medium | 61603 |
| `100555` | 8 | `T1070` Indicator Removal | IIS WebServer Log Deletion via CommandLine Utilities | medium | 61603 |
| `100556` | 8 | `T1127` T1127 | C# IL Code Compilation Via Ilasm.EXE | medium | 61603 |
| `100557` | 9 | - | ImagingDevices Unusual Parent/Child Processes | high | 61603 |
| `100558` | 9 | - | ImagingDevices Unusual Parent/Child Processes | high | 61603 |
| `100559` | 9 | `T1218` T1218 | Arbitrary File Download Via IMEWDBLD.EXE | high | 61603 |
| `100560` | 8 | `T1218` T1218 | InfDefaultInstall.exe .inf Execution | medium | 61603 |
| `100561` | 8 | `T1218` T1218 | File Download Via InstallUtil.EXE | medium | 61603 |
| `100562` | 8 | - | Suspicious Execution of InstallUtil Without Log | medium | 61603 |
| `100563` | 8 | `T1203` T1203 | Java Running with Remote Debugging | medium | 61603 |
| `100564` | 9 | `T1127` T1127 | Kavremover Dropped Binary LOLBIN Usage | high | 61603 |
| `100565` | 8 | - | Computer Password Change Via Ksetup.EXE | medium | 61603 |
| `100566` | 8 | - | Logged-On User Password Change Via Ksetup.EXE | medium | 61603 |
| `100567` | 8 | `T1218` T1218 | Uncommon Link.EXE Parent Process | medium | 61603 |
| `100568` | 8 | - | Rebuild Performance Counter Values Via Lodctr.EXE | medium | 61603 |
| `100569` | 9 | `T1685` T1685 | Suspicious Windows Trace ETW Session Tamper Via Logman.EXE | high | 61603 |
| `100570` | 9 | `T1218` T1218 | Devtoolslauncher.exe Executes Specified Binary | high | 61603 |
| `100573` | 8 | `T1218` T1218 | Gpscript Execution | medium | 61603 |
| `100574` | 8 | `T1218` T1218 | Ie4uinit Lolbin Use From Invalid Path | medium | 61603 |
| `100575` | 8 | `T1216.001` T1216.001 | Launch-VsDevShell.PS1 Proxy Execution | medium | 61603 |
| `100576` | 9 | `T1216` T1216 | Potential Manage-bde.wsf Abuse To Proxy Execution | high | 61603 |
| `100577` | 9 | `T1218` T1218 | MpiExec Lolbin | high | 61603 |
| `100578` | 8 | `T1218` T1218 | Execute Files with Msdeploy.exe | medium | 61603 |
| `100579` | 8 | `T1059` Command and Scripting Interpreter | Use of OpenConsole | medium | 61603 |
| `100580` | 9 | `T1218` T1218 | OpenWith.exe Executes Specified Binary | high | 61603 |
| `100581` | 8 | `T1059` Command and Scripting Interpreter | Use of Pcalua For Execution | medium | 61603 |
| `100582` | 9 | `T1218` T1218 | Execute Pcwrun.EXE To Leverage Follina | high | 61603 |
| `100583` | 8 | `T1218.011` T1218.011 | Code Execution via Pcwutl.dll | medium | 61603 |
| `100584` | 8 | `T1059.001` T1059.001 | Execute Code with Pester.bat as Parent | medium | 61603 |
| `100585` | 8 | `T1059.001` T1059.001 | Execute Code with Pester.bat | medium | 61603 |
| `100586` | 8 | `T1216.001` T1216.001 | Pubprn.vbs Proxy Execution | medium | 61603 |
| `100587` | 8 | `T1218` T1218 | DLL Execution via Rasautou.exe | medium | 61603 |
| `100588` | 8 | `T1218` T1218 | REGISTER_APP.VBS Proxy Execution | medium | 61603 |
| `100589` | 8 | `T1127` T1127 | Use of Remote.exe | medium | 61603 |
| `100590` | 8 | `T1127` T1127 | Use of Remote.exe | medium | 61603 |
| `100591` | 8 | `T1218` T1218 | Lolbin Runexehelper Use As Proxy | medium | 61603 |
| `100592` | 8 | `T1059` Command and Scripting Interpreter | Suspicious Runscripthelper.exe | medium | 61603 |
| `100593` | 8 | `T1218` T1218 | Use of Scriptrunner.exe | medium | 61603 |
| `100594` | 8 | `T1218` T1218 | Use Of The SFTP.EXE Binary As A LOLBIN | medium | 61603 |
| `100595` | 8 | `T1218` T1218 | SyncAppvPublishingServer Execute Arbitrary PowerShell Code | medium | 61603 |
| `100596` | 8 | `T1218` T1218 | SyncAppvPublishingServer VBS Execute Arbitrary PowerShell Code | medium | 61603 |
| `100597` | 8 | `T1127` T1127 | Use of TTDInject.exe | medium | 61603 |
| `100598` | 8 | `T1127` T1127 | Use of TTDInject.exe | medium | 61603 |
| `100599` | 8 | `T1218` T1218 | Lolbin Unregmp2.exe Use As Proxy | medium | 61603 |
| `100600` | 8 | `T1216` T1216 | UtilityFunctions.ps1 Proxy Dll | medium | 61603 |
| `100601` | 9 | `T1027.004` T1027.004 | Visual Basic Command Line Compiler Usage | high | 61603 |
| `100602` | 8 | `T1218` T1218 | Use of VisualUiaVerifyNative.exe | medium | 61603 |
| `100603` | 8 | `T1218` T1218 | Use of VisualUiaVerifyNative.exe | medium | 61603 |
| `100604` | 8 | `T1127` T1127 | Use of VSIISExeLauncher.exe | medium | 61603 |
| `100605` | 8 | `T1127` T1127 | Use of Wfc.exe | medium | 61603 |
| `100606` | 8 | `T1127` T1127 | Use of Wfc.exe | medium | 61603 |
| `100607` | 8 | `T1218` T1218 | Potential Register_App.Vbs LOLScript Abuse | medium | 61603 |
| `100608` | 8 | `T1689` T1689 | LSA PPL Protection Setting Modification via CommandLine | medium | 61603 |
| `100609` | 8 | `T1127` T1127 | Potential Mftrace.EXE Abuse | medium | 61603 |
| `100610` | 9 | `T1021.003` T1021.003 | MMC20 Lateral Movement | high | 61603 |
| `100611` | 9 | `T1204.002` T1204.002 | MMC Executing Files with Reversed Extensions Using RTLO Abuse | high | 61603 |
| `100612` | 8 | `T1036` T1036 | CodePage Modification Via MODE.COM To Russian Language | medium | 61603 |
| `100613` | 9 | `T1218` T1218 | Potential Suspicious Mofcomp Execution | high | 61603 |
| `100614` | 9 | `T1685` T1685 | Windows Defender Definition Files Removed | high | 61603 |
| `100615` | 8 | - | Suspicious Msbuild Execution By Uncommon Parent Process | medium | 61603 |
| `100616` | 9 | `T1218` T1218 | MSDT Execution Via Answer File | high | 61603 |
| `100617` | 9 | `T1202` T1202 | Potential Arbitrary Command Execution Using Msdt.EXE | high | 61603 |
| `100618` | 8 | `T1202` T1202 | Suspicious Cabinet File Execution Via Msdt.EXE | medium | 61603 |
| `100619` | 9 | `T1036` T1036 | Suspicious MSDT Parent Process | high | 61603 |
| `100620` | 8 | `T1218` T1218 | Arbitrary File Download Via MSEDGE_PROXY.EXE | medium | 61603 |
| `100621` | 9 | `T1218.005` T1218.005 | Remotely Hosted HTA File Executed Via Mshta.EXE | high | 61603 |
| `100622` | 8 | `T1059` Command and Scripting Interpreter | Wscript Shell Run In CommandLine | medium | 61603 |
| `100623` | 9 | `T1218.005` T1218.005 | Suspicious JavaScript Execution Via Mshta.EXE | high | 61603 |
| `100624` | 9 | `T1218.005` T1218.005 | Potential LethalHTA Technique Execution | high | 61603 |
| `100625` | 9 | `T1218.005` T1218.005 | Suspicious MSHTA Child Process | high | 61603 |
| `100626` | 9 | `T1140` T1140 | MSHTA Execution with Suspicious File Extensions | high | 61603 |
| `100627` | 9 | `T1106` T1106 | Suspicious Mshta.EXE Execution Patterns | high | 61603 |
| `100628` | 8 | `T1218.007` T1218.007 | DllUnregisterServer Function Call Via Msiexec.EXE | medium | 61603 |
| `100629` | 8 | `T1218.007` T1218.007 | Suspicious MsiExec Embedding Parent | medium | 61603 |
| `100630` | 8 | `T1218.007` T1218.007 | Suspicious Msiexec Execute Arbitrary DLL | medium | 61603 |
| `100632` | 8 | `T1218.007` T1218.007 | Suspicious Msiexec Quiet Install From Remote Location | medium | 61603 |
| `100633` | 9 | `T1036.005` T1036.005 | Potential MsiExec Masquerading | high | 61603 |
| `100634` | 8 | `T1218` T1218 | Arbitrary File Download Via MSOHTMED.EXE | medium | 61603 |
| `100635` | 8 | `T1218` T1218 | Arbitrary File Download Via MSPUB.EXE | medium | 61603 |
| `100636` | 8 | `T1059.001` T1059.001 | Detection of PowerShell Execution via Sqlps.exe | medium | 61603 |
| `100637` | 8 | `T1059.001` T1059.001 | SQL Client Tools PowerShell Session Detection | medium | 61603 |
| `100638` | 8 | `T1220` T1220 | Msxsl.EXE Execution | medium | 61603 |
| `100639` | 9 | `T1220` T1220 | Remote XSL Execution Via Msxsl.EXE | high | 61603 |
| `100640` | 8 | `T1686.003` T1686.003 | New Firewall Rule Added Via Netsh.EXE | medium | 61603 |
| `100641` | 9 | `T1686.003` T1686.003 | Suspicious Program Location Whitelisted In Firewall Via Netsh.EXE | high | 61603 |
| `100642` | 9 | `T1686.003` T1686.003 | RDP Connection Allowed Via Netsh.EXE | high | 61603 |
| `100643` | 8 | `T1686.003` T1686.003 | Firewall Rule Deleted Via Netsh.EXE | medium | 61603 |
| `100644` | 8 | `T1686.003` T1686.003 | Firewall Disabled via Netsh.EXE | medium | 61603 |
| `100645` | 8 | `T1686.003` T1686.003 | Netsh Allow Group Policy on Microsoft Defender Firewall | medium | 61603 |
| `100646` | 8 | - | Firewall Rule Update Via Netsh.EXE | medium | 61603 |
| `100647` | 9 | `T1127` T1127 | Potential Arbitrary Code Execution Via Node.EXE | high | 61603 |
| `100648` | 8 | `T1127` T1127 | Node Process Executions | medium | 61603 |
| `100649` | 8 | - | Nslookup PowerShell Download Cradle - ProcessCreation | medium | 61603 |
| `100650` | 8 | `T1218.008` T1218.008 | Driver/DLL Installation Via Odbcconf.EXE | medium | 61603 |
| `100651` | 9 | `T1218.008` T1218.008 | Suspicious Driver/DLL Installation Via Odbcconf.EXE | high | 61603 |
| `100652` | 9 | `T1218.008` T1218.008 | Odbcconf.EXE Suspicious DLL Location | high | 61603 |
| `100653` | 8 | `T1218.008` T1218.008 | New DLL Registered Via Odbcconf.EXE | medium | 61603 |
| `100654` | 9 | `T1218.008` T1218.008 | Potentially Suspicious DLL Registered Via Odbcconf.EXE | high | 61603 |
| `100655` | 8 | `T1218.008` T1218.008 | Response File Execution Via Odbcconf.EXE | medium | 61603 |
| `100656` | 9 | `T1218.008` T1218.008 | Suspicious Response File Execution Via Odbcconf.EXE | high | 61603 |
| `100657` | 8 | `T1218.008` T1218.008 | Uncommon Child Process Spawned By Odbcconf.EXE | medium | 61603 |
| `100658` | 9 | `T1202` T1202 | Potential Arbitrary File Download Using Office Application | high | 61603 |
| `100659` | 9 | `T1202` T1202 | Potentially Suspicious Office Document Executed From Trusted Location | high | 61603 |
| `100660` | 9 | `T1218.001` T1218.001 | OneNote.EXE Execution of Malicious Embedded Scripts | high | 61603 |
| `100661` | 9 | `T1059` Command and Scripting Interpreter | Outlook EnableUnsafeClientMailRules Setting Enabled | high | 61603 |
| `100662` | 9 | `T1204.002` T1204.002 | Suspicious Outlook Child Process | high | 61603 |
| `100663` | 9 | `T1059` Command and Scripting Interpreter | Suspicious Remote Child Process From Outlook | high | 61603 |
| `100664` | 9 | `T1204.002` T1204.002 | Suspicious Binary In User Directory Spawned From Office Application | high | 61603 |
| `100665` | 9 | `T1047` T1047 | Suspicious Microsoft Office Child Process | high | 61603 |
| `100666` | 8 | `T1202` T1202 | Potential Arbitrary DLL Load Using Winword | medium | 61603 |
| `100667` | 8 | `T1218` T1218 | Potential Mpclient.DLL Sideloading Via OfflineScannerShell.EXE Exec... | medium | 61603 |
| `100668` | 8 | `T1072` T1072 | PDQ Deploy Remote Adminstartion Tool Execution | medium | 61603 |
| `100669` | 8 | `T1072` T1072 | PDQ Deploy Remote Adminstartion Tool Execution | medium | 61603 |
| `100670` | 8 | `T1072` T1072 | PDQ Deploy Remote Adminstartion Tool Execution | medium | 61603 |
| `100671` | 8 | `T1072` T1072 | PDQ Deploy Remote Adminstartion Tool Execution | medium | 61603 |
| `100672` | 8 | - | Potentially Suspicious Execution Of PDQDeployRunner | medium | 61603 |
| `100673` | 8 | `T1059` Command and Scripting Interpreter | Perl Inline Command Execution | medium | 61603 |
| `100674` | 8 | `T1059` Command and Scripting Interpreter | Php Inline Command Execution | medium | 61603 |
| `100676` | 8 | - | Suspicious Powercfg Execution To Change Lock Screen Timeout | medium | 61603 |
| `100677` | 9 | - | AADInternals PowerShell Cmdlets Execution - ProccessCreation | high | 61603 |
| `100678` | 8 | - | Add Windows Capability Via PowerShell Cmdlet | medium | 61603 |
| `100679` | 9 | `T1685` T1685 | Potential AMSI Bypass Via .NET Reflection | high | 61603 |
| `100680` | 9 | `T1685` T1685 | Potential AMSI Bypass Via .NET Reflection | high | 61603 |
| `100681` | 8 | `T1685` T1685 | Potential AMSI Bypass Using NULL Bits | medium | 61603 |
| `100682` | 9 | `T1059.001` T1059.001 | Suspicious Encoded PowerShell Command Line | high | 61603 |
| `100683` | 9 | `T1059.001` T1059.001 | Suspicious PowerShell Encoded Command Patterns | high | 61603 |
| `100684` | 9 | - | Suspicious Obfuscated PowerShell Code | high | 61603 |
| `100685` | 9 | `T1140` T1140 | PowerShell Base64 Encoded FromBase64String Cmdlet | high | 61603 |
| `100686` | 9 | `T1140` T1140 | PowerShell Base64 Encoded FromBase64String Cmdlet | high | 61603 |
| `100687` | 9 | `T1059.001` T1059.001 | Malicious Base64 Encoded PowerShell Keywords in Command Lines | high | 61603 |
| `100688` | 9 | `T1059.001` T1059.001 | PowerShell Base64 Encoded IEX Cmdlet | high | 61603 |
| `100689` | 9 | `T1059.001` T1059.001 | PowerShell Base64 Encoded IEX Cmdlet | high | 61603 |
| `100690` | 9 | `T1059.001` T1059.001 | PowerShell Base64 Encoded Invoke Keyword | high | 61603 |
| `100691` | 9 | `T1685` T1685 | Powershell Base64 Encoded MpPreference Cmdlet | high | 61603 |
| `100692` | 9 | `T1685` T1685 | Powershell Base64 Encoded MpPreference Cmdlet | high | 61603 |
| `100693` | 9 | `T1059.001` T1059.001 | PowerShell Base64 Encoded Reflective Assembly Load | high | 61603 |
| `100694` | 9 | `T1059.001` T1059.001 | Suspicious Encoded And Obfuscated Reflection Assembly Load Function... | high | 61603 |
| `100695` | 9 | `T1059.001` T1059.001 | PowerShell Base64 Encoded WMI Classes | high | 61603 |
| `100696` | 8 | `T1216` T1216 | Potential Process Execution Proxy Via CL_Invocation.ps1 | medium | 61603 |
| `100697` | 8 | `T1216` T1216 | Assembly Loading Via CL_LoadAssembly.ps1 | medium | 61603 |
| `100698` | 8 | `T1216` T1216 | Potential Script Proxy Execution Via CL_Mutexverifiers.ps1 | medium | 61603 |
| `100699` | 8 | `T1027` Obfuscated Files or Information | ConvertTo-SecureString Cmdlet Usage Via CommandLine | medium | 61603 |
| `100700` | 9 | `T1027` Obfuscated Files or Information | Potential PowerShell Obfuscation Via Reversed Commands | high | 61603 |
| `100702` | 9 | `T1027.010` T1027.010 | Obfuscated PowerShell MSI Install via WindowsInstaller COM | high | 61603 |
| `100703` | 8 | `T1059.001` T1059.001 | PowerShell MSI Install via WindowsInstaller COM From Remote Location | medium | 61603 |
| `100704` | 9 | - | PowerShell Execution With Potential Decryption Capabilities | high | 61603 |
| `100705` | 9 | `T1685` T1685 | Powershell Defender Disable Scan Feature | high | 61603 |
| `100706` | 8 | `T1685` T1685 | Powershell Defender Exclusion | medium | 61603 |
| `100707` | 9 | `T1685` T1685 | Disable Windows Defender AV Security Monitoring | high | 61603 |
| `100708` | 8 | `T1685` T1685 | Windows Firewall Disabled via PowerShell | medium | 61603 |
| `100709` | 9 | `T1685` T1685 | Disabled IE Security Features | high | 61603 |
| `100710` | 9 | `T1685` T1685 | Disabled IE Security Features | high | 61603 |
| `100711` | 9 | `T1685` T1685 | Disabled IE Security Features | high | 61603 |
| `100712` | 8 | `T1059.001` T1059.001 | Potential PowerShell Downgrade Attack | medium | 61603 |
| `100713` | 9 | `T1059.001` T1059.001 | Obfuscated PowerShell OneLiner Execution | high | 61603 |
| `100714` | 9 | `T1059` Command and Scripting Interpreter | PowerShell Download and Execution Cradles | high | 61603 |
| `100715` | 8 | `T1059.001` T1059.001 | PowerShell Download Pattern | medium | 61603 |
| `100716` | 9 | - | Potentially Suspicious File Download From File Sharing Domain Via P... | high | 61603 |
| `100717` | 9 | `T1059.001` T1059.001 | DSInternals Suspicious PowerShell Cmdlets | high | 61603 |
| `100718` | 8 | - | Potential Suspicious Windows Feature Enabled - ProcCreation | medium | 61603 |
| `100719` | 8 | `T1059.001` T1059.001 | Suspicious Execution of Powershell with Base64 | medium | 61603 |
| `100720` | 8 | `T1059.001` T1059.001 | Powershell Inline Execution From A File | medium | 61603 |
| `100721` | 9 | `T1027` Obfuscated Files or Information | Base64 Encoded PowerShell Command Detected | high | 61603 |
| `100722` | 9 | `T1059.001` T1059.001 | Suspicious PowerShell IEX Execution Patterns | high | 61603 |
| `100723` | 9 | `T1553.004` T1553.004 | Root Certificate Installed From Susp Locations | high | 61603 |
| `100724` | 8 | `T1059.001` T1059.001 | Import PowerShell Modules From Suspicious Directories - ProcCreation | medium | 61603 |
| `100725` | 8 | - | Suspicious PowerShell Invocations - Specific - ProcessCreation | medium | 61603 |
| `100726` | 8 | - | Suspicious PowerShell Invocations - Specific - ProcessCreation | medium | 61603 |
| `100727` | 8 | - | Suspicious PowerShell Invocations - Specific - ProcessCreation | medium | 61603 |
| `100728` | 8 | - | Suspicious PowerShell Invocations - Specific - ProcessCreation | medium | 61603 |
| `100729` | 8 | - | Suspicious PowerShell Invocations - Specific - ProcessCreation | medium | 61603 |
| `100730` | 8 | - | Suspicious PowerShell Invocations - Specific - ProcessCreation | medium | 61603 |
| `100731` | 13 | `T1482` T1482 | Malicious PowerShell Commandlets - ProcessCreation | high | 61603 |
| `100732` | 9 | `T1059.001` T1059.001 | Potential PowerShell Obfuscation Via WCHAR/CHAR | high | 61603 |
| `100733` | 9 | `T1059.001` T1059.001 | Execution of Powershell Script in Public Folder | high | 61603 |
| `100734` | 9 | `T1218` T1218 | RemoteFXvGPUDisablement Abuse Via AtomicTestHarnesses | high | 61603 |
| `100735` | 9 | `T1685` T1685 | Tamper Windows Defender Remove-MpPreference | high | 61603 |
| `100736` | 9 | `T1059.001` T1059.001 | Potential Powershell ReverseShell Connection | high | 61603 |
| `100737` | 9 | `T1564.004` T1564.004 | Run PowerShell Script from ADS | high | 61603 |
| `100738` | 9 | `T1059` Command and Scripting Interpreter | Run PowerShell Script from Redirected Input Stream | high | 61603 |
| `100739` | 8 | `T1059.001` T1059.001 | Suspicious PowerShell Invocation From Script Engines | medium | 61603 |
| `100740` | 8 | `T1059.001` T1059.001 | Potentially Suspicious Powershell Script Execution From Temp Folder | medium | 61603 |
| `100741` | 9 | - | PowerShell Script Change Permission Via Set-Acl | high | 61603 |
| `100742` | 9 | - | PowerShell Set-Acl On Windows Folder | high | 61603 |
| `100743` | 8 | `T1059.001` T1059.001 | Change PowerShell Policies to an Insecure Level | medium | 61603 |
| `100744` | 8 | `T1685` T1685 | Service StartupType Change Via PowerShell Set-Service | medium | 61603 |
| `100745` | 9 | `T1059.001` T1059.001 | Exchange PowerShell Snap-Ins Usage | high | 61603 |
| `100746` | 9 | `T1059.001` T1059.001 | Suspicious PowerShell Download and Execute Pattern | high | 61603 |
| `100747` | 9 | `T1059.001` T1059.001 | Suspicious PowerShell Parameter Substring | high | 61603 |
| `100748` | 9 | `T1059.001` T1059.001 | Suspicious PowerShell Parent Process | high | 61603 |
| `100749` | 8 | `T1059.001` T1059.001 | PowerShell Script Run in AppData | medium | 61603 |
| `100751` | 9 | `T1685` T1685 | Suspicious Uninstall of Windows Defender Feature via PowerShell | high | 61603 |
| `100752` | 9 | `T1059.001` T1059.001 | Net WebClient Casing Anomalies | high | 61603 |
| `100753` | 8 | `T1553.004` T1553.004 | Suspicious X509Enrollment - Process Creation | medium | 61603 |
| `100754` | 8 | `T1059.001` T1059.001 | Suspicious XOR Encoded PowerShell Command | medium | 61603 |
| `100755` | 8 | `T1218` T1218 | Arbitrary File Download Via PresentationHost.EXE | medium | 61603 |
| `100756` | 8 | `T1218` T1218 | XBAP Execution From Uncommon Locations Via PresentationHost.EXE | medium | 61603 |
| `100757` | 8 | `T1218` T1218 | Visual Studio NodejsTools PressAnyKey Arbitrary Binary Execution | medium | 61603 |
| `100758` | 8 | `T1218` T1218 | Abusing Print Executable | medium | 61603 |
| `100759` | 8 | `T1218` T1218 | File Download Using ProtocolHandler.exe | medium | 61603 |
| `100760` | 8 | `T1218` T1218 | Potential Provlaunch.EXE Binary Proxy Execution Abuse | medium | 61603 |
| `100761` | 9 | `T1218` T1218 | Suspicious Provlaunch.EXE Child Process | high | 61603 |
| `100762` | 8 | `T1564.003` T1564.003 | PUA - AdvancedRun Execution | medium | 61603 |
| `100763` | 8 | `T1564.003` T1564.003 | PUA - AdvancedRun Execution | medium | 61603 |
| `100764` | 8 | `T1564.003` T1564.003 | PUA - AdvancedRun Execution | medium | 61603 |
| `100765` | 9 | `T1685` T1685 | PUA - CleanWipe Execution | high | 61603 |
| `100766` | 9 | `T1685` T1685 | PUA - CleanWipe Execution | high | 61603 |
| `100767` | 9 | `T1685` T1685 | PUA - CleanWipe Execution | high | 61603 |
| `100768` | 9 | `T1685` T1685 | PUA - CleanWipe Execution | high | 61603 |
| `100769` | 9 | `T1587.001` T1587.001 | PUA - CsExec Execution | high | 61603 |
| `100770` | 9 | `T1587.001` T1587.001 | PUA - CsExec Execution | high | 61603 |
| `100771` | 9 | `T1027.005` T1027.005 | PUA - DefenderCheck Execution | high | 61603 |
| `100772` | 9 | `T1027.005` T1027.005 | PUA - DefenderCheck Execution | high | 61603 |
| `100773` | 8 | `T1569.002` T1569.002 | PUA - NirCmd Execution | medium | 61603 |
| `100774` | 8 | `T1569.002` T1569.002 | PUA - NirCmd Execution | medium | 61603 |
| `100775` | 8 | `T1569.002` T1569.002 | PUA - NirCmd Execution | medium | 61603 |
| `100776` | 9 | `T1569.002` T1569.002 | PUA - NirCmd Execution As LOCAL SYSTEM | high | 61603 |
| `100777` | 9 | `T1569.002` T1569.002 | PUA - NSudo Execution | high | 61603 |
| `100778` | 8 | `T1595` T1595 | PUA - PingCastle Execution | medium | 61603 |
| `100779` | 8 | `T1595` T1595 | PUA - PingCastle Execution | medium | 61603 |
| `100780` | 8 | `T1595` T1595 | PUA - PingCastle Execution | medium | 61603 |
| `100781` | 8 | `T1595` T1595 | PUA - PingCastle Execution | medium | 61603 |
| `100782` | 8 | `T1595` T1595 | PUA - PingCastle Execution | medium | 61603 |
| `100783` | 8 | `T1595` T1595 | PUA - PingCastle Execution | medium | 61603 |
| `100784` | 8 | `T1595` T1595 | PUA - PingCastle Execution | medium | 61603 |
| `100785` | 8 | `T1595` T1595 | PUA - PingCastle Execution | medium | 61603 |
| `100786` | 9 | `T1595` T1595 | PUA - PingCastle Execution From Potentially Suspicious Parent | high | 61603 |
| `100787` | 9 | `T1595` T1595 | PUA - PingCastle Execution From Potentially Suspicious Parent | high | 61603 |
| `100788` | 9 | `T1595` T1595 | PUA - PingCastle Execution From Potentially Suspicious Parent | high | 61603 |
| `100789` | 9 | `T1595` T1595 | PUA - PingCastle Execution From Potentially Suspicious Parent | high | 61603 |
| `100790` | 9 | `T1595` T1595 | PUA - PingCastle Execution From Potentially Suspicious Parent | high | 61603 |
| `100791` | 8 | `T1072` T1072 | PUA - Radmin Viewer Utility Execution | medium | 61603 |
| `100792` | 8 | `T1072` T1072 | PUA - Radmin Viewer Utility Execution | medium | 61603 |
| `100793` | 8 | `T1072` T1072 | PUA - Radmin Viewer Utility Execution | medium | 61603 |
| `100794` | 8 | `T1036.003` T1036.003 | PUA - Potential PE Metadata Tamper Using Rcedit | medium | 61603 |
| `100795` | 9 | `T1569.002` T1569.002 | PUA - RunXCmd Execution | high | 61603 |
| `100796` | 9 | `T1059` Command and Scripting Interpreter | PUA - Wsudo Suspicious Execution | high | 61603 |
| `100797` | 9 | `T1059` Command and Scripting Interpreter | PUA - Wsudo Suspicious Execution | high | 61603 |
| `100798` | 9 | `T1059` Command and Scripting Interpreter | PUA - Wsudo Suspicious Execution | high | 61603 |
| `100799` | 9 | `T1059` Command and Scripting Interpreter | PUA - Wsudo Suspicious Execution | high | 61603 |
| `100800` | 9 | `T1059` Command and Scripting Interpreter | PUA - Wsudo Suspicious Execution | high | 61603 |
| `100801` | 9 | `T1059.006` T1059.006 | Python One-Liners with Base64 Decoding | high | 61603 |
| `100802` | 8 | `T1059` Command and Scripting Interpreter | Python Inline Command Execution | medium | 61603 |
| `100803` | 9 | `T1059` Command and Scripting Interpreter | Python Spawning Pretty TTY on Windows | high | 61603 |
| `100804` | 8 | - | Query Usage To Exfil Data | medium | 61603 |
| `100805` | 9 | `T1059` Command and Scripting Interpreter | Suspicious Greedy Compression Using Rar.EXE | high | 61603 |
| `100806` | 9 | `T1059` Command and Scripting Interpreter | Suspicious Greedy Compression Using Rar.EXE | high | 61603 |
| `100807` | 9 | `T1059` Command and Scripting Interpreter | Suspicious Greedy Compression Using Rar.EXE | high | 61603 |
| `100808` | 8 | `T1059` Command and Scripting Interpreter | Suspicious RASdial Activity | medium | 61603 |
| `100809` | 9 | `T1685` T1685 | Add SafeBoot Keys Via Reg Utility | high | 61603 |
| `100810` | 8 | `T1685` T1685 | Suspicious Windows Defender Folder Exclusion Added Via Reg.EXE | medium | 61603 |
| `100811` | 9 | `T1070.003` T1070.003 | RunMRU Registry Key Deletion | high | 61603 |
| `100812` | 9 | `T1685` T1685 | SafeBoot Registry Key Deleted Via Reg.EXE | high | 61603 |
| `100813` | 9 | `T1685` T1685 | Service Registry Key Deleted Via Reg.EXE | high | 61603 |
| `100814` | 9 | `T1685` T1685 | Disabling Windows Defender WMI Autologger Session via Reg.exe | high | 61603 |
| `100815` | 9 | `T1685` T1685 | Security Service Disabled Via Reg.EXE | high | 61603 |
| `100816` | 9 | `T1685` T1685 | Disabled Volume Snapshots | high | 61603 |
| `100817` | 9 | `T1685` T1685 | Suspicious Windows Defender Registry Key Tampering Via Reg.EXE | high | 61603 |
| `100818` | 8 | `T1685` T1685 | Write Protect For Storage Disabled | medium | 61603 |
| `100819` | 8 | `T1218.009` T1218.009 | Potentially Suspicious Execution Of Regasm/Regsvcs With Uncommon Ex... | medium | 61603 |
| `100820` | 8 | `T1218.009` T1218.009 | Potentially Suspicious Execution Of Regasm/Regsvcs From Uncommon Lo... | medium | 61603 |
| `100821` | 9 | - | IE ZoneMap Setting Downgraded To MyComputer Zone For HTTP Protocols... | high | 61603 |
| `100822` | 9 | `T1685` T1685 | Python Function Execution Security Warning Disabled In Excel | high | 61603 |
| `100823` | 9 | `T1218` T1218 | Potential Provisioning Registry Key Abuse For Binary Proxy Execution | high | 61603 |
| `100824` | 9 | - | Potential PowerShell Execution Policy Tampering - ProcCreation | high | 61603 |
| `100825` | 8 | `T1564.002` T1564.002 | Hiding User Account Via SpecialAccounts Registry Key - CommandLine | medium | 61603 |
| `100826` | 8 | `T1218.010` T1218.010 | Potential Regsvr32 Commandline Flag Anomaly | medium | 61603 |
| `100827` | 9 | `T1218.010` T1218.010 | Potentially Suspicious Regsvr32 HTTP IP Pattern | high | 61603 |
| `100828` | 8 | `T1218.010` T1218.010 | Potentially Suspicious Regsvr32 HTTP/FTP Pattern | medium | 61603 |
| `100829` | 9 | `T1218.010` T1218.010 | Suspicious Regsvr32 Execution From Remote Share | high | 61603 |
| `100830` | 9 | `T1218.010` T1218.010 | Potentially Suspicious Child Process Of Regsvr32 | high | 61603 |
| `100831` | 8 | `T1218.010` T1218.010 | Regsvr32 Execution From Potential Suspicious Location | medium | 61603 |
| `100832` | 9 | `T1218.010` T1218.010 | Regsvr32 Execution From Highly Suspicious Location | high | 61603 |
| `100833` | 9 | `T1218.010` T1218.010 | Regsvr32 DLL Execution With Suspicious File Extension | high | 61603 |
| `100834` | 8 | `T1218.010` T1218.010 | Scripting/CommandLine Process Spawned Regsvr32 | medium | 61603 |
| `100835` | 8 | - | Remote Access Tool - AnyDesk Execution With Known Revoked Signing C... | medium | 61603 |
| `100836` | 8 | - | Remote Access Tool - NetSupport Execution From Unusual Location | medium | 61603 |
| `100837` | 8 | - | Remote Access Tool - RURAT Execution From Unusual Location | medium | 61603 |
| `100838` | 8 | - | Renamed AutoHotkey.EXE Execution | medium | 61603 |
| `100839` | 9 | `T1027` Obfuscated Files or Information | Renamed AutoIt Execution | high | 61603 |
| `100840` | 9 | `T1027` Obfuscated Files or Information | Renamed AutoIt Execution | high | 61603 |
| `100841` | 9 | `T1027` Obfuscated Files or Information | Renamed AutoIt Execution | high | 61603 |
| `100842` | 8 | `T1036.003` T1036.003 | Potential Defense Evasion Via Binary Rename | medium | 61603 |
| `100843` | 9 | `T1036.003` T1036.003 | Potential Defense Evasion Via Rename Of Highly Relevant Binaries | high | 61603 |
| `100844` | 8 | `T1553` T1553 | Renamed BOINC Client Execution | medium | 61603 |
| `100845` | 8 | `T1059` Command and Scripting Interpreter | Renamed CURL.EXE Execution | medium | 61603 |
| `100846` | 8 | `T1059` Command and Scripting Interpreter | Renamed FTP.EXE Execution | medium | 61603 |
| `100847` | 9 | `T1036.003` T1036.003 | Renamed Jusched.EXE Execution | high | 61603 |
| `100848` | 9 | `T1218` T1218 | Renamed MegaSync Execution | high | 61603 |
| `100849` | 9 | `T1036.003` T1036.003 | Renamed Msdt.EXE Execution | high | 61603 |
| `100850` | 8 | - | Renamed Microsoft Teams Execution | medium | 61603 |
| `100851` | 9 | - | Renamed NetSupport RAT Execution | high | 61603 |
| `100852` | 9 | `T1059` Command and Scripting Interpreter | Renamed NirCmd.EXE Execution | high | 61603 |
| `100853` | 9 | `T1036.003` T1036.003 | Renamed Office Binary Execution | high | 61603 |
| `100854` | 9 | `T1202` T1202 | Renamed PAExec Execution | high | 61603 |
| `100855` | 9 | `T1059` Command and Scripting Interpreter | Renamed PingCastle Binary Execution | high | 61603 |
| `100856` | 9 | `T1036` T1036 | Renamed Plink Execution | high | 61603 |
| `100857` | 8 | `T1218` T1218 | Visual Studio NodejsTools PressAnyKey Renamed Execution | medium | 61603 |
| `100858` | 9 | - | Potential Renamed Rundll32 Execution | high | 61603 |
| `100859` | 9 | `T1036.003` T1036.003 | Renamed Schtasks Execution | high | 61603 |
| `100860` | 9 | `T1588.002` T1588.002 | Renamed SysInternals DebugView Execution | high | 61603 |
| `100861` | 9 | `T1036.003` T1036.003 | Renamed ProcDump Execution | high | 61603 |
| `100862` | 9 | - | Renamed PsExec Service Execution | high | 61603 |
| `100863` | 8 | `T1059` Command and Scripting Interpreter | Ruby Inline Command Execution | medium | 61603 |
| `100865` | 9 | - | Suspicious Advpack Call Via Rundll32.EXE | high | 61603 |
| `100866` | 8 | `T1218.011` T1218.011 | Rundll32 InstallScreenSaver Execution | medium | 61603 |
| `100867` | 9 | - | Mshtml.DLL RunHTMLApplication Suspicious Usage | high | 61603 |
| `100868` | 9 | `T1202` T1202 | Rundll32 Execution Without CommandLine Parameters | high | 61603 |
| `100869` | 8 | `T1027.010` T1027.010 | Potential Obfuscated Ordinal Call Via Rundll32 | medium | 61603 |
| `100870` | 8 | - | Rundll32 Spawned Via Explorer.EXE | medium | 61603 |
| `100871` | 8 | `T1036` T1036 | Suspicious Process Start Locations | medium | 61603 |
| `100872` | 8 | `T1036` T1036 | Suspicious Process Start Locations | medium | 61603 |
| `100873` | 8 | `T1218.011` T1218.011 | Suspicious Rundll32 Setupapi.dll Activity | medium | 61603 |
| `100874` | 9 | `T1218.011` T1218.011 | Shell32 DLL Execution in Suspicious Directory | high | 61603 |
| `100875` | 8 | - | Potential ShellDispatch.DLL Functionality Abuse | medium | 61603 |
| `100876` | 9 | `T1218.011` T1218.011 | RunDLL32 Spawning Explorer | high | 61603 |
| `100877` | 8 | `T1218.011` T1218.011 | Potentially Suspicious Rundll32 Activity | medium | 61603 |
| `100878` | 9 | `T1218.011` T1218.011 | Suspicious Control Panel DLL Load | high | 61603 |
| `100879` | 9 | `T1218.011` T1218.011 | Suspicious Rundll32 Execution With Image Extension | high | 61603 |
| `100880` | 9 | - | Suspicious Usage Of ShellExec_RunDLL | high | 61603 |
| `100881` | 9 | `T1218.011` T1218.011 | Suspicious ShellExec_RunDLL Call Via Ordinal | high | 61603 |
| `100882` | 9 | `T1218.011` T1218.011 | Suspicious Rundll32 Activity Invoking Sys File | high | 61603 |
| `100883` | 8 | `T1218.011` T1218.011 | Potentially Suspicious Rundll32.EXE Execution of UDL File | medium | 61603 |
| `100884` | 9 | `T1021.002` T1021.002 | Rundll32 UNC Path Execution | high | 61603 |
| `100885` | 8 | `T1218.011` T1218.011 | Rundll32 Execution With Uncommon DLL Extension | medium | 61603 |
| `100886` | 8 | - | Suspicious Workstation Locking via Rundll32 | medium | 61603 |
| `100887` | 8 | `T1685` T1685 | Service StartupType Change Via Sc.EXE | medium | 61603 |
| `100888` | 9 | `T1053.005` T1053.005 | Uncommon One Time Only Scheduled Task At 00:00 | high | 61603 |
| `100889` | 9 | `T1047` T1047 | Script Event Consumer Spawning Process | high | 61603 |
| `100890` | 9 | `T1036` T1036 | Sdiagnhost Calling Suspicious Child Process | high | 61603 |
| `100891` | 9 | `T1218` T1218 | Uncommon Child Process Of Setres.EXE | high | 61603 |
| `100892` | 8 | `T1202` T1202 | Indirect Command Execution via SFTP ProxyCommand | medium | 61603 |
| `100893` | 8 | `T1216` T1216 | Uncommon Sigverif.EXE Child Process | medium | 61603 |
| `100894` | 8 | - | Uncommon Child Processes Of SndVol.exe | medium | 61603 |
| `100895` | 9 | `T1202` T1202 | Suspicious Splwow64 Without Params | high | 61603 |
| `100896` | 9 | `T1203` T1203 | Suspicious Spool Service Child Process | high | 61603 |
| `100897` | 8 | `T1218` T1218 | Arbitrary File Download Via Squirrel.EXE | medium | 61603 |
| `100898` | 8 | `T1218` T1218 | Process Proxy Execution Via Squirrel.EXE | medium | 61603 |
| `100899` | 8 | `T1218` T1218 | Program Executed Using Proxy/Local Command Via SSH.EXE | medium | 61603 |
| `100900` | 9 | `T1218` T1218 | Execution via stordiag.exe | high | 61603 |
| `100901` | 8 | - | Start of NT Virtual DOS Machine | medium | 61603 |
| `100902` | 8 | `T1564.004` T1564.004 | Execute From Alternate Data Streams | medium | 61603 |
| `100903` | 8 | - | Potentially Suspicious Windows App Activity | medium | 61603 |
| `100904` | 8 | `T1204` User Execution | Arbitrary Shell Command Execution Via Settingcontent-Ms | medium | 61603 |
| `100905` | 9 | `T1218.011` T1218.011 | Bad Opsec Defaults Sacrificial Processes With Improper Arguments | high | 61603 |
| `100906` | 9 | `T1218.011` T1218.011 | Bad Opsec Defaults Sacrificial Processes With Improper Arguments | high | 61603 |
| `100907` | 9 | `T1218.011` T1218.011 | Bad Opsec Defaults Sacrificial Processes With Improper Arguments | high | 61603 |
| `100908` | 9 | `T1218.011` T1218.011 | Bad Opsec Defaults Sacrificial Processes With Improper Arguments | high | 61603 |
| `100909` | 9 | `T1218.011` T1218.011 | Bad Opsec Defaults Sacrificial Processes With Improper Arguments | high | 61603 |
| `100910` | 8 | `T1204.002` T1204.002 | Potential Suspicious Browser Launch From Document Reader Process | medium | 61603 |
| `100911` | 8 | `T1140` T1140 | Potential Commandline Obfuscation Using Escape Characters | medium | 61603 |
| `100912` | 9 | `T1027` Obfuscated Files or Information | Potential CommandLine Obfuscation Using Unicode Characters From Sus... | high | 61603 |
| `100913` | 9 | `T1204.001` T1204.001 | Suspicious ClickFix/FileFix Execution Pattern | high | 61603 |
| `100914` | 9 | `T1204.004` T1204.004 | Suspicious Explorer Process with Whitespace Padding - ClickFix/FileFix | high | 61603 |
| `100915` | 8 | `T1059.003` T1059.003 | Suspicious Usage of For Loop with Recursive Directory Search in CMD | medium | 61603 |
| `100916` | 8 | `T1059.003` T1059.003 | Suspicious Usage of For Loop with Recursive Directory Search in CMD | medium | 61603 |
| `100917` | 8 | `T1036` T1036 | Potential Command Line Path Traversal Evasion Attempt | medium | 61603 |
| `100918` | 8 | `T1036` T1036 | Potential Command Line Path Traversal Evasion Attempt | medium | 61603 |
| `100919` | 8 | `T1036.003` T1036.003 | Suspicious Copy From or To System Directory | medium | 61603 |
| `100920` | 8 | `T1036.003` T1036.003 | Suspicious Copy From or To System Directory | medium | 61603 |
| `100921` | 8 | `T1036.003` T1036.003 | Suspicious Copy From or To System Directory | medium | 61603 |
| `100922` | 8 | `T1036.003` T1036.003 | Suspicious Copy From or To System Directory | medium | 61603 |
| `100923` | 9 | `T1036.003` T1036.003 | LOL-Binary Copied From System Directory | high | 61603 |
| `100924` | 9 | `T1036.003` T1036.003 | LOL-Binary Copied From System Directory | high | 61603 |
| `100925` | 9 | `T1036.003` T1036.003 | LOL-Binary Copied From System Directory | high | 61603 |
| `100926` | 9 | `T1036.003` T1036.003 | LOL-Binary Copied From System Directory | high | 61603 |
| `100927` | 9 | `T1059.001` T1059.001 | Potential Data Exfiltration Activity Via CommandLine Tools | high | 61603 |
| `100928` | 9 | `T1685` T1685 | Raccine Uninstall | high | 61603 |
| `100929` | 9 | `T1685` T1685 | Raccine Uninstall | high | 61603 |
| `100930` | 9 | `T1685` T1685 | Raccine Uninstall | high | 61603 |
| `100931` | 9 | `T1036.007` T1036.007 | Suspicious Parent Double Extension File Execution | high | 61603 |
| `100932` | 9 | `T1036.007` T1036.007 | Suspicious Parent Double Extension File Execution | high | 61603 |
| `100933` | 9 | - | DumpStack.log Defender Evasion | high | 61603 |
| `100934` | 9 | - | DumpStack.log Defender Evasion | high | 61603 |
| `100935` | 8 | - | Suspicious Electron Application Child Processes | medium | 61603 |
| `100936` | 8 | - | Potentially Suspicious Electron Application CommandLine | medium | 61603 |
| `100937` | 8 | `T1059.001` T1059.001 | Hidden Powershell in Link File Pattern | medium | 61603 |
| `100938` | 9 | - | Potential Defense Evasion Activity Via Emoji Usage In CommandLine - 1 | high | 61603 |
| `100939` | 9 | - | Potential Defense Evasion Activity Via Emoji Usage In CommandLine - 2 | high | 61603 |
| `100940` | 9 | - | Potential Defense Evasion Activity Via Emoji Usage In CommandLine - 3 | high | 61603 |
| `100941` | 9 | - | Potential Defense Evasion Activity Via Emoji Usage In CommandLine - 4 | high | 61603 |
| `100942` | 9 | `T1685` T1685 | ETW Logging Tamper In .NET Processes Via CommandLine | high | 61603 |
| `100943` | 9 | `T1070` Indicator Removal | ETW Trace Evasion Activity | high | 61603 |
| `100944` | 9 | `T1070` Indicator Removal | ETW Trace Evasion Activity | high | 61603 |
| `100945` | 9 | `T1070` Indicator Removal | ETW Trace Evasion Activity | high | 61603 |
| `100946` | 9 | `T1070` Indicator Removal | ETW Trace Evasion Activity | high | 61603 |
| `100947` | 9 | `T1070` Indicator Removal | ETW Trace Evasion Activity | high | 61603 |
| `100948` | 9 | `T1070` Indicator Removal | ETW Trace Evasion Activity | high | 61603 |
| `100949` | 9 | `T1070` Indicator Removal | ETW Trace Evasion Activity | high | 61603 |
| `100950` | 9 | `T1685.005` T1685.005 | Suspicious Eventlog Clearing or Configuration Change Activity | high | 61603 |
| `100951` | 9 | `T1564` T1564 | Potentially Suspicious Execution From Parent Process In Public Folder | high | 61603 |
| `100952` | 9 | `T1036` T1036 | Process Execution From A Potentially Suspicious Folder | high | 61603 |
| `100953` | 8 | `T1059.006` T1059.006 | Suspicious File Characteristics Due to Missing Fields | medium | 61603 |
| `100954` | 9 | `T1204.004` T1204.004 | Suspicious FileFix Execution Pattern | high | 61603 |
| `100955` | 8 | `T1564.004` T1564.004 | Potential Hidden Directory Creation Via NTFS INDEX_ALLOCATION Strea... | medium | 61603 |
| `100956` | 8 | `T1036` T1036 | Potential Homoglyph Attack Using Lookalike Characters | medium | 61603 |
| `100957` | 8 | `T1036` T1036 | Potential Homoglyph Attack Using Lookalike Characters | medium | 61603 |
| `100958` | 9 | - | Execution Of Non-Existing File | high | 61603 |
| `100959` | 9 | - | Base64 MZ Header In CommandLine | high | 61603 |
| `100960` | 8 | `T1059.007` T1059.007 | Potentially Suspicious Inline JavaScript Execution via NodeJS Binary | medium | 61603 |
| `100961` | 9 | `T1106` T1106 | Potential WinAPI Calls Via CommandLine | high | 61603 |
| `100962` | 8 | - | LOLBIN Execution From Abnormal Drive | medium | 61603 |
| `100963` | 8 | `T1218` T1218 | Potential File Download Via MS-AppInstaller Protocol Handler | medium | 61603 |
| `100964` | 8 | `T1059` Command and Scripting Interpreter | Suspicious Scan Loop Network | medium | 61603 |
| `100965` | 8 | - | Process Launched Without Image Name | medium | 61603 |
| `100966` | 8 | - | Execution of Suspicious File Type Extension | medium | 61603 |
| `100967` | 9 | - | Potentially Suspicious Call To Win32_NTEventlogFile Class | high | 61603 |
| `100968` | 8 | `T1564.004` T1564.004 | Use Short Name Path in Image | medium | 61603 |
| `100969` | 8 | `T1564.004` T1564.004 | Use NTFS Short Name in Command Line | medium | 61603 |
| `100970` | 8 | `T1564.004` T1564.004 | Use NTFS Short Name in Image | medium | 61603 |
| `100971` | 9 | `T1036` T1036 | Suspicious Process Parents | high | 61603 |
| `100972` | 9 | `T1218.011` T1218.011 | Potential PowerShell Execution Via DLL | high | 61603 |
| `100973` | 13 | `T1059` Command and Scripting Interpreter | Suspicious Program Names | high | 61603 |
| `100974` | 9 | `T1059` Command and Scripting Interpreter | Suspicious Program Names | high | 61603 |
| `100975` | 14 | `T1059` Command and Scripting Interpreter | Suspicious Program Names | high | 61603 |
| `100976` | 9 | `T1036.002` T1036.002 | Potential Defense Evasion Via Right-to-Left Override | high | 61603 |
| `100977` | 9 | `T1059` Command and Scripting Interpreter | Script Interpreter Execution From Suspicious Folder | high | 61603 |
| `100978` | 9 | `T1059` Command and Scripting Interpreter | Script Interpreter Execution From Suspicious Folder | high | 61603 |
| `100979` | 9 | `T1059` Command and Scripting Interpreter | Script Interpreter Execution From Suspicious Folder | high | 61603 |
| `100980` | 9 | `T1202` T1202 | Suspicious Service Binary Directory | high | 61603 |
| `100981` | 9 | `T1059.005` T1059.005 | Windows Shell/Scripting Processes Spawning Suspicious Programs | high | 61603 |
| `100982` | 12 | `T1036` T1036 | System File Execution Location Anomaly | high | 61603 |
| `100983` | 8 | `T1218` T1218 | Malicious PE Execution by Microsoft Visual Studio Debugger | medium | 61603 |
| `100984` | 8 | - | Weak or Abused Passwords In CLI | medium | 61603 |
| `100985` | 8 | `T1059.001` T1059.001 | Usage Of Web Request Commands And Cmdlets | medium | 61603 |
| `100986` | 9 | `T1218` T1218 | Execution via WorkFolders.exe | high | 61603 |
| `100987` | 9 | `T1036.005` T1036.005 | Suspicious Process Masquerading As SvcHost.EXE | high | 61603 |
| `100988` | 8 | `T1036.005` T1036.005 | Uncommon Svchost Parent Process | medium | 61603 |
| `100989` | 8 | - | Potential Memory Dumping Activity Via LiveKD | medium | 61603 |
| `100990` | 8 | - | Potential Memory Dumping Activity Via LiveKD | medium | 61603 |
| `100991` | 9 | - | Kernel Memory Dump Via LiveKD | high | 61603 |
| `100992` | 8 | `T1569` System Services | Psexec Execution | medium | 61603 |
| `100993` | 8 | `T1569` System Services | Psexec Execution | medium | 61603 |
| `100994` | 9 | `T1587.001` T1587.001 | PsExec/PAExec Escalation to LOCAL SYSTEM | high | 61603 |
| `100995` | 9 | `T1587.001` T1587.001 | Potential PsExec Remote Execution | high | 61603 |
| `100996` | 8 | - | PsExec Service Execution | medium | 61603 |
| `100997` | 8 | - | PsExec Service Execution | medium | 61603 |
| `100998` | 9 | - | PsExec Service Child Process Execution as LOCAL SYSTEM | high | 61603 |
| `100999` | 9 | `T1685` T1685 | Sysinternals PsSuspend Suspicious Execution | high | 61603 |
| `101000` | 9 | `T1587.001` T1587.001 | Potential Privilege Escalation To LOCAL SYSTEM | high | 61603 |
| `101003` | 8 | `T1218` T1218 | Potential Binary Impersonating Sysinternals Tools | medium | 61603 |
| `101004` | 8 | `T1218` T1218 | Potential Binary Impersonating Sysinternals Tools | medium | 61603 |
| `101005` | 8 | `T1059` Command and Scripting Interpreter | Sysprep on AppData Folder | medium | 61603 |
| `101006` | 9 | - | Potential Signing Bypass Via Windows Developer Features | high | 61603 |
| `101007` | 8 | `T1222.001` T1222.001 | Suspicious Recursive Takeown | medium | 61603 |
| `101008` | 9 | `T1685` T1685 | Taskkill Symantec Endpoint Protection | high | 61603 |
| `101009` | 9 | `T1036` T1036 | Taskmgr as LOCAL_SYSTEM | high | 61603 |
| `101010` | 8 | - | New Virtual Smart Card Created Via TpmVscMgr.EXE | medium | 61603 |
| `101011` | 8 | - | Potential RDP Session Hijacking Activity | medium | 61603 |
| `101012` | 9 | `T1548.002` T1548.002 | CMSTP UAC Bypass via COM Object Access | high | 61603 |
| `101013` | 9 | `T1548.002` T1548.002 | UAC Bypass Using IDiagnostic Profile | high | 61603 |
| `101014` | 9 | `T1685` T1685 | Uninstall Crowdstrike Falcon Sensor | high | 61603 |
| `101015` | 8 | `T1218` T1218 | Verclsid.exe Runs COM Object | medium | 61603 |
| `101016` | 8 | `T1059` Command and Scripting Interpreter | Potential Persistence Via VMwareToolBoxCmd.EXE VM State Change Script | medium | 61603 |
| `101017` | 9 | `T1059` Command and Scripting Interpreter | Suspicious Persistence Via VMwareToolBoxCmd.EXE VM State Change Script | high | 61603 |
| `101018` | 9 | `T1059` Command and Scripting Interpreter | VMToolsd Suspicious Child Process | high | 61603 |
| `101019` | 8 | `T1218` T1218 | Potentially Suspicious Child Process Of VsCode | medium | 61603 |
| `101020` | 8 | `T1218` T1218 | Potential Binary Proxy Execution Via VSDiagnostics.EXE | medium | 61603 |
| `101021` | 8 | `T1202` T1202 | Proxy Execution via Vshadow | medium | 61603 |
| `101022` | 8 | `T1218` T1218 | Suspicious Vsls-Agent Command With AgentExtensionPath Load | medium | 61603 |
| `101023` | 9 | `T1685` T1685 | Vulnerable Driver Blocklist Registry Tampering Via CommandLine | high | 61603 |
| `101024` | 9 | - | Wab Execution From Non Default Location | high | 61603 |
| `101025` | 9 | - | Wab/Wabmig Unusual Parent Or Child Processes | high | 61603 |
| `101026` | 9 | - | Wab/Wabmig Unusual Parent Or Child Processes | high | 61603 |
| `101027` | 8 | `T1059.001` T1059.001 | Potentially Suspicious WebDAV LNK Execution | medium | 61603 |
| `101028` | 8 | `T1036` T1036 | Potential ReflectDebugger Content Execution Via WerFault.EXE | medium | 61603 |
| `101029` | 9 | - | Suspicious Execution Location Of Wermgr.EXE | high | 61603 |
| `101031` | 9 | - | Suspicious File Download From File Sharing Domain Via Wget.EXE | high | 61603 |
| `101032` | 9 | - | Suspicious File Download From IP Via Wget.EXE - Paths | high | 61603 |
| `101033` | 8 | - | Suspicious WindowsTerminal Child Processes | medium | 61603 |
| `101034` | 8 | `T1059` Command and Scripting Interpreter | Add New Download Source To Winget | medium | 61603 |
| `101035` | 9 | `T1059` Command and Scripting Interpreter | Add Insecure Download Source To Winget | high | 61603 |
| `101037` | 8 | `T1059` Command and Scripting Interpreter | Install New Package Via Winget Local Manifest | medium | 61603 |
| `101038` | 8 | `T1203` T1203 | Potentially Suspicious Child Process Of WinRAR.EXE | medium | 61603 |
| `101039` | 8 | `T1216` T1216 | AWL Bypass with Winrm.vbs and Malicious WsmPty.xsl/WsmTxt.xsl | medium | 61603 |
| `101040` | 8 | `T1216` T1216 | Remote Code Execute via Winrm.vbs | medium | 61603 |
| `101041` | 8 | `T1059.001` T1059.001 | Remote PowerShell Session Host Process (WinRM) | medium | 61603 |
| `101042` | 8 | `T1059.001` T1059.001 | Remote PowerShell Session Host Process (WinRM) | medium | 61603 |
| `101044` | 9 | `T1047` T1047 | Potential Windows Defender Tampering Via Wmic.EXE | high | 61603 |
| `101045` | 8 | `T1047` T1047 | New Process Created Via Wmic.EXE | medium | 61603 |
| `101046` | 8 | `T1047` T1047 | Hardware Model Reconnaissance Via Wmic.EXE | medium | 61603 |
| `101047` | 8 | `T1047` T1047 | Windows Hotfix Updates Reconnaissance Via Wmic.EXE | medium | 61603 |
| `101048` | 8 | `T1047` T1047 | Process Reconnaissance Via Wmic.EXE | medium | 61603 |
| `101049` | 8 | `T1047` T1047 | Potential Product Reconnaissance Via Wmic.EXE | medium | 61603 |
| `101050` | 8 | `T1047` T1047 | Potential Product Class Reconnaissance Via Wmic.EXE | medium | 61603 |
| `101051` | 8 | `T1047` T1047 | Service Reconnaissance Via Wmic.EXE | medium | 61603 |
| `101052` | 8 | `T1047` T1047 | Potential Unquoted Service Path Reconnaissance Via Wmic.EXE | medium | 61603 |
| `101053` | 8 | `T1047` T1047 | System Disk And Volume Reconnaissance Via Wmic.EXE | medium | 61603 |
| `101054` | 8 | `T1047` T1047 | WMIC Remote Command Execution | medium | 61603 |
| `101055` | 8 | `T1047` T1047 | Service Started/Stopped Via Wmic.EXE | medium | 61603 |
| `101056` | 8 | `T1047` T1047 | Service Startup Type Change Via Wmic.EXE | medium | 61603 |
| `101057` | 9 | `T1047` T1047 | Potential Remote SquiblyTwo Technique Execution | high | 61603 |
| `101058` | 9 | `T1204.002` T1204.002 | Suspicious WMIC Execution Via Office Process | high | 61603 |
| `101059` | 9 | `T1047` T1047 | Suspicious Process Created Via Wmic.EXE | high | 61603 |
| `101060` | 8 | `T1047` T1047 | Application Terminated Via Wmic.EXE | medium | 61603 |
| `101061` | 8 | `T1047` T1047 | Application Removed Via Wmic.EXE | medium | 61603 |
| `101062` | 9 | `T1685` T1685 | Potential Tampering With Security Products Via WMIC | high | 61603 |
| `101063` | 9 | `T1685` T1685 | Potential Tampering With Security Products Via WMIC | high | 61603 |
| `101064` | 9 | `T1685` T1685 | Potential Tampering With Security Products Via WMIC | high | 61603 |
| `101066` | 8 | `T1047` T1047 | WmiPrvSE Spawned A Process | medium | 61603 |
| `101067` | 8 | `T1047` T1047 | Potential WMI Lateral Movement WmiPrvSE Spawned PowerShell | medium | 61603 |
| `101068` | 9 | `T1047` T1047 | Suspicious WmiPrvSE Child Process | high | 61603 |
| `101069` | 8 | `T1059.005` T1059.005 | Potential Dropper Script Execution Via WScript/CScript/MSHTA | medium | 61603 |
| `101070` | 8 | - | Cscript/Wscript Potentially Suspicious Child Process | medium | 61603 |
| `101071` | 9 | `T1059.005` T1059.005 | Cscript/Wscript Uncommon Script Extension Execution | high | 61603 |
| `101072` | 8 | `T1218` T1218 | WSL Child Process Anomaly | medium | 61603 |
| `101073` | 9 | `T1059` Command and Scripting Interpreter | Installation of WSL Kali-Linux | high | 61603 |
| `101074` | 9 | `T1202` T1202 | WSL Kali-Linux Usage | high | 61603 |
| `101075` | 9 | `T1202` T1202 | WSL Kali-Linux Usage | high | 61603 |
| `101076` | 9 | `T1202` T1202 | WSL Kali-Linux Usage | high | 61603 |
| `101078` | 9 | `T1218` T1218 | Proxy Execution Via Wuauclt.EXE | high | 61603 |
| `101079` | 9 | `T1036` T1036 | Suspicious Windows Update Agent Empty Cmdline | high | 61603 |
| `101080` | 9 | - | Cab File Extraction Via Wusa.EXE From Potentially Suspicious Paths | high | 61603 |
| `101081` | 9 | - | Wusa.EXE Executed By Parent Process Located In Suspicious Location | high | 61603 |
| `101083` | 8 | - | Delete Defender Scan ShellEx Context Menu Registry Key | medium | 61614 |
| `101084` | 9 | `T1685` T1685 | Windows Credential Guard Related Registry Value Deleted - Registry | high | 61614 |
| `101085` | 9 | `T1685` T1685 | Folder Removed From Exploit Guard ProtectedFolders List - Registry | high | 61614 |
| `101086` | 9 | `T1685` T1685 | Removal Of AMSI Provider Registry Keys | high | 61614 |
| `101087` | 9 | `T1070.003` T1070.003 | RunMRU Registry Key Deletion - Registry | high | 61614 |
| `101088` | 8 | `T1685` T1685 | Removal Of Index Value to Hide Schedule Task - Registry | medium | 61614 |
| `101089` | 8 | `T1685` T1685 | Removal Of SD Value to Hide Schedule Task - Registry | medium | 61614 |
| `101090` | 9 | `T1218.003` T1218.003 | CMSTP Execution Registry Event | high | 61615 |
| `101091` | 9 | `T1685` T1685 | Windows Defender Threat Severity Default Action Modified | high | 61615 |
| `101092` | 9 | `T1608` T1608 | HybridConnectionManager Service Installation - Registry | high | 61615 |
| `101093` | 8 | `T1685` T1685 | Enable Remote Connection Between Anonymous Computer - AllowAnonymou... | medium | 61615 |
| `101094` | 9 | `T1564.001` T1564.001 | Registry Persistence via Service in Safe Mode | high | 61615 |
| `101095` | 9 | `T1685` T1685 | Potential AMSI COM Server Hijacking | high | 61615 |
| `101096` | 9 | `T1685` T1685 | AMSI Disabled via Registry Modification | high | 61615 |
| `101097` | 9 | `T1685` T1685 | Sysmon Driver Altitude Change | high | 61615 |
| `101098` | 9 | `T1685.001` T1685.001 | Change Winevt Channel Access Permission Via Registry | high | 61615 |
| `101099` | 9 | `T1685` T1685 | Windows Credential Guard Disabled - Registry | high | 61615 |
| `101100` | 9 | `T1202` T1202 | Custom File Open Handler Executes PowerShell | high | 61615 |
| `101101` | 8 | `T1685` T1685 | Windows Defender Exclusions Added - Registry | medium | 61615 |
| `101102` | 9 | `T1685` T1685 | Antivirus Filter Driver Disallowed On Dev Drive - Registry | high | 61615 |
| `101103` | 9 | `T1685` T1685 | Windows Hypervisor Enforced Code Integrity Disabled | high | 61615 |
| `101104` | 9 | `T1685` T1685 | Hypervisor Enforced Paging Translation Disabled | high | 61615 |
| `101105` | 8 | `T1070.005` T1070.005 | Disable Administrative Share Creation at Startup | medium | 61615 |
| `101106` | 9 | `T1685.001` T1685.001 | Potential AutoLogger Sessions Tampering | high | 61615 |
| `101107` | 8 | `T1686.003` T1686.003 | Disable Microsoft Defender Firewall via Registry | medium | 61615 |
| `101108` | 9 | - | Disable Macro Runtime Scan Scope | high | 61615 |
| `101109` | 8 | `T1685` T1685 | Disable Privacy Settings Experience in Registry | medium | 61615 |
| `101110` | 9 | `T1685` T1685 | Windows Defender Service Disabled - Registry | high | 61615 |
| `101111` | 8 | `T1686.003` T1686.003 | Disable Windows Firewall by Registry | medium | 61615 |
| `101112` | 9 | `T1685.001` T1685.001 | Disable Windows Event Logging Via Registry | high | 61615 |
| `101113` | 8 | `T1685` T1685 | Disable Exploit Guard Network Protection on Windows Defender | medium | 61615 |
| `101114` | 9 | `T1685` T1685 | Disabled Windows Defender Eventlog | high | 61615 |
| `101115` | 9 | `T1685` T1685 | Disable PUA Protection on Windows Defender | high | 61615 |
| `101116` | 8 | `T1685` T1685 | Disable Tamper Protection on Windows Defender | medium | 61615 |
| `101117` | 8 | `T1685` T1685 | Scripted Diagnostics Turn Off Check Enabled - Registry | medium | 61615 |
| `101118` | 9 | `T1685.001` T1685.001 | Potential EventLog File Location Tampering | high | 61615 |
| `101119` | 9 | `T1685` T1685 | Suspicious Application Allowed Through Exploit Guard | high | 61615 |
| `101120` | 9 | - | New File Association Using Exefile | high | 61615 |
| `101121` | 9 | `T1204.004` T1204.004 | FileFix - Command Evidence in TypedPaths | high | 61615 |
| `101122` | 8 | `T1564.001` T1564.001 | Displaying Hidden Files Feature Disabled | medium | 61615 |
| `101123` | 9 | `T1685` T1685 | Hide Schedule Task Via Index Value Tamper | high | 61615 |
| `101124` | 9 | - | Driver Added To Disallowed Images In HVCI - Registry | high | 61615 |
| `101125` | 9 | - | IE ZoneMap Setting Downgraded To MyComputer Zone For HTTP Protocols | high | 61615 |
| `101126` | 9 | `T1685` T1685 | Uncommon Extension In Keyboard Layout IME File Registry Value | high | 61615 |
| `101127` | 9 | `T1685` T1685 | Suspicious Path In Keyboard Layout IME File Registry Value | high | 61615 |
| `101128` | 8 | - | Internet Explorer DisableFirstRunCustomize Enabled | medium | 61615 |
| `101129` | 9 | `T1685` T1685 | Microsoft Office Protected View Disabled | high | 61615 |
| `101130` | 9 | `T1685` T1685 | Python Function Execution Security Warning Disabled In Excel - Regi... | high | 61615 |
| `101131` | 8 | `T1559.002` T1559.002 | Enable Microsoft Dynamic Data Exchange | medium | 61615 |
| `101132` | 8 | `T1559.002` T1559.002 | Enable Microsoft Dynamic Data Exchange | medium | 61615 |
| `101133` | 9 | `T1036.003` T1036.003 | Potential WerFault ReflectDebugger Registry Value Abuse | high | 61615 |
| `101134` | 9 | - | Potential Attachment Manager Settings Associations Tamper | high | 61615 |
| `101135` | 9 | - | Potential Attachment Manager Settings Attachments Tamper | high | 61615 |
| `101136` | 9 | `T1204.001` T1204.001 | Potential ClickFix Execution Pattern - Registry | high | 61615 |
| `101137` | 9 | `T1569.002` T1569.002 | PowerShell as a Service in Registry | high | 61615 |
| `101138` | 8 | - | Potential PowerShell Execution Policy Tampering | medium | 61615 |
| `101139` | 9 | `T1218` T1218 | Potential Provisioning Registry Key Abuse For Binary Proxy Executio... | high | 61615 |
| `101140` | 9 | `T1588.002` T1588.002 | Suspicious Execution Of Renamed Sysinternals Tools - Registry | high | 61615 |
| `101141` | 8 | `T1588.002` T1588.002 | PUA - Sysinternals Tools Execution - Registry | medium | 61615 |
| `101142` | 9 | `T1588.002` T1588.002 | Usage of Renamed Sysinternals Tools - RegistrySet | high | 61615 |
| `101143` | 9 | `T1059.001` T1059.001 | Potentially Suspicious Command Executed Via Run Dialog Box - Registry | high | 61615 |
| `101144` | 8 | `T1218.011` T1218.011 | ScreenSaver Registry Key Set | medium | 61615 |
| `101145` | 9 | `T1685` T1685 | Tamper With Sophos AV Registry Keys | high | 61615 |
| `101146` | 9 | `T1564.002` T1564.002 | Hiding User Account Via SpecialAccounts Registry Key | high | 61615 |
| `101147` | 8 | `T1588.002` T1588.002 | Suspicious Keyboard Layout Load | medium | 61615 |
| `101148` | 8 | `T1036.003` T1036.003 | Potential PendingFileRenameOperations Tampering | medium | 61615 |
| `101149` | 9 | `T1204.004` T1204.004 | Suspicious Space Characters in RunMRU Registry Path - ClickFix | high | 61615 |
| `101150` | 8 | `T1685` T1685 | Suspicious Service Installed | medium | 61615 |
| `101151` | 9 | `T1204.004` T1204.004 | Suspicious Space Characters in TypedPaths Registry Path - FileFix | high | 61615 |
| `101152` | 8 | `T1685` T1685 | WFP Filter Added via Registry | medium | 61615 |
| `101153` | 8 | - | Old TLS1.0/TLS1.1 Protocol Version Enabled | medium | 61615 |
| `101154` | 9 | - | Potential Signing Bypass Via Windows Developer Features - Registry | high | 61615 |
| `101155` | 9 | `T1685` T1685 | Windows Vulnerable Driver Blocklist Disabled | high | 61615 |
| `101156` | 9 | `T1218` T1218 | Execution DLL of Choice Using WAB.EXE | high | 61615 |
| `101157` | 9 | `T1685` T1685 | Disable Windows Defender Functionalities Via Registry Keys | high | 61615 |
| `101158` | 8 | - | Sysmon Configuration Change | medium | 60004 |
| `101159` | 9 | `T1564` T1564 | Sysmon Configuration Error | high | 60004 |
| `101160` | 9 | `T1564` T1564 | Sysmon Configuration Modification | high | 60004 |
| `101161` | 9 | `T1564` T1564 | Sysmon Configuration Modification | high | 60004 |
| `101162` | 9 | - | Sysmon Blocked Executable | high | 60004 |
| `101163` | 9 | - | Sysmon Blocked File Shredding | high | 60004 |
| `101164` | 8 | - | Sysmon File Executable Creation Detected | medium | 60004 |
| `101165` | 9 | `T1059.005` T1059.005 | Suspicious Scripting in a WMI Consumer | high | 61621 |

### Persistence (TA0003) — 839 rules

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
| `104017` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104018` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104019` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104020` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104021` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104022` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104023` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104024` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104025` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104026` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104027` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104028` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104029` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104030` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104031` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104032` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104033` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104034` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104035` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104036` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104037` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104038` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104039` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104040` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104041` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104042` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104043` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104044` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104045` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104046` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104047` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104048` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104049` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104050` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104051` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104052` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104053` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104054` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104055` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104056` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104057` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104058` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104059` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104060` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104061` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104062` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104063` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104064` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104065` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104066` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104067` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104068` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104069` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104070` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104071` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104072` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104073` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104074` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104075` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104076` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104077` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104078` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104079` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104080` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104081` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104082` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104083` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104084` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104085` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104086` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104087` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104088` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104089` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104090` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104091` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104092` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104093` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104094` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104095` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104096` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104097` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104098` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104099` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104100` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104101` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104102` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104103` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104104` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104105` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104106` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104107` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104108` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104109` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104110` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104111` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104112` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104113` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104114` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104115` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104116` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104117` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104118` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104119` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104120` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104121` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104122` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104123` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104124` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104125` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104126` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104127` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104128` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104129` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104130` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104131` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104132` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104133` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104134` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104135` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104136` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104137` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104138` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104139` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104140` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104141` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104142` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104143` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104144` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104145` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104146` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104147` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104148` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104149` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104150` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104151` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104152` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104153` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104154` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104155` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104156` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104157` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104158` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104159` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104160` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104161` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104162` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104163` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104164` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104165` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104166` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104167` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104168` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104169` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104170` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104171` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104172` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104173` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104174` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104175` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104176` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104177` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104178` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104179` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104180` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104181` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104182` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104183` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104184` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104185` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104186` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104187` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104188` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104189` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104190` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104191` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104192` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104193` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104194` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104195` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104196` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104197` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104198` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104199` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104200` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104201` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104202` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104203` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104204` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104205` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104206` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104207` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104208` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104209` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104210` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104211` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104212` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104213` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104214` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104215` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104216` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104217` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104218` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104219` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104220` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104221` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104222` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104223` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104224` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104225` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104226` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104227` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104228` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104229` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104230` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104231` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104232` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104233` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104234` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104235` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104236` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104237` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104238` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104239` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104240` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104241` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104242` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104243` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104244` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104245` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104246` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104247` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104248` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104249` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104250` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104251` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104252` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104253` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104254` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104255` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104256` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104257` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104258` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104259` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104260` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104261` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104262` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104263` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104264` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104265` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104266` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104267` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104268` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104269` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104270` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104271` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104272` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104273` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104274` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104275` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104276` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104277` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104278` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104279` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104280` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104281` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104282` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104283` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104284` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104285` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104286` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104287` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104288` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104289` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104290` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104291` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104292` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104293` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104294` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104295` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104296` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104297` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104298` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104299` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104300` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104301` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104302` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104303` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104304` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104305` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104306` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104307` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104308` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104309` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104310` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104311` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104312` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104313` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104314` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104315` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104316` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104317` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104318` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104319` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104320` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104321` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104322` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104323` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104324` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104325` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104326` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104327` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104328` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104329` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104330` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104331` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104332` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104333` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104334` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104335` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104336` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104337` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104338` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104339` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104340` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104341` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104342` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104343` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104344` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104345` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104346` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104347` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104348` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104349` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104350` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104351` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104352` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104353` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104354` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104355` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104356` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104357` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104358` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104359` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104360` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104361` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104362` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104363` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104364` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104365` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104366` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104367` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104368` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104369` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104370` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104371` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104372` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104373` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104374` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104375` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104376` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104377` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104378` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104379` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104380` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104381` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104382` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104383` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104384` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104385` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104386` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104387` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104388` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104389` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104390` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104391` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104392` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104393` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104394` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104395` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104396` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104397` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104398` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104399` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104400` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104401` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104402` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104403` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104404` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104405` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104406` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104407` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104408` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104409` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104410` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104411` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104412` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104413` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104414` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104415` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104416` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104417` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104418` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104419` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104420` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104421` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104422` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104423` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104424` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104425` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104426` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104427` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104428` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104429` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104430` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104431` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104432` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104433` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104434` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104435` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104436` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104437` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104438` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104439` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104440` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104441` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104442` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104443` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104444` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104445` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104446` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104447` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104448` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104449` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104450` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104451` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104452` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104453` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104454` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104455` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104456` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104457` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104458` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104459` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104460` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104461` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104462` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104463` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104464` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104465` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104466` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104467` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104468` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104469` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104470` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104471` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104472` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104473` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104474` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104475` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104476` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104477` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104478` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104479` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104480` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104481` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104482` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104483` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104484` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104485` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104486` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104487` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104488` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104489` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104490` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104491` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104492` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104493` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104494` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104495` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104496` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104497` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104498` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104499` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104500` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104501` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104502` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104503` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104504` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104505` | 9 | `T1546.003` T1546.003 | WMI event subscription (EventID 20) | medium | 61622 |
| `104506` | 9 | `T1546.003` T1546.003 | WMI event subscription (EventID 19) | medium | 61621 |
| `104507` | 7 | `T1098` T1098 | Security group created | low | 60100 |
| `104508` | 7 | `T1098` T1098 | Security group changed | low | 60100 |
| `104509` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104510` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104511` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104512` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104513` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104514` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104515` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104516` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104517` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
| `104518` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60002 |
| `104519` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60002 |
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
| `104535` | 9 | `T1505.002` T1505.002 | MSExchange Transport Agent Installation - Builtin | medium | 60000 |
| `104536` | 10 | `T1505.002` T1505.002 | Failed MSExchange Transport Agent Installation | high | 60000 |
| `104537` | 13 | `T1021.002` T1021.002 | CobaltStrike Service Installations - Security | high | 60100 |
| `104538` | 10 | `T1112` T1112 | ETW Logging Disabled In .NET Processes - Registry | high | 60100 |
| `104539` | 10 | `T1112` T1112 | ETW Logging Disabled In .NET Processes - Registry | high | 60100 |
| `104540` | 10 | `T1136.001` T1136.001 | Hidden Local User Creation | high | 60100 |
| `104541` | 10 | `T1554` T1554 | HybridConnectionManager Service Installation | high | 60100 |
| `104542` | 10 | `T1685` T1685 | NetNTLM Downgrade Attack | high | 60100 |
| `104543` | 10 | `T1543` Create or Modify System Process | Service Installed By Unusual Client - Security | high | 60100 |
| `104544` | 9 | `T1134.005` T1134.005 | Addition of SID History to Active Directory Object | medium | 60100 |
| `104545` | 9 | `T1078` Valid Accounts | Account Tampering - Suspicious Failed Logon Reasons | medium | 60100 |
| `104546` | 9 | `T1484.001` T1484.001 | Startup/Logon Script Added to Group Policy Object | medium | 60100 |
| `104547` | 10 | `T1136.001` T1136.001 | Suspicious Windows ANONYMOUS LOGON Local Account Created | high | 60100 |
| `104548` | 10 | `T1556` T1556 | Possible Shadow Credentials Added | high | 60100 |
| `104549` | 10 | `T1112` T1112 | Sysmon Channel Reference Deletion | high | 60100 |
| `104550` | 10 | `T1112` T1112 | Sysmon Channel Reference Deletion | high | 60100 |
| `104551` | 9 | `T1546.003` T1546.003 | WMI Persistence - Security | medium | 60100 |
| `104552` | 10 | `T1554` T1554 | HybridConnectionManager Service Running | high | 60000 |
| `104553` | 13 | `T1021.002` T1021.002 | CobaltStrike Service Installations - System | high | 60002 |
| `104554` | 10 | `T1543` Create or Modify System Process | KrbRelayUp Service Installation | high | 60002 |
| `104555` | 10 | `T1543.003` T1543.003 | Moriya Rootkit - System | high | 60002 |
| `104556` | 9 | - | Anydesk Remote Access Software Service Installation | medium | 60002 |
| `104557` | 9 | - | NetSupport Manager Service Install | medium | 60002 |
| `104558` | 9 | `T1543.003` T1543.003 | New PDQDeploy Service - Server Side | medium | 60002 |
| `104559` | 9 | `T1543.003` T1543.003 | New PDQDeploy Service - Client Side | medium | 60002 |
| `104560` | 10 | `T1543.003` T1543.003 | ProcessHacker Privilege Elevation | high | 60002 |
| `104561` | 9 | - | Remote Utilities Host Service Install | medium | 60002 |
| `104563` | 10 | `T1543` Create or Modify System Process | Service Installed By Unusual Client - System | high | 60002 |
| `104564` | 10 | `T1543.003` T1543.003 | Suspicious Service Installation | high | 60002 |
| `104565` | 9 | `T1543.003` T1543.003 | Uncommon Service Installation Image Path | medium | 60002 |
| `104566` | 10 | - | RTCore Suspicious Service Installation | high | 60002 |
| `104567` | 9 | `T1543.003` T1543.003 | Service Installation in Suspicious Folder | medium | 60002 |
| `104569` | 10 | `T1543.003` T1543.003 | Suspicious Service Installation Script | high | 60002 |
| `104570` | 9 | `T1546.003` T1546.003 | WMI Persistence | medium | 61621 |
| `104571` | 10 | - | Potential Suspicious Winget Package Installation | high | 61617 |
| `104572` | 10 | `T1554` T1554 | DNS HybridConnectionManager Service Bus | high | 61624 |
| `104573` | 10 | `T1543.003` T1543.003 | Malicious Driver Load | high | 61608 |
| `104574` | 13 | `T1543.003` T1543.003 | Malicious Driver Load By Name | medium | 61608 |
| `104575` | 10 | `T1543` Create or Modify System Process | PUA - Process Hacker Driver Load | high | 61608 |
| `104576` | 10 | `T1543` Create or Modify System Process | PUA - Process Hacker Driver Load | high | 61608 |
| `104577` | 9 | `T1543` Create or Modify System Process | PUA - System Informer Driver Load | medium | 61608 |
| `104578` | 9 | `T1543` Create or Modify System Process | PUA - System Informer Driver Load | medium | 61608 |
| `104579` | 10 | `T1543.003` T1543.003 | Driver Load From A Temporary Directory | high | 61608 |
| `104580` | 10 | `T1543.003` T1543.003 | Vulnerable Driver Load | high | 61608 |
| `104581` | 10 | `T1543.003` T1543.003 | Vulnerable HackSys Extreme Vulnerable Driver Load | high | 61608 |
| `104582` | 10 | `T1543.003` T1543.003 | Vulnerable HackSys Extreme Vulnerable Driver Load | high | 61608 |
| `104583` | 10 | `T1543.003` T1543.003 | Vulnerable WinRing0 Driver Load | high | 61608 |
| `104584` | 10 | `T1543.003` T1543.003 | Vulnerable WinRing0 Driver Load | high | 61608 |
| `104585` | 10 | `T1133` T1133 | Unusual File Modification by dns.exe | high | 61604 |
| `104586` | 10 | `T1133` T1133 | Unusual File Deletion by Dns.exe | high | 61625 |
| `104587` | 9 | `T1574.001` T1574.001 | Creation Of Non-Existent System DLL | medium | 61613 |
| `104588` | 10 | `T1574.001` T1574.001 | DLL Search Order Hijackig Via Additional Space in Path | high | 61613 |
| `104589` | 9 | - | Potential Persistence Attempt Via ErrorHandler.Cmd | medium | 61613 |
| `104590` | 10 | `T1505.003` T1505.003 | Suspicious ASPX File Drop by Exchange | high | 61613 |
| `104591` | 9 | `T1190` Exploit Public-Facing Application | Suspicious File Drop by Exchange | medium | 61613 |
| `104592` | 10 | `T1574.001` T1574.001 | HackTool - Powerup Write Hijack DLL | high | 61613 |
| `104593` | 10 | `T1574.001` T1574.001 | Malicious DLL File Dropped in the Teams or OneDrive Folder | high | 61613 |
| `104594` | 9 | - | Potential Persistence Via Notepad++ Plugins | medium | 61613 |
| `104595` | 10 | `T1137.006` T1137.006 | Potential Persistence Via Microsoft Office Add-In | high | 61613 |
| `104596` | 10 | `T1137.006` T1137.006 | Potential Persistence Via Microsoft Office Add-In | high | 61613 |
| `104597` | 10 | `T1137.006` T1137.006 | Potential Persistence Via Microsoft Office Add-In | high | 61613 |
| `104598` | 10 | `T1137.006` T1137.006 | Potential Persistence Via Microsoft Office Add-In | high | 61613 |
| `104599` | 10 | `T1137.003` T1137.003 | Potential Persistence Via Outlook Form | high | 61613 |
| `104600` | 10 | `T1137` T1137 | Potential Persistence Via Microsoft Office Startup Folder | high | 61613 |
| `104601` | 9 | - | Potential Binary Or Script Dropper Via PowerShell | medium | 61613 |
| `104602` | 9 | - | Potential Suspicious PowerShell Module File Created | medium | 61613 |
| `104603` | 9 | - | PowerShell Module File Created By Non-PowerShell Process | medium | 61613 |
| `104604` | 9 | `T1505.003` T1505.003 | Suspicious File Write to Webapps Root Directory | medium | 61613 |
| `104605` | 9 | `T1546.013` T1546.013 | PowerShell Profile Modification | medium | 61613 |
| `104606` | 10 | - | Suspicious File Creation Activity From Fake Recycle.Bin Folder | high | 61613 |
| `104607` | 10 | - | Suspicious File Creation Activity From Fake Recycle.Bin Folder | high | 61613 |
| `104608` | 9 | `T1546.013` T1546.013 | VsCode Powershell Profile Modification | medium | 61613 |
| `104609` | 10 | `T1068` Exploitation for Privilege Escalation | Process Explorer Driver Creation By Non-Sysinternals Binary | high | 61613 |
| `104610` | 9 | `T1068` Exploitation for Privilege Escalation | Process Monitor Driver Creation By Non-Sysinternals Binary | medium | 61613 |
| `104611` | 10 | - | Potential Privilege Escalation Attempt Via .Exe.Local Technique | high | 61613 |
| `104612` | 9 | `T1505.003` T1505.003 | Potential Webshell Creation On Static Website | medium | 61613 |
| `104613` | 10 | `T1542.001` T1542.001 | UEFI Persistence Via Wpbbin - FileCreation | high | 61613 |
| `104614` | 9 | `T1574.001` T1574.001 | Potential Antivirus Software DLL Sideloading | medium | 61609 |
| `104615` | 10 | `T1574.001` T1574.001 | Potential appverifUI.DLL Sideloading | high | 61609 |
| `104616` | 9 | `T1574.001` T1574.001 | Potential AVKkid.DLL Sideloading | medium | 61609 |
| `104617` | 9 | `T1574.001` T1574.001 | Potential CCleanerDU.DLL Sideloading | medium | 61609 |
| `104618` | 9 | `T1574.001` T1574.001 | Potential CCleanerReactivator.DLL Sideloading | medium | 61609 |
| `104619` | 9 | `T1574.001` T1574.001 | Potential Chrome Frame Helper DLL Sideloading | medium | 61609 |
| `104620` | 9 | `T1574.001` T1574.001 | Potential DLL Sideloading Via ClassicExplorer32.dll | medium | 61609 |
| `104621` | 10 | `T1574.001` T1574.001 | Potential DLL Sideloading Via comctl32.dll | high | 61609 |
| `104622` | 10 | `T1574.001` T1574.001 | System Control Panel Item Loaded From Uncommon Location | high | 61609 |
| `104623` | 9 | `T1574.001` T1574.001 | Potential DLL Sideloading Of DBGCORE.DLL | medium | 61609 |
| `104624` | 9 | `T1574.001` T1574.001 | Potential DLL Sideloading Of DBGHELP.DLL | medium | 61609 |
| `104625` | 10 | `T1574.001` T1574.001 | Potential EACore.DLL Sideloading | high | 61609 |
| `104626` | 10 | `T1574.001` T1574.001 | Potential Edputil.DLL Sideloading | high | 61609 |
| `104627` | 10 | `T1574.001` T1574.001 | Potential System DLL Sideloading From Non System Locations | high | 61609 |
| `104628` | 9 | `T1574.001` T1574.001 | Potential Goopdate.DLL Sideloading | medium | 61609 |
| `104629` | 9 | `T1574.001` T1574.001 | Potential DLL Sideloading Of Libcurl.DLL Via GUP.EXE | medium | 61609 |
| `104630` | 10 | `T1574.001` T1574.001 | Potential Iviewers.DLL Sideloading | high | 61609 |
| `104631` | 10 | `T1574.001` T1574.001 | Potential JLI.dll Side-Loading | high | 61609 |
| `104632` | 9 | `T1574.001` T1574.001 | Potential DLL Sideloading Via JsSchHlp | medium | 61609 |
| `104633` | 10 | `T1574.001` T1574.001 | Potential DLL Sideloading Of KeyScramblerIE.DLL Via KeyScrambler.EXE | high | 61609 |
| `104634` | 9 | `T1574.001` T1574.001 | Potential Libvlc.DLL Sideloading | medium | 61609 |
| `104635` | 9 | `T1574.001` T1574.001 | Potential Mfdetours.DLL Sideloading | medium | 61609 |
| `104636` | 10 | `T1574.001` T1574.001 | Unsigned Mfdetours.DLL Sideloading | high | 61609 |
| `104637` | 10 | `T1574.001` T1574.001 | Potential DLL Sideloading Of Non-Existent DLLs From System Folders | high | 61609 |
| `104638` | 10 | `T1574.001` T1574.001 | Microsoft Office DLL Sideload | high | 61609 |
| `104639` | 10 | `T1574.001` T1574.001 | Potential Rcdll.DLL Sideloading | high | 61609 |
| `104640` | 9 | `T1574.001` T1574.001 | Potential RjvPlatform.DLL Sideloading From Default Location | medium | 61609 |
| `104641` | 10 | `T1574.001` T1574.001 | Potential RjvPlatform.DLL Sideloading From Non-Default Location | high | 61609 |
| `104642` | 9 | `T1574.001` T1574.001 | Potential RoboForm.DLL Sideloading | medium | 61609 |
| `104643` | 10 | `T1574.001` T1574.001 | DLL Sideloading Of ShellChromeAPI.DLL | high | 61609 |
| `104644` | 9 | `T1574.001` T1574.001 | Potential ShellDispatch.DLL Sideloading | medium | 61609 |
| `104645` | 10 | `T1574.001` T1574.001 | Potential SmadHook.DLL Sideloading | high | 61609 |
| `104646` | 9 | `T1574.001` T1574.001 | Potential SolidPDFCreator.DLL Sideloading | medium | 61609 |
| `104647` | 9 | `T1574.001` T1574.001 | Third Party Software DLL Sideloading | medium | 61609 |
| `104648` | 10 | `T1574.001` T1574.001 | Potential Vcruntime140 DLL Sideloading | high | 61609 |
| `104649` | 9 | `T1574.001` T1574.001 | Potential Vivaldi_elf.DLL Sideloading | medium | 61609 |
| `104650` | 9 | `T1574.001` T1574.001 | VMGuestLib DLL Sideload | medium | 61609 |
| `104651` | 9 | `T1574.001` T1574.001 | VMMap Signed Dbghelp.DLL Potential Sideloading | medium | 61609 |
| `104652` | 10 | `T1574.001` T1574.001 | VMMap Unsigned Dbghelp.DLL Potential Sideloading | high | 61609 |
| `104653` | 10 | `T1574.001` T1574.001 | Potential Waveedit.DLL Sideloading | high | 61609 |
| `104654` | 9 | `T1574.001` T1574.001 | Potential Wazuh Security Platform DLL Sideloading | medium | 61609 |
| `104655` | 9 | `T1574.001` T1574.001 | Potential WWlib.DLL Sideloading | medium | 61609 |
| `104656` | 10 | `T1548.002` T1548.002 | UAC Bypass With Fake DLL | high | 61609 |
| `104657` | 10 | `T1574.007` T1574.007 | Trusted Path Bypass via Windows Directory Spoofing | high | 61609 |
| `104658` | 9 | `T1219.002` T1219.002 | Remote Access Tool - AnyDesk Incoming Connection | medium | 61605 |
| `104659` | 10 | `T1571` T1571 | Potentially Suspicious Malware Callback Communication | high | 61605 |
| `104660` | 9 | `T1571` T1571 | Communication To Uncommon Destination Ports | medium | 61605 |
| `104662` | 9 | `T1136.002` T1136.002 | Manipulation of User Computer or Group Security Principals Across AD | medium | 91801 |
| `104663` | 9 | - | Unsigned AppX Installation Attempt Using Add-AppxPackage - PsScript | medium | 91801 |
| `104664` | 10 | `T1137.006` T1137.006 | Code Executed Via Office Add-in XLL File | high | 91801 |
| `104665` | 10 | `T1059.001` T1059.001 | PowerShell Web Access Installation - PsScript | high | 91801 |
| `104666` | 10 | `T1059.001` T1059.001 | PowerShell Web Access Installation - PsScript | high | 91801 |
| `104667` | 10 | `T1059.001` T1059.001 | PowerShell Web Access Installation - PsScript | high | 91801 |
| `104668` | 10 | - | Potential Persistence Via Security Descriptors - ScriptBlock | high | 91801 |
| `104669` | 10 | `T1574.011` T1574.011 | Suspicious Service DACL Modification Via Set-Service Cmdlet - PS | high | 91801 |
| `104670` | 9 | `T1546.013` T1546.013 | Potential Persistence Via PowerShell User Profile Using Add-Content | medium | 91801 |
| `104671` | 10 | `T1574.011` T1574.011 | Abuse of Service Permissions to Hide Services Via Set-Service - PS | high | 91801 |
| `104672` | 9 | `T1112` T1112 | Registry Modification Attempt Via VBScript - PowerShell | medium | 91801 |
| `104673` | 9 | `T1546.003` T1546.003 | Powershell WMI Persistence | medium | 91801 |
| `104674` | 10 | `T1053.002` T1053.002 | Interactive AT Job | high | 61603 |
| `104675` | 9 | `T1070` Indicator Removal | Potential Ransomware or Unauthorized MBR Tampering Via Bcdedit.EXE | medium | 61603 |
| `104676` | 9 | `T1197` T1197 | File Download Via Bitsadmin | medium | 61603 |
| `104677` | 10 | `T1197` T1197 | Suspicious Download From Direct IP Via Bitsadmin | high | 61603 |
| `104678` | 10 | `T1197` T1197 | Suspicious Download From File-Sharing Website Via Bitsadmin | high | 61603 |
| `104679` | 10 | `T1197` T1197 | File With Suspicious Extension Downloaded Via Bitsadmin | high | 61603 |
| `104680` | 10 | `T1197` T1197 | File Download Via Bitsadmin To A Suspicious Target Folder | high | 61603 |
| `104681` | 9 | `T1197` T1197 | Monitoring For Persistence Via BITS | medium | 61603 |
| `104682` | 9 | `T1176.001` T1176.001 | Chromium Browser Instance Executed With Custom Extension | medium | 61603 |
| `104683` | 10 | `T1176.001` T1176.001 | Suspicious Chromium Browser Instance Executed With Custom Extension | high | 61603 |
| `104684` | 10 | `T1546.008` T1546.008 | Persistence Via Sticky Key Backdoor | high | 61603 |
| `104685` | 10 | `T1543.003` T1543.003 | Devcon Execution Disabling VMware VMCI Device | high | 61603 |
| `104686` | 10 | `T1133` T1133 | Unusual Child Process of dns.exe | high | 61603 |
| `104687` | 10 | `T1685.001` T1685.001 | Security Event Logging Disabled via MiniNt Registry Key - Process | high | 61603 |
| `104688` | 10 | `T1615` T1615 | HackTool - SharpUp PrivEsc Tool Execution | high | 61603 |
| `104689` | 10 | `T1615` T1615 | HackTool - SharpUp PrivEsc Tool Execution | high | 61603 |
| `104690` | 10 | `T1615` T1615 | HackTool - SharpUp PrivEsc Tool Execution | high | 61603 |
| `104692` | 10 | `T1505.004` T1505.004 | Suspicious IIS Module Registration | high | 61603 |
| `104693` | 9 | `T1203` T1203 | Potentially Suspicious Child Process of KeyScrambler.exe | medium | 61603 |
| `104694` | 9 | `T1136.001` T1136.001 | New User Created Via Net.EXE | medium | 61603 |
| `104695` | 10 | `T1136.001` T1136.001 | New User Created Via Net.EXE With Never Expire Option | high | 61603 |
| `104696` | 10 | `T1574.011` T1574.011 | Abuse of Service Permissions to Hide Services Via Set-Service | high | 61603 |
| `104697` | 9 | - | Unsigned AppX Installation Attempt Using Add-AppxPackage | medium | 61603 |
| `104698` | 9 | `T1505.002` T1505.002 | MSExchange Transport Agent Installation | medium | 61603 |
| `104699` | 10 | `T1543.003` T1543.003 | PUA - Kernel Driver Utility (KDU) Execution | high | 61603 |
| `104700` | 9 | `T1082` System Information Discovery | PUA - System Informer Execution | medium | 61603 |
| `104701` | 9 | `T1082` System Information Discovery | PUA - System Informer Execution | medium | 61603 |
| `104702` | 9 | `T1082` System Information Discovery | PUA - System Informer Execution | medium | 61603 |
| `104703` | 9 | `T1082` System Information Discovery | PUA - System Informer Execution | medium | 61603 |
| `104704` | 9 | `T1082` System Information Discovery | PUA - System Informer Execution | medium | 61603 |
| `104705` | 9 | `T1556.002` T1556.002 | Dropping Of Password Filter DLL | medium | 61603 |
| `104706` | 9 | `T1112` T1112 | Potentially Suspicious Desktop Background Change Using Reg.EXE | medium | 61603 |
| `104707` | 9 | `T1112` T1112 | Potential Suspicious Registry File Imported Via Reg.EXE | medium | 61603 |
| `104708` | 10 | `T1112` T1112 | RestrictedAdminMode Registry Value Tampering - ProcCreation | high | 61603 |
| `104709` | 10 | `T1112` T1112 | Enable LM Hash Storage - ProcCreation | high | 61603 |
| `104710` | 10 | `T1021.001` T1021.001 | Potential Tampering With RDP Related Registry Keys Via Reg.EXE | high | 61603 |
| `104711` | 9 | `T1546.002` T1546.002 | Suspicious ScreenSave Change by Reg.exe | medium | 61603 |
| `104712` | 10 | `T1112` T1112 | Reg Add Suspicious Paths | high | 61603 |
| `104713` | 9 | `T1112` T1112 | Imports Registry Key From a File | medium | 61603 |
| `104716` | 10 | `T1546.008` T1546.008 | Suspicious Debugger Registration Cmdline | high | 61603 |
| `104717` | 10 | `T1574.011` T1574.011 | Potential Privilege Escalation via Service Permissions Weakness | high | 61603 |
| `104718` | 9 | - | Persistence Via TypedPaths - CommandLine | medium | 61603 |
| `104719` | 9 | `T1133` T1133 | Remote Access Tool - ScreenConnect Installation Execution | medium | 61603 |
| `104720` | 10 | `T1112` T1112 | ShimCache Flush | high | 61603 |
| `104721` | 10 | `T1574.011` T1574.011 | Possible Privilege Escalation via Weak Service Permissions | high | 61603 |
| `104722` | 9 | `T1543.003` T1543.003 | New Kernel Driver Via SC.EXE | medium | 61603 |
| `104723` | 10 | `T1574.011` T1574.011 | Service DACL Abuse To Hide Services Via Sc.EXE | high | 61603 |
| `104724` | 9 | `T1574.011` T1574.011 | Service Security Descriptor Tampering Via Sc.EXE | medium | 61603 |
| `104725` | 10 | `T1543.003` T1543.003 | Suspicious Service Path Modification | high | 61603 |
| `104726` | 9 | `T1546.011` T1546.011 | Potential Shim Database Persistence via Sdbinst.EXE | medium | 61603 |
| `104727` | 9 | `T1546.011` T1546.011 | Uncommon Extension Shim Database Installation Via Sdbinst.EXE | medium | 61603 |
| `104728` | 9 | `T1211` T1211 | Writing Of Malicious Files To The Fonts Folder | medium | 61603 |
| `104729` | 10 | `T1112` T1112 | Non-privileged Usage of Reg or Powershell | high | 61603 |
| `104730` | 10 | - | Suspicious Process Execution From Fake Recycle.Bin Folder | high | 61603 |
| `104731` | 10 | `T1543.003` T1543.003 | Suspicious New Service Creation | high | 61603 |
| `104732` | 10 | `T1543.003` T1543.003 | Suspicious New Service Creation | high | 61603 |
| `104733` | 10 | `T1547.001` T1547.001 | User Shell Folders Registry Modification via CommandLine | high | 61603 |
| `104734` | 9 | `T1112` T1112 | Registry Modification Attempt Via VBScript | medium | 61603 |
| `104735` | 9 | `T1112` T1112 | Suspicious VBoxDrvInst.exe Parameters | medium | 61603 |
| `104736` | 10 | `T1505.003` T1505.003 | Chopper Webshell Process Pattern | high | 61603 |
| `104737` | 10 | `T1505.003` T1505.003 | Webshell Hacking Activity Patterns | high | 61603 |
| `104738` | 10 | `T1505.003` T1505.003 | Webshell Hacking Activity Patterns | high | 61603 |
| `104739` | 10 | `T1505.003` T1505.003 | Webshell Hacking Activity Patterns | high | 61603 |
| `104740` | 10 | `T1505.003` T1505.003 | Webshell Detection With Command Line Keywords | high | 61603 |
| `104741` | 10 | `T1505.003` T1505.003 | Webshell Detection With Command Line Keywords | high | 61603 |
| `104742` | 10 | `T1505.003` T1505.003 | Webshell Detection With Command Line Keywords | high | 61603 |
| `104743` | 10 | `T1505.003` T1505.003 | Suspicious Process By Web Server Process | high | 61603 |
| `104744` | 10 | `T1505.003` T1505.003 | Suspicious Process By Web Server Process | high | 61603 |
| `104745` | 10 | `T1505.003` T1505.003 | Suspicious Process By Web Server Process | high | 61603 |
| `104746` | 10 | `T1505.003` T1505.003 | Webshell Tool Reconnaissance Activity | high | 61603 |
| `104747` | 10 | `T1505.003` T1505.003 | Webshell Tool Reconnaissance Activity | high | 61603 |
| `104748` | 10 | `T1505.003` T1505.003 | Webshell Tool Reconnaissance Activity | high | 61603 |
| `104749` | 9 | `T1546.003` T1546.003 | WMI Persistence - Script Event Consumer | medium | 61603 |
| `104750` | 9 | `T1047` T1047 | Registry Manipulation via WMI Stdregprov | medium | 61603 |
| `104751` | 10 | `T1542.001` T1542.001 | UEFI Persistence Via Wpbbin - ProcessCreation | high | 61603 |
| `104752` | 9 | - | Potential Persistence Via Disk Cleanup Handler - Registry | medium | 61614 |
| `104753` | 10 | `T1070` Indicator Removal | Terminal Server Client Connection History Cleared - Registry | high | 61614 |
| `104754` | 10 | `T1070` Indicator Removal | Terminal Server Client Connection History Cleared - Registry | high | 61614 |
| `104755` | 9 | `T1112` T1112 | Removal of Potential COM Hijacking Registry Keys | medium | 61614 |
| `104756` | 12 | `T1136.001` T1136.001 | Creation of a Local Hidden User Account by Registry | high | 61615 |
| `104757` | 10 | `T1685.001` T1685.001 | Disable Security Events Logging Adding Reg Key MiniNt | high | 61615 |
| `104758` | 10 | `T1685.001` T1685.001 | Disable Security Events Logging Adding Reg Key MiniNt | high | 61615 |
| `104759` | 10 | `T1112` T1112 | Wdigest CredGuard Registry Modification | high | 61615 |
| `104760` | 10 | `T1112` T1112 | Registry Entries For Azorult Malware | high | 61615 |
| `104761` | 10 | `T1112` T1112 | Potential Qakbot Registry Activity | high | 61615 |
| `104762` | 9 | `T1546.002` T1546.002 | Path To Screensaver Binary Modified | medium | 61615 |
| `104763` | 10 | `T1685` T1685 | NetNTLM Downgrade Attack - Registry | high | 61615 |
| `104764` | 9 | `T1137.002` T1137.002 | Office Application Startup - Office Test | medium | 61615 |
| `104765` | 10 | `T1112` T1112 | RedMimicry Winnti Playbook Registry Manipulation | high | 61615 |
| `104766` | 9 | `T1112` T1112 | Run Once Task Configuration in Registry | medium | 61615 |
| `104767` | 10 | `T1548.002` T1548.002 | Shell Open Registry Keys Manipulation | high | 61615 |
| `104768` | 9 | `T1112` T1112 | Registry Tampering by Potentially Suspicious Processes | medium | 61615 |
| `104769` | 9 | - | Add Debugger Entry To AeDebug For Persistence | medium | 61615 |
| `104770` | 9 | `T1112` T1112 | Allow RDP Remote Assistance Feature | medium | 61615 |
| `104771` | 9 | `T1112` T1112 | New BgInfo.EXE Custom DB Path Registry Configuration | medium | 61615 |
| `104772` | 9 | `T1112` T1112 | New BgInfo.EXE Custom VBScript Registry Configuration | medium | 61615 |
| `104773` | 9 | `T1112` T1112 | New BgInfo.EXE Custom WMI Query Registry Configuration | medium | 61615 |
| `104774` | 9 | `T1137` T1137 | IE Change Domain Zone | medium | 61615 |
| `104775` | 9 | `T1112` T1112 | ClickOnce Trust Prompt Tampering | medium | 61615 |
| `104776` | 13 | `T1021.002` T1021.002 | Potential CobaltStrike Service Installations - Registry | high | 61615 |
| `104777` | 10 | `T1546` T1546 | COM Hijack via Sdclt | high | 61615 |
| `104778` | 9 | `T1564` T1564 | CrashControl CrashDump Disabled | medium | 61615 |
| `104779` | 10 | `T1685.001` T1685.001 | Security Event Logging Disabled via MiniNt Registry Key - Registry Set | high | 61615 |
| `104780` | 10 | `T1112` T1112 | Service Binary in Suspicious Folder | high | 61615 |
| `104781` | 10 | `T1112` T1112 | Service Binary in Suspicious Folder | high | 61615 |
| `104782` | 9 | `T1112` T1112 | Potentially Suspicious Desktop Background Change Via Registry | medium | 61615 |
| `104783` | 9 | `T1112` T1112 | Disable Internal Tools or Feature in Registry | medium | 61615 |
| `104784` | 9 | `T1112` T1112 | Disable Internal Tools or Feature in Registry | medium | 61615 |
| `104785` | 9 | `T1112` T1112 | Disable Windows Security Center Notifications | medium | 61615 |
| `104786` | 9 | `T1112` T1112 | Add DisallowRun Execution to Registry | medium | 61615 |
| `104787` | 9 | - | Persistence Via Disk Cleanup Handler - Autorun | medium | 61615 |
| `104788` | 9 | `T1140` T1140 | DNS-over-HTTPS Enabled by Registry | medium | 61615 |
| `104789` | 9 | `T1140` T1140 | DNS-over-HTTPS Enabled by Registry | medium | 61615 |
| `104790` | 9 | `T1140` T1140 | DNS-over-HTTPS Enabled by Registry | medium | 61615 |
| `104791` | 10 | `T1112` T1112 | ETW Logging Disabled In .NET Processes - Sysmon Registry | high | 61615 |
| `104792` | 10 | `T1112` T1112 | ETW Logging Disabled In .NET Processes - Sysmon Registry | high | 61615 |
| `104793` | 9 | `T1574.012` T1574.012 | Enabling COR Profiler Environment Variables | medium | 61615 |
| `104794` | 9 | `T1574.012` T1574.012 | Enabling COR Profiler Environment Variables | medium | 61615 |
| `104795` | 10 | `T1112` T1112 | Change User Account Associated with the FAX Service | high | 61615 |
| `104796` | 10 | `T1112` T1112 | Change the Fax Dll | high | 61615 |
| `104797` | 10 | - | Add Debugger Entry To Hangs Key For Persistence | high | 61615 |
| `104798` | 10 | - | Persistence Via Hhctrl.ocx | high | 61615 |
| `104799` | 9 | `T1137` T1137 | Registry Modification to Hidden File Extension | medium | 61615 |
| `104800` | 9 | `T1137` T1137 | Registry Modification to Hidden File Extension | medium | 61615 |
| `104801` | 9 | `T1112` T1112 | Registry Hide Function from User | medium | 61615 |
| `104802` | 9 | `T1112` T1112 | Registry Hide Function from User | medium | 61615 |
| `104803` | 10 | `T1112` T1112 | RestrictedAdminMode Registry Value Tampering | high | 61615 |
| `104804` | 10 | `T1112` T1112 | NET NGenAssemblyUsageLog Registry Key Tamper | high | 61615 |
| `104805` | 10 | `T1112` T1112 | Trust Access Disable For VBApplications | high | 61615 |
| `104806` | 10 | `T1112` T1112 | Outlook EnableUnsafeClientMailRules Setting Enabled - Registry | high | 61615 |
| `104807` | 9 | `T1137` T1137 | Outlook Security Settings Updated - Registry | medium | 61615 |
| `104808` | 10 | `T1112` T1112 | Macro Enabled In A Potentially Suspicious Document | high | 61615 |
| `104809` | 10 | `T1112` T1112 | Uncommon Microsoft Office Trusted Location Added | high | 61615 |
| `104810` | 10 | `T1112` T1112 | Office Macros Warning Disabled | high | 61615 |
| `104811` | 9 | - | Potential Persistence Via New AMSI Providers - Registry | medium | 61615 |
| `104812` | 10 | - | Potential Persistence Via AutodialDLL | high | 61615 |
| `104813` | 10 | - | Potential Persistence Via CHM Helper DLL | high | 61615 |
| `104814` | 9 | `T1112` T1112 | Potential Persistence Via Custom Protocol Handler | medium | 61615 |
| `104815` | 9 | `T1112` T1112 | Potential Persistence Via Event Viewer Events.asp | medium | 61615 |
| `104816` | 9 | - | Register New IFiltre For Persistence | medium | 61615 |
| `104817` | 9 | - | Register New IFiltre For Persistence | medium | 61615 |
| `104818` | 10 | - | Potential Persistence Via LSA Extensions | high | 61615 |
| `104819` | 10 | - | Potential Persistence Via Mpnotify | high | 61615 |
| `104820` | 10 | - | Potential Persistence Via MyComputer Registry Keys | high | 61615 |
| `104821` | 10 | - | Potential Persistence Via DLLPathOverride | high | 61615 |
| `104822` | 9 | `T1137.006` T1137.006 | Potential Persistence Via Visual Studio Tools for Office | medium | 61615 |
| `104823` | 10 | `T1112` T1112 | Potential Persistence Via Outlook Home Page | high | 61615 |
| `104824` | 10 | `T1112` T1112 | Potential Persistence Via Outlook Today Page | high | 61615 |
| `104825` | 10 | - | Potential Persistence Via TypedPaths | high | 61615 |
| `104826` | 10 | `T1137.006` T1137.006 | Potential Persistence Via Excel Add-in - Registry | high | 61615 |
| `104827` | 10 | `T1112` T1112 | Registry Modification for OCI DLL Redirection | high | 61615 |
| `104828` | 10 | `T1564.001` T1564.001 | PowerShell Logging Disabled Via Registry Key Tampering | high | 61615 |
| `104829` | 9 | - | Potential SentinelOne Shell Context Menu Scan Command Tampering | medium | 61615 |
| `104830` | 9 | `T1543.003` T1543.003 | ServiceDll Hijack | medium | 61615 |
| `104831` | 9 | `T1112` T1112 | Registry Explorer Policy Modification | medium | 61615 |
| `104832` | 9 | `T1553.003` T1553.003 | Persistence Via New SIP Provider | medium | 61615 |
| `104833` | 9 | `T1112` T1112 | Activate Suppression of Windows Security Center Notifications | medium | 61615 |
| `104834` | 10 | `T1574` T1574 | Suspicious Printer Driver Empty Manufacturer | high | 61615 |
| `104835` | 10 | `T1547.001` T1547.001 | Modify User Shell Folders Startup Value | high | 61615 |
| `104836` | 10 | - | Suspicious Environment Variable Has Been Registered | high | 61615 |
| `104837` | 10 | `T1112` T1112 | Enable LM Hash Storage | high | 61615 |
| `104838` | 9 | `T1112` T1112 | RDP Sensitive Settings Changed to Zero | medium | 61615 |
| `104839` | 10 | `T1112` T1112 | RDP Sensitive Settings Changed | high | 61615 |
| `104840` | 10 | `T1547.003` T1547.003 | New TimeProviders Registered With Uncommon DLL Name | high | 61615 |
| `104841` | 10 | `T1112` T1112 | Wdigest Enable UseLogonCredential | high | 61615 |
| `104842` | 9 | - | Enable Local Manifest Installation With Winget | medium | 61615 |
| `104843` | 9 | `T1112` T1112 | Winlogon AllowMultipleTSSessions Enable | medium | 61615 |
| `115003` | 12 | `T1543` Create or Modify System Process | service_install_then_network | high | 110061 |

### Privilege Escalation (TA0004) — 363 rules

| Rule ID | Level | Technique | Description | Confidence | Parent SID |
|---------|-------|-----------|-------------|------------|------------|
| `107000` | 8 | `T1078` Valid Accounts | Special privilege assignment | low | 60100 |
| `107001` | 11 | - | CodeIntegrity - Disallowed File For Protected Processes Has Been Bl... | high | 60000 |
| `107002` | 11 | - | CodeIntegrity - Revoked Kernel Driver Loaded | high | 60000 |
| `107003` | 11 | - | CodeIntegrity - Blocked Image Load With Revoked Certificate | high | 60000 |
| `107004` | 11 | - | CodeIntegrity - Revoked Image Loaded | high | 60000 |
| `107005` | 11 | - | CodeIntegrity - Unsigned Kernel Module Loaded | high | 60000 |
| `107006` | 11 | - | CodeIntegrity - Unsigned Image Loaded | high | 60000 |
| `107007` | 11 | - | CodeIntegrity - Unmet WHQL Requirements For Loaded Kernel Module | high | 60000 |
| `107008` | 11 | `T1574.001` T1574.001 | DNS Server Error Failed Loading the ServerLevelPluginDLL | high | 60000 |
| `107009` | 10 | `T1134.001` T1134.001 | Potential Access Token Abuse | medium | 60100 |
| `107010` | 11 | - | DiagTrackEoP Default Login Username | high | 60100 |
| `107011` | 10 | `T1133` T1133 | External Remote RDP Logon from Public IP | medium | 60100 |
| `107012` | 11 | `T1133` T1133 | External Remote SMB Logon from Public IP | high | 60100 |
| `107013` | 10 | `T1078` Valid Accounts | Failed Logon From Public IP | medium | 60100 |
| `107014` | 11 | `T1548` Abuse Elevation Control Mechanism | Potential Privilege Escalation via Local Kerberos Relay over LDAP | high | 60100 |
| `107015` | 11 | `T1098` T1098 | Powerview Add-DomainObjectAcl DCSync AD Extend Right | high | 60100 |
| `107016` | 11 | - | ADCS Certificate Template Configuration Vulnerability with Risky EKU | high | 60100 |
| `107017` | 11 | `T1098` T1098 | Enabled User Right in AD to Control User Objects | high | 60100 |
| `107018` | 11 | `T1098` T1098 | Active Directory User Backdoors | high | 60100 |
| `107019` | 10 | `T1053.002` T1053.002 | Remote Task Creation via ATSVC Named Pipe | medium | 60100 |
| `107020` | 10 | `T1484.001` T1484.001 | Windows Default Domain GPO Modification | medium | 60100 |
| `107021` | 11 | `T1053.005` T1053.005 | Persistence and Execution at Scale via GPO Scheduled Task | high | 60100 |
| `107022` | 11 | `T1053.005` T1053.005 | Persistence and Execution at Scale via GPO Scheduled Task | high | 60100 |
| `107023` | 11 | `T1134` Access Token Manipulation | HackTool - NoFilter Execution | high | 60100 |
| `107024` | 11 | `T1134` Access Token Manipulation | HackTool - NoFilter Execution | high | 60100 |
| `107025` | 14 | `T1134.001` T1134.001 | Meterpreter or Cobalt Strike Getsystem Service Installation - Security | high | 60100 |
| `107026` | 10 | `T1547.009` T1547.009 | Windows Network Access Suspicious desktop.ini Action | medium | 60100 |
| `107027` | 10 | `T1548` Abuse Elevation Control Mechanism | SCM Database Privileged Operation | medium | 60100 |
| `107028` | 10 | `T1543.003` T1543.003 | Remote Access Tool Services Have Been Installed - Security | medium | 60100 |
| `107029` | 10 | `T1098` T1098 | A New Trust Was Created To A Domain | medium | 60100 |
| `107030` | 11 | `T1098` T1098 | Password Change on Directory Service Restore Mode (DSRM) Account | high | 60100 |
| `107031` | 10 | `T1484.001` T1484.001 | Group Policy Abuse for Privilege Addition | medium | 60100 |
| `107032` | 10 | `T1078` Valid Accounts | Suspicious Remote Logon with Explicit Credentials | medium | 60100 |
| `107033` | 11 | `T1574.001` T1574.001 | Microsoft Defender Blocked from Loading Unsigned DLL | high | 60000 |
| `107034` | 11 | `T1574.001` T1574.001 | Unsigned Binary Loaded From Suspicious Location | high | 60000 |
| `107035` | 11 | `T1574.001` T1574.001 | DHCP Server Loaded the CallOut DLL | high | 60002 |
| `107036` | 11 | `T1574.001` T1574.001 | DHCP Server Error Failed Loading the CallOut DLL | high | 60002 |
| `107037` | 10 | - | Certificate Use With No Strong Mapping | medium | 60002 |
| `107038` | 11 | `T1548` Abuse Elevation Control Mechanism | Vulnerable Netlogon Secure Channel Connection Allowed | high | 60002 |
| `107039` | 14 | `T1134.001` T1134.001 | Meterpreter or Cobalt Strike Getsystem Service Installation - System | high | 60002 |
| `107040` | 10 | `T1543.003` T1543.003 | Remote Access Tool Services Have Been Installed - System | medium | 60002 |
| `107041` | 10 | `T1053.005` T1053.005 | Scheduled Task Executed From A Suspicious Location | medium | 60000 |
| `107042` | 10 | `T1053.005` T1053.005 | Scheduled Task Executed Uncommon LOLBIN | medium | 60000 |
| `107043` | 11 | `T1055.012` T1055.012 | HackTool - CACTUSTORCH Remote Thread Creation | high | 61610 |
| `107044` | 13 | `T1055.001` T1055.001 | HackTool - Potential CobaltStrike Process Injection | high | 61610 |
| `107045` | 11 | `T1055` Process Injection | Rare Remote Thread Creation By Uncommon Source Image | high | 61610 |
| `107046` | 10 | `T1055` Process Injection | Remote Thread Creation By Uncommon Source Image | medium | 61610 |
| `107047` | 10 | `T1055.003` T1055.003 | Remote Thread Creation In Uncommon Target Image | medium | 61610 |
| `107048` | 10 | `T1547.009` T1547.009 | New Custom Shim Database Created | medium | 61613 |
| `107049` | 10 | `T1546.002` T1546.002 | Suspicious Screensaver Binary File Creation | medium | 61613 |
| `107050` | 11 | `T1547.009` T1547.009 | Creation Exe for Service with Unquoted Path | high | 61613 |
| `107051` | 10 | `T1547.009` T1547.009 | Desktop.INI Created by Uncommon Process | medium | 61613 |
| `107052` | 10 | `T1566` Phishing | Potential Initial Access via DLL Search Order Hijacking | medium | 61613 |
| `107053` | 11 | `T1547.001` T1547.001 | File Creation In Suspicious Directory By Msdt.EXE | high | 61613 |
| `107054` | 10 | `T1137` T1137 | New Outlook Macro Created | medium | 61613 |
| `107055` | 11 | `T1137` T1137 | Suspicious Outlook Macro Created | high | 61613 |
| `107056` | 11 | `T1547.001` T1547.001 | Potential Startup Shortcut Persistence Via PowerShell.EXE | high | 61613 |
| `107057` | 11 | `T1547` Boot or Logon Autostart Execution | Potential RipZip Attack on Startup Folder | high | 61613 |
| `107058` | 10 | `T1547.001` T1547.001 | Startup Folder File Write | medium | 61613 |
| `107059` | 10 | `T1055` Process Injection | Created Files by Microsoft Sync Center | medium | 61613 |
| `107060` | 11 | `T1546` T1546 | Suspicious Get-Variable.exe Creation | high | 61613 |
| `107061` | 11 | `T1204.002` T1204.002 | Suspicious Startup Folder Persistence | high | 61613 |
| `107062` | 11 | `T1053` Scheduled Task/Job | Suspicious Scheduled Task Write to System32 Tasks | high | 61613 |
| `107063` | 10 | `T1547.015` T1547.015 | Windows Terminal Profile Settings Modification By Uncommon Process | medium | 61613 |
| `107064` | 11 | - | LiveKD Kernel Memory Dump File Created | high | 61613 |
| `107065` | 10 | - | LiveKD Driver Creation | medium | 61613 |
| `107066` | 11 | - | LiveKD Driver Creation By Uncommon Process | high | 61613 |
| `107067` | 11 | `T1548.002` T1548.002 | UAC Bypass Using Consent and Comctl32 - File | high | 61613 |
| `107068` | 11 | `T1548.002` T1548.002 | UAC Bypass Using .NET Code Profiler on MMC | high | 61613 |
| `107069` | 11 | - | UAC Bypass Using EventVwr | high | 61613 |
| `107070` | 11 | `T1548.002` T1548.002 | UAC Bypass Using IEInstal - File | high | 61613 |
| `107071` | 11 | `T1548.002` T1548.002 | UAC Bypass Using MSConfig Token Modification - File | high | 61613 |
| `107072` | 11 | `T1548.002` T1548.002 | UAC Bypass Using NTFS Reparse Point - File | high | 61613 |
| `107073` | 11 | `T1548.002` T1548.002 | UAC Bypass Abusing Winsat Path Parsing - File | high | 61613 |
| `107074` | 11 | `T1548.002` T1548.002 | UAC Bypass Using Windows Media Player - File | high | 61613 |
| `107075` | 11 | `T1548.002` T1548.002 | UAC Bypass Using Windows Media Player - File | high | 61613 |
| `107076` | 10 | `T1574.001` T1574.001 | Creation of WerFault.exe/Wer.dll in Unusual Folder | medium | 61613 |
| `107077` | 11 | `T1547.001` T1547.001 | WinRAR Creating Files in Startup Locations | high | 61613 |
| `107078` | 11 | `T1546.003` T1546.003 | WMI Persistence - Script Event Consumer File Write | high | 61613 |
| `107079` | 10 | `T1546.002` T1546.002 | Writing Local Admin Share | medium | 61613 |
| `107080` | 11 | `T1574.001` T1574.001 | Aruba Network Service Potential DLL Sideloading | high | 61609 |
| `107081` | 10 | `T1218` T1218 | Potential DLL Sideloading Using Coregen.exe | medium | 61609 |
| `107082` | 10 | `T1574.001` T1574.001 | Potential DLL Sideloading Of DbgModel.DLL | medium | 61609 |
| `107083` | 10 | `T1574.001` T1574.001 | Potential DLL Sideloading Of MpSvc.DLL | medium | 61609 |
| `107084` | 10 | `T1574.001` T1574.001 | Potential DLL Sideloading Of MsCorSvc.DLL | medium | 61609 |
| `107085` | 10 | `T1574.001` T1574.001 | Potential Python DLL SideLoading | medium | 61609 |
| `107086` | 11 | `T1574.001` T1574.001 | Fax Service DLL Search Order Hijack | high | 61609 |
| `107087` | 11 | `T1574.001` T1574.001 | Potential DLL Sideloading Via VMware Xfer | high | 61609 |
| `107088` | 11 | `T1574.001` T1574.001 | Potential Mpclient.DLL Sideloading | high | 61609 |
| `107089` | 10 | `T1574.001` T1574.001 | Unsigned Module Loaded by ClickOnce Application | medium | 61609 |
| `107090` | 11 | `T1574.001` T1574.001 | Suspicious Unsigned Thor Scanner Execution | high | 61609 |
| `107091` | 11 | `T1548.002` T1548.002 | UAC Bypass Using Iscsicpl - ImageLoad | high | 61609 |
| `107092` | 11 | `T1546.003` T1546.003 | WMI Persistence - Command Line Event Consumer | high | 61609 |
| `107093` | 11 | `T1055` Process Injection | Network Connection Initiated Via Notepad.EXE | high | 61605 |
| `107094` | 10 | `T1055` Process Injection | Microsoft Sync Center Suspicious Network Connections | medium | 61605 |
| `107095` | 13 | `T1055` Process Injection | CobaltStrike Named Pipe | high | 61619 |
| `107096` | 13 | `T1055` Process Injection | CobaltStrike Named Pipe | high | 61619 |
| `107097` | 13 | `T1055` Process Injection | CobaltStrike Named Pipe | high | 61619 |
| `107098` | 13 | `T1055` Process Injection | CobaltStrike Named Pipe | high | 61619 |
| `107099` | 13 | `T1055` Process Injection | CobaltStrike Named Pipe | high | 61619 |
| `107100` | 13 | `T1055` Process Injection | CobaltStrike Named Pipe | high | 61619 |
| `107101` | 13 | `T1055` Process Injection | CobaltStrike Named Pipe | high | 61619 |
| `107102` | 13 | `T1055` Process Injection | CobaltStrike Named Pipe | high | 61619 |
| `107103` | 13 | `T1055` Process Injection | CobaltStrike Named Pipe | high | 61619 |
| `107104` | 13 | `T1055` Process Injection | CobaltStrike Named Pipe | high | 61619 |
| `107105` | 13 | `T1055` Process Injection | CobaltStrike Named Pipe | high | 61619 |
| `107125` | 13 | `T1055` Process Injection | CobaltStrike Named Pipe Patterns | high | 61619 |
| `107126` | 13 | `T1055` Process Injection | CobaltStrike Named Pipe Patterns | high | 61619 |
| `107127` | 13 | `T1055` Process Injection | CobaltStrike Named Pipe Patterns | high | 61619 |
| `107128` | 11 | `T1055` Process Injection | HackTool - CoercedPotato Named Pipe Creation | high | 61619 |
| `107129` | 11 | - | HackTool - DiagTrackEoP Default Named Pipe | high | 61619 |
| `107130` | 11 | `T1055` Process Injection | HackTool - EfsPotato Named Pipe Creation | high | 61619 |
| `107131` | 11 | `T1528` T1528 | HackTool - Koh Default Named Pipe | high | 61619 |
| `107132` | 12 | `T1055` Process Injection | Malicious Named Pipe Created | high | 61619 |
| `107133` | 10 | `T1078` Valid Accounts | Suspicious Computer Machine Password by PowerShell | medium | 91801 |
| `107134` | 10 | `T1053.005` T1053.005 | Powershell Create Scheduled Task | medium | 91801 |
| `107135` | 10 | `T1053.005` T1053.005 | Powershell Create Scheduled Task | medium | 91801 |
| `107136` | 10 | `T1574.012` T1574.012 | Registry-Free Process Scope COR_PROFILER | medium | 91801 |
| `107137` | 10 | `T1078.002` T1078.002 | DMSA Service Account Created in Specific OUs - PowerShell | medium | 91801 |
| `107138` | 10 | `T1574.011` T1574.011 | Service Registry Permissions Weakness Check | medium | 91801 |
| `107139` | 10 | `T1098` T1098 | Powershell LocalAccount Manipulation | medium | 91801 |
| `107140` | 10 | `T1484.001` T1484.001 | Modify Group Policy Settings - ScriptBlockLogging | medium | 91801 |
| `107141` | 11 | `T1055` Process Injection | PowerShell ShellCode | high | 91801 |
| `107142` | 10 | `T1546.015` T1546.015 | Suspicious GetTypeFromCLSID ShellExecute | medium | 91801 |
| `107143` | 10 | `T1547.004` T1547.004 | Winlogon Helper DLL | medium | 91801 |
| `107144` | 11 | `T1548` Abuse Elevation Control Mechanism | Credential Dumping Attempt Via Svchost | high | 61612 |
| `107145` | 10 | `T1548.002` T1548.002 | Function Call From Undocumented COM Interface EditionUpgradeManager | medium | 61612 |
| `107146` | 11 | `T1548.002` T1548.002 | UAC Bypass Using WOW64 Logger DLL Hijack | high | 61612 |
| `107147` | 11 | `T1547.001` T1547.001 | Suspicious Autorun Registry Modified via WMI | high | 61603 |
| `107148` | 11 | `T1546.001` T1546.001 | Change Default File Association To Executable Via Assoc | high | 61603 |
| `107149` | 11 | `T1546.008` T1546.008 | Potential Privilege Escalation Using Symlink Between Osk and Cmd | high | 61603 |
| `107150` | 11 | `T1546.008` T1546.008 | Sticky Key Like Backdoor Execution | high | 61603 |
| `107151` | 11 | `T1218.002` T1218.002 | Control Panel Items | high | 61603 |
| `107152` | 10 | `T1078.002` T1078.002 | New DMSA Service Account Created in Specific OUs | medium | 61603 |
| `107153` | 11 | `T1055.001` T1055.001 | ManageEngine Endpoint Central Dctask64.EXE Potential Abuse | high | 61603 |
| `107154` | 10 | `T1574.001` T1574.001 | Potential DLL Sideloading Via DeviceEnroller.EXE | medium | 61603 |
| `107155` | 11 | `T1548.002` T1548.002 | PowerShell Web Access Feature Enabled Via DISM | high | 61603 |
| `107156` | 11 | `T1574.001` T1574.001 | DLL Sideloading by VMware Xfer Utility | high | 61603 |
| `107157` | 11 | `T1055` Process Injection | Dllhost.EXE Execution Anomaly | high | 61603 |
| `107158` | 11 | `T1574.001` T1574.001 | New DNS ServerLevelPluginDll Installed Via Dnscmd.EXE | high | 61603 |
| `107159` | 11 | `T1548.002` T1548.002 | Potentially Suspicious Event Viewer Child Process | high | 61603 |
| `107160` | 11 | `T1548.002` T1548.002 | Explorer NOUACCHECK Flag | high | 61603 |
| `107161` | 11 | `T1574.001` T1574.001 | Suspicious GUP Usage | high | 61603 |
| `107162` | 11 | `T1055` Process Injection | HackTool - CoercedPotato Execution | high | 61603 |
| `107163` | 11 | `T1055` Process Injection | HackTool - CoercedPotato Execution | high | 61603 |
| `107164` | 11 | `T1055` Process Injection | HackTool - CoercedPotato Execution | high | 61603 |
| `107165` | 11 | `T1047` T1047 | HackTool - CrackMapExec Execution Patterns | high | 61603 |
| `107166` | 11 | `T1055` Process Injection | HackTool - DInjector PowerShell Cradle Execution | high | 61603 |
| `107167` | 12 | `T1548.002` T1548.002 | HackTool - Empire PowerShell UAC Bypass | high | 61603 |
| `107168` | 11 | `T1055.012` T1055.012 | HackTool - HollowReaper Execution | high | 61603 |
| `107169` | 10 | `T1134.001` T1134.001 | HackTool - Impersonate Execution | medium | 61603 |
| `107170` | 11 | - | HackTool - LocalPotato Execution | high | 61603 |
| `107171` | 11 | - | HackTool - LocalPotato Execution | high | 61603 |
| `107172` | 11 | - | HackTool - LocalPotato Execution | high | 61603 |
| `107173` | 14 | `T1134.001` T1134.001 | Potential Meterpreter/CobaltStrike Activity | high | 61603 |
| `107174` | 11 | `T1134.004` T1134.004 | HackTool - PPID Spoofing SelectMyParent Tool Execution | high | 61603 |
| `107175` | 11 | `T1134.004` T1134.004 | HackTool - PPID Spoofing SelectMyParent Tool Execution | high | 61603 |
| `107176` | 11 | `T1134.004` T1134.004 | HackTool - PPID Spoofing SelectMyParent Tool Execution | high | 61603 |
| `107177` | 11 | `T1134.004` T1134.004 | HackTool - PPID Spoofing SelectMyParent Tool Execution | high | 61603 |
| `107178` | 11 | `T1134.004` T1134.004 | HackTool - PPID Spoofing SelectMyParent Tool Execution | high | 61603 |
| `107179` | 11 | `T1134.001` T1134.001 | HackTool - SharpDPAPI Execution | high | 61603 |
| `107180` | 11 | `T1134.001` T1134.001 | HackTool - SharpImpersonation Execution | high | 61603 |
| `107181` | 11 | `T1134.001` T1134.001 | HackTool - SharpImpersonation Execution | high | 61603 |
| `107182` | 11 | `T1134.001` T1134.001 | HackTool - SharpImpersonation Execution | high | 61603 |
| `107183` | 11 | `T1134.001` T1134.001 | HackTool - SharpImpersonation Execution | high | 61603 |
| `107184` | 11 | `T1134.001` T1134.001 | HackTool - SharpImpersonation Execution | high | 61603 |
| `107185` | 11 | `T1053` Scheduled Task/Job | HackTool - SharPersist Execution | high | 61603 |
| `107186` | 11 | `T1053` Scheduled Task/Job | HackTool - SharPersist Execution | high | 61603 |
| `107187` | 11 | `T1053` Scheduled Task/Job | HackTool - SharPersist Execution | high | 61603 |
| `107188` | 11 | `T1053` Scheduled Task/Job | HackTool - SharPersist Execution | high | 61603 |
| `107189` | 11 | `T1053` Scheduled Task/Job | HackTool - SharPersist Execution | high | 61603 |
| `107190` | 11 | `T1053` Scheduled Task/Job | HackTool - SharPersist Execution | high | 61603 |
| `107191` | 11 | `T1068` Exploitation for Privilege Escalation | HKTL - SharpSuccessor Privilege Escalation Tool Execution | high | 61603 |
| `107192` | 11 | `T1068` Exploitation for Privilege Escalation | HKTL - SharpSuccessor Privilege Escalation Tool Execution | high | 61603 |
| `107193` | 11 | `T1068` Exploitation for Privilege Escalation | HKTL - SharpSuccessor Privilege Escalation Tool Execution | high | 61603 |
| `107194` | 11 | `T1068` Exploitation for Privilege Escalation | HKTL - SharpSuccessor Privilege Escalation Tool Execution | high | 61603 |
| `107195` | 11 | `T1068` Exploitation for Privilege Escalation | HackTool - SysmonEOP Execution | high | 61603 |
| `107196` | 11 | `T1068` Exploitation for Privilege Escalation | HackTool - SysmonEOP Execution | high | 61603 |
| `107197` | 11 | `T1548.002` T1548.002 | HackTool - UACMe Akagi Execution | high | 61603 |
| `107198` | 11 | `T1548.002` T1548.002 | HackTool - UACMe Akagi Execution | high | 61603 |
| `107199` | 11 | `T1548.002` T1548.002 | HackTool - UACMe Akagi Execution | high | 61603 |
| `107200` | 11 | `T1548.002` T1548.002 | HackTool - UACMe Akagi Execution | high | 61603 |
| `107201` | 11 | `T1548.002` T1548.002 | HackTool - UACMe Akagi Execution | high | 61603 |
| `107202` | 11 | `T1548.002` T1548.002 | HackTool - UACMe Akagi Execution | high | 61603 |
| `107203` | 11 | `T1082` System Information Discovery | HackTool - winPEAS Execution | high | 61603 |
| `107204` | 11 | `T1082` System Information Discovery | HackTool - winPEAS Execution | high | 61603 |
| `107205` | 11 | `T1082` System Information Discovery | HackTool - winPEAS Execution | high | 61603 |
| `107206` | 11 | `T1082` System Information Discovery | HackTool - winPEAS Execution | high | 61603 |
| `107207` | 11 | `T1082` System Information Discovery | HackTool - winPEAS Execution | high | 61603 |
| `107208` | 11 | `T1082` System Information Discovery | HackTool - winPEAS Execution | high | 61603 |
| `107209` | 10 | - | Windows Kernel Debugger Execution | medium | 61603 |
| `107210` | 10 | - | Windows Kernel Debugger Execution | medium | 61603 |
| `107211` | 11 | `T1055.001` T1055.001 | Mavinject Inject DLL Into Running Process | high | 61603 |
| `107212` | 11 | `T1574.008` T1574.008 | Using SettingSyncHost.exe as LOLBin | high | 61603 |
| `107213` | 10 | `T1547` Boot or Logon Autostart Execution | Suspicious Driver Install by pnputil.exe | medium | 61603 |
| `107214` | 11 | `T1547` Boot or Logon Autostart Execution | Suspicious GrpConv Execution | high | 61603 |
| `107215` | 10 | `T1055.001` T1055.001 | Potential DLL Injection Or Execution Using Tracker.exe | medium | 61603 |
| `107216` | 10 | `T1484.001` T1484.001 | Windows Default Domain GPO Modification via GPME | medium | 61603 |
| `107217` | 11 | `T1574.001` T1574.001 | Potential Mpclient.DLL Sideloading Via Defender Binaries | high | 61603 |
| `107218` | 11 | `T1055` Process Injection | Potential Process Injection Via Msra.EXE | high | 61603 |
| `107219` | 10 | `T1546.007` T1546.007 | Potential Persistence Via Netsh Helper DLL | medium | 61603 |
| `107220` | 11 | `T1543.003` T1543.003 | Suspicious Service DACL Modification Via Set-Service Cmdlet | high | 61603 |
| `107221` | 11 | `T1134.002` T1134.002 | PUA - AdvancedRun Suspicious Execution | high | 61603 |
| `107222` | 10 | `T1547.001` T1547.001 | Potential Persistence Attempt Via Run Keys Using Reg.EXE | medium | 61603 |
| `107223` | 10 | `T1547.001` T1547.001 | Direct Autorun Keys Modification | medium | 61603 |
| `107224` | 10 | `T1484.001` T1484.001 | Modify Group Policy Settings | medium | 61603 |
| `107225` | 10 | `T1574.011` T1574.011 | Changing Existing Service ImagePath Value Via Reg.EXE | medium | 61603 |
| `107226` | 11 | `T1548` Abuse Elevation Control Mechanism | Regedit as Trusted Installer | high | 61603 |
| `107227` | 10 | `T1574` T1574 | DLL Execution Via Register-cimprovider.exe | medium | 61603 |
| `107228` | 11 | `T1037.001` T1037.001 | Potential Persistence Via Logon Scripts - CommandLine | high | 61603 |
| `107229` | 10 | `T1574` T1574 | Regsvr32 DLL Execution With Uncommon Extension | medium | 61603 |
| `107230` | 11 | `T1036` T1036 | Renamed ZOHO Dctask64 Execution | high | 61603 |
| `107231` | 11 | `T1055.001` T1055.001 | Renamed Mavinject.EXE Execution | high | 61603 |
| `107232` | 11 | `T1574.001` T1574.001 | Renamed Vmnat.exe Execution | high | 61603 |
| `107233` | 11 | `T1055` Process Injection | Suspicious Rundll32 Invoking Inline VBScript | high | 61603 |
| `107234` | 11 | `T1212` T1212 | Suspicious NTLM Authentication on the Printer Spooler Service | high | 61603 |
| `107235` | 11 | `T1546.015` T1546.015 | Rundll32 Registered COM Objects | high | 61603 |
| `107236` | 11 | `T1543.003` T1543.003 | Allow Service Access Using Security Descriptor Tampering Via Sc.EXE | high | 61603 |
| `107237` | 11 | `T1543.003` T1543.003 | Deny Service Access Using Security Descriptor Tampering Via Sc.EXE | high | 61603 |
| `107238` | 10 | `T1543.003` T1543.003 | Potential Persistence Attempt Via Existing Service Tampering | medium | 61603 |
| `107239` | 11 | `T1053.005` T1053.005 | Suspicious Schtasks Execution AppData Folder | high | 61603 |
| `107240` | 11 | `T1053.005` T1053.005 | Suspicious Modification Of Scheduled Tasks | high | 61603 |
| `107241` | 11 | `T1053.005` T1053.005 | Suspicious Scheduled Task Creation Involving Temp Folder | high | 61603 |
| `107242` | 10 | `T1053.005` T1053.005 | Scheduled Task Creation with Curl and PowerShell Execution Combo | medium | 61603 |
| `107243` | 10 | `T1053.005` T1053.005 | Schedule Task Creation From Env Variable Or Potentially Suspicious ... | medium | 61603 |
| `107244` | 11 | `T1053.005` T1053.005 | Schtasks From Suspicious Folders | high | 61603 |
| `107245` | 10 | `T1053.005` T1053.005 | Suspicious Scheduled Task Name As GUID | medium | 61603 |
| `107246` | 11 | `T1053.005` T1053.005 | Potential SSH Tunnel Persistence Install Using A Scheduled Task | high | 61603 |
| `107247` | 10 | `T1053.005` T1053.005 | Potential Persistence Via Microsoft Compatibility Appraiser | medium | 61603 |
| `107248` | 11 | `T1053.005` T1053.005 | Potential Persistence Via Powershell Search Order Hijacking - Task | high | 61603 |
| `107249` | 10 | `T1053.005` T1053.005 | Scheduled Task Executing Payload from Registry | medium | 61603 |
| `107250` | 11 | `T1053.005` T1053.005 | Scheduled Task Executing Encoded Payload from Registry | high | 61603 |
| `107251` | 11 | `T1053.005` T1053.005 | Suspicious Schtasks Schedule Types | high | 61603 |
| `107252` | 10 | `T1053.005` T1053.005 | Suspicious Schtasks Schedule Type With High Privileges | medium | 61603 |
| `107253` | 10 | `T1036.005` T1036.005 | Suspicious Scheduled Task Creation via Masqueraded XML File | medium | 61603 |
| `107254` | 11 | `T1053.005` T1053.005 | Suspicious Command Patterns In Scheduled Task Creation | high | 61603 |
| `107255` | 11 | `T1053.005` T1053.005 | Schtasks Creation Or Modification With SYSTEM Privileges | high | 61603 |
| `107256` | 12 | `T1053.005` T1053.005 | Scheduled Task Creation Masquerading as System Processes | high | 61603 |
| `107257` | 10 | `T1548.002` T1548.002 | Sdclt Child Processes | medium | 61603 |
| `107258` | 10 | `T1574.005` T1574.005 | Setup16.EXE Execution With Custom .Lst File | medium | 61603 |
| `107259` | 12 | `T1548` Abuse Elevation Control Mechanism | Abused Debug Privilege by Arbitrary Parent Processes | high | 61603 |
| `107260` | 10 | `T1098` T1098 | User Added to Local Administrators Group | medium | 61603 |
| `107261` | 11 | `T1098` T1098 | User Added To Highly Privileged Group | high | 61603 |
| `107262` | 10 | `T1548.002` T1548.002 | Always Install Elevated Windows Installer | medium | 61603 |
| `107263` | 10 | `T1548.002` T1548.002 | Always Install Elevated Windows Installer | medium | 61603 |
| `107264` | 11 | `T1134.002` T1134.002 | Suspicious Child Process Created as System | high | 61603 |
| `107265` | 10 | `T1548.002` T1548.002 | Always Install Elevated MSI Spawned Cmd And Powershell | medium | 61603 |
| `107266` | 10 | `T1059` Command and Scripting Interpreter | Elevated System Shell Spawned From Uncommon Parent Location | medium | 61603 |
| `107267` | 10 | - | Suspicious RunAs-Like Flag Combination | medium | 61603 |
| `107268` | 10 | `T1548.002` T1548.002 | Registry Modification of MS-settings Protocol Handler | medium | 61603 |
| `107269` | 10 | `T1055` Process Injection | Process Creation Using Sysnative Folder | medium | 61603 |
| `107270` | 11 | `T1574.001` T1574.001 | Tasks Folder Evasion | high | 61603 |
| `107271` | 10 | `T1055` Process Injection | Suspicious Userinit Child Process | medium | 61603 |
| `107272` | 11 | `T1055` Process Injection | Suspect Svchost Activity | high | 61603 |
| `107273` | 11 | `T1036.005` T1036.005 | Uncommon Svchost Command Line Parameter | high | 61603 |
| `107274` | 10 | `T1543.003` T1543.003 | Sysinternals PsService Execution | medium | 61603 |
| `107275` | 10 | `T1543.003` T1543.003 | Sysinternals PsService Execution | medium | 61603 |
| `107276` | 10 | `T1543.003` T1543.003 | Sysinternals PsSuspend Execution | medium | 61603 |
| `107277` | 10 | `T1543.003` T1543.003 | Sysinternals PsSuspend Execution | medium | 61603 |
| `107278` | 11 | `T1548.002` T1548.002 | UAC Bypass Using ChangePK and SLUI | high | 61603 |
| `107279` | 11 | `T1548.002` T1548.002 | UAC Bypass Using Disk Cleanup | high | 61603 |
| `107280` | 11 | `T1548.002` T1548.002 | Bypass UAC via CMSTP | high | 61603 |
| `107281` | 11 | `T1548.002` T1548.002 | UAC Bypass Tools Using ComputerDefaults | high | 61603 |
| `107282` | 11 | `T1548.002` T1548.002 | UAC Bypass Using Consent and Comctl32 - Process | high | 61603 |
| `107283` | 11 | `T1548.002` T1548.002 | UAC Bypass Using DismHost | high | 61603 |
| `107284` | 11 | - | UAC Bypass Using Event Viewer RecentViews | high | 61603 |
| `107285` | 11 | `T1548.002` T1548.002 | Bypass UAC via Fodhelper.exe | high | 61603 |
| `107286` | 10 | `T1548` Abuse Elevation Control Mechanism | UAC Bypass via Windows Firewall Snap-In Hijack | medium | 61603 |
| `107287` | 11 | `T1548.002` T1548.002 | UAC Bypass via ICMLuaUtil | high | 61603 |
| `107288` | 11 | `T1548.002` T1548.002 | UAC Bypass Using IEInstal - Process | high | 61603 |
| `107289` | 11 | `T1548.002` T1548.002 | UAC Bypass Using MSConfig Token Modification - Process | high | 61603 |
| `107290` | 11 | `T1548.002` T1548.002 | UAC Bypass Using NTFS Reparse Point - Process | high | 61603 |
| `107291` | 11 | `T1548.002` T1548.002 | UAC Bypass Using NTFS Reparse Point - Process | high | 61603 |
| `107292` | 11 | `T1548.002` T1548.002 | UAC Bypass Using PkgMgr and DISM | high | 61603 |
| `107293` | 10 | `T1548.002` T1548.002 | Potential UAC Bypass Via Sdclt.EXE | medium | 61603 |
| `107294` | 11 | `T1548.002` T1548.002 | TrustedPath UAC Bypass Pattern | high | 61603 |
| `107295` | 11 | `T1548.002` T1548.002 | UAC Bypass Abusing Winsat Path Parsing - Process | high | 61603 |
| `107296` | 11 | `T1548.002` T1548.002 | UAC Bypass Using Windows Media Player - Process | high | 61603 |
| `107297` | 11 | `T1548.002` T1548.002 | UAC Bypass Using Windows Media Player - Process | high | 61603 |
| `107298` | 11 | `T1548.002` T1548.002 | Bypass UAC via WSReset.exe | high | 61603 |
| `107299` | 11 | `T1548.002` T1548.002 | UAC Bypass WSReset | high | 61603 |
| `107300` | 11 | `T1037.001` T1037.001 | Uncommon Userinit Child Process | high | 61603 |
| `107301` | 11 | `T1055` Process Injection | Suspicious Child Process Of Wermgr.EXE | high | 61603 |
| `107302` | 11 | `T1033` T1033 | Whoami.EXE Execution From Privileged Process | high | 61603 |
| `107303` | 11 | `T1033` T1033 | Security Privileges Enumeration Via Whoami.EXE | high | 61603 |
| `107304` | 11 | `T1546.003` T1546.003 | WMI Backdoor Exchange Transport Agent | high | 61603 |
| `107305` | 10 | `T1047` T1047 | Password Set to Never Expire via WMI | medium | 61603 |
| `107306` | 11 | `T1546.003` T1546.003 | New ActiveScriptEventConsumer Created Via Wmic.EXE | high | 61603 |
| `107307` | 11 | `T1574.001` T1574.001 | Xwizard.EXE Execution From Non-Default Location | high | 61603 |
| `107308` | 10 | `T1055.012` T1055.012 | Potential Process Hollowing Activity | medium | 61627 |
| `107309` | 11 | `T1548.002` T1548.002 | UAC Bypass Via Wsreset | high | 61615 |
| `107310` | 11 | `T1547.001` T1547.001 | Narrator's Feedback-Hub Persistence | high | 61615 |
| `107311` | 11 | `T1547.001` T1547.001 | Narrator's Feedback-Hub Persistence | high | 61615 |
| `107312` | 10 | `T1546.009` T1546.009 | New DLL Added to AppCertDlls Registry Key | medium | 61615 |
| `107313` | 10 | `T1546.009` T1546.009 | New DLL Added to AppCertDlls Registry Key | medium | 61615 |
| `107314` | 10 | `T1546.010` T1546.010 | New DLL Added to AppInit_DLLs Registry Key | medium | 61615 |
| `107315` | 11 | `T1547` Boot or Logon Autostart Execution | Registry Persistence Mechanisms in Recycle Bin | high | 61615 |
| `107316` | 11 | `T1547` Boot or Logon Autostart Execution | Registry Persistence Mechanisms in Recycle Bin | high | 61615 |
| `107317` | 11 | `T1547` Boot or Logon Autostart Execution | WINEKEY Registry Modification | high | 61615 |
| `107318` | 11 | `T1547.005` T1547.005 | Security Support Provider (SSP) Added to LSA Configuration | high | 61615 |
| `107319` | 11 | `T1546.008` T1546.008 | Sticky Key Like Backdoor Usage - Registry | high | 61615 |
| `107320` | 10 | `T1218` T1218 | Atbroker Registry Change | medium | 61615 |
| `107321` | 11 | `T1547.001` T1547.001 | Suspicious Run Key from Download | high | 61615 |
| `107322` | 12 | `T1547.008` T1547.008 | DLL Load via LSASS | high | 61615 |
| `107323` | 10 | `T1547.010` T1547.010 | Add Port Monitor Persistence in Registry | medium | 61615 |
| `107324` | 10 | `T1547.001` T1547.001 | Classes Autorun Keys Modification | medium | 61615 |
| `107325` | 10 | `T1547.001` T1547.001 | Common Autorun Keys Modification | medium | 61615 |
| `107326` | 10 | `T1547.001` T1547.001 | CurrentControlSet Autorun Keys Modification | medium | 61615 |
| `107327` | 10 | `T1547.001` T1547.001 | CurrentVersion Autorun Keys Modification | medium | 61615 |
| `107328` | 10 | `T1547.001` T1547.001 | CurrentVersion NT Autorun Keys Modification | medium | 61615 |
| `107329` | 10 | `T1547.001` T1547.001 | Internet Explorer Autorun Keys Modification | medium | 61615 |
| `107330` | 10 | `T1547.001` T1547.001 | Office Autorun Keys Modification | medium | 61615 |
| `107331` | 10 | `T1547.001` T1547.001 | Session Manager Autorun Keys Modification | medium | 61615 |
| `107332` | 10 | `T1547.001` T1547.001 | System Scripts Autorun Keys Modification | medium | 61615 |
| `107333` | 10 | `T1547.001` T1547.001 | WinSock2 Autorun Keys Modification | medium | 61615 |
| `107334` | 10 | `T1547.001` T1547.001 | Wow6432Node CurrentVersion Autorun Keys Modification | medium | 61615 |
| `107335` | 10 | `T1547.001` T1547.001 | Wow6432Node Classes Autorun Keys Modification | medium | 61615 |
| `107336` | 10 | `T1547.001` T1547.001 | Wow6432Node Windows NT CurrentVersion Autorun Keys Modification | medium | 61615 |
| `107337` | 11 | `T1548.002` T1548.002 | Bypass UAC Using DelegateExecute | high | 61615 |
| `107338` | 11 | `T1547.010` T1547.010 | Bypass UAC Using Event Viewer | high | 61615 |
| `107339` | 11 | `T1548.002` T1548.002 | Bypass UAC Using SilentCleanup Task | high | 61615 |
| `107340` | 11 | `T1547.010` T1547.010 | Default RDP Port Changed to Non Standard Port | high | 61615 |
| `107341` | 10 | `T1574` T1574 | Potential Registry Persistence Attempt Via DbgManagedDebugger | medium | 61615 |
| `107342` | 11 | `T1574.001` T1574.001 | DHCP Callout DLL Installation | high | 61615 |
| `107343` | 11 | `T1547.001` T1547.001 | Windows Event Log Access Tampering Via Registry | high | 61615 |
| `107344` | 11 | `T1547.001` T1547.001 | Windows Event Log Access Tampering Via Registry | high | 61615 |
| `107345` | 11 | `T1574.001` T1574.001 | New DNS ServerLevelPluginDll Installed | high | 61615 |
| `107346` | 11 | `T1546.007` T1546.007 | New Netsh Helper DLL Registered From A Suspicious Location | high | 61615 |
| `107347` | 10 | `T1546.007` T1546.007 | Potential Persistence Via Netsh Helper DLL - Registry | medium | 61615 |
| `107348` | 11 | `T1137` T1137 | Potential Persistence Via Outlook LoadMacroProviderOnBoot Setting | high | 61615 |
| `107349` | 11 | `T1137` T1137 | Outlook Macro Execution Without Warning Setting Enabled | high | 61615 |
| `107350` | 10 | `T1546.011` T1546.011 | Potential Persistence Via AppCompat RegisterAppRestart Layer | medium | 61615 |
| `107351` | 11 | `T1546.012` T1546.012 | Potential Persistence Via App Paths Default Property | high | 61615 |
| `107352` | 10 | `T1546.015` T1546.015 | Potential Persistence Using DebugPath | medium | 61615 |
| `107353` | 10 | `T1546.015` T1546.015 | Potential Persistence Using DebugPath | medium | 61615 |
| `107354` | 11 | `T1546.015` T1546.015 | COM Object Hijacking Via Modification Of Default System CLSID Defau... | high | 61615 |
| `107355` | 10 | `T1546.015` T1546.015 | Potential COM Object Hijacking Via TreatAs Subkey - Registry | medium | 61615 |
| `107356` | 11 | `T1546.015` T1546.015 | Potential PSFactoryBuffer COM Hijacking | high | 61615 |
| `107357` | 11 | `T1546.012` T1546.012 | Potential Persistence Via GlobalFlags | high | 61615 |
| `107358` | 11 | `T1546.012` T1546.012 | Potential Persistence Via GlobalFlags | high | 61615 |
| `107359` | 10 | `T1037.001` T1037.001 | Potential Persistence Via Logon Scripts - Registry | medium | 61615 |
| `107360` | 10 | `T1546.015` T1546.015 | Potential Persistence Via Scrobj.dll COM Hijacking | medium | 61615 |
| `107361` | 10 | `T1546.011` T1546.011 | Potential Persistence Via Shim Database Modification | medium | 61615 |
| `107362` | 11 | `T1546.011` T1546.011 | Suspicious Shim Database Patching Activity | high | 61615 |
| `107363` | 11 | `T1546.011` T1546.011 | Potential Persistence Via Shim Database In Uncommon Location | high | 61615 |
| `107364` | 10 | `T1547.001` T1547.001 | Suspicious PowerShell In Registry Run Keys | medium | 61615 |
| `107365` | 11 | `T1547.001` T1547.001 | Registry Persistence via Explorer Run Key | high | 61615 |
| `107366` | 11 | `T1547.001` T1547.001 | New RUN Key Pointing to Suspicious Folder | high | 61615 |
| `107367` | 10 | `T1548.002` T1548.002 | Suspicious Shell Open Command Registry Modification | medium | 61615 |
| `107368` | 11 | `T1053` Scheduled Task/Job | Scheduled TaskCache Change by Uncommon Program | high | 61615 |
| `107369` | 11 | `T1053.005` T1053.005 | Potential Registry Persistence Attempt Via Windows Telemetry | high | 61615 |
| `107370` | 10 | `T1546.015` T1546.015 | COM Hijacking via TreatAs | medium | 61615 |
| `107371` | 11 | `T1548.002` T1548.002 | UAC Bypass via Event Viewer | high | 61615 |
| `107372` | 11 | `T1548.002` T1548.002 | UAC Bypass via Sdclt | high | 61615 |
| `107374` | 11 | `T1548.002` T1548.002 | UAC Bypass Abusing Winsat Path Parsing - Registry | high | 61615 |
| `107375` | 11 | `T1548.002` T1548.002 | UAC Bypass Using Windows Media Player - Registry | high | 61615 |
| `107376` | 10 | `T1548.002` T1548.002 | UAC Disabled | medium | 61615 |
| `107377` | 10 | `T1548.002` T1548.002 | UAC Notification Disabled | medium | 61615 |
| `107378` | 10 | `T1548.002` T1548.002 | UAC Secure Desktop Prompt Disabled | medium | 61615 |
| `107379` | 11 | `T1547.001` T1547.001 | VBScript Payload Stored in Registry | high | 61615 |
| `107380` | 11 | `T1547.004` T1547.004 | Winlogon Notify Key Logon Persistence | high | 61615 |
| `107381` | 10 | `T1546.003` T1546.003 | WMI Event Subscription | medium | 61621 |
| `107382` | 11 | `T1047` T1047 | Suspicious Encoded Scripts in a WMI Consumer | high | 61621 |

### Defense Evasion (TA0005) — 42 rules

| Rule ID | Level | Technique | Description | Confidence | Parent SID |
|---------|-------|-----------|-------------|------------|------------|
| `112000` | 9 | `T1574.002` T1574.002 | DLL loaded from suspicious path | medium | 61609 |
| `112001` | 10 | `T1218.011` T1218.011 | Suspicious process: rundll32 | high | 61603 |
| `112002` | 9 | `T1218.011` T1218.011 | File created by rundll32 | medium | 61613 |
| `112003` | 9 | `T1574.002` T1574.002 | DLL loaded from suspicious path | medium | 61609 |
| `112004` | 10 | `T1197` T1197 | Suspicious process: bitsadmin | high | 61603 |
| `112005` | 10 | `T1197` T1197 | Suspicious process: bitsadmin | high | 61603 |
| `112006` | 10 | `T1218.010` T1218.010 | Suspicious process: regsvr32 | high | 61603 |
| `112007` | 10 | `T1218.010` T1218.010 | Suspicious process: regsvr32 | high | 61603 |
| `112008` | 10 | `T1218.010` T1218.010 | DLL sideloading by regsvr32 | high | 61609 |
| `112009` | 10 | `T1218.010` T1218.010 | Network connection by regsvr32 | high | 61605 |
| `112010` | 10 | `T1140` T1140 | Suspicious process: certutil | high | 61603 |
| `112011` | 10 | `T1140` T1140 | Suspicious process: certutil | high | 61603 |
| `112012` | 9 | `T1140` T1140 | File created by certutil | medium | 61613 |
| `112013` | 10 | `T1218.004` T1218.004 | Suspicious process: installutil | high | 61603 |
| `112014` | 10 | `T1218.004` T1218.004 | Suspicious process: installutil | high | 61603 |
| `112015` | 10 | `T1218.005` T1218.005 | Suspicious process: mshta | high | 61603 |
| `112016` | 10 | `T1218.005` T1218.005 | Suspicious process: mshta | high | 61603 |
| `112017` | 10 | `T1218.005` T1218.005 | DLL sideloading by mshta | high | 61609 |
| `112018` | 10 | `T1218.005` T1218.005 | Network connection by mshta | high | 61605 |
| `112019` | 10 | `T1218.005` T1218.005 | Network connection by mshta | high | 61605 |
| `112020` | 10 | `T1218.003` T1218.003 | Suspicious process: cmstp | high | 61603 |
| `112021` | 10 | `T1218.011` T1218.011 | Suspicious process: rundll32 | high | 61603 |
| `112022` | 10 | `T1218.011` T1218.011 | DLL sideloading by rundll32 | high | 61609 |
| `112023` | 10 | `T1218.011` T1218.011 | Network connection by rundll32 | high | 61605 |
| `112024` | 10 | `T1140` T1140 | Network connection by certutil | high | 61605 |
| `112025` | 10 | `T1218.003` T1218.003 | Suspicious process: cmstp | high | 61603 |
| `112026` | 9 | `T1574.002` T1574.002 | DLL loaded from suspicious path | medium | 61609 |
| `112027` | 10 | `T1218.011` T1218.011 | Network connection by rundll32 | high | 61605 |
| `112028` | 9 | `T1574.002` T1574.002 | DLL loaded from suspicious path | medium | 61609 |
| `112029` | 9 | `T1112` T1112 | Registry persistence via shell | medium | 61615 |
| `112030` | 9 | `T1112` T1112 | Registry persistence via shell | medium | 61614 |
| `112031` | 10 | `T1218.007` T1218.007 | DLL sideloading by msiexec | high | 61609 |
| `112032` | 10 | `T1218.011` T1218.011 | Network connection by rundll32 | high | 61605 |
| `112033` | 10 | `T1218.010` T1218.010 | Network connection by regsvr32 | high | 61605 |
| `112034` | 10 | `T1218.005` T1218.005 | Network connection by mshta | high | 61605 |
| `112035` | 10 | `T1218.005` T1218.005 | Network connection by mshta | high | 61605 |
| `112036` | 9 | `T1574.002` T1574.002 | DLL loaded from suspicious path | medium | 61609 |
| `112037` | 9 | `T1036` T1036 | Account renamed | medium | 60100 |
| `112038` | 9 | `T1562.001` T1562.001 | Suspicious PowerShell: set-mppreference -disablerealtimemonitoring | medium | 91801 |
| `112039` | 9 | `T1112` T1112 | Registry persistence via currentversion\explorer\shell | medium | 61614 |
| `112040` | 9 | `T1027` Obfuscated Files or Information | Suspicious PowerShell: invoke-obfuscation | medium | 91801 |
| `112041` | 10 | `T1218.004` T1218.004 | DLL sideloading by installutil | high | 61609 |

### Credential Access (TA0006) — 290 rules

| Rule ID | Level | Technique | Description | Confidence | Parent SID |
|---------|-------|-----------|-------------|------------|------------|
| `108500` | 11 | `T1003.002` T1003.002 | Suspicious command: reg save | medium | 61603 |
| `108501` | 12 | `T1003.001` T1003.001 | LSASS memory access | high | 61612 |
| `108502` | 12 | `T1003.001` T1003.001 | Suspicious process: procdump | high | 61603 |
| `108503` | 11 | `T1003.003` T1003.003 | Suspicious command: ntdsutil | medium | 61603 |
| `108504` | 9 | `T1110` Brute Force | Failed logon attempt | low | 60100 |
| `108505` | 12 | `T1003.001` T1003.001 | Remote thread injection into LSASS | high | 61610 |
| `108506` | 12 | `T1003.001` T1003.001 | LSASS memory access | high | 61612 |
| `108507` | 11 | `T1003.001` T1003.001 | Suspicious PowerShell: minidump | medium | 91801 |
| `108508` | 12 | `T1003.001` T1003.001 | LSASS memory access | high | 61612 |
| `108509` | 12 | `T1003.001` T1003.001 | LSASS memory access | high | 61612 |
| `108510` | 12 | `T1003.001` T1003.001 | LSASS memory access | high | 61612 |
| `108511` | 11 | `T1003.001` T1003.001 | File created by procdump | medium | 61613 |
| `108512` | 11 | `T1003.001` T1003.001 | Suspicious command: dumpert | medium | 61603 |
| `108513` | 11 | `T1003.001` T1003.001 | Suspicious command: comsvcs.dll | medium | 61603 |
| `108514` | 11 | `T1003.001` T1003.001 | Suspicious command: minidump | medium | 61603 |
| `108515` | 12 | `T1003.001` T1003.001 | LSASS memory access | high | 61612 |
| `108516` | 12 | `T1003.001` T1003.001 | LSASS memory access | high | 61612 |
| `108517` | 13 | `T1003` OS Credential Dumping | Suspicious service: mimikatz driver (mimidrv) | high | 60002 |
| `108518` | 13 | `T1003` OS Credential Dumping | PowerShell module: invoke-mimikatz | medium | 91801 |
| `108519` | 13 | `T1003.001` T1003.001 | PowerShell module: sekurlsa:: | medium | 91801 |
| `108520` | 13 | `T1003` OS Credential Dumping | Suspicious process: mimikatz | high | 61603 |
| `108521` | 11 | `T1003.001` T1003.001 | Suspicious PowerShell: comsvcs.dll | medium | 91801 |
| `108522` | 13 | `T1003` OS Credential Dumping | Suspicious PowerShell: invoke-mimikatz | medium | 91801 |
| `108523` | 12 | `T1003.001` T1003.001 | LSASS Process Crashed - Application | high | 60003 |
| `108524` | 11 | `T1003.003` T1003.003 | Ntdsutil Abuse | medium | 60003 |
| `108525` | 11 | `T1110` Brute Force | MSSQL Server Failed Logon From External Network | medium | 60003 |
| `108526` | 11 | `T1649` T1649 | Certificate Private Key Acquired | medium | 60000 |
| `108527` | 11 | `T1649` T1649 | Certificate Exported From Local Certificate Store | medium | 60000 |
| `108528` | 11 | - | Standard User In High Privileged Group | medium | 60000 |
| `108529` | 11 | `T1110` Brute Force | NTLM Brute Force | medium | 60000 |
| `108530` | 12 | `T1003.006` T1003.006 | Active Directory Replication from Non Machine Account | high | 60100 |
| `108531` | 13 | `T1003.006` T1003.006 | Mimikatz DC Sync | high | 60100 |
| `108532` | 12 | `T1003.004` T1003.004 | DPAPI Domain Backup Key Extraction | high | 60100 |
| `108533` | 11 | `T1003.004` T1003.004 | DPAPI Domain Master Key Backup Attempt | medium | 60100 |
| `108534` | 12 | `T1003.002` T1003.002 | Possible Impacket SecretDump Remote Activity | high | 60100 |
| `108535` | 11 | `T1558.003` T1558.003 | Kerberoasting Activity - Initial Query | medium | 60100 |
| `108536` | 12 | `T1003.001` T1003.001 | LSASS Access From Non System Account | medium | 60100 |
| `108537` | 12 | `T1003.001` T1003.001 | Credential Dumping Tools Service Execution - Security | high | 60100 |
| `108538` | 12 | `T1003` OS Credential Dumping | WCE wceaux.dll Access | high | 60100 |
| `108539` | 12 | `T1187` T1187 | Possible PetitPotam Coerce Authentication Attempt | high | 60100 |
| `108540` | 12 | `T1187` T1187 | PetitPotam Suspicious Kerberos TGT Request | high | 60100 |
| `108541` | 11 | `T1207` T1207 | Possible DC Shadow Attack | medium | 60100 |
| `108542` | 11 | `T1207` T1207 | Possible DC Shadow Attack | medium | 60100 |
| `108543` | 12 | `T1558` Steal or Forge Kerberos Tickets | Replay Attack Detected | high | 60100 |
| `108544` | 11 | `T1003` OS Credential Dumping | File Access Of Signal Desktop Sensitive Data | medium | 60100 |
| `108545` | 12 | `T1212` T1212 | Kerberos Manipulation | high | 60100 |
| `108546` | 12 | `T1003.001` T1003.001 | Password Dumper Activity on LSASS | high | 60100 |
| `108547` | 12 | `T1003.001` T1003.001 | Potentially Suspicious AccessMask Requested From LSASS | medium | 60100 |
| `108548` | 12 | `T1003.001` T1003.001 | Potentially Suspicious AccessMask Requested From LSASS | medium | 60100 |
| `108549` | 11 | `T1558.003` T1558.003 | Suspicious Kerberos RC4 Ticket Encryption | medium | 60100 |
| `108550` | 12 | `T1528` T1528 | Suspicious Teams Application Related ObjectAcess Event | high | 60100 |
| `108551` | 12 | `T1003.002` T1003.002 | Transferring Files with Credential Data via Network Shares | medium | 60100 |
| `108552` | 12 | `T1558.003` T1558.003 | User Couldn't Call a Privileged Service 'LsaRegisterLogonProcess' | high | 60100 |
| `108553` | 11 | `T1110.001` T1110.001 | Suspicious Rejected SMB Guest Logon From IP | medium | 60000 |
| `108554` | 12 | `T1003.002` T1003.002 | Critical Hive In Suspicious Location Access Bits Cleared | high | 60002 |
| `108555` | 11 | `T1003.002` T1003.002 | Crash Dump Created By Operating System | medium | 60002 |
| `108556` | 12 | `T1003.001` T1003.001 | Credential Dumping Tools Service Execution - System | high | 60002 |
| `108557` | 12 | `T1003.001` T1003.001 | LSASS Access Detected via Attack Surface Reduction | high | 60005 |
| `108558` | 12 | `T1555.005` T1555.005 | Remote Thread Created In KeePass.EXE | high | 61610 |
| `108559` | 12 | - | Remote Thread Creation In Mstsc.Exe From Suspicious Location | high | 61610 |
| `108560` | 12 | `T1003.001` T1003.001 | Potential Credential Dumping Attempt Via PowerShell Remote Thread | high | 61610 |
| `108561` | 12 | `T1003.001` T1003.001 | Password Dumper Remote Thread in LSASS | high | 61610 |
| `108562` | 12 | `T1599.001` T1599.001 | WinDivert Driver Load | high | 61608 |
| `108563` | 12 | `T1599.001` T1599.001 | WinDivert Driver Load | high | 61608 |
| `108564` | 11 | `T1003` OS Credential Dumping | Credential Manager Access By Uncommon Applications | medium | 61613 |
| `108565` | 11 | `T1555.004` T1555.004 | Access To Windows Credential History File By Uncommon Applications | medium | 61613 |
| `108566` | 11 | `T1003` OS Credential Dumping | Access To Crypto Currency Wallets By Uncommon Applications | medium | 61613 |
| `108567` | 11 | `T1555.004` T1555.004 | Access To Windows DPAPI Master Keys By Uncommon Applications | medium | 61613 |
| `108568` | 11 | `T1552.006` T1552.006 | Access To Potentially Sensitive Sysvol Files By Uncommon Applications | medium | 61613 |
| `108569` | 11 | `T1528` T1528 | Microsoft Teams Sensitive File Access By Uncommon Applications | medium | 61613 |
| `108570` | 12 | `T1003.001` T1003.001 | Cred Dump Tools Dropped Files | high | 61613 |
| `108571` | 12 | `T1003.001` T1003.001 | Cred Dump Tools Dropped Files | high | 61613 |
| `108573` | 12 | `T1003.001` T1003.001 | HackTool - Dumpert Process Dumper Default File | high | 61613 |
| `108574` | 12 | `T1552.001` T1552.001 | HackTool - Typical HiveNightmare SAM File Export | high | 61613 |
| `108575` | 12 | `T1552.001` T1552.001 | HackTool - Typical HiveNightmare SAM File Export | high | 61613 |
| `108576` | 13 | `T1558` Steal or Forge Kerberos Tickets | HackTool - Mimikatz Kirbi File Creation | high | 61613 |
| `108577` | 12 | - | HackTool - NPPSpy Hacktool Usage | high | 61613 |
| `108578` | 12 | `T1003.002` T1003.002 | HackTool - QuarksPwDump Dump File | high | 61613 |
| `108580` | 12 | `T1003.001` T1003.001 | HackTool - SafetyKatz Dump Indicator | high | 61613 |
| `108582` | 12 | `T1003.001` T1003.001 | LSASS Process Memory Dump Files | high | 61613 |
| `108583` | 12 | `T1003.001` T1003.001 | LSASS Process Memory Dump Files | high | 61613 |
| `108584` | 12 | `T1003.001` T1003.001 | LSASS Process Memory Dump Files | high | 61613 |
| `108585` | 12 | `T1003.001` T1003.001 | LSASS Process Memory Dump Files | high | 61613 |
| `108586` | 12 | `T1003.001` T1003.001 | LSASS Process Memory Dump Files | high | 61613 |
| `108587` | 12 | `T1003.001` T1003.001 | LSASS Process Dump Artefact In CrashDumps Folder | high | 61613 |
| `108588` | 12 | `T1003.001` T1003.001 | WerFault LSASS Process Memory Dump | high | 61613 |
| `108589` | 12 | `T1003.003` T1003.003 | NTDS.DIT Creation By Uncommon Parent Process | high | 61613 |
| `108590` | 12 | `T1003.002` T1003.002 | NTDS.DIT Creation By Uncommon Process | high | 61613 |
| `108591` | 12 | `T1003.003` T1003.003 | NTDS Exfiltration Filename Patterns | high | 61613 |
| `108592` | 12 | `T1003.002` T1003.002 | Potential SAM Database Dump | high | 61613 |
| `108593` | 12 | `T1003.002` T1003.002 | Potential SAM Database Dump | high | 61613 |
| `108594` | 12 | `T1555` T1555 | DPAPI Backup Keys And Certificate Export Activity IOC | high | 61613 |
| `108595` | 12 | `T1003.001` T1003.001 | LSASS Process Memory Dump Creation Via Taskmgr.EXE | high | 61613 |
| `108596` | 12 | `T1003.001` T1003.001 | Suspicious Renamed Comsvcs DLL Loaded By Rundll32 | high | 61609 |
| `108597` | 11 | `T1056.002` T1056.002 | CredUI.DLL Loaded By Uncommon Process | medium | 61609 |
| `108598` | 12 | `T1003.001` T1003.001 | Suspicious Unsigned Dbghelp/Dbgcore DLL Loaded | high | 61609 |
| `108599` | 12 | `T1218` T1218 | Time Travel Debugging Utility Usage - Image | high | 61609 |
| `108600` | 12 | `T1003.001` T1003.001 | Unsigned Image Loaded Into LSASS Process | medium | 61609 |
| `108601` | 12 | `T1003` OS Credential Dumping | Suspicious Loading of Dbgcore/Dbghelp DLLs from Uncommon Location | high | 61609 |
| `108602` | 11 | `T1558` Steal or Forge Kerberos Tickets | Uncommon Outbound Kerberos Connection | medium | 61605 |
| `108603` | 13 | `T1003.001` T1003.001 | HackTool - Credential Dumping Tools Named Pipe Created | high | 61619 |
| `108604` | 12 | `T1003.003` T1003.003 | Suspicious Get-ADDBAccount Usage | high | 91801 |
| `108605` | 11 | `T1555.003` T1555.003 | Access to Browser Login Data | medium | 91801 |
| `108606` | 12 | `T1003.003` T1003.003 | Create Volume Shadow Copy with Powershell | high | 91801 |
| `108607` | 11 | `T1555` T1555 | Dump Credentials from Windows Credential Manager With PowerShell | medium | 91801 |
| `108608` | 11 | `T1555` T1555 | Dump Credentials from Windows Credential Manager With PowerShell | medium | 91801 |
| `108609` | 11 | `T1555` T1555 | Dump Credentials from Windows Credential Manager With PowerShell | medium | 91801 |
| `108610` | 11 | `T1555` T1555 | Enumerate Credentials from Windows Credential Manager With PowerShell | medium | 91801 |
| `108611` | 11 | `T1552.004` T1552.004 | Certificate Exported Via PowerShell - ScriptBlock | medium | 91801 |
| `108612` | 11 | `T1003.006` T1003.006 | Suspicious Get-ADReplAccount | medium | 91801 |
| `108613` | 12 | `T1003` OS Credential Dumping | HackTool - Rubeus Execution - ScriptBlock | high | 91801 |
| `108614` | 12 | `T1046` T1046 | HackTool - WinPwn Execution - ScriptBlock | high | 91801 |
| `108615` | 11 | `T1056.001` T1056.001 | Powershell Keylogging | medium | 91801 |
| `108616` | 11 | `T1056.001` T1056.001 | Powershell Keylogging | medium | 91801 |
| `108617` | 12 | `T1003` OS Credential Dumping | Live Memory Dump Using Powershell | high | 91801 |
| `108618` | 11 | `T1040` T1040 | Potential Packet Capture Activity Via Start-NetEventSession - Scrip... | medium | 91801 |
| `108619` | 13 | `T1003` OS Credential Dumping | Potential Invoke-Mimikatz PowerShell Script | high | 91801 |
| `108620` | 13 | `T1003` OS Credential Dumping | Potential Invoke-Mimikatz PowerShell Script | high | 91801 |
| `108621` | 13 | `T1003` OS Credential Dumping | Potential Invoke-Mimikatz PowerShell Script | high | 91801 |
| `108622` | 12 | `T1059.001` T1059.001 | PowerShell Credential Prompt | high | 91801 |
| `108623` | 12 | `T1558.003` T1558.003 | Suspicious Kerberos Ticket Request via PowerShell Script - ScriptBlock | high | 91801 |
| `108624` | 11 | `T1552.001` T1552.001 | Extracting Information with PowerShell | medium | 91801 |
| `108625` | 12 | `T1003.001` T1003.001 | PowerShell Get-Process LSASS in ScriptBlock | high | 91801 |
| `108626` | 12 | - | Veeam Backup Servers Credential Dumping Script Execution | high | 91801 |
| `108627` | 13 | `T1003.001` T1003.001 | HackTool - Generic Process Access | high | 61612 |
| `108628` | 12 | `T1003.001` T1003.001 | HackTool - Generic Process Access | high | 61612 |
| `108629` | 12 | `T1003.001` T1003.001 | Lsass Memory Dump via Comsvcs DLL | high | 61612 |
| `108630` | 12 | `T1003.001` T1003.001 | LSASS Memory Access by Tool With Dump Keyword In Name | high | 61612 |
| `108631` | 12 | `T1003.001` T1003.001 | Potential Credential Dumping Activity Via LSASS | medium | 61612 |
| `108632` | 12 | `T1003.001` T1003.001 | Credential Dumping Activity By Python Based Tool | high | 61612 |
| `108633` | 12 | `T1003.001` T1003.001 | Remote LSASS Process Access Through Windows Remote Management | high | 61612 |
| `108634` | 12 | `T1003.001` T1003.001 | Suspicious LSASS Access Via MalSecLogon | high | 61612 |
| `108635` | 12 | `T1003.001` T1003.001 | Potentially Suspicious GrantedAccess Flags On LSASS | medium | 61612 |
| `108636` | 12 | `T1003.001` T1003.001 | Credential Dumping Attempt Via WerFault | high | 61612 |
| `108637` | 12 | `T1003.001` T1003.001 | LSASS Access From Potentially White-Listed Processes | high | 61612 |
| `108638` | 12 | `T1003.001` T1003.001 | Suspicious Process Access to LSASS with Dbgcore/Dbghelp DLLs | high | 61612 |
| `108639` | 12 | `T1185` T1185 | Potential Data Stealing Via Chromium Headless Debugging | high | 61603 |
| `108640` | 11 | `T1185` T1185 | Browser Started with Remote Debugging | medium | 61603 |
| `108641` | 11 | `T1185` T1185 | Browser Started with Remote Debugging | medium | 61603 |
| `108642` | 12 | `T1218.011` T1218.011 | Process Access via TrolleyExpress Exclusion | high | 61603 |
| `108643` | 12 | - | Copy .DMP/.DUMP Files From Remote Share Via Cmd.EXE | high | 61603 |
| `108644` | 12 | `T1003.002` T1003.002 | VolumeShadowCopy Symlink Creation Via Mklink | high | 61603 |
| `108645` | 11 | `T1003.005` T1003.005 | New Generic Credentials Added Via Cmdkey.EXE | medium | 61603 |
| `108646` | 12 | `T1003.005` T1003.005 | Potential Reconnaissance For Cached Credentials Via Cmdkey.EXE | high | 61603 |
| `108647` | 12 | `T1036` T1036 | CreateDump Process Dump | high | 61603 |
| `108648` | 12 | `T1003.001` T1003.001 | Potential Windows Defender AV Bypass Via Dump64.EXE Rename | high | 61603 |
| `108649` | 11 | `T1036` T1036 | DumpMinitool Execution | medium | 61603 |
| `108650` | 12 | `T1036` T1036 | Suspicious DumpMinitool Execution | high | 61603 |
| `108651` | 11 | `T1003` OS Credential Dumping | Esentutl Gather Credentials | medium | 61603 |
| `108652` | 12 | `T1003.002` T1003.002 | Copying Sensitive Files with Credential Data | high | 61603 |
| `108653` | 11 | `T1218` T1218 | Remote File Download Via Findstr.EXE | medium | 61603 |
| `108654` | 12 | `T1552.006` T1552.006 | Findstr GPP Passwords | high | 61603 |
| `108655` | 12 | `T1552.006` T1552.006 | LSASS Process Reconnaissance Via Findstr.EXE | high | 61603 |
| `108656` | 11 | `T1552.006` T1552.006 | Permission Misconfiguration Reconnaissance Via Findstr.EXE | medium | 61603 |
| `108657` | 12 | `T1003.001` T1003.001 | HackTool - CrackMapExec Process Patterns | high | 61603 |
| `108658` | 12 | `T1003.001` T1003.001 | HackTool - CrackMapExec Process Patterns | high | 61603 |
| `108659` | 12 | `T1003.001` T1003.001 | HackTool - CrackMapExec Process Patterns | high | 61603 |
| `108660` | 12 | `T1003.001` T1003.001 | HackTool - CreateMiniDump Execution | high | 61603 |
| `108661` | 12 | `T1003.001` T1003.001 | HackTool - CreateMiniDump Execution | high | 61603 |
| `108662` | 12 | `T1003.001` T1003.001 | HackTool - Doppelanger LSASS Dumper Execution | high | 61603 |
| `108663` | 12 | `T1003.001` T1003.001 | HackTool - Doppelanger LSASS Dumper Execution | high | 61603 |
| `108664` | 12 | `T1003.001` T1003.001 | HackTool - Dumpert Process Dumper Execution | high | 61603 |
| `108665` | 12 | `T1003.001` T1003.001 | HackTool - Dumpert Process Dumper Execution | high | 61603 |
| `108666` | 12 | `T1588.002` T1588.002 | Hacktool Execution - Imphash | high | 61603 |
| `108667` | 12 | `T1588.002` T1588.002 | Hacktool Execution - PE Metadata | high | 61603 |
| `108668` | 12 | `T1003.001` T1003.001 | HackTool - HandleKatz LSASS Dumper Execution | high | 61603 |
| `108669` | 12 | `T1003.001` T1003.001 | HackTool - HandleKatz LSASS Dumper Execution | high | 61603 |
| `108670` | 12 | `T1003.001` T1003.001 | HackTool - HandleKatz LSASS Dumper Execution | high | 61603 |
| `108671` | 12 | `T1110.002` T1110.002 | HackTool - Hashcat Password Cracker Execution | high | 61603 |
| `108672` | 12 | `T1110.002` T1110.002 | HackTool - Hashcat Password Cracker Execution | high | 61603 |
| `108673` | 12 | `T1110` Brute Force | HackTool - Hydra Password Bruteforce Execution | high | 61603 |
| `108674` | 12 | `T1003.001` T1003.001 | HackTool - Inveigh Execution | high | 61603 |
| `108675` | 12 | `T1003.001` T1003.001 | HackTool - Inveigh Execution | high | 61603 |
| `108676` | 12 | `T1003.001` T1003.001 | HackTool - Inveigh Execution | high | 61603 |
| `108677` | 12 | `T1003.001` T1003.001 | HackTool - Inveigh Execution | high | 61603 |
| `108678` | 12 | `T1558.003` T1558.003 | HackTool - KrbRelay Execution | high | 61603 |
| `108679` | 12 | `T1558.003` T1558.003 | HackTool - KrbRelay Execution | high | 61603 |
| `108680` | 12 | `T1558.003` T1558.003 | HackTool - KrbRelay Execution | high | 61603 |
| `108681` | 12 | `T1558.003` T1558.003 | HackTool - KrbRelay Execution | high | 61603 |
| `108682` | 12 | `T1558.003` T1558.003 | HackTool - KrbRelay Execution | high | 61603 |
| `108683` | 12 | `T1558.003` T1558.003 | HackTool - RemoteKrbRelay Execution | high | 61603 |
| `108684` | 12 | `T1558.003` T1558.003 | HackTool - KrbRelayUp Execution | high | 61603 |
| `108685` | 12 | `T1558.003` T1558.003 | HackTool - KrbRelayUp Execution | high | 61603 |
| `108686` | 12 | `T1558.003` T1558.003 | HackTool - KrbRelayUp Execution | high | 61603 |
| `108687` | 12 | `T1558.003` T1558.003 | HackTool - KrbRelayUp Execution | high | 61603 |
| `108688` | 12 | `T1558.003` T1558.003 | HackTool - KrbRelayUp Execution | high | 61603 |
| `108689` | 11 | - | HackTool - LaZagne Execution | medium | 61603 |
| `108690` | 11 | - | HackTool - LaZagne Execution | medium | 61603 |
| `108691` | 13 | `T1003.001` T1003.001 | HackTool - Mimikatz Execution | high | 61603 |
| `108692` | 13 | `T1003.001` T1003.001 | HackTool - Mimikatz Execution | high | 61603 |
| `108693` | 13 | `T1003.001` T1003.001 | HackTool - Mimikatz Execution | high | 61603 |
| `108694` | 12 | `T1003.002` T1003.002 | HackTool - Pypykatz Credentials Dumping Activity | high | 61603 |
| `108695` | 12 | `T1003.002` T1003.002 | HackTool - Quarks PwDump Execution | high | 61603 |
| `108696` | 12 | `T1003.002` T1003.002 | HackTool - Quarks PwDump Execution | high | 61603 |
| `108697` | 12 | `T1003` OS Credential Dumping | HackTool - Rubeus Execution | high | 61603 |
| `108698` | 12 | `T1003` OS Credential Dumping | HackTool - Rubeus Execution | high | 61603 |
| `108699` | 12 | `T1003` OS Credential Dumping | HackTool - Rubeus Execution | high | 61603 |
| `108700` | 12 | `T1003` OS Credential Dumping | HackTool - Rubeus Execution | high | 61603 |
| `108701` | 12 | `T1003.001` T1003.001 | HackTool - SafetyKatz Execution | high | 61603 |
| `108702` | 12 | `T1003.001` T1003.001 | HackTool - SafetyKatz Execution | high | 61603 |
| `108703` | 12 | `T1003.001` T1003.001 | HackTool - SafetyKatz Execution | high | 61603 |
| `108704` | 12 | `T1555` T1555 | HackTool - SecurityXploded Execution | high | 61603 |
| `108705` | 12 | `T1555` T1555 | HackTool - SecurityXploded Execution | high | 61603 |
| `108706` | 12 | `T1555` T1555 | HackTool - SecurityXploded Execution | high | 61603 |
| `108707` | 12 | `T1003.001` T1003.001 | HackTool - Windows Credential Editor (WCE) Execution | high | 61603 |
| `108708` | 12 | `T1003.001` T1003.001 | HackTool - Windows Credential Editor (WCE) Execution | high | 61603 |
| `108709` | 12 | `T1046` T1046 | HackTool - WinPwn Execution | high | 61603 |
| `108711` | 12 | `T1003.001` T1003.001 | HackTool - WSASS Execution | high | 61603 |
| `108712` | 12 | `T1003.001` T1003.001 | HackTool - WSASS Execution | high | 61603 |
| `108713` | 12 | `T1036` T1036 | HackTool - XORDump Execution | high | 61603 |
| `108714` | 12 | `T1036` T1036 | HackTool - XORDump Execution | high | 61603 |
| `108715` | 12 | `T1003` OS Credential Dumping | Microsoft IIS Service Account Password Dumped | high | 61603 |
| `108716` | 12 | `T1003` OS Credential Dumping | Microsoft IIS Connection Strings Decryption | high | 61603 |
| `108717` | 11 | `T1003.001` T1003.001 | Dumping Process via Sqldumper.exe | medium | 61603 |
| `108718` | 12 | `T1218` T1218 | Time Travel Debugging Utility Usage | high | 61603 |
| `108719` | 12 | `T1003` OS Credential Dumping | Potential Credential Dumping Via LSASS Process Clone | high | 61603 |
| `108720` | 11 | `T1003.003` T1003.003 | Suspicious Usage Of Active Directory Diagnostic Tool (ntdsutil.exe) | medium | 61603 |
| `108721` | 11 | `T1003.003` T1003.003 | Invocation of Active Directory Diagnostic Tool (ntdsutil.exe) | medium | 61603 |
| `108722` | 11 | `T1552.001` T1552.001 | Potential PowerShell Console History Access Attempt via History File | medium | 61603 |
| `108723` | 11 | `T1552.004` T1552.004 | Certificate Exported Via PowerShell | medium | 61603 |
| `108724` | 12 | `T1552.004` T1552.004 | PowerShell Get-Process LSASS | high | 61603 |
| `108725` | 12 | `T1558.003` T1558.003 | Suspicious Kerberos Ticket Request via CLI | high | 61603 |
| `108726` | 12 | `T1003.002` T1003.002 | PowerShell SAM Copy | high | 61603 |
| `108727` | 12 | `T1003.003` T1003.003 | Sensitive File Dump Via Print.EXE | high | 61603 |
| `108728` | 12 | `T1003.003` T1003.003 | PUA - DIT Snapshot Viewer | high | 61603 |
| `108729` | 12 | `T1003.003` T1003.003 | PUA - DIT Snapshot Viewer | high | 61603 |
| `108730` | 12 | `T1003` OS Credential Dumping | PUA - Memory Dump Mount Via MemProcFS | high | 61603 |
| `108731` | 11 | `T1056.002` T1056.002 | PUA - Mouse Lock Execution | medium | 61603 |
| `108732` | 11 | `T1056.002` T1056.002 | PUA - Mouse Lock Execution | medium | 61603 |
| `108733` | 11 | `T1056.002` T1056.002 | PUA - Mouse Lock Execution | medium | 61603 |
| `108734` | 11 | `T1555.003` T1555.003 | PUA - WebBrowserPassView Execution | medium | 61603 |
| `108735` | 11 | `T1555.003` T1555.003 | PUA - WebBrowserPassView Execution | medium | 61603 |
| `108736` | 12 | `T1003.001` T1003.001 | Process Memory Dump via RdrLeakDiag.EXE | high | 61603 |
| `108737` | 12 | `T1003.002` T1003.002 | Dumping of Sensitive Hives Via Reg.EXE | high | 61603 |
| `108738` | 11 | `T1552.002` T1552.002 | Enumeration for Credentials in Registry | medium | 61603 |
| `108739` | 11 | `T1552.002` T1552.002 | Enumeration for 3rd Party Creds From CLI | medium | 61603 |
| `108740` | 12 | `T1552.002` T1552.002 | Registry Export of Third-Party Credentials | high | 61603 |
| `108741` | 12 | `T1003` OS Credential Dumping | Potential Credential Dumping Attempt Using New NetworkProvider - CLI | high | 61603 |
| `108742` | 12 | `T1528` T1528 | Renamed BrowserCore.EXE Execution | high | 61603 |
| `108743` | 12 | `T1036` T1036 | Renamed CreateDump Utility Execution | high | 61603 |
| `108744` | 12 | `T1036` T1036 | Renamed CreateDump Utility Execution | high | 61603 |
| `108745` | 12 | `T1036` T1036 | Renamed CreateDump Utility Execution | high | 61603 |
| `108747` | 12 | `T1555.004` T1555.004 | Suspicious Key Manager Access | high | 61603 |
| `108748` | 12 | `T1036` T1036 | Process Memory Dump Via Comsvcs.DLL | high | 61603 |
| `108749` | 12 | `T1555` T1555 | Suspicious Serv-U Process Pattern | high | 61603 |
| `108750` | 11 | `T1558.003` T1558.003 | Potential SPN Enumeration Via Setspn.EXE | medium | 61603 |
| `108751` | 12 | `T1539` T1539 | SQLite Chromium Profile Data DB Access | high | 61603 |
| `108752` | 12 | `T1539` T1539 | SQLite Firefox Profile Data DB Access | high | 61603 |
| `108753` | 11 | `T1555.003` T1555.003 | Potential Browser Data Stealing | medium | 61603 |
| `108754` | 11 | `T1552` T1552 | Potentially Suspicious EventLog Recon Activity Using Log Query Util... | medium | 61603 |
| `108755` | 11 | `T1552` T1552 | Potentially Suspicious EventLog Recon Activity Using Log Query Util... | medium | 61603 |
| `108756` | 11 | `T1528` T1528 | Potentially Suspicious JWT Token Search Via CLI | medium | 61603 |
| `108757` | 12 | `T1003.001` T1003.001 | LSASS Dump Keyword In CommandLine | high | 61603 |
| `108758` | 12 | `T1003.001` T1003.001 | LSASS Dump Keyword In CommandLine | high | 61603 |
| `108759` | 12 | `T1003.001` T1003.001 | LSASS Dump Keyword In CommandLine | high | 61603 |
| `108760` | 12 | `T1003.001` T1003.001 | LSASS Dump Keyword In CommandLine | high | 61603 |
| `108761` | 11 | `T1040` T1040 | Potential Network Sniffing Activity Using Network Tools | medium | 61603 |
| `108762` | 11 | `T1040` T1040 | Potential Network Sniffing Activity Using Network Tools | medium | 61603 |
| `108763` | 12 | `T1003.003` T1003.003 | Suspicious Process Patterns NTDS.DIT Exfil | high | 61603 |
| `108764` | 12 | `T1003.003` T1003.003 | Suspicious Process Patterns NTDS.DIT Exfil | high | 61603 |
| `108765` | 12 | `T1003.003` T1003.003 | Suspicious Process Patterns NTDS.DIT Exfil | high | 61603 |
| `108766` | 12 | `T1003.003` T1003.003 | Suspicious Process Patterns NTDS.DIT Exfil | high | 61603 |
| `108767` | 12 | `T1003.003` T1003.003 | Suspicious Process Patterns NTDS.DIT Exfil | high | 61603 |
| `108768` | 12 | `T1003.003` T1003.003 | Suspicious Process Patterns NTDS.DIT Exfil | high | 61603 |
| `108769` | 12 | `T1003.003` T1003.003 | Suspicious Process Patterns NTDS.DIT Exfil | high | 61603 |
| `108770` | 11 | `T1552.004` T1552.004 | Private Keys Reconnaissance Via CommandLine Tools | medium | 61603 |
| `108771` | 12 | `T1552` T1552 | Script Interpreter Spawning Credential Scanner - Windows | high | 61603 |
| `108772` | 11 | `T1003` OS Credential Dumping | Shadow Copies Creation Using Operating Systems Utilities | medium | 61603 |
| `108773` | 12 | `T1134` Access Token Manipulation | Suspicious SYSTEM User Process Creation | high | 61603 |
| `108774` | 11 | `T1552.006` T1552.006 | Suspicious SYSVOL Domain Group Policy Access | medium | 61603 |
| `108775` | 11 | `T1036` T1036 | Procdump Execution | medium | 61603 |
| `108776` | 12 | `T1036` T1036 | Potential SysInternals ProcDump Evasion | high | 61603 |
| `108777` | 12 | `T1036` T1036 | Potential SysInternals ProcDump Evasion | high | 61603 |
| `108778` | 12 | `T1036` T1036 | Potential SysInternals ProcDump Evasion | high | 61603 |
| `108779` | 12 | `T1036` T1036 | Potential LSASS Process Dump Via Procdump | high | 61603 |
| `108780` | 11 | `T1003` OS Credential Dumping | Loaded Module Enumeration Via Tasklist.EXE | medium | 61603 |
| `108781` | 11 | `T1528` T1528 | Potentially Suspicious Command Targeting Teams Sensitive Files | medium | 61603 |
| `108782` | 11 | `T1555.004` T1555.004 | Windows Credential Manager Access via VaultCmd | medium | 61603 |
| `108783` | 12 | `T1003.003` T1003.003 | Sensitive File Dump Via Wbadmin.EXE | high | 61603 |
| `108784` | 12 | `T1003.003` T1003.003 | Sensitive File Recovery From Backup Via Wbadmin.EXE | high | 61603 |
| `108785` | 12 | `T1003.001` T1003.001 | Potential Credential Dumping Via WER | high | 61603 |
| `108786` | 12 | `T1685` T1685 | PPL Tampering Via WerFaultSecure | high | 61603 |
| `108787` | 12 | `T1003.002` T1003.002 | Esentutl Volume Shadow Copy Service Keys | high | 61615 |
| `108788` | 12 | `T1003.001` T1003.001 | Windows Credential Editor Registry | high | 61615 |
| `108789` | 12 | `T1003.001` T1003.001 | Potential Credential Dumping Via LSASS SilentProcessExit Technique | high | 61615 |
| `108790` | 12 | `T1556` T1556 | Directory Service Restore Mode(DSRM) Registry Value Tampering | high | 61615 |
| `108791` | 12 | `T1003.001` T1003.001 | Lsass Full Dump Request Via DumpType Registry Settings | high | 61615 |
| `108792` | 11 | `T1003` OS Credential Dumping | Potential Credential Dumping Attempt Using New NetworkProvider - REG | medium | 61615 |
| `108793` | 12 | `T1003` OS Credential Dumping | Potentially Suspicious ODBC Driver Registered | high | 61615 |
| `115002` | 12 | `T1110` Brute Force | brute_force_then_logon | high | 112501 |

### Discovery (TA0007) — 137 rules

| Rule ID | Level | Technique | Description | Confidence | Parent SID |
|---------|-------|-----------|-------------|------------|------------|
| `111000` | 6 | `T1087.001` T1087.001 | Suspicious command: net user | medium | 61603 |
| `111001` | 6 | `T1069.002` T1069.002 | Potential Active Directory Reconnaissance/Enumeration Via LDAP | medium | 60000 |
| `111002` | 6 | `T1012` T1012 | Azure AD Health Monitoring Agent Registry Keys Access | medium | 60100 |
| `111003` | 6 | `T1012` T1012 | Azure AD Health Service Agents Registry Keys Access | medium | 60100 |
| `111004` | 7 | `T1087.002` T1087.002 | AD Privileged Users or Groups Reconnaissance | high | 60100 |
| `111005` | 6 | `T1087.002` T1087.002 | Potential AD User Enumeration From Non-Machine Account | medium | 60100 |
| `111006` | 7 | `T1087` Account Discovery | Hacktool Ruler | high | 60100 |
| `111007` | 6 | `T1201` T1201 | Password Policy Enumerated | medium | 60100 |
| `111008` | 6 | `T1040` T1040 | Windows Pcap Drivers | medium | 60100 |
| `111009` | 7 | `T1012` T1012 | SAM Registry Hive Handle Request | high | 60100 |
| `111010` | 6 | `T1010` T1010 | SCM Database Handle Failure | medium | 60100 |
| `111011` | 7 | `T1087.002` T1087.002 | Reconnaissance Activity | high | 60100 |
| `111012` | 7 | `T1012` T1012 | SysKey Registry Keys Access | high | 60100 |
| `111013` | 6 | `T1046` T1046 | Advanced IP Scanner - File Event | medium | 61613 |
| `111014` | 11 | `T1087.001` T1087.001 | BloodHound Collection Files | high | 61613 |
| `111015` | 6 | - | GatherNetworkInfo.VBS Reconnaissance Script Output | medium | 61613 |
| `111016` | 6 | `T1087.002` T1087.002 | ADExplorer Writing Complete AD Snapshot Into .dat File | medium | 61613 |
| `111017` | 6 | `T1087` Account Discovery | Uncommon Connection to Active Directory Web Services | medium | 61605 |
| `111018` | 6 | `T1016` T1016 | Suspicious Network Connection to IP Lookup Service APIs | medium | 61605 |
| `111019` | 6 | `T1046` T1046 | Python Initiated Connection | medium | 61605 |
| `111020` | 6 | - | Potential Active Directory Enumeration Using AD Module - PsModule | medium | 91801 |
| `111021` | 6 | - | Potential Active Directory Enumeration Using AD Module - PsScript | medium | 91801 |
| `111022` | 6 | - | Potential Active Directory Enumeration Using AD Module - PsScript | medium | 91801 |
| `111023` | 7 | `T1059.001` T1059.001 | PowerShell ADRecon Execution | high | 91801 |
| `111024` | 6 | `T1033` T1033 | Get-ADUser Enumeration Using UserAccountControl Flags | medium | 91801 |
| `111025` | 6 | `T1033` T1033 | Computer Discovery And Export Via Get-ADComputer Cmdlet - PowerShell | medium | 91801 |
| `111026` | 6 | `T1497.001` T1497.001 | Powershell Detect Virtualization Environment | medium | 91801 |
| `111027` | 6 | `T1018` T1018 | DirectorySearcher Powershell Exploitation | medium | 91801 |
| `111028` | 6 | `T1518.001` T1518.001 | Security Software Discovery Via Powershell Script | medium | 91801 |
| `111029` | 6 | - | PowerShell Hotfix Enumeration | medium | 91801 |
| `111030` | 6 | `T1018` T1018 | Potential Unconstrained Delegation Discovery Via Get-ADComputer - S... | medium | 91801 |
| `111031` | 6 | `T1083` File and Directory Discovery | Powershell Sensitive File Discovery | medium | 91801 |
| `111032` | 6 | `T1518` T1518 | Detected Windows Software Discovery - PowerShell | medium | 91801 |
| `111033` | 6 | `T1083` File and Directory Discovery | Powershell Directory Enumeration | medium | 91801 |
| `111034` | 6 | `T1033` T1033 | User Discovery And Export Via Get-ADUser Cmdlet - PowerShell | medium | 91801 |
| `111035` | 6 | `T1614.001` T1614.001 | Console CodePage Lookup Via CHCP | medium | 61603 |
| `111036` | 6 | - | Potential Discovery Activity Via Dnscmd.EXE | medium | 61603 |
| `111037` | 7 | - | Potential Recon Activity Using DriverQuery.EXE | high | 61603 |
| `111038` | 6 | - | DriverQuery.EXE Execution | medium | 61603 |
| `111039` | 6 | `T1482` T1482 | Domain Trust Discovery Via Dsquery | medium | 61603 |
| `111040` | 7 | `T1082` System Information Discovery | Suspicious Kernel Dump Using Dtrace | high | 61603 |
| `111041` | 7 | `T1082` System Information Discovery | Suspicious Kernel Dump Using Dtrace | high | 61603 |
| `111042` | 7 | `T1135` T1135 | File Explorer Folder Opened Using Explorer Folder Shortcut Via Shell | high | 61603 |
| `111043` | 6 | `T1057` T1057 | Recon Command Output Piped To Findstr.EXE | medium | 61603 |
| `111044` | 6 | `T1518.001` T1518.001 | Security Tools Keyword Lookup Via Findstr.EXE | medium | 61603 |
| `111045` | 7 | `T1518.001` T1518.001 | Sysmon Discovery Via Default Driver Altitude Using Findstr.EXE | high | 61603 |
| `111046` | 6 | `T1615` T1615 | Gpresult Display Group Policy Information | medium | 61603 |
| `111047` | 11 | `T1087.001` T1087.001 | HackTool - Bloodhound/Sharphound Execution | high | 61603 |
| `111048` | 11 | `T1087.001` T1087.001 | HackTool - Bloodhound/Sharphound Execution | high | 61603 |
| `111049` | 11 | `T1087.001` T1087.001 | HackTool - Bloodhound/Sharphound Execution | high | 61603 |
| `111050` | 11 | `T1087.001` T1087.001 | HackTool - Bloodhound/Sharphound Execution | high | 61603 |
| `111051` | 11 | `T1087.001` T1087.001 | HackTool - Bloodhound/Sharphound Execution | high | 61603 |
| `111052` | 11 | `T1087.001` T1087.001 | HackTool - Bloodhound/Sharphound Execution | high | 61603 |
| `111053` | 11 | `T1087.001` T1087.001 | HackTool - Bloodhound/Sharphound Execution | high | 61603 |
| `111054` | 7 | `T1649` T1649 | HackTool - Certify Execution | high | 61603 |
| `111055` | 11 | `T1649` T1649 | HackTool - Certipy Execution | high | 61603 |
| `111056` | 7 | `T1018` T1018 | HackTool - NetExec Execution | high | 61603 |
| `111057` | 6 | - | HackTool - SharpLDAPmonitor Execution | medium | 61603 |
| `111058` | 6 | - | HackTool - SharpLDAPmonitor Execution | medium | 61603 |
| `111059` | 6 | - | HackTool - SharpLDAPmonitor Execution | medium | 61603 |
| `111060` | 7 | `T1033` T1033 | HackTool - SharpLdapWhoami Execution | high | 61603 |
| `111061` | 7 | `T1033` T1033 | HackTool - SharpLdapWhoami Execution | high | 61603 |
| `111062` | 7 | `T1033` T1033 | HackTool - SharpLdapWhoami Execution | high | 61603 |
| `111063` | 7 | `T1033` T1033 | HackTool - SharpLdapWhoami Execution | high | 61603 |
| `111064` | 7 | `T1049` T1049 | HackTool - SharpView Execution | high | 61603 |
| `111065` | 7 | `T1049` T1049 | HackTool - SharpView Execution | high | 61603 |
| `111066` | 7 | `T1049` T1049 | HackTool - SharpView Execution | high | 61603 |
| `111067` | 7 | `T1087` Account Discovery | HackTool - SOAPHound Execution | high | 61603 |
| `111068` | 7 | `T1482` T1482 | HackTool - TruffleSnout Execution | high | 61603 |
| `111069` | 7 | `T1482` T1482 | HackTool - TruffleSnout Execution | high | 61603 |
| `111070` | 6 | `T1615` T1615 | Potential Reconnaissance Activity Via GatherNetworkInfo.VBS | medium | 61603 |
| `111071` | 6 | `T1087.001` T1087.001 | Suspicious Group And Account Reconnaissance Activity Using Net.EXE | medium | 61603 |
| `111072` | 6 | `T1040` T1040 | New Network Trace Capture Started Via Netsh.EXE | medium | 61603 |
| `111073` | 6 | `T1040` T1040 | Harvesting Of Wifi Credentials Via Netsh.EXE | medium | 61603 |
| `111074` | 6 | `T1016` T1016 | Potential Recon Activity Via Nltest.EXE | medium | 61603 |
| `111075` | 7 | `T1087` Account Discovery | Network Reconnaissance Activity | high | 61603 |
| `111076` | 6 | `T1040` T1040 | PktMon.EXE Execution | medium | 61603 |
| `111077` | 6 | `T1040` T1040 | PktMon.EXE Execution | medium | 61603 |
| `111078` | 6 | - | Potential Active Directory Enumeration Using AD Module - ProcCreation | medium | 61603 |
| `111079` | 6 | `T1033` T1033 | Computer Discovery And Export Via Get-ADComputer Cmdlet | medium | 61603 |
| `111080` | 6 | `T1087.001` T1087.001 | Suspicious Reconnaissance Activity Using Get-LocalGroupMember Cmdlet | medium | 61603 |
| `111081` | 6 | `T1033` T1033 | User Discovery And Export Via Get-ADUser Cmdlet | medium | 61603 |
| `111082` | 7 | `T1087.002` T1087.002 | PUA - Suspicious ActiveDirectory Enumeration Via AdFind.EXE | high | 61603 |
| `111083` | 7 | `T1087.002` T1087.002 | PUA - Suspicious ActiveDirectory Enumeration Via AdFind.EXE | high | 61603 |
| `111084` | 7 | `T1087.002` T1087.002 | PUA - Suspicious ActiveDirectory Enumeration Via AdFind.EXE | high | 61603 |
| `111085` | 6 | `T1087.002` T1087.002 | PUA - AdFind.EXE Execution | medium | 61603 |
| `111086` | 6 | `T1087.002` T1087.002 | PUA - AdFind.EXE Execution | medium | 61603 |
| `111087` | 6 | `T1087.002` T1087.002 | PUA - AdFind.EXE Execution | medium | 61603 |
| `111088` | 7 | `T1018` T1018 | PUA - AdFind Suspicious Execution | high | 61603 |
| `111089` | 6 | `T1046` T1046 | PUA - Advanced IP Scanner Execution | medium | 61603 |
| `111090` | 6 | `T1046` T1046 | PUA - Advanced IP Scanner Execution | medium | 61603 |
| `111091` | 6 | `T1046` T1046 | PUA - Advanced IP Scanner Execution | medium | 61603 |
| `111092` | 6 | `T1046` T1046 | PUA - Advanced IP Scanner Execution | medium | 61603 |
| `111093` | 6 | `T1046` T1046 | PUA - Advanced Port Scanner Execution | medium | 61603 |
| `111094` | 6 | `T1046` T1046 | PUA - Advanced Port Scanner Execution | medium | 61603 |
| `111095` | 6 | `T1046` T1046 | PUA - Advanced Port Scanner Execution | medium | 61603 |
| `111096` | 6 | `T1046` T1046 | PUA - Advanced Port Scanner Execution | medium | 61603 |
| `111097` | 7 | `T1590.001` T1590.001 | PUA - Crassus Execution | high | 61603 |
| `111098` | 7 | `T1590.001` T1590.001 | PUA - Crassus Execution | high | 61603 |
| `111099` | 7 | `T1590.001` T1590.001 | PUA - Crassus Execution | high | 61603 |
| `111100` | 6 | `T1046` T1046 | PUA - SoftPerfect Netscan Execution | medium | 61603 |
| `111101` | 6 | `T1046` T1046 | PUA - SoftPerfect Netscan Execution | medium | 61603 |
| `111102` | 6 | `T1046` T1046 | PUA - SoftPerfect Netscan Execution | medium | 61603 |
| `111103` | 6 | `T1046` T1046 | PUA - NimScan Execution | medium | 61603 |
| `111104` | 6 | `T1046` T1046 | PUA - NimScan Execution | medium | 61603 |
| `111105` | 6 | `T1046` T1046 | PUA - Nmap/Zenmap Execution | medium | 61603 |
| `111106` | 6 | `T1046` T1046 | PUA - Nmap/Zenmap Execution | medium | 61603 |
| `111107` | 6 | `T1622` T1622 | PUA - Process Hacker Execution | medium | 61603 |
| `111108` | 6 | `T1622` T1622 | PUA - Process Hacker Execution | medium | 61603 |
| `111109` | 6 | `T1622` T1622 | PUA - Process Hacker Execution | medium | 61603 |
| `111110` | 6 | `T1622` T1622 | PUA - Process Hacker Execution | medium | 61603 |
| `111111` | 6 | `T1622` T1622 | PUA - Process Hacker Execution | medium | 61603 |
| `111112` | 6 | `T1622` T1622 | PUA - Process Hacker Execution | medium | 61603 |
| `111113` | 7 | `T1526` T1526 | PUA - Seatbelt Execution | high | 61603 |
| `111114` | 6 | `T1083` File and Directory Discovery | PUA - TruffleHog Execution | medium | 61603 |
| `111115` | 6 | `T1012` T1012 | Potential Configuration And Service Reconnaissance Via Reg.EXE | medium | 61603 |
| `111116` | 6 | `T1518` T1518 | Detected Windows Software Discovery | medium | 61603 |
| `111117` | 6 | `T1614.001` T1614.001 | System Language Discovery via Reg.Exe | medium | 61603 |
| `111118` | 7 | `T1018` T1018 | Renamed AdFind Execution | high | 61603 |
| `111119` | 7 | `T1018` T1018 | Renamed AdFind Execution | high | 61603 |
| `111120` | 7 | `T1018` T1018 | Renamed AdFind Execution | high | 61603 |
| `111121` | 7 | `T1033` T1033 | Renamed Whoami Execution | high | 61603 |
| `111122` | 7 | `T1615` T1615 | Suspicious Reconnaissance Activity Via GatherNetworkInfo.VBS | high | 61603 |
| `111123` | 6 | - | Obfuscated IP Download Activity | medium | 61603 |
| `111124` | 6 | - | Obfuscated IP Via CLI | medium | 61603 |
| `111125` | 7 | `T1033` T1033 | WhoAmI as Parameter | high | 61603 |
| `111126` | 6 | `T1069.001` T1069.001 | Permission Check Via Accesschk.EXE | medium | 61603 |
| `111127` | 6 | `T1087.002` T1087.002 | Active Directory Database Snapshot Via ADExplorer | medium | 61603 |
| `111128` | 7 | `T1087.002` T1087.002 | Suspicious Active Directory Database Snapshot Via ADExplorer | high | 61603 |
| `111129` | 6 | `T1087` Account Discovery | Suspicious Use of PsLogList | medium | 61603 |
| `111130` | 7 | `T1124` T1124 | Use of W32tm as Timer | high | 61603 |
| `111131` | 6 | `T1033` T1033 | Enumerate All Information With Whoami.EXE | medium | 61603 |
| `111132` | 6 | `T1033` T1033 | Group Membership Reconnaissance Via Whoami.EXE | medium | 61603 |
| `111133` | 6 | `T1033` T1033 | Whoami.EXE Execution With Output Option | medium | 61603 |
| `111134` | 6 | `T1033` T1033 | Whoami.EXE Execution Anomaly | medium | 61603 |
| `111135` | 6 | `T1047` T1047 | Computer System Reconnaissance Via Wmic.EXE | medium | 61603 |
| `111136` | 6 | `T1082` System Information Discovery | Uncommon System Information Discovery Via Wmic.EXE | medium | 61603 |

### Lateral Movement (TA0008) — 72 rules

| Rule ID | Level | Technique | Description | Confidence | Parent SID |
|---------|-------|-----------|-------------|------------|------------|
| `112500` | 8 | `T1078` Valid Accounts | Explicit credential logon | low | 60100 |
| `112501` | 8 | `T1021.001` T1021.001 | Remote logon (type 3) | low | 60100 |
| `112502` | 8 | `T1021.001` T1021.001 | Remote logon (type 10) | low | 60100 |
| `112503` | 11 | `T1021.002` T1021.002 | Suspicious named pipe: \ntsvcs | high | 61620 |
| `112504` | 11 | `T1021.002` T1021.002 | Suspicious named pipe: \scerpc | high | 61620 |
| `112505` | 11 | `T1021.002` T1021.002 | Suspicious process: psexesvc | high | 61603 |
| `112506` | 11 | `T1021.002` T1021.002 | Suspicious process: psexec | high | 61603 |
| `112507` | 11 | `T1021.002` T1021.002 | Suspicious named pipe: \psexe | high | 61619 |
| `112508` | 11 | `T1021.002` T1021.002 | Suspicious named pipe: \psexe | high | 61620 |
| `112509` | 10 | `T1021.002` T1021.002 | File created by psexec | medium | 61613 |
| `112510` | 10 | `T1021.002` T1021.002 | DNS query by psexec | medium | 61624 |
| `112511` | 11 | `T1021.002` T1021.002 | Suspicious service: PSEXESVC | high | 60002 |
| `112512` | 11 | `T1072` T1072 | Restricted Software Access By SRP | high | 60003 |
| `112513` | 10 | `T1021.004` T1021.004 | OpenSSH Server Listening On Socket | medium | 60000 |
| `112514` | 11 | `T1550.002` T1550.002 | Successful Overpass the Hash Attempt | high | 60100 |
| `112515` | 10 | `T1550.002` T1550.002 | Pass the Hash Activity 2 | medium | 60100 |
| `112516` | 10 | `T1550.002` T1550.002 | Pass the Hash Activity 2 | medium | 60100 |
| `112517` | 11 | `T1021.001` T1021.001 | RDP Login from Localhost | high | 60100 |
| `112518` | 10 | `T1021.002` T1021.002 | DCERPC SMB Spoolss Named Pipe | medium | 60100 |
| `112519` | 11 | `T1021.002` T1021.002 | DCOM InternetExplorer.Application Iertutil DLL Hijack - Security | high | 60100 |
| `112520` | 11 | `T1021.002` T1021.002 | Impacket PsExec Execution | high | 60100 |
| `112521` | 11 | `T1021.002` T1021.002 | First Time Seen Remote Named Pipe | high | 60100 |
| `112525` | 10 | `T1021.001` T1021.001 | Denied Access To Remote Desktop | medium | 60100 |
| `112526` | 11 | `T1021.002` T1021.002 | Protected Storage Service Access | high | 60100 |
| `112527` | 11 | `T1558.003` T1558.003 | Register new Logon Process by Rubeus | high | 60100 |
| `112528` | 11 | `T1021.002` T1021.002 | SMB Create Remote File Admin Share | high | 60100 |
| `112529` | 10 | `T1558.003` T1558.003 | Uncommon Outbound Kerberos Connection - Security | medium | 60100 |
| `112530` | 11 | `T1021.002` T1021.002 | Suspicious PsExec Execution | high | 60100 |
| `112531` | 10 | `T1021.002` T1021.002 | Remote Service Activity via SVCCTL Named Pipe | medium | 60100 |
| `112532` | 10 | `T1021.002` T1021.002 | Unsigned or Unencrypted SMB Connection to Share Established | medium | 60000 |
| `112533` | 10 | `T1550.002` T1550.002 | NTLMv1 Logon Between Client and Server | medium | 60002 |
| `112534` | 11 | `T1210` T1210 | Zerologon Exploitation Using Well-known Tools | high | 60002 |
| `112535` | 11 | `T1021.002` T1021.002 | smbexec.py Service Installation | high | 60002 |
| `112536` | 11 | `T1021.002` T1021.002 | Potential DCOM InternetExplorer.Application DLL Hijack | high | 61613 |
| `112537` | 11 | `T1136.002` T1136.002 | PSEXEC Remote Execution File Artefact | high | 61613 |
| `112541` | 11 | `T1021.002` T1021.002 | Potential DCOM InternetExplorer.Application DLL Hijack - Image Load | high | 61609 |
| `112542` | 10 | `T1546.003` T1546.003 | WMI ActiveScriptEventConsumers Activity Via Scrcons.EXE DLL Load | medium | 61609 |
| `112543` | 11 | `T1218` T1218 | BaaUpdate.exe Suspicious DLL Load | high | 61609 |
| `112544` | 11 | `T1021.001` T1021.001 | Outbound RDP Connections Over Non-Standard Tools | high | 61605 |
| `112545` | 10 | `T1021.002` T1021.002 | PUA - CSExec Default Named Pipe | medium | 61619 |
| `112546` | 10 | `T1021.002` T1021.002 | PUA - RemCom Default Named Pipe | medium | 61619 |
| `112547` | 11 | - | HackTool - Evil-WinRm Execution - PowerShell Module | high | 91801 |
| `112548` | 10 | `T1021.006` T1021.006 | Enable Windows Remote Management | medium | 91801 |
| `112549` | 10 | `T1021.006` T1021.006 | Execute Invoke-command on Remote Host | medium | 91801 |
| `112550` | 10 | `T1021.002` T1021.002 | Suspicious New-PSDrive to Admin Share | medium | 91801 |
| `112551` | 11 | `T1218` T1218 | Suspicious BitLocker Access Agent Update Utility Execution | high | 61603 |
| `112552` | 10 | `T1072` T1072 | Suspicious Csi.exe Usage | medium | 61603 |
| `112553` | 10 | `T1021.006` T1021.006 | HackTool - WinRM Access Via Evil-WinRM | medium | 61603 |
| `112554` | 11 | `T1021.002` T1021.002 | HackTool - SharpMove Tool Execution | high | 61603 |
| `112555` | 11 | - | HackTool - Wmiexec Default Powershell Command | high | 61603 |
| `112556` | 10 | `T1210` T1210 | Suspicious SysAidServer Child | medium | 61603 |
| `112557` | 11 | `T1021.003` T1021.003 | MMC Spawning Windows Shell | high | 61603 |
| `112558` | 11 | `T1563.002` T1563.002 | Potential MSTSC Shadowing Activity | high | 61603 |
| `112559` | 10 | `T1021.001` T1021.001 | New Remote Desktop Connection Initiated Via Mstsc.EXE | medium | 61603 |
| `112560` | 11 | - | Mstsc.EXE Execution From Uncommon Parent | high | 61603 |
| `112561` | 10 | `T1021.002` T1021.002 | Windows Admin Share Mount Via Net.EXE | medium | 61603 |
| `112562` | 11 | `T1021.002` T1021.002 | Windows Internet Hosted WebDav Share Mount Via Net.EXE | high | 61603 |
| `112563` | 10 | `T1090` T1090 | New Port Forwarding Rule Added Via Netsh.EXE | medium | 61603 |
| `112564` | 11 | `T1090` T1090 | RDP Port Forwarding Rule Added Via Netsh.EXE | high | 61603 |
| `112565` | 11 | `T1021.003` T1021.003 | Potential Excel.EXE DCOM Lateral Movement Via ActivateMicrosoftApp | high | 61603 |
| `112566` | 10 | `T1021.001` T1021.001 | RDP Enable or Disable via Win32_TerminalServiceSetting WMI Class | medium | 61603 |
| `112567` | 11 | `T1021.002` T1021.002 | Rundll32 Execution Without Parameters | high | 61603 |
| `112568` | 11 | `T1021.003` T1021.003 | Suspicious Speech Runtime Binary Child Process | high | 61603 |
| `112569` | 10 | `T1039` T1039 | Copy From Or To Admin Share Or Sysvol Folder | medium | 61603 |
| `112570` | 11 | `T1021` Remote Services | Privilege Escalation via Named Pipe Impersonation | high | 61603 |
| `112571` | 10 | `T1021` Remote Services | Potential Remote Desktop Tunneling | medium | 61603 |
| `112572` | 11 | `T1563.002` T1563.002 | Suspicious RDP Redirect Using TSCON | high | 61603 |
| `112573` | 11 | `T1021.005` T1021.005 | Suspicious UltraVNC Execution | high | 61603 |
| `112574` | 11 | `T1021.006` T1021.006 | Winrs Local Command Execution | high | 61603 |
| `112575` | 10 | `T1021.006` T1021.006 | Potential Lateral Movement via Windows Remote Shell | medium | 61603 |
| `112576` | 10 | `T1090` T1090 | New PortProxy Registry Entry Added | medium | 61615 |
| `115000` | 12 | `T1021` Remote Services | discovery_then_lateral_movement | high | 112501 |

### Collection (TA0009) — 51 rules

| Rule ID | Level | Technique | Description | Confidence | Parent SID |
|---------|-------|-----------|-------------|------------|------------|
| `113500` | 8 | `T1557.001` T1557.001 | RottenPotato Like Attack Pattern | high | 60100 |
| `113501` | 7 | `T1123` T1123 | Processes Accessing the Microphone and Webcam | medium | 60100 |
| `113502` | 8 | `T1557.003` T1557.003 | Potential Kerberos Coercion by Spoofing SPNs via DNS Manipulation | high | 60100 |
| `113503` | 8 | `T1557.003` T1557.003 | Potential Kerberos Coercion by Spoofing SPNs via DNS Manipulation | high | 60100 |
| `113504` | 7 | `T1039` T1039 | Suspicious Access to Sensitive File Extensions | medium | 60100 |
| `113505` | 8 | `T1557.001` T1557.001 | Local Privilege Escalation Indicator TabTip | high | 60002 |
| `113506` | 7 | `T1195.002` T1195.002 | Notepad++ Updater DNS Query to Uncommon Domains | medium | 61624 |
| `113507` | 8 | `T1557.001` T1557.001 | Suspicious DNS Query Indicating Kerberos Coercion via DNS Object SP... | high | 61624 |
| `113508` | 8 | `T1195.002` T1195.002 | Uncommon File Created by Notepad++ Updater Gup.EXE | high | 61613 |
| `113509` | 7 | `T1005` T1005 | ADFS Database Named Pipe Connection By Uncommon Tool | medium | 61619 |
| `113510` | 7 | `T1074.001` T1074.001 | Zip A Folder With PowerShell For Staging In Temp - PowerShell | medium | 91801 |
| `113511` | 7 | `T1115` T1115 | PowerShell Get Clipboard | medium | 91801 |
| `113512` | 7 | `T1074.001` T1074.001 | Zip A Folder With PowerShell For Staging In Temp  - PowerShell Module | medium | 91801 |
| `113513` | 7 | `T1119` T1119 | Automated Collection Command PowerShell | medium | 91801 |
| `113514` | 7 | `T1113` T1113 | Windows Screen Capture with CopyFromScreen | medium | 91801 |
| `113515` | 7 | `T1056.001` T1056.001 | Potential Keylogger Activity | medium | 91801 |
| `113516` | 7 | `T1114.001` T1114.001 | Powershell Local Email Collection | medium | 91801 |
| `113517` | 7 | `T1119` T1119 | Recon Information for Export with PowerShell | medium | 91801 |
| `113518` | 7 | `T1074.001` T1074.001 | Zip A Folder With PowerShell For Staging In Temp - PowerShell Script | medium | 91801 |
| `113519` | 7 | `T1560.001` T1560.001 | 7Zip Compressing Dump Files | medium | 61603 |
| `113520` | 7 | `T1560.001` T1560.001 | Compress Data and Lock With Password for Exfiltration With 7-ZIP | medium | 61603 |
| `113521` | 7 | `T1005` T1005 | Esentutl Steals Browser Information | medium | 61603 |
| `113522` | 8 | `T1195.002` T1195.002 | Suspicious Child Process of Notepad++ Updater - GUP.Exe | high | 61603 |
| `113523` | 8 | `T1557.001` T1557.001 | HackTool - ADCSPwn Execution | high | 61603 |
| `113524` | 8 | `T1557.001` T1557.001 | HackTool - Impacket Tools Execution | high | 61603 |
| `113525` | 13 | `T1557.001` T1557.001 | HackTool - Impacket Tools Execution | high | 61603 |
| `113526` | 8 | `T1557.001` T1557.001 | Potential SMB Relay Attack Tool Execution | high | 61603 |
| `113527` | 8 | `T1557.001` T1557.001 | Potential SMB Relay Attack Tool Execution | high | 61603 |
| `113528` | 8 | `T1557.001` T1557.001 | Potential SMB Relay Attack Tool Execution | high | 61603 |
| `113529` | 8 | `T1557.001` T1557.001 | Attempts of Kerberos Coercion Via DNS SPN Spoofing | high | 61603 |
| `113530` | 8 | `T1560.001` T1560.001 | Suspicious Manipulation Of Default Accounts Via Net.EXE | high | 61603 |
| `113531` | 7 | `T1123` T1123 | Audio Capture via PowerShell | medium | 61603 |
| `113532` | 7 | `T1115` T1115 | PowerShell Get-Clipboard Cmdlet Via CLI | medium | 61603 |
| `113533` | 7 | `T1074.001` T1074.001 | Folder Compress To Potentially Suspicious Output Via Compress-Archi... | medium | 61603 |
| `113534` | 7 | `T1113` T1113 | Screen Capture Activity Via Psr.EXE | medium | 61603 |
| `113535` | 8 | `T1560.001` T1560.001 | Rar Usage with Password and Compression Level | high | 61603 |
| `113536` | 7 | `T1113` T1113 | Windows Recall Feature Enabled Via Reg.EXE | medium | 61603 |
| `113537` | 7 | - | Renamed Remote Utilities RAT (RURAT) Execution | medium | 61603 |
| `113538` | 7 | `T1685.001` T1685.001 | Potential Suspicious Activity Using SeCEdit | medium | 61603 |
| `113539` | 7 | `T1123` T1123 | Audio Capture via SoundRecorder | medium | 61603 |
| `113540` | 7 | `T1005` T1005 | Veeam Backup Database Suspicious Query | medium | 61603 |
| `113541` | 8 | `T1005` T1005 | VeeamBackup Database Credentials Dump Via Sqlcmd.EXE | high | 61603 |
| `113542` | 7 | `T1119` T1119 | Automated Collection Command Prompt | medium | 61603 |
| `113543` | 7 | `T1119` T1119 | Recon Information for Export with Command Prompt | medium | 61603 |
| `113544` | 7 | `T1560.001` T1560.001 | Winrar Compressing Dump Files | medium | 61603 |
| `113545` | 7 | `T1560.001` T1560.001 | WinRAR Execution in Non-Standard Folder | medium | 61603 |
| `113546` | 7 | `T1560.001` T1560.001 | Compress Data and Lock With Password for Exfiltration With WINZIP | medium | 61603 |
| `113547` | 7 | `T1113` T1113 | Windows Recall Feature Enabled - DisableAIDataAnalysis Value Deleted | medium | 61614 |
| `113548` | 8 | `T1125` T1125 | Suspicious Camera and Microphone Access | high | 61615 |
| `113549` | 7 | `T1113` T1113 | Periodic Backup For System Registry Hives Enabled | medium | 61615 |
| `113550` | 7 | `T1113` T1113 | Windows Recall Feature Enabled - Registry | medium | 61615 |

### Command and Control (TA0011) — 191 rules

| Rule ID | Level | Technique | Description | Confidence | Parent SID |
|---------|-------|-----------|-------------|------------|------------|
| `110000` | 9 | `T1105` Ingress Tool Transfer | Executable dropped in downloads | medium | 61613 |
| `110001` | 9 | `T1105` Ingress Tool Transfer | Executable dropped in appdata | medium | 61613 |
| `110002` | 9 | `T1105` Ingress Tool Transfer | Executable dropped in temp | medium | 61613 |
| `110003` | 9 | `T1105` Ingress Tool Transfer | Executable dropped in programdata | medium | 61613 |
| `110004` | 9 | `T1105` Ingress Tool Transfer | Executable dropped in public | medium | 61613 |
| `110005` | 10 | `T1219.002` T1219.002 | Atera Agent Installation | high | 60003 |
| `110006` | 13 | `T1071.004` T1071.004 | Suspicious Cobalt Strike DNS Beaconing - DNS Client | high | 60000 |
| `110007` | 9 | - | DNS Query To Put.io - DNS Client | medium | 60000 |
| `110008` | 10 | `T1090.003` T1090.003 | Query Tor Onion Address - DNS Client | high | 60000 |
| `110009` | 9 | `T1219.002` T1219.002 | Potential Remote Desktop Connection to Non-Domain Host | medium | 60000 |
| `110010` | 10 | `T1090.001` T1090.001 | RDP over Reverse SSH Tunnel WFP | high | 60100 |
| `110011` | 10 | `T1001.003` T1001.003 | Suspicious LDAP-Attributes Used | high | 60100 |
| `110012` | 10 | `T1027` Obfuscated Files or Information | Password Protected ZIP File Opened (Suspicious Filenames) | high | 60100 |
| `110013` | 9 | `T1219.002` T1219.002 | Mesh Agent Service Installation | medium | 60002 |
| `110014` | 9 | `T1219.002` T1219.002 | TacticalRMM Service Installation | medium | 60002 |
| `110015` | 10 | `T1090` T1090 | Ngrok Usage with Remote Desktop Service | high | 60000 |
| `110016` | 9 | `T1105` Ingress Tool Transfer | AppX Package Installation Attempts Via AppInstaller.EXE | medium | 61624 |
| `110017` | 9 | `T1071.001` T1071.001 | Cloudflared Tunnels Related DNS Requests | medium | 61624 |
| `110018` | 9 | `T1071.004` T1071.004 | DNS Query To Common Malware Hosting and Shortener Services | medium | 61624 |
| `110019` | 9 | `T1071.001` T1071.001 | DNS Query To Devtunnels Domain | medium | 61624 |
| `110020` | 9 | `T1219.002` T1219.002 | DNS Query To AzureWebsites.NET By Non-Browser Process | medium | 61624 |
| `110021` | 10 | `T1071.004` T1071.004 | DNS Query by Finger Utility | high | 61624 |
| `110022` | 13 | `T1071.004` T1071.004 | Suspicious Cobalt Strike DNS Beaconing - Sysmon | high | 61624 |
| `110023` | 13 | `T1071.004` T1071.004 | Suspicious Cobalt Strike DNS Beaconing - Sysmon | high | 61624 |
| `110024` | 9 | `T1219.002` T1219.002 | DNS Query To Remote Access Software Domain From Non-Browser App | medium | 61624 |
| `110025` | 9 | `T1219.002` T1219.002 | DNS Query To Remote Access Software Domain From Non-Browser App | medium | 61624 |
| `110026` | 9 | `T1219.002` T1219.002 | TeamViewer Domain Query By Non-TeamViewer Application | medium | 61624 |
| `110027` | 10 | `T1090.003` T1090.003 | DNS Query Tor .Onion Address - Sysmon | high | 61624 |
| `110028` | 9 | `T1071.001` T1071.001 | DNS Query To Visual Studio Code Tunnels Domain | medium | 61624 |
| `110029` | 9 | `T1001.003` T1001.003 | ADSI-Cache File Creation By Uncommon Tool | medium | 61613 |
| `110030` | 9 | `T1219.002` T1219.002 | Anydesk Temporary Artefact | medium | 61613 |
| `110031` | 10 | `T1219.002` T1219.002 | Suspicious Binary Writes Via AnyDesk | high | 61613 |
| `110032` | 10 | `T1127` T1127 | Suspicious File Created by ArcSOC.exe | high | 61613 |
| `110033` | 9 | `T1105` Ingress Tool Transfer | Potentially Suspicious File Creation by OpenEDR's ITSMService | medium | 61613 |
| `110034` | 9 | `T1219.002` T1219.002 | GoToAssist Temporary Installation Artefact | medium | 61613 |
| `110035` | 10 | `T1219.002` T1219.002 | HackTool - Inveigh Execution Artefacts | high | 61613 |
| `110036` | 10 | `T1219.002` T1219.002 | HackTool - RemoteKrbRelay SMB Relay Secrets Dump Module Indicators | high | 61613 |
| `110037` | 9 | `T1219.002` T1219.002 | Installation of TeamViewer Desktop | medium | 61613 |
| `110038` | 9 | `T1219.002` T1219.002 | ScreenConnect Temporary Installation Artefact | medium | 61613 |
| `110039` | 10 | `T1105` Ingress Tool Transfer | Suspicious Desktopimgdownldr Target File | high | 61613 |
| `110040` | 10 | `T1218` T1218 | Legitimate Application Writing Files In Uncommon Location | high | 61613 |
| `110041` | 9 | `T1219.002` T1219.002 | TeamViewer Remote Session | medium | 61613 |
| `110042` | 9 | `T1219.002` T1219.002 | TeamViewer Remote Session | medium | 61613 |
| `110043` | 10 | `T1219.002` T1219.002 | Hijack Legit RDP Session to Move Laterally | high | 61613 |
| `110044` | 9 | - | Visual Studio Code Tunnel Remote File Creation | medium | 61613 |
| `110045` | 10 | - | Renamed VsCode Code Tunnel Execution - File Indicator | high | 61613 |
| `110046` | 10 | `T1071` Application Layer Protocol | HackTool - SILENTTRINITY Stager DLL Load | high | 61609 |
| `110047` | 10 | `T1105` Ingress Tool Transfer | Uncommon Network Connection Initiated By Certutil.EXE | high | 61605 |
| `110048` | 9 | `T1102` T1102 | Network Connection Initiated To AzureWebsites.NET By Non-Browser Pr... | medium | 61605 |
| `110049` | 10 | `T1102` T1102 | New Connection Initiated To Potential Dead Drop Resolver Domain | high | 61605 |
| `110050` | 10 | `T1105` Ingress Tool Transfer | Suspicious Dropbox API Usage | high | 61605 |
| `110051` | 9 | `T1102` T1102 | Suspicious Non-Browser Network Communication With Google API | medium | 61605 |
| `110052` | 10 | `T1572` T1572 | Communication To LocaltoNet Tunneling Service Initiated | high | 61605 |
| `110053` | 9 | `T1041` T1041 | Network Communication Initiated To Portmap.IO Domain | medium | 61605 |
| `110054` | 9 | `T1102` T1102 | Suspicious Non-Browser Network Communication With Telegram API | medium | 61605 |
| `110055` | 10 | `T1071.004` T1071.004 | Network Connection Initiated via Finger.EXE | high | 61605 |
| `110056` | 10 | `T1105` Ingress Tool Transfer | Network Connection Initiated By IMEWDBLD.EXE | high | 61605 |
| `110057` | 9 | - | Office Application Initiated Network Connection Over Uncommon Ports | medium | 61605 |
| `110058` | 10 | `T1572` T1572 | RDP Over Reverse SSH Tunnel | high | 61605 |
| `110059` | 10 | `T1572` T1572 | RDP to HTTP or HTTPS Target Ports | high | 61605 |
| `110060` | 10 | `T1105` Ingress Tool Transfer | Network Communication Initiated To File Sharing Domains From Proces... | high | 61605 |
| `110061` | 10 | `T1105` Ingress Tool Transfer | Network Connection Initiated From Process Located In Potentially Su... | high | 61605 |
| `110062` | 9 | - | Suspicious Wordpad Outbound Connections | medium | 61605 |
| `110063` | 9 | `T1105` Ingress Tool Transfer | Local Network Connection Initiated By Script Interpreter | medium | 61605 |
| `110064` | 10 | `T1105` Ingress Tool Transfer | Outbound Network Connection Initiated By Script Interpreter | high | 61605 |
| `110065` | 9 | `T1095` T1095 | Netcat The Powershell Version | medium | 91801 |
| `110066` | 9 | `T1105` Ingress Tool Transfer | Potential COM Objects Download Cradles Usage - PS Script | medium | 91801 |
| `110067` | 9 | `T1132.001` T1132.001 | Suspicious FromBase64String Usage On Gzip Archive - Ps Script | medium | 91801 |
| `110068` | 9 | `T1071.001` T1071.001 | Change User Agents with WebRequest | medium | 91801 |
| `110069` | 9 | `T1090` T1090 | Suspicious TCP Tunnel Via PowerShell Script | medium | 91801 |
| `110070` | 9 | `T1571` T1571 | Testing Usage of Uncommonly Used Port | medium | 91801 |
| `110071` | 10 | `T1105` Ingress Tool Transfer | File Download with Headless Browser | high | 61603 |
| `110072` | 9 | `T1105` Ingress Tool Transfer | File Download From Browser Process Via Inline URL | medium | 61603 |
| `110073` | 10 | `T1090.003` T1090.003 | Tor Client/Browser Execution | high | 61603 |
| `110074` | 10 | `T1090.003` T1090.003 | Tor Client/Browser Execution | high | 61603 |
| `110075` | 10 | `T1090.003` T1090.003 | Tor Client/Browser Execution | high | 61603 |
| `110076` | 9 | `T1105` Ingress Tool Transfer | File Download via CertOC.EXE | medium | 61603 |
| `110078` | 10 | `T1105` Ingress Tool Transfer | Suspicious CertReq Command to Download | high | 61603 |
| `110079` | 9 | `T1027` Obfuscated Files or Information | Suspicious Download Via Certutil.EXE | medium | 61603 |
| `110080` | 10 | `T1027` Obfuscated Files or Information | Suspicious File Downloaded From Direct IP Via Certutil.EXE | high | 61603 |
| `110081` | 10 | `T1027` Obfuscated Files or Information | Suspicious File Downloaded From File-Sharing Website Via Certutil.EXE | high | 61603 |
| `110082` | 9 | `T1090.001` T1090.001 | Cloudflared Portable Execution | medium | 61603 |
| `110083` | 9 | `T1090.001` T1090.001 | Cloudflared Quick Tunnel Execution | medium | 61603 |
| `110084` | 9 | `T1102` T1102 | Cloudflared Tunnel Connections Cleanup | medium | 61603 |
| `110085` | 9 | `T1102` T1102 | Cloudflared Tunnel Execution | medium | 61603 |
| `110086` | 10 | `T1218` T1218 | Curl Download And Execute Combination | high | 61603 |
| `110087` | 9 | `T1105` Ingress Tool Transfer | Potential Download/Upload Activity Using Type Command | medium | 61603 |
| `110088` | 9 | `T1105` Ingress Tool Transfer | Potential Download/Upload Activity Using Type Command | medium | 61603 |
| `110089` | 10 | `T1105` Ingress Tool Transfer | Suspicious Curl.EXE Download | high | 61603 |
| `110090` | 9 | `T1105` Ingress Tool Transfer | Remote File Download Via Desktopimgdownldr Utility | medium | 61603 |
| `110091` | 10 | `T1105` Ingress Tool Transfer | Suspicious Desktopimgdownldr Command | high | 61603 |
| `110092` | 10 | `T1105` Ingress Tool Transfer | Finger.EXE Execution | high | 61603 |
| `110093` | 10 | `T1105` Ingress Tool Transfer | Finger.EXE Execution | high | 61603 |
| `110094` | 9 | `T1105` Ingress Tool Transfer | Arbitrary File Download Via GfxDownloadWrapper.EXE | medium | 61603 |
| `110095` | 9 | `T1102.002` T1102.002 | Github Self-Hosted Runner Execution | medium | 61603 |
| `110096` | 10 | `T1105` Ingress Tool Transfer | File Download Using Notepad++ GUP Utility | high | 61603 |
| `110097` | 10 | `T1090` T1090 | HackTool - Htran/NATBypass Execution | high | 61603 |
| `110098` | 10 | `T1090` T1090 | HackTool - Htran/NATBypass Execution | high | 61603 |
| `110099` | 10 | `T1090.001` T1090.001 | HackTool - SharpChisel Execution | high | 61603 |
| `110100` | 10 | `T1090.001` T1090.001 | HackTool - SharpChisel Execution | high | 61603 |
| `110101` | 10 | `T1071` Application Layer Protocol | HackTool - SILENTTRINITY Stager Execution | high | 61603 |
| `110102` | 10 | `T1105` Ingress Tool Transfer | File Download And Execution Via IEExec.EXE | high | 61603 |
| `110103` | 10 | `T1102` T1102 | Suspicious Child Process Of Manage Engine ServiceDesk | high | 61603 |
| `110104` | 9 | `T1218` T1218 | Import LDAP Data Interchange Format File Via Ldifde.EXE | medium | 61603 |
| `110105` | 9 | `T1105` Ingress Tool Transfer | Suspicious Diantz Download and Compress Into a CAB File | medium | 61603 |
| `110106` | 9 | `T1105` Ingress Tool Transfer | Suspicious Extrac32 Execution | medium | 61603 |
| `110107` | 10 | `T1105` Ingress Tool Transfer | PrintBrm ZIP Creation of Extraction | high | 61603 |
| `110109` | 10 | `T1218` T1218 | File Download Via Windows Defender MpCmpRun.EXE | high | 61603 |
| `110110` | 9 | `T1218.007` T1218.007 | MsiExec Web Install | medium | 61603 |
| `110111` | 10 | `T1219.002` T1219.002 | Suspicious Mstsc.EXE Execution With Local RDP File | high | 61603 |
| `110112` | 10 | `T1572` T1572 | Suspicious Plink Port Forwarding | high | 61603 |
| `110113` | 10 | `T1572` T1572 | Potential RDP Tunneling Via Plink | high | 61603 |
| `110114` | 9 | `T1132.001` T1132.001 | Gzip Archive Decode Via PowerShell | medium | 61603 |
| `110115` | 9 | `T1105` Ingress Tool Transfer | Potential COM Objects Download Cradles Usage - Process Creation | medium | 61603 |
| `110116` | 9 | `T1059.001` T1059.001 | Potential DLL File Download Via PowerShell Invoke-WebRequest | medium | 61603 |
| `110117` | 9 | `T1132.001` T1132.001 | Suspicious FromBase64String Usage On Gzip Archive - Process Creation | medium | 61603 |
| `110118` | 9 | `T1105` Ingress Tool Transfer | Suspicious Invoke-WebRequest Execution With DirectIP | medium | 61603 |
| `110119` | 10 | `T1105` Ingress Tool Transfer | Suspicious Invoke-WebRequest Execution | high | 61603 |
| `110120` | 10 | `T1572` T1572 | PUA - 3Proxy Execution | high | 61603 |
| `110121` | 10 | `T1572` T1572 | PUA - 3Proxy Execution | high | 61603 |
| `110122` | 10 | `T1572` T1572 | PUA - 3Proxy Execution | high | 61603 |
| `110123` | 10 | `T1090.001` T1090.001 | PUA - Chisel Tunneling Tool Execution | high | 61603 |
| `110124` | 10 | `T1090` T1090 | PUA - Fast Reverse Proxy (FRP) Execution | high | 61603 |
| `110125` | 10 | `T1090` T1090 | PUA - Fast Reverse Proxy (FRP) Execution | high | 61603 |
| `110126` | 10 | `T1090` T1090 | PUA - Fast Reverse Proxy (FRP) Execution | high | 61603 |
| `110127` | 10 | `T1090` T1090 | PUA- IOX Tunneling Tool Execution | high | 61603 |
| `110128` | 10 | `T1090` T1090 | PUA- IOX Tunneling Tool Execution | high | 61603 |
| `110129` | 10 | `T1090` T1090 | PUA- IOX Tunneling Tool Execution | high | 61603 |
| `110130` | 10 | `T1095` T1095 | PUA - Netcat Suspicious Execution | high | 61603 |
| `110131` | 10 | `T1095` T1095 | PUA - Netcat Suspicious Execution | high | 61603 |
| `110132` | 10 | `T1572` T1572 | PUA - Ngrok Execution | high | 61603 |
| `110133` | 10 | `T1572` T1572 | PUA - Ngrok Execution | high | 61603 |
| `110134` | 10 | `T1572` T1572 | PUA - Ngrok Execution | high | 61603 |
| `110135` | 10 | `T1572` T1572 | PUA - Ngrok Execution | high | 61603 |
| `110136` | 10 | `T1105` Ingress Tool Transfer | PUA - Nimgrab Execution | high | 61603 |
| `110137` | 10 | `T1105` Ingress Tool Transfer | PUA - Nimgrab Execution | high | 61603 |
| `110138` | 10 | `T1090` T1090 | PUA - NPS Tunneling Tool Execution | high | 61603 |
| `110139` | 10 | `T1090` T1090 | PUA - NPS Tunneling Tool Execution | high | 61603 |
| `110140` | 10 | `T1090` T1090 | PUA - NPS Tunneling Tool Execution | high | 61603 |
| `110141` | 10 | `T1090` T1090 | PUA - NPS Tunneling Tool Execution | high | 61603 |
| `110142` | 9 | `T1090` T1090 | Potentially Suspicious Usage Of Qemu | medium | 61603 |
| `110143` | 9 | `T1219.002` T1219.002 | Remote Access Tool - AnyDesk Execution | medium | 61603 |
| `110144` | 9 | `T1219.002` T1219.002 | Remote Access Tool - AnyDesk Execution | medium | 61603 |
| `110145` | 9 | `T1219.002` T1219.002 | Remote Access Tool - AnyDesk Execution | medium | 61603 |
| `110146` | 9 | `T1219.002` T1219.002 | Remote Access Tool - AnyDesk Execution | medium | 61603 |
| `110147` | 9 | `T1219.002` T1219.002 | Remote Access Tool - AnyDesk Piped Password Via CLI | medium | 61603 |
| `110148` | 10 | `T1219.002` T1219.002 | Remote Access Tool - AnyDesk Silent Installation | high | 61603 |
| `110149` | 10 | `T1219.002` T1219.002 | Remote Access Tool - Anydesk Execution From Suspicious Folder | high | 61603 |
| `110150` | 9 | `T1219.002` T1219.002 | Remote Access Tool - GoToAssist Execution | medium | 61603 |
| `110151` | 9 | `T1219.002` T1219.002 | Remote Access Tool - GoToAssist Execution | medium | 61603 |
| `110152` | 9 | `T1219.002` T1219.002 | Remote Access Tool - GoToAssist Execution | medium | 61603 |
| `110153` | 9 | `T1219.002` T1219.002 | Remote Access Tool - LogMeIn Execution | medium | 61603 |
| `110154` | 9 | `T1219.002` T1219.002 | Remote Access Tool - LogMeIn Execution | medium | 61603 |
| `110155` | 9 | `T1219.002` T1219.002 | Remote Access Tool - LogMeIn Execution | medium | 61603 |
| `110156` | 9 | `T1219.002` T1219.002 | Remote Access Tool - Potential MeshAgent Execution - Windows | medium | 61603 |
| `110157` | 9 | `T1219.002` T1219.002 | Remote Access Tool - MeshAgent Command Execution via MeshCentral | medium | 61603 |
| `110158` | 9 | `T1219.002` T1219.002 | Remote Access Tool - NetSupport Execution | medium | 61603 |
| `110159` | 9 | `T1219.002` T1219.002 | Remote Access Tool - NetSupport Execution | medium | 61603 |
| `110160` | 9 | `T1219.002` T1219.002 | Remote Access Tool - NetSupport Execution | medium | 61603 |
| `110161` | 9 | `T1219.002` T1219.002 | Remote Access Tool - NetSupport Execution | medium | 61603 |
| `110162` | 10 | `T1219.002` T1219.002 | Remote Access Tool - Renamed MeshAgent Execution - Windows | high | 61603 |
| `110163` | 9 | `T1219.002` T1219.002 | Remote Access Tool - ScreenConnect Execution | medium | 61603 |
| `110164` | 9 | `T1219.002` T1219.002 | Remote Access Tool - ScreenConnect Execution | medium | 61603 |
| `110165` | 9 | `T1219.002` T1219.002 | Remote Access Tool - ScreenConnect Execution | medium | 61603 |
| `110166` | 9 | `T1219.002` T1219.002 | Remote Access Tool - ScreenConnect Potential Suspicious Remote Comm... | medium | 61603 |
| `110167` | 9 | `T1219.002` T1219.002 | Remote Access Tool - Simple Help Execution | medium | 61603 |
| `110168` | 9 | `T1219` T1219 | Remote Access Tool - TacticalRMM Agent Registration to Potentially ... | medium | 61603 |
| `110169` | 9 | `T1219.002` T1219.002 | Remote Access Tool - UltraViewer Execution | medium | 61603 |
| `110170` | 9 | `T1219.002` T1219.002 | Remote Access Tool - UltraViewer Execution | medium | 61603 |
| `110171` | 9 | `T1219.002` T1219.002 | Remote Access Tool - UltraViewer Execution | medium | 61603 |
| `110172` | 10 | `T1090.001` T1090.001 | Renamed Cloudflared.EXE Execution | high | 61603 |
| `110173` | 10 | `T1090.001` T1090.001 | Renamed Cloudflared.EXE Execution | high | 61603 |
| `110174` | 10 | `T1090.001` T1090.001 | Renamed Cloudflared.EXE Execution | high | 61603 |
| `110175` | 10 | `T1090.001` T1090.001 | Renamed Cloudflared.EXE Execution | high | 61603 |
| `110176` | 9 | `T1572` T1572 | Port Forwarding Activity Via SSH.EXE | medium | 61603 |
| `110177` | 10 | `T1572` T1572 | Potential RDP Tunneling Via SSH | high | 61603 |
| `110178` | 9 | `T1219.002` T1219.002 | Potential Amazon SSM Agent Hijacking | medium | 61603 |
| `110179` | 10 | `T1105` Ingress Tool Transfer | Suspicious Download from Office Domain | high | 61603 |
| `110180` | 10 | `T1219` T1219 | Suspicious Velociraptor Child Process | high | 61603 |
| `110181` | 10 | `T1219.002` T1219.002 | Suspicious TSCON Start as SYSTEM | high | 61603 |
| `110182` | 9 | `T1219.002` T1219.002 | Use of UltraVNC Remote Access Software | medium | 61603 |
| `110183` | 9 | `T1219.002` T1219.002 | Use of UltraVNC Remote Access Software | medium | 61603 |
| `110184` | 9 | `T1219.002` T1219.002 | Use of UltraVNC Remote Access Software | medium | 61603 |
| `110185` | 9 | `T1219.002` T1219.002 | Use of UltraVNC Remote Access Software | medium | 61603 |
| `110186` | 9 | `T1071.001` T1071.001 | Visual Studio Code Tunnel Execution | medium | 61603 |
| `110187` | 9 | `T1071.001` T1071.001 | Visual Studio Code Tunnel Execution | medium | 61603 |
| `110188` | 9 | `T1071.001` T1071.001 | Visual Studio Code Tunnel Execution | medium | 61603 |
| `110189` | 9 | `T1071.001` T1071.001 | Visual Studio Code Tunnel Shell Execution | medium | 61603 |
| `110190` | 10 | `T1071.001` T1071.001 | Renamed Visual Studio Code Tunnel Execution | high | 61603 |
| `110191` | 9 | `T1071.001` T1071.001 | Visual Studio Code Tunnel Service Installation | medium | 61603 |
| `110192` | 10 | `T1105` Ingress Tool Transfer | Lolbas OneDriveStandaloneUpdater.exe Proxy Download | high | 61615 |

### Exfiltration (TA0010) — 36 rules

| Rule ID | Level | Technique | Description | Confidence | Parent SID |
|---------|-------|-----------|-------------|------------|------------|
| `114500` | 12 | `T1485` Data Destruction | MSSQL Destructive Query | medium | 60003 |
| `114501` | 13 | `T1567.002` T1567.002 | DNS Query for Anonfiles.com Domain - DNS Client | high | 60000 |
| `114502` | 12 | `T1567.002` T1567.002 | DNS Query To MEGA Hosting Website - DNS Client | medium | 60000 |
| `114503` | 12 | `T1048` T1048 | Tap Driver Installation | medium | 60002 |
| `114504` | 13 | `T1567.002` T1567.002 | DNS Query for Anonfiles.com Domain - Sysmon | high | 61624 |
| `114505` | 12 | `T1567.002` T1567.002 | DNS Query To MEGA Hosting Website | medium | 61624 |
| `114506` | 12 | `T1567.002` T1567.002 | Rclone Config File Creation | medium | 61613 |
| `114507` | 12 | `T1567` T1567 | Network Connection Initiated To BTunnels Domains | medium | 61605 |
| `114508` | 12 | `T1567` T1567 | Network Connection Initiated To Cloudflared Tunnels Domains | medium | 61605 |
| `114509` | 12 | `T1567.001` T1567.001 | Network Connection Initiated To DevTunnels Domain | medium | 61605 |
| `114510` | 13 | `T1567` T1567 | Process Initiated Network Connection To Ngrok Domain | high | 61605 |
| `114511` | 13 | `T1567` T1567 | Communication To Ngrok Tunneling Service Initiated | high | 61605 |
| `114512` | 12 | `T1567` T1567 | Network Connection Initiated To Visual Studio Code Tunnels Domain | medium | 61605 |
| `114513` | 12 | `T1048.003` T1048.003 | Suspicious Outbound SMTP Connections | medium | 61605 |
| `114514` | 12 | - | Potential Data Exfiltration Via Audio File | medium | 91801 |
| `114515` | 12 | `T1048.003` T1048.003 | PowerShell ICMP Exfiltration | medium | 91801 |
| `114516` | 13 | `T1048` T1048 | Powershell DNSExfiltration | high | 91801 |
| `114517` | 13 | - | Suspicious PowerShell Mailbox Export to Share - PS | high | 91801 |
| `114518` | 12 | `T1020` T1020 | PowerShell Script With File Hostname Resolving Capabilities | medium | 91801 |
| `114519` | 12 | `T1567` T1567 | Arbitrary File Download Via ConfigSecurityPolicy.EXE | medium | 61603 |
| `114520` | 12 | `T1087.002` T1087.002 | Active Directory Structure Export Via Csvde.EXE | medium | 61603 |
| `114521` | 13 | `T1048.001` T1048.001 | DNS Exfiltration and Tunneling Tools Execution | high | 61603 |
| `114522` | 13 | `T1048.001` T1048.001 | DNS Exfiltration and Tunneling Tools Execution | high | 61603 |
| `114523` | 12 | - | Active Directory Structure Export Via Ldifde.EXE | medium | 61603 |
| `114524` | 12 | `T1567` T1567 | LOLBAS Data Exfiltration by DataSvcUtil.exe | medium | 61603 |
| `114525` | 13 | - | Email Exifiltration Via Powershell | high | 61603 |
| `114526` | 13 | - | Suspicious PowerShell Mailbox Export to Share | high | 61603 |
| `114527` | 13 | `T1567.002` T1567.002 | PUA - Rclone Execution | high | 61603 |
| `114528` | 13 | `T1048` T1048 | PUA - Restic Backup Tool Execution | high | 61603 |
| `114529` | 13 | `T1048` T1048 | PUA - Restic Backup Tool Execution | high | 61603 |
| `114530` | 13 | `T1048` T1048 | PUA - Restic Backup Tool Execution | high | 61603 |
| `114531` | 13 | `T1012` T1012 | Exports Critical Registry Keys To a File | high | 61603 |
| `114532` | 12 | `T1048.003` T1048.003 | WebDav Client Execution Via Rundll32.EXE | medium | 61603 |
| `114534` | 13 | `T1048` T1048 | Suspicious Redirection to Local Admin Share | high | 61603 |
| `114535` | 12 | `T1048` T1048 | Tap Installer Execution | medium | 61603 |
| `115001` | 13 | `T1003` OS Credential Dumping | credential_access_then_exfil | high | 110061 |

### Impact (TA0040) — 44 rules

| Rule ID | Level | Technique | Description | Confidence | Parent SID |
|---------|-------|-----------|-------------|------------|------------|
| `114000` | 13 | `T1490` T1490 | Suspicious command: shadow copy | medium | 61603 |
| `114001` | 13 | `T1489` Service Stop | Suspicious PowerShell: stop-service | medium | 91801 |
| `114002` | 13 | `T1070.004` T1070.004 | Potential Secure Deletion with SDelete | medium | 60100 |
| `114003` | 13 | `T1557` T1557 | ISATAP Router Address Was Set | medium | 60002 |
| `114004` | 14 | `T1499.001` T1499.001 | NTFS Vulnerability Exploitation | high | 60002 |
| `114005` | 14 | `T1489` Service Stop | Important Scheduled Task Deleted or Disabled | high | 60000 |
| `114006` | 13 | `T1490` T1490 | Backup Files Deleted | medium | 61625 |
| `114007` | 13 | `T1486` Data Encrypted for Impact | Suspicious Appended Extension | medium | 61613 |
| `114008` | 14 | `T1486` Data Encrypted for Impact | Load Of RstrtMgr.DLL By A Suspicious Process | high | 61609 |
| `114009` | 14 | `T1490` T1490 | Suspicious Volume Shadow Copy VSS_PS.dll Load | high | 61609 |
| `114010` | 14 | `T1490` T1490 | Suspicious Volume Shadow Copy Vssapi.dll Load | high | 61609 |
| `114011` | 13 | `T1490` T1490 | Potentially Suspicious Volume Shadow Copy Vsstrace.dll Load | medium | 61609 |
| `114012` | 14 | `T1496` T1496 | Network Communication With Crypto Mining Pool | high | 61605 |
| `114013` | 14 | `T1490` T1490 | Delete Volume Shadow Copies Via WMI With PowerShell | high | 91801 |
| `114014` | 14 | `T1565` T1565 | Powershell Add Name Resolution Policy Table Rule | high | 91801 |
| `114015` | 13 | `T1531` T1531 | Remove Account From Domain Admin Group | medium | 91801 |
| `114016` | 14 | `T1490` T1490 | Deletion of Volume Shadow Copies via WMI with PowerShell - PS Script | high | 91801 |
| `114017` | 14 | `T1490` T1490 | Boot Configuration Tampering Via Bcdedit.EXE | high | 61603 |
| `114018` | 13 | `T1485` Data Destruction | Deleted Data Overwritten Via Cipher.EXE | medium | 61603 |
| `114019` | 14 | `T1490` T1490 | Copy From VolumeShadowCopy Via Cmd.EXE | high | 61603 |
| `114020` | 14 | `T1070` Indicator Removal | Fsutil Suspicious Invocation | high | 61603 |
| `114021` | 13 | `T1486` Data Encrypted for Impact | Portable Gpg.EXE Execution | medium | 61603 |
| `114022` | 14 | `T1490` T1490 | Deletion of Volume Shadow Copies via WMI with PowerShell | high | 61603 |
| `114023` | 13 | `T1490` T1490 | Windows Recovery Environment Disabled Via Reagentc | medium | 61603 |
| `114024` | 14 | `T1486` Data Encrypted for Impact | Suspicious Reg Add BitLocker | high | 61603 |
| `114025` | 14 | `T1490` T1490 | System Restore Registry Modification via CommandLine | high | 61603 |
| `114026` | 14 | `T1486` Data Encrypted for Impact | Renamed Gpg.EXE Execution | high | 61603 |
| `114027` | 14 | `T1485` Data Destruction | Renamed Sysinternals Sdelete Execution | high | 61603 |
| `114028` | 14 | `T1489` Service Stop | Delete Important Scheduled Task | high | 61603 |
| `114029` | 14 | `T1489` Service Stop | Delete All Scheduled Tasks | high | 61603 |
| `114030` | 14 | `T1489` Service Stop | Disable Important Scheduled Task | high | 61603 |
| `114031` | 13 | `T1529` T1529 | Suspicious Execution of Shutdown | medium | 61603 |
| `114032` | 13 | `T1529` T1529 | Suspicious Execution of Shutdown to Log Out | medium | 61603 |
| `114033` | 14 | `T1496` T1496 | Potential Crypto Mining Activity | high | 61603 |
| `114034` | 14 | `T1490` T1490 | Sensitive File Access Via Volume Shadow Copy Backup | high | 61603 |
| `114035` | 14 | `T1489` Service Stop | Suspicious Windows Service Tampering | high | 61603 |
| `114036` | 14 | `T1070` Indicator Removal | Shadow Copies Deletion Using Operating Systems Utilities | high | 61603 |
| `114037` | 14 | `T1485` Data Destruction | Potential File Overwrite Via Sysinternals SDelete | high | 61603 |
| `114038` | 14 | `T1490` T1490 | All Backups Deleted Via Wbadmin.EXE | high | 61603 |
| `114039` | 13 | `T1490` T1490 | Windows Backup Deleted Via Wbadmin.EXE | medium | 61603 |
| `114040` | 13 | `T1490` T1490 | File Recovery From Backup Via Wbadmin.EXE | medium | 61603 |
| `114041` | 14 | `T1490` T1490 | Registry Disable System Restore | high | 61615 |
| `114042` | 13 | `T1490` T1490 | New Root or CA or AuthRoot Certificate to Store | medium | 61615 |
| `114043` | 14 | `T1491.001` T1491.001 | Potential Ransomware Activity Using LegalNotice Message | high | 61615 |

## Exported Rule Files

Rules are exported in three parallel views. Each view contains the same rules, organized differently:

### `database/rules/by_tactic/`
_One XML file per MITRE ATT&CK tactic. Best for broad deployment._

| File | Rules |
|------|-------|
| `collection.xml` | 51 |
| `command_and_control.xml` | 191 |
| `credential_access.xml` | 290 |
| `defense_evasion.xml` | 42 |
| `discovery.xml` | 137 |
| `execution.xml` | 1118 |
| `exfiltration.xml` | 36 |
| `impact.xml` | 44 |
| `initial_access.xml` | 32 |
| `lateral_movement.xml` | 72 |
| `persistence.xml` | 839 |
| `privilege_escalation.xml` | 363 |

### `database/rules/by_technique/`
_One XML file per MITRE technique. Best for selective/granular deployment._

| File | Rules |
|------|-------|
| `T1001.003_unknown.xml` | 2 |
| `T1003.001_unknown.xml` | 93 |
| `T1003.002_unknown.xml` | 17 |
| `T1003.003_unknown.xml` | 20 |
| `T1003.004_unknown.xml` | 2 |
| `T1003.005_unknown.xml` | 2 |
| `T1003.006_unknown.xml` | 3 |
| `T1003_credential_dumping.xml` | 29 |
| `T1005_data_from_local_system.xml` | 4 |
| `T1010_unknown.xml` | 1 |
| `T1012_unknown.xml` | 6 |
| `T1016_unknown.xml` | 2 |
| `T1018_unknown.xml` | 7 |
| `T1020_unknown.xml` | 1 |
| `T1021.001_unknown.xml` | 8 |
| `T1021.002_unknown.xml` | 35 |
| `T1021.003_unknown.xml` | 4 |
| `T1021.004_unknown.xml` | 1 |
| `T1021.005_unknown.xml` | 1 |
| `T1021.006_unknown.xml` | 5 |
| `T1021_remote_services.xml` | 3 |
| `T1027.004_unknown.xml` | 2 |
| `T1027.005_unknown.xml` | 2 |
| `T1027.009_unknown.xml` | 0 |
| `T1027.010_unknown.xml` | 2 |
| `T1027_obfuscated_files.xml` | 52 |
| `T1033_unknown.xml` | 17 |
| `T1036.002_unknown.xml` | 2 |
| `T1036.003_unknown.xml` | 19 |
| `T1036.005_unknown.xml` | 8 |
| `T1036.007_unknown.xml` | 5 |
| `T1036_unknown.xml` | 45 |
| `T1037.001_unknown.xml` | 3 |
| `T1039_data_from_network_shared.xml` | 2 |
| `T1040_unknown.xml` | 8 |
| `T1041_exfil_over_c2.xml` | 1 |
| `T1046_unknown.xml` | 19 |
| `T1047_unknown.xml` | 52 |
| `T1048.001_unknown.xml` | 2 |
| `T1048.003_unknown.xml` | 3 |
| `T1048_exfil_over_alt_protocol.xml` | 8 |
| `T1049_unknown.xml` | 3 |
| `T1053.002_unknown.xml` | 2 |
| `T1053.005_unknown.xml` | 30 |
| `T1053_scheduled_task.xml` | 8 |
| `T1055.001_unknown.xml` | 5 |
| `T1055.003_unknown.xml` | 1 |
| `T1055.012_unknown.xml` | 3 |
| `T1055_process_injection.xml` | 35 |
| `T1056.001_unknown.xml` | 3 |
| `T1056.002_unknown.xml` | 4 |
| `T1057_unknown.xml` | 1 |
| `T1059.001_unknown.xml` | 123 |
| `T1059.003_unknown.xml` | 12 |
| `T1059.005_unknown.xml` | 11 |
| `T1059.006_unknown.xml` | 2 |
| `T1059.007_unknown.xml` | 1 |
| `T1059_command_scripting.xml` | 68 |
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
| `T1078_valid_accounts.xml` | 9 |
| `T1082_system_info_discovery.xml` | 18 |
| `T1083_file_directory_discovery.xml` | 3 |
| `T1087.001_unknown.xml` | 11 |
| `T1087.002_unknown.xml` | 13 |
| `T1087_account_discovery.xml` | 5 |
| `T1090.001_unknown.xml` | 10 |
| `T1090.003_unknown.xml` | 5 |
| `T1090_unknown.xml` | 18 |
| `T1095_unknown.xml` | 3 |
| `T1098_unknown.xml` | 11 |
| `T1102.002_unknown.xml` | 1 |
| `T1102_unknown.xml` | 7 |
| `T1105_ingress_tool_transfer.xml` | 40 |
| `T1106_unknown.xml` | 6 |
| `T1110.001_unknown.xml` | 1 |
| `T1110.002_unknown.xml` | 2 |
| `T1110_brute_force.xml` | 5 |
| `T1112_unknown.xml` | 62 |
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
| `T1136.001_unknown.xml` | 6 |
| `T1136.002_unknown.xml` | 2 |
| `T1137.002_unknown.xml` | 1 |
| `T1137.003_unknown.xml` | 1 |
| `T1137.006_unknown.xml` | 7 |
| `T1137_unknown.xml` | 9 |
| `T1140_unknown.xml` | 11 |
| `T1176.001_unknown.xml` | 2 |
| `T1185_unknown.xml` | 3 |
| `T1187_unknown.xml` | 2 |
| `T1190_exploit_public_app.xml` | 6 |
| `T1195.002_unknown.xml` | 3 |
| `T1195_unknown.xml` | 1 |
| `T1197_unknown.xml` | 13 |
| `T1200_unknown.xml` | 1 |
| `T1201_unknown.xml` | 1 |
| `T1202_unknown.xml` | 21 |
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
| `T1218.003_unknown.xml` | 7 |
| `T1218.004_unknown.xml` | 3 |
| `T1218.005_unknown.xml` | 11 |
| `T1218.007_unknown.xml` | 7 |
| `T1218.008_unknown.xml` | 8 |
| `T1218.009_unknown.xml` | 3 |
| `T1218.010_unknown.xml` | 14 |
| `T1218.011_unknown.xml` | 34 |
| `T1218_unknown.xml` | 110 |
| `T1219.002_unknown.xml` | 54 |
| `T1219_unknown.xml` | 2 |
| `T1220_unknown.xml` | 3 |
| `T1222.001_unknown.xml` | 2 |
| `T1222_unknown.xml` | 1 |
| `T1482_unknown.xml` | 6 |
| `T1484.001_unknown.xml` | 6 |
| `T1485_data_destruction.xml` | 4 |
| `T1486_data_encrypted_for_impact.xml` | 5 |
| `T1489_service_stop.xml` | 6 |
| `T1490_unknown.xml` | 18 |
| `T1491.001_unknown.xml` | 1 |
| `T1496_unknown.xml` | 2 |
| `T1497.001_unknown.xml` | 1 |
| `T1499.001_unknown.xml` | 1 |
| `T1505.002_unknown.xml` | 3 |
| `T1505.003_unknown.xml` | 20 |
| `T1505.004_unknown.xml` | 1 |
| `T1518.001_unknown.xml` | 3 |
| `T1518_unknown.xml` | 2 |
| `T1526_unknown.xml` | 1 |
| `T1528_unknown.xml` | 6 |
| `T1529_unknown.xml` | 2 |
| `T1531_unknown.xml` | 1 |
| `T1539_unknown.xml` | 2 |
| `T1542.001_unknown.xml` | 2 |
| `T1543.003_unknown.xml` | 532 |
| `T1543_create_modify_service.xml` | 10 |
| `T1546.001_unknown.xml` | 1 |
| `T1546.002_unknown.xml` | 4 |
| `T1546.003_unknown.xml` | 20 |
| `T1546.007_unknown.xml` | 3 |
| `T1546.008_unknown.xml` | 5 |
| `T1546.009_unknown.xml` | 2 |
| `T1546.010_unknown.xml` | 1 |
| `T1546.011_unknown.xml` | 6 |
| `T1546.012_unknown.xml` | 3 |
| `T1546.013_unknown.xml` | 3 |
| `T1546.015_unknown.xml` | 9 |
| `T1546_unknown.xml` | 2 |
| `T1547.001_unknown.xml` | 35 |
| `T1547.003_unknown.xml` | 1 |
| `T1547.004_unknown.xml` | 4 |
| `T1547.005_unknown.xml` | 1 |
| `T1547.008_unknown.xml` | 1 |
| `T1547.009_unknown.xml` | 4 |
| `T1547.010_unknown.xml` | 3 |
| `T1547.015_unknown.xml` | 1 |
| `T1547_boot_autostart.xml` | 6 |
| `T1548.002_unknown.xml` | 62 |
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
| `T1556.002_unknown.xml` | 1 |
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
| `T1564.004_unknown.xml` | 14 |
| `T1564.006_unknown.xml` | 1 |
| `T1564_unknown.xml` | 7 |
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
| `T1588_unknown.xml` | 1 |
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
| `T1685_unknown.xml` | 120 |
| `T1686.003_unknown.xml` | 14 |
| `T1689_unknown.xml` | 1 |
| `unknown_collection.xml` | 1 |
| `unknown_command_and_control.xml` | 5 |
| `unknown_credential_access.xml` | 7 |
| `unknown_discovery.xml` | 14 |
| `unknown_execution.xml` | 157 |
| `unknown_exfiltration.xml` | 5 |
| `unknown_initial_access.xml` | 4 |
| `unknown_lateral_movement.xml` | 3 |
| `unknown_persistence.xml` | 38 |
| `unknown_privilege_escalation.xml` | 22 |

### `database/rules/by_source/`
_Grouped by Windows event source (Sysmon, Security, PowerShell, System). Aligns with Wazuh decoder structure._

| File | Rules |
|------|-------|
| `application.xml` | 60 |
| `composite.xml` | 4 |
| `powershell.xml` | 211 |
| `security.xml` | 152 |
| `sysmon.xml` | 2200 |
| `system.xml` | 588 |

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
