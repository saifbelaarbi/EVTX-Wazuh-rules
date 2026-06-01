# Wazuh Rule Database Report

> Generated: 2026-06-01 21:23 UTC
> Pipeline version: 1.0.0

## Overview

| Metric | Value |
|--------|-------|
| Total rules generated | **3072** |
| EVTX files processed | 2081 |
| EVTX sources used | 1 |
| MITRE tactics covered | 12 / 12 |
| MITRE techniques covered | 264 |
| Rule ID range | 100000 - 120000 |

## Alert Level Distribution

| Level | Wazuh Severity | Count | Percentage |
|-------|----------------|-------|------------|
| 6 | Low relevance | 87 | 2.8% █ |
| 7 | Bad word matching | 75 | 2.4% █ |
| 8 | First time seen | 491 | 16.0% ███████ |
| 9 | Error from invalid source | 1295 | 42.2% █████████████████████ |
| 10 | Multiple user-generated errors | 426 | 13.9% ██████ |
| 11 | Integrity checking warning | 334 | 10.9% █████ |
| 12 | High importance event | 229 | 7.5% ███ |
| 13 | Unusual error (high importance) | 104 | 3.4% █ |
| 14 | High importance security event | 31 | 1.0%  |

## Detection Confidence Distribution

| Confidence | Count | Description |
|------------|-------|-------------|
| high | 1452 | Exact tool/process name match |
| medium | 1612 | Command-line pattern or behavioral indicator |
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

### Execution (TA0002) — 1000 rules

| Rule ID | Level | Technique | Description | Confidence | Parent SID |
|---------|-------|-----------|-------------|------------|------------|
| `101000` | 9 | `T1047` T1047 | Suspicious process: wmic | high | 61603 |
| `101001` | 8 | `T1059.001` T1059.001 | Suspicious command: iex( | medium | 61603 |
| `101002` | 8 | `T1047` T1047 | File created by wmic | medium | 61613 |
| `101003` | 9 | `T1047` T1047 | Network connection by wmic | high | 61605 |
| `101004` | 8 | `T1059.001` T1059.001 | Suspicious command: -nop  | medium | 61603 |
| `101005` | 9 | `T1047` T1047 | DLL sideloading by wmic | high | 61609 |
| `101006` | 9 | `T1047` T1047 | Network connection by wmic | high | 61605 |
| `101007` | 8 | `T1059.001` T1059.001 | Suspicious command: bypass | medium | 61603 |
| `101008` | 8 | `T1059.001` T1059.001 | Suspicious command: -w hidden | medium | 61603 |
| `101009` | 8 | `T1059.001` T1059.001 | Suspicious PowerShell: downloadstring | medium | 91801 |
| `101010` | 8 | `T1059.001` T1059.001 | Suspicious PowerShell: iex( | medium | 91801 |
| `101011` | 8 | `T1059.001` T1059.001 | PowerShell module: downloadstring | medium | 91801 |
| `101012` | 8 | `T1059.001` T1059.001 | PowerShell module: iex( | medium | 91801 |
| `101013` | 8 | `T1059.001` T1059.001 | PowerShell module: invoke-expression | medium | 91801 |
| `101014` | 8 | `T1059.001` T1059.001 | Suspicious PowerShell: bypass | medium | 91801 |
| `101015` | 8 | `T1047` T1047 | Suspicious PowerShell: invoke-wmimethod | medium | 91801 |
| `101016` | 8 | `T1059.001` T1059.001 | Suspicious PowerShell: invoke-expression | medium | 91801 |
| `101017` | 8 | `T1059.001` T1059.001 | Suspicious PowerShell: invoke-webrequest | medium | 91801 |
| `101018` | 8 | `T1059.001` T1059.001 | Suspicious PowerShell: -nop  | medium | 91801 |
| `101019` | 9 | `T1685` T1685 | Windows Filtering Platform Blocked Connection From EDR Agent Binary | high | 60100 |
| `101020` | 9 | `T1222.001` T1222.001 | AD Object WriteDAC Access | high | 60100 |
| `101021` | 9 | `T1685` T1685 | Weak Encryption Enabled and Kerberoast | high | 60100 |
| `101022` | 9 | `T1685.005` T1685.005 | Security Eventlog Cleared | high | 60100 |
| `101023` | 9 | `T1685.005` T1685.005 | Security Eventlog Cleared | high | 60100 |
| `101024` | 9 | `T1685.001` T1685.001 | Important Windows Event Auditing Disabled | high | 60100 |
| `101025` | 9 | `T1685.001` T1685.001 | Important Windows Event Auditing Disabled | high | 60100 |
| `101026` | 9 | `T1685` T1685 | HackTool - EDRSilencer Execution - Filter Added | high | 60100 |
| `101027` | 9 | `T1027` Obfuscated Files or Information | Invoke-Obfuscation CLIP+ Launcher - Security | high | 60100 |
| `101028` | 9 | `T1027` Obfuscated Files or Information | Invoke-Obfuscation Obfuscated IEX Invocation - Security | high | 60100 |
| `101029` | 9 | `T1027` Obfuscated Files or Information | Invoke-Obfuscation STDIN+ Launcher - Security | high | 60100 |
| `101030` | 9 | `T1027` Obfuscated Files or Information | Invoke-Obfuscation VAR+ Launcher - Security | high | 60100 |
| `101031` | 8 | `T1027` Obfuscated Files or Information | Invoke-Obfuscation COMPRESS OBFUSCATION - Security | medium | 60100 |
| `101032` | 8 | `T1027` Obfuscated Files or Information | Invoke-Obfuscation RUNDLL LAUNCHER - Security | medium | 60100 |
| `101033` | 9 | `T1027` Obfuscated Files or Information | Invoke-Obfuscation Via Stdin - Security | high | 60100 |
| `101034` | 9 | `T1027` Obfuscated Files or Information | Invoke-Obfuscation Via Use Clip - Security | high | 60100 |
| `101035` | 9 | `T1027` Obfuscated Files or Information | Invoke-Obfuscation Via Use MSHTA - Security | high | 60100 |
| `101036` | 9 | `T1027` Obfuscated Files or Information | Invoke-Obfuscation Via Use Rundll32 - Security | high | 60100 |
| `101037` | 9 | `T1027` Obfuscated Files or Information | Invoke-Obfuscation VAR++ LAUNCHER OBFUSCATION - Security | high | 60100 |
| `101038` | 8 | - | Potential AS-REP Roasting via Kerberos TGT Requests | medium | 60100 |
| `101039` | 8 | `T1036` T1036 | New or Renamed User Account with '$' Character | medium | 60100 |
| `101040` | 8 | `T1036` T1036 | New or Renamed User Account with '$' Character | medium | 60100 |
| `101041` | 9 | `T1569.002` T1569.002 | PowerShell Scripts Installed as Services - Security | high | 60100 |
| `101042` | 9 | `T1059.001` T1059.001 | Remote PowerShell Sessions Network Connections (WinRM) | high | 60100 |
| `101043` | 8 | `T1027` Obfuscated Files or Information | Password Protected ZIP File Opened | medium | 60100 |
| `101044` | 9 | `T1053.005` T1053.005 | Suspicious Scheduled Task Creation | high | 60100 |
| `101045` | 9 | `T1053.005` T1053.005 | Important Scheduled Task Deleted/Disabled | high | 60100 |
| `101046` | 9 | `T1053.005` T1053.005 | Suspicious Scheduled Task Update | high | 60100 |
| `101047` | 8 | `T1685` T1685 | Potential Privileged System Service Operation - SeLoadDriverPrivilege | medium | 60100 |
| `101048` | 8 | `T1685` T1685 | Windows Defender Exclusion List Modified | medium | 60100 |
| `101049` | 8 | `T1685` T1685 | Windows Defender Exclusion Registry Key - Write Access Requested | medium | 60100 |
| `101050` | 9 | `T1047` T1047 | T1047 Wmiprvse Wbemcomn DLL Hijack | high | 60100 |
| `101051` | 9 | `T1685` T1685 | Sysmon Application Crashed | high | 60106 |
| `101052` | 8 | `T1685.005` T1685.005 | Eventlog Cleared | medium | 60106 |
| `101053` | 9 | `T1685.005` T1685.005 | Important Windows Eventlog Cleared | high | 60106 |
| `101054` | 8 | `T1685` T1685 | Windows Defender Threat Detection Service Disabled | medium | 60106 |
| `101055` | 9 | `T1027` Obfuscated Files or Information | Invoke-Obfuscation CLIP+ Launcher - System | high | 60106 |
| `101056` | 9 | `T1027` Obfuscated Files or Information | Invoke-Obfuscation Obfuscated IEX Invocation - System | high | 60106 |
| `101057` | 9 | `T1027` Obfuscated Files or Information | Invoke-Obfuscation STDIN+ Launcher - System | high | 60106 |
| `101058` | 9 | `T1027` Obfuscated Files or Information | Invoke-Obfuscation VAR+ Launcher - System | high | 60106 |
| `101059` | 8 | `T1027` Obfuscated Files or Information | Invoke-Obfuscation COMPRESS OBFUSCATION - System | medium | 60106 |
| `101060` | 8 | `T1027` Obfuscated Files or Information | Invoke-Obfuscation RUNDLL LAUNCHER - System | medium | 60106 |
| `101061` | 9 | `T1027` Obfuscated Files or Information | Invoke-Obfuscation Via Stdin - System | high | 60106 |
| `101062` | 9 | `T1027` Obfuscated Files or Information | Invoke-Obfuscation Via Use Clip - System | high | 60106 |
| `101063` | 9 | `T1027` Obfuscated Files or Information | Invoke-Obfuscation Via Use MSHTA - System | high | 60106 |
| `101064` | 9 | `T1027` Obfuscated Files or Information | Invoke-Obfuscation Via Use Rundll32 - System | high | 60106 |
| `101065` | 9 | `T1027` Obfuscated Files or Information | Invoke-Obfuscation VAR++ LAUNCHER OBFUSCATION - System | high | 60106 |
| `101066` | 9 | `T1569.002` T1569.002 | PowerShell Scripts Installed as Services | high | 60106 |
| `101067` | 8 | `T1569.002` T1569.002 | CSExec Service Installation | medium | 60106 |
| `101068` | 9 | `T1569.002` T1569.002 | HackTool Service Registration or Execution | high | 60106 |
| `101069` | 8 | `T1569.002` T1569.002 | PAExec Service Installation | medium | 60106 |
| `101070` | 8 | `T1569.002` T1569.002 | RemCom Service Installation | medium | 60106 |
| `101071` | 8 | `T1569.002` T1569.002 | PsExec Service Installation | medium | 60106 |
| `101072` | 9 | - | Important Windows Service Terminated With Error | high | 60106 |
| `101073` | 9 | - | Important Windows Service Terminated Unexpectedly | high | 60106 |
| `101074` | 8 | `T1218.011` T1218.011 | Remote Thread Creation Via PowerShell In Uncommon Target | medium | 61610 |
| `101075` | 9 | `T1127` T1127 | Remote Thread Creation Ttdinject.exe Proxy | high | 61610 |
| `101076` | 8 | `T1564.004` T1564.004 | Hidden Executable In NTFS Alternate Data Stream | medium | 61617 |
| `101077` | 8 | - | Creation Of a Suspicious ADS File Outside a Browser Download | medium | 61617 |
| `101078` | 9 | `T1564.004` T1564.004 | Suspicious File Download From File Sharing Websites -  File Stream | high | 61617 |
| `101079` | 8 | `T1564.004` T1564.004 | Unusual File Download From File Sharing Websites - File Stream | medium | 61617 |
| `101080` | 9 | `T1564.004` T1564.004 | HackTool Named File Stream Created | high | 61617 |
| `101081` | 9 | `T1564.004` T1564.004 | Exports Registry Key To an Alternate Data Stream | high | 61617 |
| `101082` | 9 | `T1564.004` T1564.004 | Unusual File Download from Direct IP Address | high | 61617 |
| `101083` | 9 | - | Potentially Suspicious File Download From ZIP TLD | high | 61617 |
| `101084` | 8 | `T1559.001` T1559.001 | DNS Query Request By Regsvr32.EXE | medium | 61624 |
| `101085` | 8 | `T1590` T1590 | Suspicious DNS Query for IP Lookup Service APIs | medium | 61624 |
| `101086` | 8 | `T1070` Indicator Removal | EventLog EVTX File Deleted | medium | 61625 |
| `101087` | 9 | `T1070` Indicator Removal | Exchange PowerShell Cmdlet History Deleted | high | 61625 |
| `101088` | 8 | `T1070` Indicator Removal | IIS WebServer Access Logs Deleted | medium | 61625 |
| `101089` | 8 | - | Process Deletion of Its Own Executable | medium | 61625 |
| `101090` | 8 | `T1070` Indicator Removal | PowerShell Console History Logs Deleted | medium | 61625 |
| `101091` | 9 | `T1070.004` T1070.004 | Prefetch File Deleted | high | 61625 |
| `101092` | 8 | `T1070` Indicator Removal | Tomcat WebServer Logs Deleted | medium | 61625 |
| `101093` | 8 | `T1070.004` T1070.004 | File Deleted Via Sysinternals SDelete | medium | 61625 |
| `101094` | 8 | `T1070.004` T1070.004 | ADS Zone.Identifier Deleted By Uncommon Application | medium | 61625 |
| `101095` | 8 | - | Assembly DLL Creation Via AspNetCompiler | medium | 61613 |
| `101096` | 8 | `T1685.001` T1685.001 | EVTX Created In Uncommon Location | medium | 61613 |
| `101097` | 8 | `T1036.005` T1036.005 | Files With System DLL Name In Unsuspected Locations | medium | 61613 |
| `101098` | 12 | `T1036.005` T1036.005 | Files With System Process Name In Unsuspected Locations | medium | 61613 |
| `101099` | 9 | `T1059.005` T1059.005 | WScript or CScript Dropper - File | high | 61613 |
| `101100` | 8 | `T1569.002` T1569.002 | CSExec Service File Creation | medium | 61613 |
| `101101` | 8 | - | Potentially Suspicious DMP/HDMP File Creation | medium | 61613 |
| `101102` | 9 | `T1021.002` T1021.002 | HackTool - NetExec File Indicators | high | 61613 |
| `101103` | 9 | `T1021.002` T1021.002 | HackTool - NetExec File Indicators | high | 61613 |
| `101104` | 9 | `T1059.005` T1059.005 | Adwind RAT / JRAT File Artifact | high | 61613 |
| `101105` | 9 | `T1059.005` T1059.005 | Adwind RAT / JRAT File Artifact | high | 61613 |
| `101106` | 9 | - | Uncommon File Creation By Mysql Daemon Process | high | 61613 |
| `101107` | 9 | `T1218` T1218 | Suspicious DotNET CLR Usage Log Artifact | high | 61613 |
| `101108` | 9 | - | Suspicious File Creation In Uncommon AppData Folder | high | 61613 |
| `101109` | 8 | `T1218.011` T1218.011 | SCR File Write Event | medium | 61613 |
| `101110` | 8 | - | OneNote Attachment File Dropped In Suspicious Location | medium | 61613 |
| `101111` | 9 | - | Suspicious File Created Via OneNote Application | high | 61613 |
| `101112` | 8 | - | Publisher Attachment File Dropped In Suspicious Location | medium | 61613 |
| `101113` | 9 | `T1204.002` T1204.002 | File With Uncommon Extension Created By An Office Application | high | 61613 |
| `101114` | 9 | `T1587.001` T1587.001 | Uncommon File Created In Office Startup Folder | high | 61613 |
| `101115` | 9 | `T1059` Command and Scripting Interpreter | PCRE.NET Package Temp Files | high | 61613 |
| `101116` | 8 | `T1059` Command and Scripting Interpreter | Suspicious File Created In PerfLogs | medium | 61613 |
| `101117` | 13 | `T1059.001` T1059.001 | Malicious PowerShell Scripts - FileCreation | high | 61613 |
| `101118` | 9 | `T1059.001` T1059.001 | Malicious PowerShell Scripts - FileCreation | high | 61613 |
| `101119` | 8 | - | PSScriptPolicyTest Creation By Uncommon Process | medium | 61613 |
| `101120` | 9 | - | .RDP File Created By Uncommon Application | high | 61613 |
| `101121` | 9 | `T1027` Obfuscated Files or Information | Potential Winnti Dropper Activity | high | 61613 |
| `101122` | 9 | - | PDF File Created By RegEdit.EXE | high | 61613 |
| `101123` | 8 | `T1569.002` T1569.002 | RemCom Service File Creation | medium | 61613 |
| `101124` | 8 | `T1218` T1218 | Self Extraction Directive File Created In Potentially Suspicious Lo... | medium | 61613 |
| `101125` | 9 | `T1059` Command and Scripting Interpreter | Windows Shell/Scripting Application File Write to Suspicious Folder | high | 61613 |
| `101126` | 9 | `T1059` Command and Scripting Interpreter | Windows Shell/Scripting Application File Write to Suspicious Folder | high | 61613 |
| `101127` | 12 | `T1036` T1036 | Windows Binaries Write Suspicious Extensions | high | 61613 |
| `101128` | 9 | `T1036` T1036 | Windows Binaries Write Suspicious Extensions | high | 61613 |
| `101129` | 9 | `T1564` T1564 | Suspicious Creation with Colorcpl | high | 61613 |
| `101130` | 8 | `T1036.005` T1036.005 | Suspicious Files in Default GPO Folder | medium | 61613 |
| `101131` | 8 | - | Creation of a Diagcab | medium | 61613 |
| `101132` | 9 | `T1036.007` T1036.007 | Suspicious Double Extension Files | high | 61613 |
| `101133` | 9 | `T1036.007` T1036.007 | Suspicious Double Extension Files | high | 61613 |
| `101134` | 9 | `T1564` T1564 | Suspicious Executable File Creation | high | 61613 |
| `101135` | 8 | `T1564.004` T1564.004 | Potential Hidden Directory Creation Via NTFS INDEX_ALLOCATION Stream | medium | 61613 |
| `101136` | 8 | `T1036` T1036 | Potential Homoglyph Attack Using Lookalike Characters in Filename | medium | 61613 |
| `101137` | 8 | `T1036` T1036 | Potential Homoglyph Attack Using Lookalike Characters in Filename | medium | 61613 |
| `101138` | 9 | `T1218` T1218 | Legitimate Application Dropped Archive | high | 61613 |
| `101139` | 9 | `T1218` T1218 | Legitimate Application Dropped Executable | high | 61613 |
| `101140` | 9 | `T1218` T1218 | Legitimate Application Dropped Script | high | 61613 |
| `101141` | 8 | `T1036.007` T1036.007 | Suspicious LNK Double Extension File Created | medium | 61613 |
| `101142` | 8 | `T1685` T1685 | Suspicious PROCEXP152.sys File Created In TMP | medium | 61613 |
| `101143` | 9 | `T1204` User Execution | Suspicious Binaries and Scripts in Public Folder | high | 61613 |
| `101144` | 9 | `T1036.002` T1036.002 | Potential File Extension Spoofing Using Right-to-Left Override | high | 61613 |
| `101145` | 8 | - | Drop Binaries Into Spool Drivers Color Folder | medium | 61613 |
| `101146` | 9 | `T1059.001` T1059.001 | Suspicious Interactive PowerShell as SYSTEM | high | 61613 |
| `101147` | 8 | - | Potentially Suspicious WDAC Policy File Creation | medium | 61613 |
| `101148` | 8 | - | WinSxS Executable File Creation By Non-System Process | medium | 61613 |
| `101149` | 9 | `T1548.002` T1548.002 | UAC Bypass Using IDiagnostic Profile - File | high | 61613 |
| `101150` | 8 | `T1587.001` T1587.001 | VHD Image Download Via Browser | medium | 61613 |
| `101151` | 8 | `T1216` T1216 | AWL Bypass with Winrm.vbs and Malicious WsmPty.xsl/WsmTxt.xsl - File | medium | 61613 |
| `101152` | 9 | `T1047` T1047 | Wmiprvse Wbemcomn DLL Hijack - File | high | 61613 |
| `101153` | 8 | `T1059` Command and Scripting Interpreter | Clfs.SYS Loaded By Process Located In a Potential Suspicious Location | medium | 61609 |
| `101154` | 9 | `T1218.003` T1218.003 | DLL Loaded From Suspicious Location Via Cmspt.EXE | high | 61609 |
| `101155` | 8 | - | Amsi.DLL Loaded Via LOLBIN Process | medium | 61609 |
| `101156` | 9 | `T1059` Command and Scripting Interpreter | PCRE.NET Package Image Load | high | 61609 |
| `101157` | 9 | `T1202` T1202 | Diagnostic Library Sdiageng.DLL Loaded By Msdt.EXE | high | 61609 |
| `101158` | 8 | `T1059.001` T1059.001 | PowerShell Core DLL Loaded By Non PowerShell Process | medium | 61609 |
| `101159` | 8 | `T1129` T1129 | Unsigned .node File Loaded | medium | 61609 |
| `101160` | 9 | `T1685.001` T1685.001 | HackTool - SharpEvtMute DLL Load | high | 61609 |
| `101161` | 8 | `T1204.002` T1204.002 | DotNET Assembly DLL Loaded Via Office Application | medium | 61609 |
| `101162` | 8 | `T1204.002` T1204.002 | CLR DLL Loaded Via Office Applications | medium | 61609 |
| `101163` | 9 | `T1204.002` T1204.002 | GAC DLL Loaded Via Office Applications | high | 61609 |
| `101164` | 8 | `T1204.002` T1204.002 | Microsoft Excel Add-In Loaded From Uncommon Location | medium | 61609 |
| `101165` | 8 | `T1204.002` T1204.002 | Microsoft VBA For Outlook Addin Loaded Via Outlook | medium | 61609 |
| `101166` | 8 | - | PowerShell Core DLL Loaded Via Office Application | medium | 61609 |
| `101167` | 9 | `T1204.002` T1204.002 | VBA DLL Loaded Via Office Application | high | 61609 |
| `101168` | 8 | `T1204.002` T1204.002 | Remote DLL Load Via Rundll32.EXE | medium | 61609 |
| `101169` | 9 | `T1059` Command and Scripting Interpreter | Abusable DLL Potential Sideloading From Suspicious Location | high | 61609 |
| `101170` | 8 | `T1070` Indicator Removal | DLL Load By System Process From Suspicious Locations | medium | 61609 |
| `101171` | 9 | `T1055` Process Injection | DotNet CLR DLL Loaded By Scripting Applications | high | 61609 |
| `101172` | 8 | `T1218.011` T1218.011 | Unsigned DLL Loaded by Windows Utility | medium | 61609 |
| `101173` | 8 | `T1059.005` T1059.005 | MMC Loading Script Engines DLLs | medium | 61609 |
| `101174` | 8 | `T1220` T1220 | WMIC Loading Scripting Libraries | medium | 61609 |
| `101175` | 9 | `T1047` T1047 | Wmiprvse Wbemcomn DLL Hijack | high | 61609 |
| `101176` | 8 | `T1059.001` T1059.001 | Suspicious WSMAN Provider Image Loads | medium | 61609 |
| `101177` | 9 | `T1218` T1218 | Network Connection Initiated By AddinUtil.EXE | high | 61605 |
| `101178` | 9 | `T1218.003` T1218.003 | Outbound Network Connection Initiated By Cmstp.EXE | high | 61605 |
| `101179` | 9 | `T1071.001` T1071.001 | Outbound Network Connection Initiated By Microsoft Dialer | high | 61605 |
| `101180` | 9 | `T1203` T1203 | Network Connection Initiated By Eqnedt32.EXE | high | 61605 |
| `101181` | 8 | `T1203` T1203 | Office Application Initiated Network Connection To Non-Local IP | medium | 61605 |
| `101182` | 8 | `T1218.009` T1218.009 | RegAsm.EXE Initiating Network Connection To Public IP | medium | 61605 |
| `101183` | 8 | `T1559.001` T1559.001 | Network Connection Initiated By Regsvr32.EXE | medium | 61605 |
| `101184` | 8 | `T1218.011` T1218.011 | Rundll32 Internet Connection | medium | 61605 |
| `101185` | 9 | `T1127.001` T1127.001 | Silenttrinity Stager Msbuild Activity | high | 61605 |
| `101186` | 9 | - | Suspicious Network Connection Binary No CommandLine | high | 61605 |
| `101187` | 9 | `T1059.001` T1059.001 | Potential Remote PowerShell Session Initiated | high | 61605 |
| `101188` | 8 | `T1218.011` T1218.011 | Outbound Network Connection To Public IP Via Winlogon | medium | 61605 |
| `101189` | 8 | `T1218` T1218 | Potentially Suspicious Wuauclt Network Connection | medium | 61605 |
| `101190` | 8 | `T1059.001` T1059.001 | Alternate PowerShell Hosts Pipe | medium | 61619 |
| `101191` | 8 | `T1569.002` T1569.002 | PUA - PAExec Default Named Pipe | medium | 61619 |
| `101192` | 8 | `T1047` T1047 | WMI Event Consumer Created Named Pipe | medium | 61619 |
| `101193` | 8 | `T1569.002` T1569.002 | PsExec Tool Execution From Suspicious Locations - PipeName | medium | 61619 |
| `101194` | 8 | `T1059.001` T1059.001 | Nslookup PowerShell Download Cradle | medium | 91801 |
| `101195` | 8 | `T1059.001` T1059.001 | PowerShell Downgrade Attack - PowerShell | medium | 91801 |
| `101196` | 9 | `T1059.001` T1059.001 | PowerShell Called from an Executable Version Mismatch | high | 91801 |
| `101197` | 8 | `T1059.001` T1059.001 | Alternate PowerShell Hosts - PowerShell Module | medium | 91801 |
| `101198` | 9 | `T1059.001` T1059.001 | Bad Opsec Powershell Code Artifacts | high | 91801 |
| `101199` | 8 | `T1070.003` T1070.003 | Clear PowerShell History - PowerShell Module | medium | 91801 |
| `101200` | 8 | `T1070.003` T1070.003 | Clear PowerShell History - PowerShell Module | medium | 91801 |
| `101201` | 13 | `T1059.001` T1059.001 | Malicious PowerShell Scripts - PoshModule | high | 91801 |
| `101202` | 9 | `T1059.001` T1059.001 | Malicious PowerShell Scripts - PoshModule | high | 91801 |
| `101203` | 9 | `T1027` Obfuscated Files or Information | Invoke-Obfuscation CLIP+ Launcher - PowerShell Module | high | 91801 |
| `101204` | 9 | `T1027` Obfuscated Files or Information | Invoke-Obfuscation Obfuscated IEX Invocation - PowerShell Module | high | 91801 |
| `101205` | 9 | `T1027` Obfuscated Files or Information | Invoke-Obfuscation STDIN+ Launcher - PowerShell Module | high | 91801 |
| `101206` | 9 | `T1027` Obfuscated Files or Information | Invoke-Obfuscation VAR+ Launcher - PowerShell Module | high | 91801 |
| `101207` | 8 | `T1027` Obfuscated Files or Information | Invoke-Obfuscation COMPRESS OBFUSCATION - PowerShell Module | medium | 91801 |
| `101208` | 8 | `T1027` Obfuscated Files or Information | Invoke-Obfuscation RUNDLL LAUNCHER - PowerShell Module | medium | 91801 |
| `101209` | 9 | `T1027` Obfuscated Files or Information | Invoke-Obfuscation Via Stdin - PowerShell Module | high | 91801 |
| `101210` | 9 | `T1027` Obfuscated Files or Information | Invoke-Obfuscation Via Use Clip - PowerShell Module | high | 91801 |
| `101211` | 9 | `T1027` Obfuscated Files or Information | Invoke-Obfuscation Via Use MSHTA - PowerShell Module | high | 91801 |
| `101212` | 9 | `T1027` Obfuscated Files or Information | Invoke-Obfuscation Via Use Rundll32 - PowerShell Module | high | 91801 |
| `101213` | 9 | `T1027` Obfuscated Files or Information | Invoke-Obfuscation VAR++ LAUNCHER OBFUSCATION - PowerShell Module | high | 91801 |
| `101214` | 13 | `T1482` T1482 | Malicious PowerShell Commandlets - PoshModule | high | 91801 |
| `101215` | 9 | `T1059.001` T1059.001 | Remote PowerShell Session (PS Module) | high | 91801 |
| `101216` | 9 | `T1218` T1218 | Potential RemoteFXvGPUDisablement.EXE Abuse - PowerShell Module | high | 91801 |
| `101217` | 8 | `T1059.001` T1059.001 | Suspicious PowerShell Download - PoshModule | medium | 91801 |
| `101218` | 9 | `T1059.001` T1059.001 | Suspicious PowerShell Invocations - Generic - PowerShell Module | high | 91801 |
| `101219` | 9 | `T1059.001` T1059.001 | Suspicious PowerShell Invocations - Specific - PowerShell Module | high | 91801 |
| `101220` | 9 | `T1059.001` T1059.001 | Suspicious PowerShell Invocations - Specific - PowerShell Module | high | 91801 |
| `101221` | 9 | `T1059.001` T1059.001 | Suspicious PowerShell Invocations - Specific - PowerShell Module | high | 91801 |
| `101222` | 9 | `T1059.001` T1059.001 | Suspicious PowerShell Invocations - Specific - PowerShell Module | high | 91801 |
| `101223` | 9 | `T1059.001` T1059.001 | Suspicious PowerShell Invocations - Specific - PowerShell Module | high | 91801 |
| `101224` | 9 | `T1059.001` T1059.001 | Suspicious PowerShell Invocations - Specific - PowerShell Module | high | 91801 |
| `101225` | 8 | `T1218` T1218 | SyncAppvPublishingServer Bypass Powershell Restriction - PS Module | medium | 91801 |
| `101226` | 9 | - | AADInternals PowerShell Cmdlets Execution - PsScript | high | 91801 |
| `101227` | 8 | - | Add Windows Capability Via PowerShell Script | medium | 91801 |
| `101228` | 9 | `T1685` T1685 | AMSI Bypass Pattern Assembly GetType | high | 91801 |
| `101229` | 8 | `T1685` T1685 | Potential AMSI Bypass Script Using NULL Bits | medium | 91801 |
| `101230` | 9 | `T1059.001` T1059.001 | Silence.EDA Detection | high | 91801 |
| `101231` | 8 | `T1070.003` T1070.003 | Clear PowerShell History - PowerShell | medium | 91801 |
| `101232` | 8 | `T1070.003` T1070.003 | Clear PowerShell History - PowerShell | medium | 91801 |
| `101233` | 9 | `T1070` Indicator Removal | Clearing Windows Console History | high | 91801 |
| `101234` | 8 | `T1059.001` T1059.001 | PowerShell Create Local User | medium | 91801 |
| `101235` | 9 | `T1070.003` T1070.003 | Disable Powershell Command History | high | 91801 |
| `101236` | 9 | `T1685` T1685 | Disable-WindowsOptionalFeature Command PowerShell | high | 91801 |
| `101237` | 8 | `T1620` T1620 | Potential In-Memory Execution Using Reflection.Assembly | medium | 91801 |
| `101238` | 9 | `T1059.001` T1059.001 | DSInternals Suspicious PowerShell Cmdlets - ScriptBlock | high | 91801 |
| `101239` | 8 | - | Potential Suspicious Windows Feature Enabled | medium | 91801 |
| `101240` | 9 | `T1070` Indicator Removal | Disable of ETW Trace - Powershell | high | 91801 |
| `101241` | 9 | `T1070` Indicator Removal | Disable of ETW Trace - Powershell | high | 91801 |
| `101242` | 8 | `T1059.001` T1059.001 | Import PowerShell Modules From Suspicious Directories | medium | 91801 |
| `101243` | 9 | `T1027` Obfuscated Files or Information | Invoke-Obfuscation CLIP+ Launcher - PowerShell | high | 91801 |
| `101244` | 9 | `T1027` Obfuscated Files or Information | Invoke-Obfuscation Obfuscated IEX Invocation - PowerShell | high | 91801 |
| `101245` | 9 | `T1027` Obfuscated Files or Information | Invoke-Obfuscation STDIN+ Launcher - Powershell | high | 91801 |
| `101246` | 9 | `T1027` Obfuscated Files or Information | Invoke-Obfuscation VAR+ Launcher - PowerShell | high | 91801 |
| `101247` | 8 | `T1027` Obfuscated Files or Information | Invoke-Obfuscation COMPRESS OBFUSCATION - PowerShell | medium | 91801 |
| `101248` | 8 | `T1027` Obfuscated Files or Information | Invoke-Obfuscation RUNDLL LAUNCHER - PowerShell | medium | 91801 |
| `101249` | 9 | `T1027` Obfuscated Files or Information | Invoke-Obfuscation Via Stdin - Powershell | high | 91801 |
| `101250` | 9 | `T1027` Obfuscated Files or Information | Invoke-Obfuscation Via Use Clip - Powershell | high | 91801 |
| `101251` | 9 | `T1027` Obfuscated Files or Information | Invoke-Obfuscation Via Use MSHTA - PowerShell | high | 91801 |
| `101252` | 9 | `T1027` Obfuscated Files or Information | Invoke-Obfuscation Via Use Rundll32 - PowerShell | high | 91801 |
| `101253` | 9 | `T1027` Obfuscated Files or Information | Invoke-Obfuscation VAR++ LAUNCHER OBFUSCATION - PowerShell | high | 91801 |
| `101254` | 13 | `T1482` T1482 | Malicious PowerShell Commandlets - ScriptBlock | high | 91801 |
| `101255` | 13 | `T1059.001` T1059.001 | Malicious PowerShell Keywords | medium | 91801 |
| `101256` | 8 | `T1059.001` T1059.001 | Powershell MsXml COM Object | medium | 91801 |
| `101257` | 13 | `T1059.001` T1059.001 | Malicious Nishang PowerShell Commandlets | high | 91801 |
| `101258` | 9 | `T1564.004` T1564.004 | NTFS Alternate Data Stream | high | 91801 |
| `101259` | 9 | `T1059.001` T1059.001 | PowerView PowerShell Cmdlets - ScriptBlock | high | 91801 |
| `101260` | 9 | `T1059.001` T1059.001 | PSAsyncShell - Asynchronous TCP Reverse Shell | high | 91801 |
| `101261` | 9 | `T1059.001` T1059.001 | PowerShell PSAttack | high | 91801 |
| `101262` | 8 | `T1059.001` T1059.001 | PowerShell Remote Session Creation | medium | 91801 |
| `101263` | 9 | `T1218` T1218 | Potential RemoteFXvGPUDisablement.EXE Abuse - PowerShell ScriptBlock | high | 91801 |
| `101264` | 8 | `T1553.004` T1553.004 | Root Certificate Installed - PowerShell | medium | 91801 |
| `101265` | 8 | `T1553.004` T1553.004 | Root Certificate Installed - PowerShell | medium | 91801 |
| `101266` | 8 | `T1553.005` T1553.005 | Suspicious Invoke-Item From Mount-DiskImage | medium | 91801 |
| `101267` | 9 | `T1222` T1222 | PowerShell Set-Acl On Windows Folder - PsScript | high | 91801 |
| `101268` | 8 | `T1059.001` T1059.001 | Change PowerShell Policies to an Insecure Level - PowerShell | medium | 91801 |
| `101269` | 9 | `T1059.001` T1059.001 | Malicious ShellIntel PowerShell Commandlets | high | 91801 |
| `101270` | 8 | `T1564.004` T1564.004 | Powershell Store File In Alternate Data Stream | medium | 91801 |
| `101271` | 8 | `T1685.005` T1685.005 | Suspicious Eventlog Clear | medium | 91801 |
| `101272` | 8 | `T1685.005` T1685.005 | Suspicious Eventlog Clear | medium | 91801 |
| `101273` | 8 | `T1685.005` T1685.005 | Suspicious Eventlog Clear | medium | 91801 |
| `101274` | 8 | `T1059.001` T1059.001 | Suspicious PowerShell Download - Powershell Script | medium | 91801 |
| `101275` | 8 | `T1059.003` T1059.003 | Powershell Execute Batch Script | medium | 91801 |
| `101276` | 8 | `T1202` T1202 | Troubleshooting Pack Cmdlet Execution | medium | 91801 |
| `101277` | 8 | `T1564.006` T1564.006 | Suspicious Hyper-V Cmdlets | medium | 91801 |
| `101278` | 9 | `T1059.001` T1059.001 | Suspicious PowerShell Invocations - Generic | high | 91801 |
| `101279` | 9 | `T1059.001` T1059.001 | Suspicious PowerShell Invocations - Specific | high | 91801 |
| `101280` | 9 | `T1059.001` T1059.001 | Suspicious PowerShell Invocations - Specific | high | 91801 |
| `101281` | 9 | `T1059.001` T1059.001 | Suspicious PowerShell Invocations - Specific | high | 91801 |
| `101282` | 9 | `T1059.001` T1059.001 | Suspicious PowerShell Invocations - Specific | high | 91801 |
| `101283` | 9 | `T1059.001` T1059.001 | Suspicious PowerShell Invocations - Specific | high | 91801 |
| `101284` | 9 | `T1059.001` T1059.001 | Suspicious PowerShell Invocations - Specific | high | 91801 |
| `101285` | 8 | `T1070.003` T1070.003 | Suspicious IO.FileStream | medium | 91801 |
| `101286` | 8 | `T1059.001` T1059.001 | Potential Suspicious PowerShell Keywords | medium | 91801 |
| `101287` | 8 | `T1070.005` T1070.005 | PowerShell Deleted Mounted Share | medium | 91801 |
| `101288` | 8 | `T1036.003` T1036.003 | Suspicious Start-Process PassThru | medium | 91801 |
| `101289` | 8 | `T1553.005` T1553.005 | Suspicious Unblock-File | medium | 91801 |
| `101290` | 8 | `T1564.003` T1564.003 | Suspicious PowerShell WindowStyle Option | medium | 91801 |
| `101291` | 8 | - | PowerShell Write-EventLog Usage | medium | 91801 |
| `101292` | 8 | `T1218` T1218 | SyncAppvPublishingServer Execution to Bypass Powershell Restriction | medium | 91801 |
| `101293` | 9 | `T1685` T1685 | Tamper Windows Defender Remove-MpPreference - ScriptBlockLogging | high | 91801 |
| `101294` | 9 | `T1685` T1685 | Tamper Windows Defender - ScriptBlockLogging | high | 91801 |
| `101295` | 8 | `T1070.006` T1070.006 | Powershell Timestomp | medium | 91801 |
| `101296` | 8 | `T1059.001` T1059.001 | Usage Of Web Request Commands And Cmdlets - ScriptBlock | medium | 91801 |
| `101297` | 8 | - | Potentially Suspicious Call To Win32_NTEventlogFile Class - PSScript | medium | 91801 |
| `101298` | 8 | `T1218.007` T1218.007 | PowerShell WMI Win32_Product Install MSI | medium | 91801 |
| `101299` | 9 | `T1059.001` T1059.001 | Potential WinAPI Calls Via PowerShell Scripts | high | 91801 |
| `101300` | 9 | `T1059.001` T1059.001 | Potential WinAPI Calls Via PowerShell Scripts | high | 91801 |
| `101301` | 9 | `T1059.001` T1059.001 | Potential WinAPI Calls Via PowerShell Scripts | high | 91801 |
| `101302` | 9 | `T1059.001` T1059.001 | Potential WinAPI Calls Via PowerShell Scripts | high | 91801 |
| `101303` | 8 | `T1685` T1685 | Windows Defender Exclusions Added - PowerShell | medium | 91801 |
| `101304` | 8 | `T1686.003` T1686.003 | Windows Firewall Profile Disabled | medium | 91801 |
| `101305` | 8 | `T1047` T1047 | WMIC Unquoted Services Path Lookup - PowerShell | medium | 91801 |
| `101306` | 9 | `T1047` T1047 | WMImplant Hack Tool | high | 91801 |
| `101307` | 8 | `T1553.004` T1553.004 | Suspicious X509Enrollment - Ps Script | medium | 91801 |
| `101308` | 8 | `T1059.001` T1059.001 | Powershell XML Execute Command | medium | 91801 |
| `101309` | 9 | `T1218.003` T1218.003 | CMSTP Execution Process Access | high | 61612 |
| `101310` | 13 | `T1106` T1106 | HackTool - CobaltStrike BOF Injection Pattern | high | 61612 |
| `101311` | 12 | `T1106` T1106 | HackTool - HandleKatz Duplicating LSASS Handle | high | 61612 |
| `101312` | 9 | `T1204.002` T1204.002 | HackTool - LittleCorporal Generated Maldoc Injection | high | 61612 |
| `101313` | 9 | `T1685.001` T1685.001 | HackTool - SysmonEnte Execution | high | 61612 |
| `101314` | 8 | `T1106` T1106 | Potential Direct Syscall of NtOpenProcess | medium | 61612 |
| `101315` | 9 | `T1685.001` T1685.001 | Suspicious Svchost Process Access | high | 61612 |
| `101316` | 9 | `T1685` T1685 | Suspicious Process Access of MsMpEng by WerFaultSecure - EDR-Freeze | high | 61612 |
| `101317` | 8 | - | Potential DLL Injection Via AccCheckConsole | medium | 61603 |
| `101318` | 9 | `T1218` T1218 | Suspicious AddinUtil.EXE CommandLine Execution | high | 61603 |
| `101319` | 8 | `T1218` T1218 | Uncommon Child Process Of AddinUtil.EXE | medium | 61603 |
| `101320` | 8 | `T1218` T1218 | Uncommon AddinUtil.EXE CommandLine Execution | medium | 61603 |
| `101321` | 8 | `T1218` T1218 | AddinUtil.EXE Execution From Uncommon Directory | medium | 61603 |
| `101322` | 9 | `T1003.001` T1003.001 | Potential Adplus.EXE Abuse | high | 61603 |
| `101323` | 8 | `T1218` T1218 | AgentExecutor PowerShell Execution | medium | 61603 |
| `101324` | 9 | `T1218` T1218 | Suspicious AgentExecutor PowerShell Execution | high | 61603 |
| `101325` | 9 | `T1685` T1685 | Windows AMSI Related Registry Tampering Via CommandLine | high | 61603 |
| `101326` | 8 | `T1218` T1218 | Uncommon Child Process Of Appvlp.EXE | medium | 61603 |
| `101327` | 9 | `T1059` Command and Scripting Interpreter | Suspicious ArcSOC.exe Child Process | high | 61603 |
| `101328` | 8 | `T1127` T1127 | AspNetCompiler Execution | medium | 61603 |
| `101329` | 9 | `T1127` T1127 | Suspicious Child Process of AspNetCompiler | high | 61603 |
| `101330` | 9 | `T1127` T1127 | Potentially Suspicious ASP.NET Compilation Via AspNetCompiler | high | 61603 |
| `101331` | 8 | `T1218` T1218 | Uncommon  Assistive Technology Applications Execution Via AtBroker.EXE | medium | 61603 |
| `101332` | 8 | `T1564.001` T1564.001 | Hiding Files with Attrib.exe | medium | 61603 |
| `101333` | 9 | `T1564.001` T1564.001 | Set Suspicious Files as System Files Using Attrib.EXE | high | 61603 |
| `101334` | 9 | `T1685.001` T1685.001 | Audit Policy Tampering Via NT Resource Kit Auditpol | high | 61603 |
| `101335` | 9 | `T1685.001` T1685.001 | Audit Policy Tampering Via Auditpol | high | 61603 |
| `101336` | 9 | `T1685.001` T1685.001 | Windows EventLog Autologger Session Registry Modification Via Comma... | high | 61603 |
| `101337` | 8 | `T1202` T1202 | Indirect Inline Command Execution Via Bash.EXE | medium | 61603 |
| `101338` | 8 | `T1202` T1202 | Indirect Command Execution From Script File Via Bash.EXE | medium | 61603 |
| `101339` | 8 | `T1048` T1048 | Data Export From MSSQL Table Via BCP.EXE | medium | 61603 |
| `101340` | 9 | `T1059.005` T1059.005 | Suspicious Child Process Of BgInfo.EXE | high | 61603 |
| `101341` | 8 | `T1059.005` T1059.005 | Uncommon Child Process Of BgInfo.EXE | medium | 61603 |
| `101342` | 9 | - | Chromium Browser Headless Execution To Mockbin Like Site | high | 61603 |
| `101343` | 9 | `T1036` T1036 | Suspicious Calculator Usage | high | 61603 |
| `101344` | 8 | `T1106` T1106 | Potential Binary Proxy Execution Via Cdb.EXE | medium | 61603 |
| `101345` | 8 | `T1553.004` T1553.004 | New Root Certificate Installed Via CertMgr.EXE | medium | 61603 |
| `101346` | 8 | `T1218` T1218 | DLL Loaded via CertOC.EXE | medium | 61603 |
| `101347` | 9 | `T1218` T1218 | Suspicious DLL Loaded via CertOC.EXE | high | 61603 |
| `101348` | 8 | `T1553.004` T1553.004 | New Root Certificate Installed Via Certutil.EXE | medium | 61603 |
| `101349` | 9 | `T1027` Obfuscated Files or Information | File Decoded From Base64/Hex Via Certutil.EXE | high | 61603 |
| `101350` | 8 | `T1027` Obfuscated Files or Information | File Encoded To Base64 Via Certutil.EXE | medium | 61603 |
| `101351` | 9 | `T1027` Obfuscated Files or Information | Suspicious File Encoded To Base64 Via Certutil.EXE | high | 61603 |
| `101352` | 9 | `T1027` Obfuscated Files or Information | File In Suspicious Location Encoded To Base64 Via Certutil.EXE | high | 61603 |
| `101353` | 8 | `T1027` Obfuscated Files or Information | Certificate Exported Via Certutil.EXE | medium | 61603 |
| `101354` | 9 | `T1218` T1218 | Potential NTLM Coercion Via Certutil.EXE | high | 61603 |
| `101355` | 8 | `T1036` T1036 | Suspicious CodePage Switch Via CHCP | medium | 61603 |
| `101356` | 8 | `T1070.004` T1070.004 | Greedy File Deletion Using Del | medium | 61603 |
| `101357` | 8 | `T1059` Command and Scripting Interpreter | Potential Dosfuscation Activity | medium | 61603 |
| `101358` | 8 | `T1059.003` T1059.003 | Command Line Execution with Suspicious URL and AppData Strings | medium | 61603 |
| `101359` | 8 | `T1564.003` T1564.003 | Cmd Launched with Hidden Start Flags to Suspicious Targets | medium | 61603 |
| `101360` | 9 | `T1059.001` T1059.001 | Suspicious File Execution From Internet Hosted WebDav Share | high | 61603 |
| `101361` | 9 | `T1059.001` T1059.001 | Cmd.EXE Missing Space Characters Execution Anomaly | high | 61603 |
| `101362` | 9 | `T1059.001` T1059.001 | Cmd.EXE Missing Space Characters Execution Anomaly | high | 61603 |
| `101363` | 9 | `T1059.001` T1059.001 | Cmd.EXE Missing Space Characters Execution Anomaly | high | 61603 |
| `101364` | 9 | - | NtdllPipe Like Activity Execution | high | 61603 |
| `101365` | 9 | `T1059.003` T1059.003 | Potential CommandLine Path Traversal Via Cmd.EXE | high | 61603 |
| `101366` | 8 | `T1070.004` T1070.004 | Potentially Suspicious Ping/Copy Command Combination | medium | 61603 |
| `101367` | 9 | `T1070.004` T1070.004 | Suspicious Ping/Del Command Combination | high | 61603 |
| `101368` | 8 | `T1218` T1218 | Potentially Suspicious CMD Shell Output Redirect | medium | 61603 |
| `101369` | 8 | `T1059.003` T1059.003 | Read Contents From Stdin Via Cmd.EXE | medium | 61603 |
| `101370` | 12 | `T1059` Command and Scripting Interpreter | Unusual Parent Process For Cmd.EXE | medium | 61603 |
| `101371` | 8 | `T1218` T1218 | Potential Arbitrary File Download Via Cmdl32.EXE | medium | 61603 |
| `101372` | 9 | `T1218.003` T1218.003 | CMSTP Execution Process Creation | high | 61603 |
| `101373` | 8 | `T1059.003` T1059.003 | OpenEDR Spawning Command Shell | medium | 61603 |
| `101374` | 8 | `T1059.001` T1059.001 | Powershell Executed From Headless ConHost Process | medium | 61603 |
| `101375` | 9 | `T1059.003` T1059.003 | Conhost.exe CommandLine Path Traversal | high | 61603 |
| `101376` | 8 | `T1202` T1202 | Uncommon Child Process Of Conhost.EXE | medium | 61603 |
| `101377` | 9 | `T1202` T1202 | Potentially Suspicious Child Processes Spawned by ConHost | high | 61603 |
| `101378` | 12 | `T1059` Command and Scripting Interpreter | Conhost Spawned By Uncommon Parent Process | medium | 61603 |
| `101379` | 9 | `T1685` T1685 | Windows Credential Guard Registry Tampering Via CommandLine | high | 61603 |
| `101380` | 8 | `T1027.004` T1027.004 | Dynamic .NET Compilation Via Csc.EXE | medium | 61603 |
| `101381` | 9 | `T1059.005` T1059.005 | Csc.EXE Execution Form Potentially Suspicious Parent | high | 61603 |
| `101382` | 9 | `T1127` T1127 | Suspicious Use of CSharp Interactive Console | high | 61603 |
| `101383` | 8 | - | Potential Cookies Session Hijacking | medium | 61603 |
| `101384` | 8 | - | Curl Web Request With Potential Custom User-Agent | medium | 61603 |
| `101385` | 8 | - | File Download From IP URL Via Curl.EXE | medium | 61603 |
| `101386` | 9 | - | Suspicious File Download From IP Via Curl.EXE | high | 61603 |
| `101387` | 9 | - | Suspicious File Download From File Sharing Domain Via Curl.EXE | high | 61603 |
| `101388` | 8 | - | Insecure Transfer Via Curl.EXE | medium | 61603 |
| `101389` | 8 | - | Insecure Proxy/DOH Transfer Via Curl.EXE | medium | 61603 |
| `101390` | 8 | - | Local File Read Using Curl.EXE | medium | 61603 |
| `101391` | 9 | `T1216` T1216 | Suspicious CustomShellHost Execution | high | 61603 |
| `101392` | 8 | `T1218` T1218 | Uncommon Child Process Of Defaultpack.EXE | medium | 61603 |
| `101393` | 9 | `T1685` T1685 | PowerShell Defender Threat Severity Default Action Set to 'Allow' o... | high | 61603 |
| `101394` | 9 | `T1685` T1685 | Windows Defender Context Menu Removed | high | 61603 |
| `101395` | 8 | `T1218` T1218 | DeviceCredentialDeployment Execution | medium | 61603 |
| `101396` | 8 | `T1218` T1218 | Arbitrary MSI Download Via Devinit.EXE | medium | 61603 |
| `101397` | 8 | - | Potentially Suspicious Child Process Of ClickOnce Application | medium | 61603 |
| `101398` | 8 | `T1218` T1218 | Potentially Suspicious Child Process Of DiskShadow.EXE | medium | 61603 |
| `101399` | 8 | `T1218` T1218 | Diskshadow Script Mode - Uncommon Script Extension Execution | medium | 61603 |
| `101400` | 8 | `T1218` T1218 | Diskshadow Script Mode - Execution From Potential Suspicious Location | medium | 61603 |
| `101401` | 8 | `T1685` T1685 | Dism Remove Online Package | medium | 61603 |
| `101402` | 8 | `T1685` T1685 | Dism Remove Online Package | medium | 61603 |
| `101403` | 8 | `T1218` T1218 | Potential Application Whitelisting Bypass via Dnx.EXE | medium | 61603 |
| `101404` | 8 | `T1218` T1218 | Arbitrary DLL or Csproj Code Execution Via Dotnet.EXE | medium | 61603 |
| `101405` | 8 | `T1218` T1218 | Binary Proxy Execution Via Dotnet-Trace.EXE | medium | 61603 |
| `101406` | 8 | `T1218` T1218 | Process Memory Dump Via Dotnet-Dump | medium | 61603 |
| `101407` | 8 | `T1218` T1218 | Potentially Over Permissive Permissions Granted Using Dsacls.EXE | medium | 61603 |
| `101408` | 8 | `T1218` T1218 | Potential Password Spraying Attempt Using Dsacls.EXE | medium | 61603 |
| `101409` | 8 | `T1218` T1218 | New Capture Session Launched Via DXCap.EXE | medium | 61603 |
| `101410` | 8 | `T1218` T1218 | Potentially Suspicious Cabinet File Expansion | medium | 61603 |
| `101411` | 8 | `T1036` T1036 | Explorer Process Tree Break | medium | 61603 |
| `101412` | 8 | `T1036` T1036 | Explorer Process Tree Break | medium | 61603 |
| `101413` | 8 | `T1036` T1036 | Findstr Launching .lnk File | medium | 61603 |
| `101414` | 8 | `T1070` Indicator Removal | Filter Driver Unloaded Via Fltmc.EXE | medium | 61603 |
| `101415` | 9 | `T1070` Indicator Removal | Sysmon Driver Unloaded Via Fltmc.EXE | high | 61603 |
| `101416` | 9 | `T1036` T1036 | Forfiles.EXE Child Process Masquerading | high | 61603 |
| `101417` | 8 | `T1059` Command and Scripting Interpreter | Forfiles Command Execution | medium | 61603 |
| `101418` | 9 | - | Uncommon FileSystem Load Attempt By Format.com | high | 61603 |
| `101419` | 8 | `T1059` Command and Scripting Interpreter | Use of FSharp Interpreters | medium | 61603 |
| `101420` | 8 | `T1059` Command and Scripting Interpreter | Use of FSharp Interpreters | medium | 61603 |
| `101421` | 8 | `T1059` Command and Scripting Interpreter | Potentially Suspicious NTFS Symlink Behavior Modification | medium | 61603 |
| `101422` | 8 | `T1059` Command and Scripting Interpreter | Potential Arbitrary Command Execution Via FTP.EXE | medium | 61603 |
| `101423` | 8 | `T1593.003` T1593.003 | Suspicious Git Clone | medium | 61603 |
| `101424` | 9 | - | Potentially Suspicious GoogleUpdate Child Process | high | 61603 |
| `101425` | 8 | - | File Decryption Using Gpg4win | medium | 61603 |
| `101426` | 8 | - | File Encryption Using Gpg4win | medium | 61603 |
| `101427` | 9 | - | File Encryption/Decryption Via Gpg4win From Suspicious Locations | high | 61603 |
| `101428` | 8 | - | Arbitrary Binary Execution Using GUP Utility | medium | 61603 |
| `101429` | 9 | `T1218.001` T1218.001 | Remote CHM File Download/Execution Via HH.EXE | high | 61603 |
| `101430` | 9 | `T1047` T1047 | HTML Help HH.EXE Suspicious Child Process | high | 61603 |
| `101431` | 9 | `T1047` T1047 | Suspicious HH.EXE Execution | high | 61603 |
| `101432` | 9 | `T1218.011` T1218.011 | HackTool - F-Secure C3 Load by Rundll32 | high | 61603 |
| `101433` | 13 | `T1059.003` T1059.003 | Operator Bloopers Cobalt Strike Commands | high | 61603 |
| `101434` | 13 | `T1059.003` T1059.003 | Operator Bloopers Cobalt Strike Modules | high | 61603 |
| `101435` | 13 | `T1218.011` T1218.011 | CobaltStrike Load by Rundll32 | high | 61603 |
| `101436` | 13 | `T1059` Command and Scripting Interpreter | Potential CobaltStrike Process Patterns | high | 61603 |
| `101437` | 13 | `T1059` Command and Scripting Interpreter | Potential CobaltStrike Process Patterns | high | 61603 |
| `101438` | 13 | `T1059` Command and Scripting Interpreter | Potential CobaltStrike Process Patterns | high | 61603 |
| `101439` | 13 | `T1059` Command and Scripting Interpreter | Potential CobaltStrike Process Patterns | high | 61603 |
| `101440` | 9 | `T1059.001` T1059.001 | HackTool - Covenant PowerShell Launcher | high | 61603 |
| `101441` | 9 | `T1059.001` T1059.001 | HackTool - Covenant PowerShell Launcher | high | 61603 |
| `101442` | 9 | `T1047` T1047 | HackTool - CrackMapExec Execution | high | 61603 |
| `101443` | 9 | `T1047` T1047 | HackTool - CrackMapExec Execution | high | 61603 |
| `101444` | 9 | `T1047` T1047 | HackTool - CrackMapExec Execution | high | 61603 |
| `101445` | 9 | `T1047` T1047 | HackTool - CrackMapExec Execution | high | 61603 |
| `101446` | 9 | `T1047` T1047 | HackTool - CrackMapExec Execution | high | 61603 |
| `101447` | 9 | `T1047` T1047 | HackTool - CrackMapExec Execution | high | 61603 |
| `101448` | 9 | `T1047` T1047 | HackTool - CrackMapExec Execution | high | 61603 |
| `101449` | 9 | `T1059.001` T1059.001 | HackTool - CrackMapExec PowerShell Obfuscation | high | 61603 |
| `101450` | 9 | `T1685` T1685 | Hacktool - EDR-Freeze Execution | high | 61603 |
| `101451` | 9 | `T1685` T1685 | Hacktool - EDR-Freeze Execution | high | 61603 |
| `101452` | 9 | `T1685` T1685 | HackTool - EDRSilencer Execution | high | 61603 |
| `101453` | 9 | `T1685` T1685 | HackTool - EDRSilencer Execution | high | 61603 |
| `101454` | 9 | `T1685` T1685 | HackTool - EDRSilencer Execution | high | 61603 |
| `101455` | 12 | `T1059.001` T1059.001 | HackTool - Empire PowerShell Launch Parameters | high | 61603 |
| `101456` | 9 | - | HackTool - GMER Rootkit Detector and Remover Execution | high | 61603 |
| `101457` | 9 | - | HackTool - GMER Rootkit Detector and Remover Execution | high | 61603 |
| `101458` | 9 | `T1047` T1047 | HackTool - Potential Impacket Lateral Movement Activity | high | 61603 |
| `101459` | 9 | `T1047` T1047 | HackTool - Potential Impacket Lateral Movement Activity | high | 61603 |
| `101460` | 9 | `T1027` Obfuscated Files or Information | Invoke-Obfuscation CLIP+ Launcher | high | 61603 |
| `101461` | 9 | `T1027` Obfuscated Files or Information | Invoke-Obfuscation Obfuscated IEX Invocation | high | 61603 |
| `101462` | 9 | `T1027` Obfuscated Files or Information | Invoke-Obfuscation Obfuscated IEX Invocation | high | 61603 |
| `101463` | 9 | `T1027` Obfuscated Files or Information | Invoke-Obfuscation Obfuscated IEX Invocation | high | 61603 |
| `101464` | 9 | `T1027` Obfuscated Files or Information | Invoke-Obfuscation Obfuscated IEX Invocation | high | 61603 |
| `101465` | 9 | `T1027` Obfuscated Files or Information | Invoke-Obfuscation Obfuscated IEX Invocation | high | 61603 |
| `101466` | 9 | `T1027` Obfuscated Files or Information | Invoke-Obfuscation Obfuscated IEX Invocation | high | 61603 |
| `101467` | 9 | `T1027` Obfuscated Files or Information | Invoke-Obfuscation Obfuscated IEX Invocation | high | 61603 |
| `101468` | 9 | `T1027` Obfuscated Files or Information | Invoke-Obfuscation STDIN+ Launcher | high | 61603 |
| `101469` | 9 | `T1027` Obfuscated Files or Information | Invoke-Obfuscation VAR+ Launcher | high | 61603 |
| `101470` | 8 | `T1027` Obfuscated Files or Information | Invoke-Obfuscation COMPRESS OBFUSCATION | medium | 61603 |
| `101471` | 9 | `T1027` Obfuscated Files or Information | Invoke-Obfuscation Via Stdin | high | 61603 |
| `101472` | 9 | `T1027` Obfuscated Files or Information | Invoke-Obfuscation Via Use Clip | high | 61603 |
| `101473` | 9 | `T1027` Obfuscated Files or Information | Invoke-Obfuscation Via Use MSHTA | high | 61603 |
| `101474` | 9 | `T1027` Obfuscated Files or Information | Invoke-Obfuscation VAR++ LAUNCHER OBFUSCATION | high | 61603 |
| `101475` | 8 | `T1059.003` T1059.003 | HackTool - Jlaive In-Memory Assembly Execution | medium | 61603 |
| `101476` | 9 | `T1059.003` T1059.003 | HackTool - Koadic Execution | high | 61603 |
| `101477` | 9 | `T1082` System Information Discovery | HackTool - PCHunter Execution | high | 61603 |
| `101478` | 9 | `T1082` System Information Discovery | HackTool - PCHunter Execution | high | 61603 |
| `101479` | 9 | `T1082` System Information Discovery | HackTool - PCHunter Execution | high | 61603 |
| `101480` | 9 | `T1082` System Information Discovery | HackTool - PCHunter Execution | high | 61603 |
| `101481` | 12 | `T1053.005` T1053.005 | HackTool - Default PowerSploit/Empire Scheduled Task Creation | high | 61603 |
| `101482` | 9 | `T1685` T1685 | HackTool - PowerTool Execution | high | 61603 |
| `101483` | 9 | `T1685` T1685 | HackTool - PowerTool Execution | high | 61603 |
| `101484` | 9 | `T1587` T1587 | HackTool - PurpleSharp Execution | high | 61603 |
| `101485` | 9 | `T1587` T1587 | HackTool - PurpleSharp Execution | high | 61603 |
| `101486` | 9 | `T1587` T1587 | HackTool - PurpleSharp Execution | high | 61603 |
| `101487` | 9 | `T1106` T1106 | HackTool - RedMimicry Winnti Playbook Execution | high | 61603 |
| `101488` | 9 | `T1685.001` T1685.001 | HackTool - SharpEvtMute Execution | high | 61603 |
| `101489` | 9 | `T1685.001` T1685.001 | HackTool - SharpEvtMute Execution | high | 61603 |
| `101490` | 9 | `T1685.001` T1685.001 | HackTool - SharpEvtMute Execution | high | 61603 |
| `101491` | 9 | `T1210` T1210 | HackTool - SharpWSUS/WSUSpendu Execution | high | 61603 |
| `101492` | 9 | `T1059` Command and Scripting Interpreter | HackTool - Sliver C2 Implant Activity Pattern | high | 61603 |
| `101493` | 9 | `T1059` Command and Scripting Interpreter | HackTool - Stracciatella Execution | high | 61603 |
| `101494` | 9 | `T1059` Command and Scripting Interpreter | HackTool - Stracciatella Execution | high | 61603 |
| `101495` | 9 | `T1059` Command and Scripting Interpreter | HackTool - Stracciatella Execution | high | 61603 |
| `101496` | 9 | `T1059` Command and Scripting Interpreter | HackTool - Stracciatella Execution | high | 61603 |
| `101497` | 8 | `T1218` T1218 | Suspicious ZipExec Execution | medium | 61603 |
| `101498` | 9 | `T1685` T1685 | Hypervisor-protected Code Integrity (HVCI) Related Registry Tamperi... | high | 61603 |
| `101499` | 8 | `T1036` T1036 | Potential Fake Instance Of Hxtsr.EXE Executed | medium | 61603 |
| `101500` | 8 | `T1564.001` T1564.001 | Use Icacls to Hide File to Everyone | medium | 61603 |
| `101501` | 9 | `T1218` T1218 | Self Extracting Package Creation Via Iexpress.EXE From Potentially ... | high | 61603 |
| `101502` | 9 | `T1685.001` T1685.001 | Disable Windows IIS HTTP Logging | high | 61603 |
| `101503` | 8 | - | Suspicious IIS URL GlobalRules Rewrite Via AppCmd | medium | 61603 |
| `101504` | 8 | `T1070` Indicator Removal | IIS WebServer Log Deletion via CommandLine Utilities | medium | 61603 |
| `101505` | 8 | `T1127` T1127 | C# IL Code Compilation Via Ilasm.EXE | medium | 61603 |
| `101506` | 9 | - | ImagingDevices Unusual Parent/Child Processes | high | 61603 |
| `101507` | 9 | - | ImagingDevices Unusual Parent/Child Processes | high | 61603 |
| `101508` | 9 | `T1218` T1218 | Arbitrary File Download Via IMEWDBLD.EXE | high | 61603 |
| `101509` | 8 | `T1218` T1218 | InfDefaultInstall.exe .inf Execution | medium | 61603 |
| `101510` | 8 | `T1218` T1218 | File Download Via InstallUtil.EXE | medium | 61603 |
| `101511` | 8 | - | Suspicious Execution of InstallUtil Without Log | medium | 61603 |
| `101512` | 8 | `T1203` T1203 | Java Running with Remote Debugging | medium | 61603 |
| `101513` | 9 | `T1127` T1127 | Kavremover Dropped Binary LOLBIN Usage | high | 61603 |
| `101514` | 8 | - | Computer Password Change Via Ksetup.EXE | medium | 61603 |
| `101515` | 8 | - | Logged-On User Password Change Via Ksetup.EXE | medium | 61603 |
| `101516` | 8 | `T1218` T1218 | Uncommon Link.EXE Parent Process | medium | 61603 |
| `101517` | 8 | - | Rebuild Performance Counter Values Via Lodctr.EXE | medium | 61603 |
| `101518` | 9 | `T1685` T1685 | Suspicious Windows Trace ETW Session Tamper Via Logman.EXE | high | 61603 |
| `101519` | 9 | `T1218` T1218 | Devtoolslauncher.exe Executes Specified Binary | high | 61603 |
| `101520` | 8 | `T1564.004` T1564.004 | Suspicious Diantz Alternate Data Stream Execution | medium | 61603 |
| `101521` | 8 | `T1564.004` T1564.004 | Suspicious Extrac32 Alternate Data Stream Execution | medium | 61603 |
| `101522` | 8 | `T1218` T1218 | Gpscript Execution | medium | 61603 |
| `101523` | 8 | `T1218` T1218 | Ie4uinit Lolbin Use From Invalid Path | medium | 61603 |
| `101524` | 8 | `T1216.001` T1216.001 | Launch-VsDevShell.PS1 Proxy Execution | medium | 61603 |
| `101525` | 9 | `T1216` T1216 | Potential Manage-bde.wsf Abuse To Proxy Execution | high | 61603 |
| `101526` | 9 | `T1218` T1218 | MpiExec Lolbin | high | 61603 |
| `101527` | 8 | `T1218` T1218 | Execute Files with Msdeploy.exe | medium | 61603 |
| `101528` | 8 | `T1059` Command and Scripting Interpreter | Use of OpenConsole | medium | 61603 |
| `101529` | 9 | `T1218` T1218 | OpenWith.exe Executes Specified Binary | high | 61603 |
| `101530` | 8 | `T1059` Command and Scripting Interpreter | Use of Pcalua For Execution | medium | 61603 |
| `101531` | 9 | `T1218` T1218 | Execute Pcwrun.EXE To Leverage Follina | high | 61603 |
| `101532` | 8 | `T1218.011` T1218.011 | Code Execution via Pcwutl.dll | medium | 61603 |
| `101533` | 8 | `T1059.001` T1059.001 | Execute Code with Pester.bat as Parent | medium | 61603 |
| `101534` | 8 | `T1059.001` T1059.001 | Execute Code with Pester.bat | medium | 61603 |
| `101535` | 8 | `T1216.001` T1216.001 | Pubprn.vbs Proxy Execution | medium | 61603 |
| `101536` | 8 | `T1218` T1218 | DLL Execution via Rasautou.exe | medium | 61603 |
| `101537` | 8 | `T1218` T1218 | REGISTER_APP.VBS Proxy Execution | medium | 61603 |
| `101538` | 8 | `T1127` T1127 | Use of Remote.exe | medium | 61603 |
| `101539` | 8 | `T1127` T1127 | Use of Remote.exe | medium | 61603 |
| `101540` | 8 | `T1218` T1218 | Lolbin Runexehelper Use As Proxy | medium | 61603 |
| `101541` | 8 | `T1059` Command and Scripting Interpreter | Suspicious Runscripthelper.exe | medium | 61603 |
| `101542` | 8 | `T1218` T1218 | Use of Scriptrunner.exe | medium | 61603 |
| `101543` | 8 | `T1218` T1218 | Use Of The SFTP.EXE Binary As A LOLBIN | medium | 61603 |
| `101544` | 8 | `T1218` T1218 | SyncAppvPublishingServer Execute Arbitrary PowerShell Code | medium | 61603 |
| `101545` | 8 | `T1218` T1218 | SyncAppvPublishingServer VBS Execute Arbitrary PowerShell Code | medium | 61603 |
| `101546` | 8 | `T1127` T1127 | Use of TTDInject.exe | medium | 61603 |
| `101547` | 8 | `T1127` T1127 | Use of TTDInject.exe | medium | 61603 |
| `101548` | 8 | `T1218` T1218 | Lolbin Unregmp2.exe Use As Proxy | medium | 61603 |
| `101549` | 8 | `T1216` T1216 | UtilityFunctions.ps1 Proxy Dll | medium | 61603 |
| `101550` | 9 | `T1027.004` T1027.004 | Visual Basic Command Line Compiler Usage | high | 61603 |
| `101551` | 8 | `T1218` T1218 | Use of VisualUiaVerifyNative.exe | medium | 61603 |
| `101552` | 8 | `T1218` T1218 | Use of VisualUiaVerifyNative.exe | medium | 61603 |
| `101553` | 8 | `T1127` T1127 | Use of VSIISExeLauncher.exe | medium | 61603 |
| `101554` | 8 | `T1127` T1127 | Use of Wfc.exe | medium | 61603 |
| `101555` | 8 | `T1127` T1127 | Use of Wfc.exe | medium | 61603 |
| `101556` | 8 | `T1218` T1218 | Potential Register_App.Vbs LOLScript Abuse | medium | 61603 |
| `101557` | 8 | `T1689` T1689 | LSA PPL Protection Setting Modification via CommandLine | medium | 61603 |
| `101558` | 8 | `T1127` T1127 | Potential Mftrace.EXE Abuse | medium | 61603 |
| `101559` | 9 | `T1021.003` T1021.003 | MMC20 Lateral Movement | high | 61603 |
| `101560` | 9 | `T1204.002` T1204.002 | MMC Executing Files with Reversed Extensions Using RTLO Abuse | high | 61603 |
| `101561` | 8 | `T1036` T1036 | CodePage Modification Via MODE.COM To Russian Language | medium | 61603 |
| `101562` | 9 | `T1218` T1218 | Potential Suspicious Mofcomp Execution | high | 61603 |
| `101563` | 9 | `T1685` T1685 | Windows Defender Definition Files Removed | high | 61603 |
| `101564` | 8 | - | Suspicious Msbuild Execution By Uncommon Parent Process | medium | 61603 |
| `101565` | 9 | `T1218` T1218 | MSDT Execution Via Answer File | high | 61603 |
| `101566` | 9 | `T1202` T1202 | Potential Arbitrary Command Execution Using Msdt.EXE | high | 61603 |
| `101567` | 8 | `T1202` T1202 | Suspicious Cabinet File Execution Via Msdt.EXE | medium | 61603 |
| `101568` | 9 | `T1036` T1036 | Suspicious MSDT Parent Process | high | 61603 |
| `101569` | 8 | `T1218` T1218 | Arbitrary File Download Via MSEDGE_PROXY.EXE | medium | 61603 |
| `101570` | 9 | `T1218.005` T1218.005 | Remotely Hosted HTA File Executed Via Mshta.EXE | high | 61603 |
| `101571` | 8 | `T1059` Command and Scripting Interpreter | Wscript Shell Run In CommandLine | medium | 61603 |
| `101572` | 9 | `T1218.005` T1218.005 | Suspicious JavaScript Execution Via Mshta.EXE | high | 61603 |
| `101573` | 9 | `T1218.005` T1218.005 | Potential LethalHTA Technique Execution | high | 61603 |
| `101574` | 9 | `T1218.005` T1218.005 | Suspicious MSHTA Child Process | high | 61603 |
| `101575` | 9 | `T1140` T1140 | MSHTA Execution with Suspicious File Extensions | high | 61603 |
| `101576` | 9 | `T1106` T1106 | Suspicious Mshta.EXE Execution Patterns | high | 61603 |
| `101577` | 8 | `T1218.007` T1218.007 | DllUnregisterServer Function Call Via Msiexec.EXE | medium | 61603 |
| `101578` | 8 | `T1218.007` T1218.007 | Suspicious MsiExec Embedding Parent | medium | 61603 |
| `101579` | 8 | `T1218.007` T1218.007 | Suspicious Msiexec Execute Arbitrary DLL | medium | 61603 |
| `101580` | 8 | `T1218.007` T1218.007 | Msiexec Quiet Installation | medium | 61603 |
| `101581` | 8 | `T1218.007` T1218.007 | Suspicious Msiexec Quiet Install From Remote Location | medium | 61603 |
| `101582` | 9 | `T1036.005` T1036.005 | Potential MsiExec Masquerading | high | 61603 |
| `101583` | 8 | `T1218` T1218 | Arbitrary File Download Via MSOHTMED.EXE | medium | 61603 |
| `101584` | 8 | `T1218` T1218 | Arbitrary File Download Via MSPUB.EXE | medium | 61603 |
| `101585` | 8 | `T1059.001` T1059.001 | Detection of PowerShell Execution via Sqlps.exe | medium | 61603 |
| `101586` | 8 | `T1059.001` T1059.001 | SQL Client Tools PowerShell Session Detection | medium | 61603 |
| `101587` | 8 | `T1220` T1220 | Msxsl.EXE Execution | medium | 61603 |
| `101588` | 9 | `T1220` T1220 | Remote XSL Execution Via Msxsl.EXE | high | 61603 |
| `101589` | 8 | `T1686.003` T1686.003 | New Firewall Rule Added Via Netsh.EXE | medium | 61603 |
| `101590` | 9 | `T1686.003` T1686.003 | Suspicious Program Location Whitelisted In Firewall Via Netsh.EXE | high | 61603 |
| `101591` | 9 | `T1686.003` T1686.003 | RDP Connection Allowed Via Netsh.EXE | high | 61603 |
| `101592` | 8 | `T1686.003` T1686.003 | Firewall Rule Deleted Via Netsh.EXE | medium | 61603 |
| `101593` | 8 | `T1686.003` T1686.003 | Firewall Disabled via Netsh.EXE | medium | 61603 |
| `101594` | 8 | `T1686.003` T1686.003 | Netsh Allow Group Policy on Microsoft Defender Firewall | medium | 61603 |
| `101595` | 8 | - | Firewall Rule Update Via Netsh.EXE | medium | 61603 |
| `101596` | 9 | `T1127` T1127 | Potential Arbitrary Code Execution Via Node.EXE | high | 61603 |
| `101597` | 8 | `T1127` T1127 | Node Process Executions | medium | 61603 |
| `101598` | 8 | - | Nslookup PowerShell Download Cradle - ProcessCreation | medium | 61603 |
| `101599` | 8 | `T1218.008` T1218.008 | Driver/DLL Installation Via Odbcconf.EXE | medium | 61603 |
| `101600` | 9 | `T1218.008` T1218.008 | Suspicious Driver/DLL Installation Via Odbcconf.EXE | high | 61603 |
| `101601` | 9 | `T1218.008` T1218.008 | Odbcconf.EXE Suspicious DLL Location | high | 61603 |
| `101602` | 8 | `T1218.008` T1218.008 | New DLL Registered Via Odbcconf.EXE | medium | 61603 |
| `101603` | 9 | `T1218.008` T1218.008 | Potentially Suspicious DLL Registered Via Odbcconf.EXE | high | 61603 |
| `101604` | 8 | `T1218.008` T1218.008 | Response File Execution Via Odbcconf.EXE | medium | 61603 |
| `101605` | 9 | `T1218.008` T1218.008 | Suspicious Response File Execution Via Odbcconf.EXE | high | 61603 |
| `101606` | 8 | `T1218.008` T1218.008 | Uncommon Child Process Spawned By Odbcconf.EXE | medium | 61603 |
| `101607` | 9 | `T1202` T1202 | Potential Arbitrary File Download Using Office Application | high | 61603 |
| `101608` | 9 | `T1202` T1202 | Potentially Suspicious Office Document Executed From Trusted Location | high | 61603 |
| `101609` | 9 | `T1218.001` T1218.001 | OneNote.EXE Execution of Malicious Embedded Scripts | high | 61603 |
| `101610` | 9 | `T1059` Command and Scripting Interpreter | Outlook EnableUnsafeClientMailRules Setting Enabled | high | 61603 |
| `101611` | 9 | `T1204.002` T1204.002 | Suspicious Outlook Child Process | high | 61603 |
| `101612` | 9 | `T1059` Command and Scripting Interpreter | Suspicious Remote Child Process From Outlook | high | 61603 |
| `101613` | 9 | `T1204.002` T1204.002 | Suspicious Binary In User Directory Spawned From Office Application | high | 61603 |
| `101614` | 9 | `T1047` T1047 | Suspicious Microsoft Office Child Process | high | 61603 |
| `101615` | 8 | `T1202` T1202 | Potential Arbitrary DLL Load Using Winword | medium | 61603 |
| `101616` | 8 | `T1218` T1218 | Potential Mpclient.DLL Sideloading Via OfflineScannerShell.EXE Exec... | medium | 61603 |
| `101617` | 8 | `T1072` T1072 | PDQ Deploy Remote Adminstartion Tool Execution | medium | 61603 |
| `101618` | 8 | `T1072` T1072 | PDQ Deploy Remote Adminstartion Tool Execution | medium | 61603 |
| `101619` | 8 | `T1072` T1072 | PDQ Deploy Remote Adminstartion Tool Execution | medium | 61603 |
| `101620` | 8 | `T1072` T1072 | PDQ Deploy Remote Adminstartion Tool Execution | medium | 61603 |
| `101621` | 8 | - | Potentially Suspicious Execution Of PDQDeployRunner | medium | 61603 |
| `101622` | 8 | `T1059` Command and Scripting Interpreter | Perl Inline Command Execution | medium | 61603 |
| `101623` | 8 | `T1059` Command and Scripting Interpreter | Php Inline Command Execution | medium | 61603 |
| `101624` | 9 | `T1140` T1140 | Ping Hex IP | high | 61603 |
| `101625` | 8 | - | Suspicious Powercfg Execution To Change Lock Screen Timeout | medium | 61603 |
| `101626` | 9 | - | AADInternals PowerShell Cmdlets Execution - ProccessCreation | high | 61603 |
| `101627` | 8 | - | Add Windows Capability Via PowerShell Cmdlet | medium | 61603 |
| `101628` | 9 | `T1685` T1685 | Potential AMSI Bypass Via .NET Reflection | high | 61603 |
| `101629` | 9 | `T1685` T1685 | Potential AMSI Bypass Via .NET Reflection | high | 61603 |
| `101630` | 8 | `T1685` T1685 | Potential AMSI Bypass Using NULL Bits | medium | 61603 |
| `101631` | 9 | `T1059.001` T1059.001 | Suspicious Encoded PowerShell Command Line | high | 61603 |
| `101632` | 9 | `T1059.001` T1059.001 | Suspicious PowerShell Encoded Command Patterns | high | 61603 |
| `101633` | 9 | - | Suspicious Obfuscated PowerShell Code | high | 61603 |
| `101634` | 9 | `T1140` T1140 | PowerShell Base64 Encoded FromBase64String Cmdlet | high | 61603 |
| `101635` | 9 | `T1140` T1140 | PowerShell Base64 Encoded FromBase64String Cmdlet | high | 61603 |
| `101636` | 9 | `T1059.001` T1059.001 | Malicious Base64 Encoded PowerShell Keywords in Command Lines | high | 61603 |
| `101637` | 9 | `T1059.001` T1059.001 | PowerShell Base64 Encoded IEX Cmdlet | high | 61603 |
| `101638` | 9 | `T1059.001` T1059.001 | PowerShell Base64 Encoded IEX Cmdlet | high | 61603 |
| `101639` | 9 | `T1059.001` T1059.001 | PowerShell Base64 Encoded Invoke Keyword | high | 61603 |
| `101640` | 9 | `T1685` T1685 | Powershell Base64 Encoded MpPreference Cmdlet | high | 61603 |
| `101641` | 9 | `T1685` T1685 | Powershell Base64 Encoded MpPreference Cmdlet | high | 61603 |
| `101642` | 9 | `T1059.001` T1059.001 | PowerShell Base64 Encoded Reflective Assembly Load | high | 61603 |
| `101643` | 9 | `T1059.001` T1059.001 | Suspicious Encoded And Obfuscated Reflection Assembly Load Function... | high | 61603 |
| `101644` | 9 | `T1059.001` T1059.001 | PowerShell Base64 Encoded WMI Classes | high | 61603 |
| `101645` | 8 | `T1216` T1216 | Potential Process Execution Proxy Via CL_Invocation.ps1 | medium | 61603 |
| `101646` | 8 | `T1216` T1216 | Assembly Loading Via CL_LoadAssembly.ps1 | medium | 61603 |
| `101647` | 8 | `T1216` T1216 | Potential Script Proxy Execution Via CL_Mutexverifiers.ps1 | medium | 61603 |
| `101648` | 8 | `T1027` Obfuscated Files or Information | ConvertTo-SecureString Cmdlet Usage Via CommandLine | medium | 61603 |
| `101649` | 9 | `T1027` Obfuscated Files or Information | Potential PowerShell Obfuscation Via Reversed Commands | high | 61603 |
| `101650` | 9 | `T1027` Obfuscated Files or Information | Potential PowerShell Command Line Obfuscation | high | 61603 |
| `101651` | 9 | `T1027.010` T1027.010 | Obfuscated PowerShell MSI Install via WindowsInstaller COM | high | 61603 |
| `101652` | 8 | `T1059.001` T1059.001 | PowerShell MSI Install via WindowsInstaller COM From Remote Location | medium | 61603 |
| `101653` | 9 | - | PowerShell Execution With Potential Decryption Capabilities | high | 61603 |
| `101654` | 9 | `T1685` T1685 | Powershell Defender Disable Scan Feature | high | 61603 |
| `101655` | 8 | `T1685` T1685 | Powershell Defender Exclusion | medium | 61603 |
| `101656` | 9 | `T1685` T1685 | Disable Windows Defender AV Security Monitoring | high | 61603 |
| `101657` | 8 | `T1685` T1685 | Windows Firewall Disabled via PowerShell | medium | 61603 |
| `101658` | 9 | `T1685` T1685 | Disabled IE Security Features | high | 61603 |
| `101659` | 9 | `T1685` T1685 | Disabled IE Security Features | high | 61603 |
| `101660` | 9 | `T1685` T1685 | Disabled IE Security Features | high | 61603 |
| `101661` | 8 | `T1059.001` T1059.001 | Potential PowerShell Downgrade Attack | medium | 61603 |
| `101662` | 9 | `T1059.001` T1059.001 | Obfuscated PowerShell OneLiner Execution | high | 61603 |
| `101663` | 9 | `T1059` Command and Scripting Interpreter | PowerShell Download and Execution Cradles | high | 61603 |
| `101664` | 8 | `T1059.001` T1059.001 | PowerShell Download Pattern | medium | 61603 |
| `101665` | 9 | - | Potentially Suspicious File Download From File Sharing Domain Via P... | high | 61603 |
| `101666` | 9 | `T1059.001` T1059.001 | DSInternals Suspicious PowerShell Cmdlets | high | 61603 |
| `101667` | 8 | - | Potential Suspicious Windows Feature Enabled - ProcCreation | medium | 61603 |
| `101668` | 8 | `T1059.001` T1059.001 | Suspicious Execution of Powershell with Base64 | medium | 61603 |
| `101669` | 8 | `T1059.001` T1059.001 | Powershell Inline Execution From A File | medium | 61603 |
| `101670` | 9 | `T1027` Obfuscated Files or Information | Base64 Encoded PowerShell Command Detected | high | 61603 |
| `101671` | 9 | `T1059.001` T1059.001 | Suspicious PowerShell IEX Execution Patterns | high | 61603 |
| `101672` | 9 | `T1553.004` T1553.004 | Root Certificate Installed From Susp Locations | high | 61603 |
| `101673` | 8 | `T1059.001` T1059.001 | Import PowerShell Modules From Suspicious Directories - ProcCreation | medium | 61603 |
| `101674` | 8 | - | Suspicious PowerShell Invocations - Specific - ProcessCreation | medium | 61603 |
| `101675` | 8 | - | Suspicious PowerShell Invocations - Specific - ProcessCreation | medium | 61603 |
| `101676` | 8 | - | Suspicious PowerShell Invocations - Specific - ProcessCreation | medium | 61603 |
| `101677` | 8 | - | Suspicious PowerShell Invocations - Specific - ProcessCreation | medium | 61603 |
| `101678` | 8 | - | Suspicious PowerShell Invocations - Specific - ProcessCreation | medium | 61603 |
| `101679` | 8 | - | Suspicious PowerShell Invocations - Specific - ProcessCreation | medium | 61603 |
| `101680` | 13 | `T1482` T1482 | Malicious PowerShell Commandlets - ProcessCreation | high | 61603 |
| `101681` | 9 | `T1059.001` T1059.001 | Potential PowerShell Obfuscation Via WCHAR/CHAR | high | 61603 |
| `101682` | 9 | `T1059.001` T1059.001 | Execution of Powershell Script in Public Folder | high | 61603 |
| `101683` | 9 | `T1218` T1218 | RemoteFXvGPUDisablement Abuse Via AtomicTestHarnesses | high | 61603 |
| `101684` | 9 | `T1685` T1685 | Tamper Windows Defender Remove-MpPreference | high | 61603 |
| `101685` | 9 | `T1059.001` T1059.001 | Potential Powershell ReverseShell Connection | high | 61603 |
| `101686` | 9 | `T1564.004` T1564.004 | Run PowerShell Script from ADS | high | 61603 |
| `101687` | 9 | `T1059` Command and Scripting Interpreter | Run PowerShell Script from Redirected Input Stream | high | 61603 |
| `101688` | 8 | `T1059.001` T1059.001 | Suspicious PowerShell Invocation From Script Engines | medium | 61603 |
| `101689` | 8 | `T1059.001` T1059.001 | Potentially Suspicious Powershell Script Execution From Temp Folder | medium | 61603 |
| `101690` | 9 | - | PowerShell Script Change Permission Via Set-Acl | high | 61603 |
| `101691` | 9 | - | PowerShell Set-Acl On Windows Folder | high | 61603 |
| `101692` | 8 | `T1059.001` T1059.001 | Change PowerShell Policies to an Insecure Level | medium | 61603 |
| `101693` | 8 | `T1685` T1685 | Service StartupType Change Via PowerShell Set-Service | medium | 61603 |
| `101694` | 9 | `T1059.001` T1059.001 | Exchange PowerShell Snap-Ins Usage | high | 61603 |
| `101695` | 9 | `T1059.001` T1059.001 | Suspicious PowerShell Download and Execute Pattern | high | 61603 |
| `101696` | 9 | `T1059.001` T1059.001 | Suspicious PowerShell Parameter Substring | high | 61603 |
| `101697` | 9 | `T1059.001` T1059.001 | Suspicious PowerShell Parent Process | high | 61603 |
| `101698` | 8 | `T1059.001` T1059.001 | PowerShell Script Run in AppData | medium | 61603 |
| `101699` | 9 | `T1027.009` T1027.009 | Powershell Token Obfuscation - Process Creation | high | 61603 |
| `101700` | 9 | `T1685` T1685 | Suspicious Uninstall of Windows Defender Feature via PowerShell | high | 61603 |
| `101701` | 9 | `T1059.001` T1059.001 | Net WebClient Casing Anomalies | high | 61603 |
| `101702` | 8 | `T1553.004` T1553.004 | Suspicious X509Enrollment - Process Creation | medium | 61603 |
| `101703` | 8 | `T1059.001` T1059.001 | Suspicious XOR Encoded PowerShell Command | medium | 61603 |
| `101704` | 8 | `T1218` T1218 | Arbitrary File Download Via PresentationHost.EXE | medium | 61603 |
| `101705` | 8 | `T1218` T1218 | XBAP Execution From Uncommon Locations Via PresentationHost.EXE | medium | 61603 |
| `101706` | 8 | `T1218` T1218 | Visual Studio NodejsTools PressAnyKey Arbitrary Binary Execution | medium | 61603 |
| `101707` | 8 | `T1218` T1218 | Abusing Print Executable | medium | 61603 |
| `101708` | 8 | `T1218` T1218 | File Download Using ProtocolHandler.exe | medium | 61603 |
| `101709` | 8 | `T1218` T1218 | Potential Provlaunch.EXE Binary Proxy Execution Abuse | medium | 61603 |
| `101710` | 9 | `T1218` T1218 | Suspicious Provlaunch.EXE Child Process | high | 61603 |
| `101711` | 8 | `T1564.003` T1564.003 | PUA - AdvancedRun Execution | medium | 61603 |
| `101712` | 8 | `T1564.003` T1564.003 | PUA - AdvancedRun Execution | medium | 61603 |
| `101713` | 8 | `T1564.003` T1564.003 | PUA - AdvancedRun Execution | medium | 61603 |
| `101714` | 9 | `T1685` T1685 | PUA - CleanWipe Execution | high | 61603 |
| `101715` | 9 | `T1685` T1685 | PUA - CleanWipe Execution | high | 61603 |
| `101716` | 9 | `T1685` T1685 | PUA - CleanWipe Execution | high | 61603 |
| `101717` | 9 | `T1685` T1685 | PUA - CleanWipe Execution | high | 61603 |
| `101718` | 9 | `T1587.001` T1587.001 | PUA - CsExec Execution | high | 61603 |
| `101719` | 9 | `T1587.001` T1587.001 | PUA - CsExec Execution | high | 61603 |
| `101720` | 9 | `T1027.005` T1027.005 | PUA - DefenderCheck Execution | high | 61603 |
| `101721` | 9 | `T1027.005` T1027.005 | PUA - DefenderCheck Execution | high | 61603 |
| `101722` | 8 | `T1569.002` T1569.002 | PUA - NirCmd Execution | medium | 61603 |
| `101723` | 8 | `T1569.002` T1569.002 | PUA - NirCmd Execution | medium | 61603 |
| `101724` | 8 | `T1569.002` T1569.002 | PUA - NirCmd Execution | medium | 61603 |
| `101725` | 9 | `T1569.002` T1569.002 | PUA - NirCmd Execution As LOCAL SYSTEM | high | 61603 |
| `101726` | 9 | `T1569.002` T1569.002 | PUA - NSudo Execution | high | 61603 |
| `101727` | 8 | `T1595` T1595 | PUA - PingCastle Execution | medium | 61603 |
| `101728` | 8 | `T1595` T1595 | PUA - PingCastle Execution | medium | 61603 |
| `101729` | 8 | `T1595` T1595 | PUA - PingCastle Execution | medium | 61603 |
| `101730` | 8 | `T1595` T1595 | PUA - PingCastle Execution | medium | 61603 |
| `101731` | 8 | `T1595` T1595 | PUA - PingCastle Execution | medium | 61603 |
| `101732` | 8 | `T1595` T1595 | PUA - PingCastle Execution | medium | 61603 |
| `101733` | 8 | `T1595` T1595 | PUA - PingCastle Execution | medium | 61603 |
| `101734` | 8 | `T1595` T1595 | PUA - PingCastle Execution | medium | 61603 |
| `101735` | 9 | `T1595` T1595 | PUA - PingCastle Execution From Potentially Suspicious Parent | high | 61603 |
| `101736` | 9 | `T1595` T1595 | PUA - PingCastle Execution From Potentially Suspicious Parent | high | 61603 |
| `101737` | 9 | `T1595` T1595 | PUA - PingCastle Execution From Potentially Suspicious Parent | high | 61603 |
| `101738` | 9 | `T1595` T1595 | PUA - PingCastle Execution From Potentially Suspicious Parent | high | 61603 |
| `101739` | 9 | `T1595` T1595 | PUA - PingCastle Execution From Potentially Suspicious Parent | high | 61603 |
| `101740` | 8 | `T1072` T1072 | PUA - Radmin Viewer Utility Execution | medium | 61603 |
| `101741` | 8 | `T1072` T1072 | PUA - Radmin Viewer Utility Execution | medium | 61603 |
| `101742` | 8 | `T1072` T1072 | PUA - Radmin Viewer Utility Execution | medium | 61603 |
| `101743` | 8 | `T1036.003` T1036.003 | PUA - Potential PE Metadata Tamper Using Rcedit | medium | 61603 |
| `101744` | 9 | `T1569.002` T1569.002 | PUA - RunXCmd Execution | high | 61603 |
| `101745` | 9 | `T1059` Command and Scripting Interpreter | PUA - Wsudo Suspicious Execution | high | 61603 |
| `101746` | 9 | `T1059` Command and Scripting Interpreter | PUA - Wsudo Suspicious Execution | high | 61603 |
| `101747` | 9 | `T1059` Command and Scripting Interpreter | PUA - Wsudo Suspicious Execution | high | 61603 |
| `101748` | 9 | `T1059` Command and Scripting Interpreter | PUA - Wsudo Suspicious Execution | high | 61603 |
| `101749` | 9 | `T1059` Command and Scripting Interpreter | PUA - Wsudo Suspicious Execution | high | 61603 |
| `101750` | 9 | `T1059.006` T1059.006 | Python One-Liners with Base64 Decoding | high | 61603 |
| `101751` | 8 | `T1059` Command and Scripting Interpreter | Python Inline Command Execution | medium | 61603 |
| `101752` | 9 | `T1059` Command and Scripting Interpreter | Python Spawning Pretty TTY on Windows | high | 61603 |
| `101753` | 8 | - | Query Usage To Exfil Data | medium | 61603 |
| `101754` | 9 | `T1059` Command and Scripting Interpreter | Suspicious Greedy Compression Using Rar.EXE | high | 61603 |
| `101755` | 9 | `T1059` Command and Scripting Interpreter | Suspicious Greedy Compression Using Rar.EXE | high | 61603 |
| `101756` | 9 | `T1059` Command and Scripting Interpreter | Suspicious Greedy Compression Using Rar.EXE | high | 61603 |
| `101757` | 8 | `T1059` Command and Scripting Interpreter | Suspicious RASdial Activity | medium | 61603 |
| `101758` | 9 | `T1685` T1685 | Add SafeBoot Keys Via Reg Utility | high | 61603 |
| `101759` | 8 | `T1685` T1685 | Suspicious Windows Defender Folder Exclusion Added Via Reg.EXE | medium | 61603 |
| `101760` | 9 | `T1070.003` T1070.003 | RunMRU Registry Key Deletion | high | 61603 |
| `101761` | 9 | `T1685` T1685 | SafeBoot Registry Key Deleted Via Reg.EXE | high | 61603 |
| `101762` | 9 | `T1685` T1685 | Service Registry Key Deleted Via Reg.EXE | high | 61603 |
| `101763` | 9 | `T1685` T1685 | Disabling Windows Defender WMI Autologger Session via Reg.exe | high | 61603 |
| `101764` | 9 | `T1685` T1685 | Security Service Disabled Via Reg.EXE | high | 61603 |
| `101765` | 9 | `T1685` T1685 | Disabled Volume Snapshots | high | 61603 |
| `101766` | 9 | `T1685` T1685 | Suspicious Windows Defender Registry Key Tampering Via Reg.EXE | high | 61603 |
| `101767` | 8 | `T1685` T1685 | Write Protect For Storage Disabled | medium | 61603 |
| `101768` | 8 | `T1218.009` T1218.009 | Potentially Suspicious Execution Of Regasm/Regsvcs With Uncommon Ex... | medium | 61603 |
| `101769` | 8 | `T1218.009` T1218.009 | Potentially Suspicious Execution Of Regasm/Regsvcs From Uncommon Lo... | medium | 61603 |
| `101770` | 9 | - | IE ZoneMap Setting Downgraded To MyComputer Zone For HTTP Protocols... | high | 61603 |
| `101771` | 9 | `T1685` T1685 | Python Function Execution Security Warning Disabled In Excel | high | 61603 |
| `101772` | 9 | `T1218` T1218 | Potential Provisioning Registry Key Abuse For Binary Proxy Execution | high | 61603 |
| `101773` | 9 | - | Potential PowerShell Execution Policy Tampering - ProcCreation | high | 61603 |
| `101774` | 8 | `T1564.002` T1564.002 | Hiding User Account Via SpecialAccounts Registry Key - CommandLine | medium | 61603 |
| `101775` | 8 | `T1218.010` T1218.010 | Potential Regsvr32 Commandline Flag Anomaly | medium | 61603 |
| `101776` | 9 | `T1218.010` T1218.010 | Potentially Suspicious Regsvr32 HTTP IP Pattern | high | 61603 |
| `101777` | 8 | `T1218.010` T1218.010 | Potentially Suspicious Regsvr32 HTTP/FTP Pattern | medium | 61603 |
| `101778` | 9 | `T1218.010` T1218.010 | Suspicious Regsvr32 Execution From Remote Share | high | 61603 |
| `101779` | 9 | `T1218.010` T1218.010 | Potentially Suspicious Child Process Of Regsvr32 | high | 61603 |
| `101780` | 8 | `T1218.010` T1218.010 | Regsvr32 Execution From Potential Suspicious Location | medium | 61603 |
| `101781` | 9 | `T1218.010` T1218.010 | Regsvr32 Execution From Highly Suspicious Location | high | 61603 |
| `101782` | 9 | `T1218.010` T1218.010 | Regsvr32 DLL Execution With Suspicious File Extension | high | 61603 |
| `101783` | 8 | `T1218.010` T1218.010 | Scripting/CommandLine Process Spawned Regsvr32 | medium | 61603 |
| `101784` | 8 | - | Remote Access Tool - AnyDesk Execution With Known Revoked Signing C... | medium | 61603 |
| `101785` | 8 | - | Remote Access Tool - NetSupport Execution From Unusual Location | medium | 61603 |
| `101786` | 8 | - | Remote Access Tool - RURAT Execution From Unusual Location | medium | 61603 |
| `101787` | 8 | - | Renamed AutoHotkey.EXE Execution | medium | 61603 |
| `101788` | 9 | `T1027` Obfuscated Files or Information | Renamed AutoIt Execution | high | 61603 |
| `101789` | 9 | `T1027` Obfuscated Files or Information | Renamed AutoIt Execution | high | 61603 |
| `101790` | 9 | `T1027` Obfuscated Files or Information | Renamed AutoIt Execution | high | 61603 |
| `101791` | 8 | `T1036.003` T1036.003 | Potential Defense Evasion Via Binary Rename | medium | 61603 |
| `101792` | 9 | `T1036.003` T1036.003 | Potential Defense Evasion Via Rename Of Highly Relevant Binaries | high | 61603 |
| `101793` | 8 | `T1553` T1553 | Renamed BOINC Client Execution | medium | 61603 |
| `101794` | 8 | `T1059` Command and Scripting Interpreter | Renamed CURL.EXE Execution | medium | 61603 |
| `101795` | 8 | `T1059` Command and Scripting Interpreter | Renamed FTP.EXE Execution | medium | 61603 |
| `101796` | 9 | `T1036.003` T1036.003 | Renamed Jusched.EXE Execution | high | 61603 |
| `101797` | 9 | `T1218` T1218 | Renamed MegaSync Execution | high | 61603 |
| `101798` | 9 | `T1036.003` T1036.003 | Renamed Msdt.EXE Execution | high | 61603 |
| `101799` | 8 | - | Renamed Microsoft Teams Execution | medium | 61603 |
| `101800` | 9 | - | Renamed NetSupport RAT Execution | high | 61603 |
| `101801` | 9 | `T1059` Command and Scripting Interpreter | Renamed NirCmd.EXE Execution | high | 61603 |
| `101802` | 9 | `T1036.003` T1036.003 | Renamed Office Binary Execution | high | 61603 |
| `101803` | 9 | `T1202` T1202 | Renamed PAExec Execution | high | 61603 |
| `101804` | 9 | `T1059` Command and Scripting Interpreter | Renamed PingCastle Binary Execution | high | 61603 |
| `101805` | 9 | `T1036` T1036 | Renamed Plink Execution | high | 61603 |
| `101806` | 8 | `T1218` T1218 | Visual Studio NodejsTools PressAnyKey Renamed Execution | medium | 61603 |
| `101807` | 9 | - | Potential Renamed Rundll32 Execution | high | 61603 |
| `101808` | 9 | `T1036.003` T1036.003 | Renamed Schtasks Execution | high | 61603 |
| `101809` | 9 | `T1588.002` T1588.002 | Renamed SysInternals DebugView Execution | high | 61603 |
| `101810` | 9 | `T1036.003` T1036.003 | Renamed ProcDump Execution | high | 61603 |
| `101811` | 9 | - | Renamed PsExec Service Execution | high | 61603 |
| `101812` | 8 | `T1059` Command and Scripting Interpreter | Ruby Inline Command Execution | medium | 61603 |
| `101813` | 9 | `T1564.004` T1564.004 | Potential Rundll32 Execution With DLL Stored In ADS | high | 61603 |
| `101814` | 9 | - | Suspicious Advpack Call Via Rundll32.EXE | high | 61603 |
| `101815` | 8 | `T1218.011` T1218.011 | Rundll32 InstallScreenSaver Execution | medium | 61603 |
| `101816` | 9 | - | Mshtml.DLL RunHTMLApplication Suspicious Usage | high | 61603 |
| `101817` | 9 | `T1202` T1202 | Rundll32 Execution Without CommandLine Parameters | high | 61603 |
| `101818` | 8 | `T1027.010` T1027.010 | Potential Obfuscated Ordinal Call Via Rundll32 | medium | 61603 |
| `101819` | 8 | - | Rundll32 Spawned Via Explorer.EXE | medium | 61603 |
| `101820` | 8 | `T1036` T1036 | Suspicious Process Start Locations | medium | 61603 |
| `101821` | 8 | `T1036` T1036 | Suspicious Process Start Locations | medium | 61603 |
| `101822` | 8 | `T1218.011` T1218.011 | Suspicious Rundll32 Setupapi.dll Activity | medium | 61603 |
| `101823` | 9 | `T1218.011` T1218.011 | Shell32 DLL Execution in Suspicious Directory | high | 61603 |
| `101824` | 8 | - | Potential ShellDispatch.DLL Functionality Abuse | medium | 61603 |
| `101825` | 9 | `T1218.011` T1218.011 | RunDLL32 Spawning Explorer | high | 61603 |
| `101826` | 8 | `T1218.011` T1218.011 | Potentially Suspicious Rundll32 Activity | medium | 61603 |
| `101827` | 9 | `T1218.011` T1218.011 | Suspicious Control Panel DLL Load | high | 61603 |
| `101828` | 9 | `T1218.011` T1218.011 | Suspicious Rundll32 Execution With Image Extension | high | 61603 |
| `101829` | 9 | - | Suspicious Usage Of ShellExec_RunDLL | high | 61603 |
| `101830` | 9 | `T1218.011` T1218.011 | Suspicious ShellExec_RunDLL Call Via Ordinal | high | 61603 |
| `101831` | 9 | `T1218.011` T1218.011 | Suspicious Rundll32 Activity Invoking Sys File | high | 61603 |
| `101832` | 8 | `T1218.011` T1218.011 | Potentially Suspicious Rundll32.EXE Execution of UDL File | medium | 61603 |
| `101833` | 9 | `T1021.002` T1021.002 | Rundll32 UNC Path Execution | high | 61603 |
| `101834` | 8 | `T1218.011` T1218.011 | Rundll32 Execution With Uncommon DLL Extension | medium | 61603 |
| `101835` | 8 | - | Suspicious Workstation Locking via Rundll32 | medium | 61603 |
| `101836` | 8 | `T1685` T1685 | Service StartupType Change Via Sc.EXE | medium | 61603 |
| `101837` | 9 | `T1053.005` T1053.005 | Uncommon One Time Only Scheduled Task At 00:00 | high | 61603 |
| `101838` | 9 | `T1047` T1047 | Script Event Consumer Spawning Process | high | 61603 |
| `101839` | 9 | `T1036` T1036 | Sdiagnhost Calling Suspicious Child Process | high | 61603 |
| `101840` | 9 | `T1218` T1218 | Uncommon Child Process Of Setres.EXE | high | 61603 |
| `101841` | 8 | `T1202` T1202 | Indirect Command Execution via SFTP ProxyCommand | medium | 61603 |
| `101842` | 8 | `T1216` T1216 | Uncommon Sigverif.EXE Child Process | medium | 61603 |
| `101843` | 8 | - | Uncommon Child Processes Of SndVol.exe | medium | 61603 |
| `101844` | 9 | `T1202` T1202 | Suspicious Splwow64 Without Params | high | 61603 |
| `101845` | 9 | `T1203` T1203 | Suspicious Spool Service Child Process | high | 61603 |
| `101846` | 8 | `T1218` T1218 | Arbitrary File Download Via Squirrel.EXE | medium | 61603 |
| `101847` | 8 | `T1218` T1218 | Process Proxy Execution Via Squirrel.EXE | medium | 61603 |
| `101848` | 8 | `T1218` T1218 | Program Executed Using Proxy/Local Command Via SSH.EXE | medium | 61603 |
| `101849` | 9 | `T1218` T1218 | Execution via stordiag.exe | high | 61603 |
| `101850` | 8 | - | Start of NT Virtual DOS Machine | medium | 61603 |
| `101851` | 8 | `T1564.004` T1564.004 | Execute From Alternate Data Streams | medium | 61603 |
| `101852` | 8 | - | Potentially Suspicious Windows App Activity | medium | 61603 |
| `101853` | 8 | `T1204` User Execution | Arbitrary Shell Command Execution Via Settingcontent-Ms | medium | 61603 |
| `101854` | 9 | `T1218.011` T1218.011 | Bad Opsec Defaults Sacrificial Processes With Improper Arguments | high | 61603 |
| `101855` | 9 | `T1218.011` T1218.011 | Bad Opsec Defaults Sacrificial Processes With Improper Arguments | high | 61603 |
| `101856` | 9 | `T1218.011` T1218.011 | Bad Opsec Defaults Sacrificial Processes With Improper Arguments | high | 61603 |
| `101857` | 9 | `T1218.011` T1218.011 | Bad Opsec Defaults Sacrificial Processes With Improper Arguments | high | 61603 |
| `101858` | 9 | `T1218.011` T1218.011 | Bad Opsec Defaults Sacrificial Processes With Improper Arguments | high | 61603 |
| `101859` | 8 | `T1204.002` T1204.002 | Potential Suspicious Browser Launch From Document Reader Process | medium | 61603 |
| `101860` | 8 | `T1140` T1140 | Potential Commandline Obfuscation Using Escape Characters | medium | 61603 |
| `101861` | 9 | `T1027` Obfuscated Files or Information | Potential CommandLine Obfuscation Using Unicode Characters From Sus... | high | 61603 |
| `101862` | 9 | `T1204.001` T1204.001 | Suspicious ClickFix/FileFix Execution Pattern | high | 61603 |
| `101863` | 9 | `T1204.004` T1204.004 | Suspicious Explorer Process with Whitespace Padding - ClickFix/FileFix | high | 61603 |
| `101864` | 8 | `T1059.003` T1059.003 | Suspicious Usage of For Loop with Recursive Directory Search in CMD | medium | 61603 |
| `101865` | 8 | `T1059.003` T1059.003 | Suspicious Usage of For Loop with Recursive Directory Search in CMD | medium | 61603 |
| `101866` | 8 | `T1036` T1036 | Potential Command Line Path Traversal Evasion Attempt | medium | 61603 |
| `101867` | 8 | `T1036` T1036 | Potential Command Line Path Traversal Evasion Attempt | medium | 61603 |
| `101868` | 8 | `T1036.003` T1036.003 | Suspicious Copy From or To System Directory | medium | 61603 |
| `101869` | 8 | `T1036.003` T1036.003 | Suspicious Copy From or To System Directory | medium | 61603 |
| `101870` | 8 | `T1036.003` T1036.003 | Suspicious Copy From or To System Directory | medium | 61603 |
| `101871` | 8 | `T1036.003` T1036.003 | Suspicious Copy From or To System Directory | medium | 61603 |
| `101872` | 9 | `T1036.003` T1036.003 | LOL-Binary Copied From System Directory | high | 61603 |
| `101873` | 9 | `T1036.003` T1036.003 | LOL-Binary Copied From System Directory | high | 61603 |
| `101874` | 9 | `T1036.003` T1036.003 | LOL-Binary Copied From System Directory | high | 61603 |
| `101875` | 9 | `T1036.003` T1036.003 | LOL-Binary Copied From System Directory | high | 61603 |
| `101876` | 9 | `T1059.001` T1059.001 | Potential Data Exfiltration Activity Via CommandLine Tools | high | 61603 |
| `101877` | 9 | `T1685` T1685 | Raccine Uninstall | high | 61603 |
| `101878` | 9 | `T1685` T1685 | Raccine Uninstall | high | 61603 |
| `101879` | 9 | `T1685` T1685 | Raccine Uninstall | high | 61603 |
| `101880` | 9 | `T1036.007` T1036.007 | Suspicious Parent Double Extension File Execution | high | 61603 |
| `101881` | 9 | `T1036.007` T1036.007 | Suspicious Parent Double Extension File Execution | high | 61603 |
| `101882` | 9 | - | DumpStack.log Defender Evasion | high | 61603 |
| `101883` | 9 | - | DumpStack.log Defender Evasion | high | 61603 |
| `101884` | 8 | - | Suspicious Electron Application Child Processes | medium | 61603 |
| `101885` | 8 | - | Potentially Suspicious Electron Application CommandLine | medium | 61603 |
| `101886` | 8 | `T1059.001` T1059.001 | Hidden Powershell in Link File Pattern | medium | 61603 |
| `101887` | 9 | - | Potential Defense Evasion Activity Via Emoji Usage In CommandLine - 1 | high | 61603 |
| `101888` | 9 | - | Potential Defense Evasion Activity Via Emoji Usage In CommandLine - 2 | high | 61603 |
| `101889` | 9 | - | Potential Defense Evasion Activity Via Emoji Usage In CommandLine - 3 | high | 61603 |
| `101890` | 9 | - | Potential Defense Evasion Activity Via Emoji Usage In CommandLine - 4 | high | 61603 |
| `101891` | 9 | `T1685` T1685 | ETW Logging Tamper In .NET Processes Via CommandLine | high | 61603 |
| `101892` | 9 | `T1070` Indicator Removal | ETW Trace Evasion Activity | high | 61603 |
| `101893` | 9 | `T1070` Indicator Removal | ETW Trace Evasion Activity | high | 61603 |
| `101894` | 9 | `T1070` Indicator Removal | ETW Trace Evasion Activity | high | 61603 |
| `101895` | 9 | `T1070` Indicator Removal | ETW Trace Evasion Activity | high | 61603 |
| `101896` | 9 | `T1070` Indicator Removal | ETW Trace Evasion Activity | high | 61603 |
| `101897` | 9 | `T1070` Indicator Removal | ETW Trace Evasion Activity | high | 61603 |
| `101898` | 9 | `T1070` Indicator Removal | ETW Trace Evasion Activity | high | 61603 |
| `101899` | 9 | `T1685.005` T1685.005 | Suspicious Eventlog Clearing or Configuration Change Activity | high | 61603 |
| `101900` | 9 | `T1564` T1564 | Potentially Suspicious Execution From Parent Process In Public Folder | high | 61603 |
| `101901` | 9 | `T1036` T1036 | Process Execution From A Potentially Suspicious Folder | high | 61603 |
| `101902` | 8 | `T1059.006` T1059.006 | Suspicious File Characteristics Due to Missing Fields | medium | 61603 |
| `101903` | 9 | `T1204.004` T1204.004 | Suspicious FileFix Execution Pattern | high | 61603 |
| `101904` | 8 | `T1564.004` T1564.004 | Potential Hidden Directory Creation Via NTFS INDEX_ALLOCATION Strea... | medium | 61603 |
| `101905` | 8 | `T1036` T1036 | Potential Homoglyph Attack Using Lookalike Characters | medium | 61603 |
| `101906` | 8 | `T1036` T1036 | Potential Homoglyph Attack Using Lookalike Characters | medium | 61603 |
| `101907` | 9 | - | Execution Of Non-Existing File | high | 61603 |
| `101908` | 9 | - | Base64 MZ Header In CommandLine | high | 61603 |
| `101909` | 8 | `T1059.007` T1059.007 | Potentially Suspicious Inline JavaScript Execution via NodeJS Binary | medium | 61603 |
| `101910` | 9 | `T1106` T1106 | Potential WinAPI Calls Via CommandLine | high | 61603 |
| `101911` | 8 | - | LOLBIN Execution From Abnormal Drive | medium | 61603 |
| `101912` | 8 | `T1218` T1218 | Potential File Download Via MS-AppInstaller Protocol Handler | medium | 61603 |
| `101913` | 8 | `T1059` Command and Scripting Interpreter | Suspicious Scan Loop Network | medium | 61603 |
| `101914` | 8 | - | Process Launched Without Image Name | medium | 61603 |
| `101915` | 8 | - | Execution of Suspicious File Type Extension | medium | 61603 |
| `101916` | 9 | - | Potentially Suspicious Call To Win32_NTEventlogFile Class | high | 61603 |
| `101917` | 8 | `T1564.004` T1564.004 | Use Short Name Path in Image | medium | 61603 |
| `101918` | 8 | `T1564.004` T1564.004 | Use NTFS Short Name in Command Line | medium | 61603 |
| `101919` | 8 | `T1564.004` T1564.004 | Use NTFS Short Name in Image | medium | 61603 |
| `101920` | 9 | `T1036` T1036 | Suspicious Process Parents | high | 61603 |
| `101921` | 9 | `T1218.011` T1218.011 | Potential PowerShell Execution Via DLL | high | 61603 |
| `101922` | 13 | `T1059` Command and Scripting Interpreter | Suspicious Program Names | high | 61603 |
| `101923` | 9 | `T1059` Command and Scripting Interpreter | Suspicious Program Names | high | 61603 |
| `101924` | 14 | `T1059` Command and Scripting Interpreter | Suspicious Program Names | high | 61603 |
| `101925` | 9 | `T1036.002` T1036.002 | Potential Defense Evasion Via Right-to-Left Override | high | 61603 |
| `101926` | 9 | `T1059` Command and Scripting Interpreter | Script Interpreter Execution From Suspicious Folder | high | 61603 |
| `101927` | 9 | `T1059` Command and Scripting Interpreter | Script Interpreter Execution From Suspicious Folder | high | 61603 |
| `101928` | 9 | `T1059` Command and Scripting Interpreter | Script Interpreter Execution From Suspicious Folder | high | 61603 |
| `101929` | 9 | `T1202` T1202 | Suspicious Service Binary Directory | high | 61603 |
| `101930` | 9 | `T1059.005` T1059.005 | Windows Shell/Scripting Processes Spawning Suspicious Programs | high | 61603 |
| `101931` | 12 | `T1036` T1036 | System File Execution Location Anomaly | high | 61603 |
| `101932` | 8 | `T1218` T1218 | Malicious PE Execution by Microsoft Visual Studio Debugger | medium | 61603 |
| `101933` | 8 | - | Weak or Abused Passwords In CLI | medium | 61603 |
| `101934` | 8 | `T1059.001` T1059.001 | Usage Of Web Request Commands And Cmdlets | medium | 61603 |
| `101935` | 9 | `T1218` T1218 | Execution via WorkFolders.exe | high | 61603 |
| `101936` | 9 | `T1036.005` T1036.005 | Suspicious Process Masquerading As SvcHost.EXE | high | 61603 |
| `101937` | 8 | `T1036.005` T1036.005 | Uncommon Svchost Parent Process | medium | 61603 |
| `101938` | 8 | - | Potential Memory Dumping Activity Via LiveKD | medium | 61603 |
| `101939` | 8 | - | Potential Memory Dumping Activity Via LiveKD | medium | 61603 |
| `101940` | 9 | - | Kernel Memory Dump Via LiveKD | high | 61603 |
| `101941` | 8 | `T1569` System Services | Psexec Execution | medium | 61603 |
| `101942` | 8 | `T1569` System Services | Psexec Execution | medium | 61603 |
| `101943` | 9 | `T1587.001` T1587.001 | PsExec/PAExec Escalation to LOCAL SYSTEM | high | 61603 |
| `101944` | 9 | `T1587.001` T1587.001 | Potential PsExec Remote Execution | high | 61603 |
| `101945` | 8 | - | PsExec Service Execution | medium | 61603 |
| `101946` | 8 | - | PsExec Service Execution | medium | 61603 |
| `101947` | 9 | - | PsExec Service Child Process Execution as LOCAL SYSTEM | high | 61603 |
| `101948` | 9 | `T1685` T1685 | Sysinternals PsSuspend Suspicious Execution | high | 61603 |
| `101949` | 9 | `T1587.001` T1587.001 | Potential Privilege Escalation To LOCAL SYSTEM | high | 61603 |
| `101950` | 8 | `T1685` T1685 | Sysmon Configuration Update | medium | 61603 |
| `101951` | 9 | `T1685` T1685 | Uninstall Sysinternals Sysmon | high | 61603 |
| `101952` | 8 | `T1218` T1218 | Potential Binary Impersonating Sysinternals Tools | medium | 61603 |
| `101953` | 8 | `T1218` T1218 | Potential Binary Impersonating Sysinternals Tools | medium | 61603 |
| `101954` | 8 | `T1059` Command and Scripting Interpreter | Sysprep on AppData Folder | medium | 61603 |
| `101955` | 9 | - | Potential Signing Bypass Via Windows Developer Features | high | 61603 |
| `101956` | 8 | `T1222.001` T1222.001 | Suspicious Recursive Takeown | medium | 61603 |
| `101957` | 9 | `T1685` T1685 | Taskkill Symantec Endpoint Protection | high | 61603 |
| `101958` | 9 | `T1036` T1036 | Taskmgr as LOCAL_SYSTEM | high | 61603 |
| `101959` | 8 | - | New Virtual Smart Card Created Via TpmVscMgr.EXE | medium | 61603 |
| `101960` | 8 | - | Potential RDP Session Hijacking Activity | medium | 61603 |
| `101961` | 9 | `T1548.002` T1548.002 | CMSTP UAC Bypass via COM Object Access | high | 61603 |
| `101962` | 9 | `T1548.002` T1548.002 | UAC Bypass Using IDiagnostic Profile | high | 61603 |
| `101963` | 9 | `T1685` T1685 | Uninstall Crowdstrike Falcon Sensor | high | 61603 |
| `101964` | 8 | `T1218` T1218 | Verclsid.exe Runs COM Object | medium | 61603 |
| `101965` | 8 | `T1059` Command and Scripting Interpreter | Potential Persistence Via VMwareToolBoxCmd.EXE VM State Change Script | medium | 61603 |
| `101966` | 9 | `T1059` Command and Scripting Interpreter | Suspicious Persistence Via VMwareToolBoxCmd.EXE VM State Change Script | high | 61603 |
| `101967` | 9 | `T1059` Command and Scripting Interpreter | VMToolsd Suspicious Child Process | high | 61603 |
| `101968` | 8 | `T1218` T1218 | Potentially Suspicious Child Process Of VsCode | medium | 61603 |
| `101969` | 8 | `T1218` T1218 | Potential Binary Proxy Execution Via VSDiagnostics.EXE | medium | 61603 |
| `101970` | 8 | `T1202` T1202 | Proxy Execution via Vshadow | medium | 61603 |
| `101971` | 8 | `T1218` T1218 | Suspicious Vsls-Agent Command With AgentExtensionPath Load | medium | 61603 |
| `101972` | 9 | `T1685` T1685 | Vulnerable Driver Blocklist Registry Tampering Via CommandLine | high | 61603 |
| `101973` | 9 | - | Wab Execution From Non Default Location | high | 61603 |
| `101974` | 9 | - | Wab/Wabmig Unusual Parent Or Child Processes | high | 61603 |
| `101975` | 9 | - | Wab/Wabmig Unusual Parent Or Child Processes | high | 61603 |
| `101976` | 8 | `T1059.001` T1059.001 | Potentially Suspicious WebDAV LNK Execution | medium | 61603 |
| `101977` | 8 | `T1036` T1036 | Potential ReflectDebugger Content Execution Via WerFault.EXE | medium | 61603 |
| `101978` | 9 | - | Suspicious Execution Location Of Wermgr.EXE | high | 61603 |
| `101979` | 9 | - | Suspicious File Download From IP Via Wget.EXE | high | 61603 |
| `101980` | 9 | - | Suspicious File Download From File Sharing Domain Via Wget.EXE | high | 61603 |
| `101981` | 9 | - | Suspicious File Download From IP Via Wget.EXE - Paths | high | 61603 |
| `101982` | 8 | - | Suspicious WindowsTerminal Child Processes | medium | 61603 |
| `101983` | 8 | `T1059` Command and Scripting Interpreter | Add New Download Source To Winget | medium | 61603 |
| `101984` | 9 | `T1059` Command and Scripting Interpreter | Add Insecure Download Source To Winget | high | 61603 |
| `101985` | 8 | `T1059` Command and Scripting Interpreter | Add Potential Suspicious New Download Source To Winget | medium | 61603 |
| `101986` | 8 | `T1059` Command and Scripting Interpreter | Install New Package Via Winget Local Manifest | medium | 61603 |
| `101987` | 8 | `T1203` T1203 | Potentially Suspicious Child Process Of WinRAR.EXE | medium | 61603 |
| `101988` | 8 | `T1216` T1216 | AWL Bypass with Winrm.vbs and Malicious WsmPty.xsl/WsmTxt.xsl | medium | 61603 |
| `101989` | 8 | `T1216` T1216 | Remote Code Execute via Winrm.vbs | medium | 61603 |
| `101990` | 8 | `T1059.001` T1059.001 | Remote PowerShell Session Host Process (WinRM) | medium | 61603 |
| `101991` | 8 | `T1059.001` T1059.001 | Remote PowerShell Session Host Process (WinRM) | medium | 61603 |
| `101992` | 8 | `T1218` T1218 | Wlrmdr.EXE Uncommon Argument Or Child Process | medium | 61603 |
| `101993` | 9 | `T1047` T1047 | Potential Windows Defender Tampering Via Wmic.EXE | high | 61603 |
| `101994` | 8 | `T1047` T1047 | New Process Created Via Wmic.EXE | medium | 61603 |
| `101995` | 8 | `T1047` T1047 | Hardware Model Reconnaissance Via Wmic.EXE | medium | 61603 |
| `101996` | 8 | `T1047` T1047 | Windows Hotfix Updates Reconnaissance Via Wmic.EXE | medium | 61603 |
| `101997` | 8 | `T1047` T1047 | Process Reconnaissance Via Wmic.EXE | medium | 61603 |
| `101998` | 8 | `T1047` T1047 | Potential Product Reconnaissance Via Wmic.EXE | medium | 61603 |
| `101999` | 8 | `T1047` T1047 | Potential Product Class Reconnaissance Via Wmic.EXE | medium | 61603 |

### Persistence (TA0003) — 825 rules

| Rule ID | Level | Technique | Description | Confidence | Parent SID |
|---------|-------|-----------|-------------|------------|------------|
| `102000` | 9 | `T1547.001` T1547.001 | Registry persistence via currentversion\run | medium | 61615 |
| `102001` | 9 | `T1547.001` T1547.001 | Registry persistence via currentversion\run | medium | 61614 |
| `102002` | 9 | `T1547.001` T1547.001 | Registry persistence via currentversion\runonce | medium | 61615 |
| `102003` | 9 | `T1547.001` T1547.001 | Registry persistence via currentversion\runonce | medium | 61614 |
| `102004` | 9 | `T1547.004` T1547.004 | Registry persistence via userinit | medium | 61615 |
| `102005` | 9 | `T1546.003` T1546.003 | WMI event subscription (EventID 19) | medium | 61621 |
| `102006` | 9 | `T1546.003` T1546.003 | WMI event subscription (EventID 20) | medium | 61622 |
| `102007` | 9 | `T1546.003` T1546.003 | WMI event subscription (EventID 21) | medium | 61623 |
| `102008` | 9 | `T1136.001` T1136.001 | User account created | medium | 60100 |
| `102009` | 9 | `T1053.005` T1053.005 | Scheduled task created | medium | 60100 |
| `102010` | 7 | `T1098` T1098 | Member added to group | low | 60100 |
| `102011` | 9 | `T1547.004` T1547.004 | Registry persistence via winlogon\ | medium | 61615 |
| `102012` | 9 | `T1546.003` T1546.003 | WMI event subscription (EventID 20) | medium | 61622 |
| `102013` | 9 | `T1546.003` T1546.003 | WMI event subscription (EventID 21) | medium | 61623 |
| `102014` | 9 | `T1546.003` T1546.003 | WMI event subscription (EventID 19) | medium | 61621 |
| `102015` | 9 | `T1546.003` T1546.003 | WMI event subscription (EventID 20) | medium | 61622 |
| `102016` | 9 | `T1546.003` T1546.003 | WMI event subscription (EventID 21) | medium | 61623 |
| `102017` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102018` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102019` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102020` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102021` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102022` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102023` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102024` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102025` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102026` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102027` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102028` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102029` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102030` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102031` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102032` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102033` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102034` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102035` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102036` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102037` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102038` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102039` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102040` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102041` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102042` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102043` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102044` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102045` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102046` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102047` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102048` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102049` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102050` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102051` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102052` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102053` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102054` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102055` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102056` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102057` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102058` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102059` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102060` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102061` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102062` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102063` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102064` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102065` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102066` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102067` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102068` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102069` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102070` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102071` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102072` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102073` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102074` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102075` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102076` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102077` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102078` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102079` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102080` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102081` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102082` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102083` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102084` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102085` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102086` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102087` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102088` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102089` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102090` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102091` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102092` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102093` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102094` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102095` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102096` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102097` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102098` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102099` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102100` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102101` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102102` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102103` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102104` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102105` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102106` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102107` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102108` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102109` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102110` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102111` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102112` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102113` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102114` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102115` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102116` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102117` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102118` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102119` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102120` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102121` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102122` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102123` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102124` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102125` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102126` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102127` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102128` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102129` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102130` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102131` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102132` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102133` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102134` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102135` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102136` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102137` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102138` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102139` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102140` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102141` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102142` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102143` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102144` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102145` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102146` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102147` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102148` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102149` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102150` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102151` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102152` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102153` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102154` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102155` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102156` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102157` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102158` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102159` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102160` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102161` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102162` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102163` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102164` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102165` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102166` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102167` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102168` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102169` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102170` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102171` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102172` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102173` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102174` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102175` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102176` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102177` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102178` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102179` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102180` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102181` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102182` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102183` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102184` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102185` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102186` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102187` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102188` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102189` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102190` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102191` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102192` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102193` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102194` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102195` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102196` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102197` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102198` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102199` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102200` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102201` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102202` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102203` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102204` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102205` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102206` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102207` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102208` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102209` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102210` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102211` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102212` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102213` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102214` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102215` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102216` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102217` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102218` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102219` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102220` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102221` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102222` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102223` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102224` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102225` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102226` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102227` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102228` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102229` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102230` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102231` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102232` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102233` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102234` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102235` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102236` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102237` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102238` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102239` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102240` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102241` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102242` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102243` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102244` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102245` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102246` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102247` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102248` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102249` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102250` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102251` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102252` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102253` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102254` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102255` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102256` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102257` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102258` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102259` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102260` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102261` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102262` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102263` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102264` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102265` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102266` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102267` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102268` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102269` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102270` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102271` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102272` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102273` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102274` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102275` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102276` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102277` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102278` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102279` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102280` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102281` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102282` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102283` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102284` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102285` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102286` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102287` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102288` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102289` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102290` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102291` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102292` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102293` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102294` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102295` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102296` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102297` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102298` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102299` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102300` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102301` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102302` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102303` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102304` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102305` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102306` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102307` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102308` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102309` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102310` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102311` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102312` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102313` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102314` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102315` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102316` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102317` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102318` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102319` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102320` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102321` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102322` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102323` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102324` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102325` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102326` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102327` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102328` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102329` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102330` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102331` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102332` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102333` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102334` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102335` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102336` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102337` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102338` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102339` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102340` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102341` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102342` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102343` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102344` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102345` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102346` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102347` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102348` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102349` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102350` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102351` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102352` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102353` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102354` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102355` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102356` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102357` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102358` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102359` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102360` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102361` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102362` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102363` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102364` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102365` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102366` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102367` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102368` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102369` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102370` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102371` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102372` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102373` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102374` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102375` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102376` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102377` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102378` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102379` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102380` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102381` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102382` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102383` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102384` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102385` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102386` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102387` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102388` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102389` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102390` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102391` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102392` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102393` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102394` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102395` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102396` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102397` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102398` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102399` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102400` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102401` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102402` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102403` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102404` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102405` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102406` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102407` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102408` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102409` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102410` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102411` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102412` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102413` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102414` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102415` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102416` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102417` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102418` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102419` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102420` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102421` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102422` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102423` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102424` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102425` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102426` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102427` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102428` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102429` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102430` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102431` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102432` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102433` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102434` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102435` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102436` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102437` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102438` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102439` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102440` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102441` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102442` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102443` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102444` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102445` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102446` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102447` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102448` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102449` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102450` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102451` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102452` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102453` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102454` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102455` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102456` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102457` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102458` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102459` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102460` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102461` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102462` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102463` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102464` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102465` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102466` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102467` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102468` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102469` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102470` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102471` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102472` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102473` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102474` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102475` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102476` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102477` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102478` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102479` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102480` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102481` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102482` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102483` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102484` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102485` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102486` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102487` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102488` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102489` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102490` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102491` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102492` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102493` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102494` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102495` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102496` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102497` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102498` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102499` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102500` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102501` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102502` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102503` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102504` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102505` | 9 | `T1546.003` T1546.003 | WMI event subscription (EventID 20) | medium | 61622 |
| `102506` | 9 | `T1546.003` T1546.003 | WMI event subscription (EventID 19) | medium | 61621 |
| `102507` | 7 | `T1098` T1098 | Security group created | low | 60100 |
| `102508` | 7 | `T1098` T1098 | Security group changed | low | 60100 |
| `102509` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102510` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102511` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102512` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102513` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102514` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102515` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102516` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102517` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102518` | 9 | `T1543.003` T1543.003 | Suspicious service path: powershell | medium | 60106 |
| `102519` | 9 | `T1543.003` T1543.003 | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102520` | 13 | `T1021.002` T1021.002 | CobaltStrike Service Installations - Security | high | 60100 |
| `102521` | 10 | `T1112` T1112 | ETW Logging Disabled In .NET Processes - Registry | high | 60100 |
| `102522` | 10 | `T1112` T1112 | ETW Logging Disabled In .NET Processes - Registry | high | 60100 |
| `102523` | 10 | `T1136.001` T1136.001 | Hidden Local User Creation | high | 60100 |
| `102524` | 10 | `T1554` T1554 | HybridConnectionManager Service Installation | high | 60100 |
| `102525` | 10 | `T1685` T1685 | NetNTLM Downgrade Attack | high | 60100 |
| `102526` | 10 | `T1543` Create or Modify System Process | Service Installed By Unusual Client - Security | high | 60100 |
| `102527` | 9 | `T1134.005` T1134.005 | Addition of SID History to Active Directory Object | medium | 60100 |
| `102528` | 9 | `T1078` Valid Accounts | Account Tampering - Suspicious Failed Logon Reasons | medium | 60100 |
| `102529` | 9 | `T1484.001` T1484.001 | Startup/Logon Script Added to Group Policy Object | medium | 60100 |
| `102530` | 10 | `T1136.001` T1136.001 | Suspicious Windows ANONYMOUS LOGON Local Account Created | high | 60100 |
| `102531` | 10 | `T1556` T1556 | Possible Shadow Credentials Added | high | 60100 |
| `102532` | 10 | `T1112` T1112 | Sysmon Channel Reference Deletion | high | 60100 |
| `102533` | 10 | `T1112` T1112 | Sysmon Channel Reference Deletion | high | 60100 |
| `102534` | 9 | `T1546.003` T1546.003 | WMI Persistence - Security | medium | 60100 |
| `102535` | 13 | `T1021.002` T1021.002 | CobaltStrike Service Installations - System | high | 60106 |
| `102536` | 10 | `T1543` Create or Modify System Process | KrbRelayUp Service Installation | high | 60106 |
| `102537` | 10 | `T1543.003` T1543.003 | Moriya Rootkit - System | high | 60106 |
| `102538` | 9 | - | Anydesk Remote Access Software Service Installation | medium | 60106 |
| `102539` | 9 | - | NetSupport Manager Service Install | medium | 60106 |
| `102540` | 9 | `T1543.003` T1543.003 | New PDQDeploy Service - Server Side | medium | 60106 |
| `102541` | 9 | `T1543.003` T1543.003 | New PDQDeploy Service - Client Side | medium | 60106 |
| `102542` | 10 | `T1543.003` T1543.003 | ProcessHacker Privilege Elevation | high | 60106 |
| `102543` | 9 | - | Remote Utilities Host Service Install | medium | 60106 |
| `102544` | 10 | `T1543.003` T1543.003 | Sliver C2 Default Service Installation | high | 60106 |
| `102545` | 10 | `T1543` Create or Modify System Process | Service Installed By Unusual Client - System | high | 60106 |
| `102546` | 10 | `T1543.003` T1543.003 | Suspicious Service Installation | high | 60106 |
| `102547` | 9 | `T1543.003` T1543.003 | Uncommon Service Installation Image Path | medium | 60106 |
| `102548` | 10 | - | RTCore Suspicious Service Installation | high | 60106 |
| `102549` | 9 | `T1543.003` T1543.003 | Service Installation in Suspicious Folder | medium | 60106 |
| `102550` | 10 | `T1543.003` T1543.003 | Service Installation with Suspicious Folder Pattern | high | 60106 |
| `102551` | 10 | `T1543.003` T1543.003 | Suspicious Service Installation Script | high | 60106 |
| `102552` | 10 | - | Potential Suspicious Winget Package Installation | high | 61617 |
| `102553` | 10 | `T1554` T1554 | DNS HybridConnectionManager Service Bus | high | 61624 |
| `102554` | 10 | `T1543.003` T1543.003 | Malicious Driver Load | high | 61608 |
| `102555` | 13 | `T1543.003` T1543.003 | Malicious Driver Load By Name | medium | 61608 |
| `102556` | 10 | `T1543` Create or Modify System Process | PUA - Process Hacker Driver Load | high | 61608 |
| `102557` | 10 | `T1543` Create or Modify System Process | PUA - Process Hacker Driver Load | high | 61608 |
| `102558` | 9 | `T1543` Create or Modify System Process | PUA - System Informer Driver Load | medium | 61608 |
| `102559` | 9 | `T1543` Create or Modify System Process | PUA - System Informer Driver Load | medium | 61608 |
| `102560` | 10 | `T1543.003` T1543.003 | Driver Load From A Temporary Directory | high | 61608 |
| `102561` | 10 | `T1543.003` T1543.003 | Vulnerable Driver Load | high | 61608 |
| `102562` | 10 | `T1543.003` T1543.003 | Vulnerable HackSys Extreme Vulnerable Driver Load | high | 61608 |
| `102563` | 10 | `T1543.003` T1543.003 | Vulnerable HackSys Extreme Vulnerable Driver Load | high | 61608 |
| `102564` | 10 | `T1543.003` T1543.003 | Vulnerable WinRing0 Driver Load | high | 61608 |
| `102565` | 10 | `T1543.003` T1543.003 | Vulnerable WinRing0 Driver Load | high | 61608 |
| `102566` | 10 | `T1133` T1133 | Unusual File Modification by dns.exe | high | 61604 |
| `102567` | 10 | `T1133` T1133 | Unusual File Deletion by Dns.exe | high | 61625 |
| `102568` | 9 | `T1574.001` T1574.001 | Creation Of Non-Existent System DLL | medium | 61613 |
| `102569` | 10 | `T1574.001` T1574.001 | DLL Search Order Hijackig Via Additional Space in Path | high | 61613 |
| `102570` | 9 | - | Potential Persistence Attempt Via ErrorHandler.Cmd | medium | 61613 |
| `102571` | 10 | `T1505.003` T1505.003 | Suspicious ASPX File Drop by Exchange | high | 61613 |
| `102572` | 9 | `T1190` Exploit Public-Facing Application | Suspicious File Drop by Exchange | medium | 61613 |
| `102573` | 10 | `T1574.001` T1574.001 | HackTool - Powerup Write Hijack DLL | high | 61613 |
| `102574` | 10 | `T1574.001` T1574.001 | Malicious DLL File Dropped in the Teams or OneDrive Folder | high | 61613 |
| `102575` | 9 | - | Potential Persistence Via Notepad++ Plugins | medium | 61613 |
| `102576` | 10 | `T1137.006` T1137.006 | Potential Persistence Via Microsoft Office Add-In | high | 61613 |
| `102577` | 10 | `T1137.006` T1137.006 | Potential Persistence Via Microsoft Office Add-In | high | 61613 |
| `102578` | 10 | `T1137.006` T1137.006 | Potential Persistence Via Microsoft Office Add-In | high | 61613 |
| `102579` | 10 | `T1137.006` T1137.006 | Potential Persistence Via Microsoft Office Add-In | high | 61613 |
| `102580` | 10 | `T1137.003` T1137.003 | Potential Persistence Via Outlook Form | high | 61613 |
| `102581` | 10 | `T1137` T1137 | Potential Persistence Via Microsoft Office Startup Folder | high | 61613 |
| `102582` | 9 | - | Potential Binary Or Script Dropper Via PowerShell | medium | 61613 |
| `102583` | 9 | - | Potential Suspicious PowerShell Module File Created | medium | 61613 |
| `102584` | 9 | - | PowerShell Module File Created By Non-PowerShell Process | medium | 61613 |
| `102585` | 9 | `T1505.003` T1505.003 | Suspicious File Write to Webapps Root Directory | medium | 61613 |
| `102586` | 9 | `T1546.013` T1546.013 | PowerShell Profile Modification | medium | 61613 |
| `102587` | 10 | - | Suspicious File Creation Activity From Fake Recycle.Bin Folder | high | 61613 |
| `102588` | 10 | - | Suspicious File Creation Activity From Fake Recycle.Bin Folder | high | 61613 |
| `102589` | 9 | `T1546.013` T1546.013 | VsCode Powershell Profile Modification | medium | 61613 |
| `102590` | 10 | `T1068` Exploitation for Privilege Escalation | Process Explorer Driver Creation By Non-Sysinternals Binary | high | 61613 |
| `102591` | 9 | `T1068` Exploitation for Privilege Escalation | Process Monitor Driver Creation By Non-Sysinternals Binary | medium | 61613 |
| `102592` | 10 | - | Potential Privilege Escalation Attempt Via .Exe.Local Technique | high | 61613 |
| `102593` | 9 | `T1505.003` T1505.003 | Potential Webshell Creation On Static Website | medium | 61613 |
| `102594` | 10 | `T1542.001` T1542.001 | UEFI Persistence Via Wpbbin - FileCreation | high | 61613 |
| `102595` | 9 | `T1574.001` T1574.001 | Potential Antivirus Software DLL Sideloading | medium | 61609 |
| `102596` | 10 | `T1574.001` T1574.001 | Potential appverifUI.DLL Sideloading | high | 61609 |
| `102597` | 9 | `T1574.001` T1574.001 | Potential AVKkid.DLL Sideloading | medium | 61609 |
| `102598` | 9 | `T1574.001` T1574.001 | Potential CCleanerDU.DLL Sideloading | medium | 61609 |
| `102599` | 9 | `T1574.001` T1574.001 | Potential CCleanerReactivator.DLL Sideloading | medium | 61609 |
| `102600` | 9 | `T1574.001` T1574.001 | Potential Chrome Frame Helper DLL Sideloading | medium | 61609 |
| `102601` | 9 | `T1574.001` T1574.001 | Potential DLL Sideloading Via ClassicExplorer32.dll | medium | 61609 |
| `102602` | 10 | `T1574.001` T1574.001 | Potential DLL Sideloading Via comctl32.dll | high | 61609 |
| `102603` | 10 | `T1574.001` T1574.001 | System Control Panel Item Loaded From Uncommon Location | high | 61609 |
| `102604` | 9 | `T1574.001` T1574.001 | Potential DLL Sideloading Of DBGCORE.DLL | medium | 61609 |
| `102605` | 9 | `T1574.001` T1574.001 | Potential DLL Sideloading Of DBGHELP.DLL | medium | 61609 |
| `102606` | 10 | `T1574.001` T1574.001 | Potential EACore.DLL Sideloading | high | 61609 |
| `102607` | 10 | `T1574.001` T1574.001 | Potential Edputil.DLL Sideloading | high | 61609 |
| `102608` | 10 | `T1574.001` T1574.001 | Potential System DLL Sideloading From Non System Locations | high | 61609 |
| `102609` | 9 | `T1574.001` T1574.001 | Potential Goopdate.DLL Sideloading | medium | 61609 |
| `102610` | 9 | `T1574.001` T1574.001 | Potential DLL Sideloading Of Libcurl.DLL Via GUP.EXE | medium | 61609 |
| `102611` | 10 | `T1574.001` T1574.001 | Potential Iviewers.DLL Sideloading | high | 61609 |
| `102612` | 10 | `T1574.001` T1574.001 | Potential JLI.dll Side-Loading | high | 61609 |
| `102613` | 9 | `T1574.001` T1574.001 | Potential DLL Sideloading Via JsSchHlp | medium | 61609 |
| `102614` | 10 | `T1574.001` T1574.001 | Potential DLL Sideloading Of KeyScramblerIE.DLL Via KeyScrambler.EXE | high | 61609 |
| `102615` | 9 | `T1574.001` T1574.001 | Potential Libvlc.DLL Sideloading | medium | 61609 |
| `102616` | 9 | `T1574.001` T1574.001 | Potential Mfdetours.DLL Sideloading | medium | 61609 |
| `102617` | 10 | `T1574.001` T1574.001 | Unsigned Mfdetours.DLL Sideloading | high | 61609 |
| `102618` | 10 | `T1574.001` T1574.001 | Potential DLL Sideloading Of Non-Existent DLLs From System Folders | high | 61609 |
| `102619` | 10 | `T1574.001` T1574.001 | Microsoft Office DLL Sideload | high | 61609 |
| `102620` | 10 | `T1574.001` T1574.001 | Potential Rcdll.DLL Sideloading | high | 61609 |
| `102621` | 9 | `T1574.001` T1574.001 | Potential RjvPlatform.DLL Sideloading From Default Location | medium | 61609 |
| `102622` | 10 | `T1574.001` T1574.001 | Potential RjvPlatform.DLL Sideloading From Non-Default Location | high | 61609 |
| `102623` | 9 | `T1574.001` T1574.001 | Potential RoboForm.DLL Sideloading | medium | 61609 |
| `102624` | 10 | `T1574.001` T1574.001 | DLL Sideloading Of ShellChromeAPI.DLL | high | 61609 |
| `102625` | 9 | `T1574.001` T1574.001 | Potential ShellDispatch.DLL Sideloading | medium | 61609 |
| `102626` | 10 | `T1574.001` T1574.001 | Potential SmadHook.DLL Sideloading | high | 61609 |
| `102627` | 9 | `T1574.001` T1574.001 | Potential SolidPDFCreator.DLL Sideloading | medium | 61609 |
| `102628` | 9 | `T1574.001` T1574.001 | Third Party Software DLL Sideloading | medium | 61609 |
| `102629` | 10 | `T1574.001` T1574.001 | Potential Vcruntime140 DLL Sideloading | high | 61609 |
| `102630` | 9 | `T1574.001` T1574.001 | Potential Vivaldi_elf.DLL Sideloading | medium | 61609 |
| `102631` | 9 | `T1574.001` T1574.001 | VMGuestLib DLL Sideload | medium | 61609 |
| `102632` | 9 | `T1574.001` T1574.001 | VMMap Signed Dbghelp.DLL Potential Sideloading | medium | 61609 |
| `102633` | 10 | `T1574.001` T1574.001 | VMMap Unsigned Dbghelp.DLL Potential Sideloading | high | 61609 |
| `102634` | 10 | `T1574.001` T1574.001 | Potential Waveedit.DLL Sideloading | high | 61609 |
| `102635` | 9 | `T1574.001` T1574.001 | Potential Wazuh Security Platform DLL Sideloading | medium | 61609 |
| `102636` | 9 | `T1574.001` T1574.001 | Potential WWlib.DLL Sideloading | medium | 61609 |
| `102637` | 10 | `T1548.002` T1548.002 | UAC Bypass With Fake DLL | high | 61609 |
| `102638` | 10 | `T1574.007` T1574.007 | Trusted Path Bypass via Windows Directory Spoofing | high | 61609 |
| `102639` | 9 | `T1219.002` T1219.002 | Remote Access Tool - AnyDesk Incoming Connection | medium | 61605 |
| `102640` | 10 | `T1571` T1571 | Potentially Suspicious Malware Callback Communication | high | 61605 |
| `102641` | 9 | `T1571` T1571 | Communication To Uncommon Destination Ports | medium | 61605 |
| `102642` | 10 | `T1556.002` T1556.002 | Powershell Install a DLL in System Directory | high | 91801 |
| `102643` | 9 | `T1136.002` T1136.002 | Manipulation of User Computer or Group Security Principals Across AD | medium | 91801 |
| `102644` | 9 | - | Unsigned AppX Installation Attempt Using Add-AppxPackage - PsScript | medium | 91801 |
| `102645` | 10 | `T1137.006` T1137.006 | Code Executed Via Office Add-in XLL File | high | 91801 |
| `102646` | 10 | `T1059.001` T1059.001 | PowerShell Web Access Installation - PsScript | high | 91801 |
| `102647` | 10 | `T1059.001` T1059.001 | PowerShell Web Access Installation - PsScript | high | 91801 |
| `102648` | 10 | `T1059.001` T1059.001 | PowerShell Web Access Installation - PsScript | high | 91801 |
| `102649` | 10 | - | Potential Persistence Via Security Descriptors - ScriptBlock | high | 91801 |
| `102650` | 10 | `T1574.011` T1574.011 | Suspicious Service DACL Modification Via Set-Service Cmdlet - PS | high | 91801 |
| `102651` | 9 | `T1546.013` T1546.013 | Potential Persistence Via PowerShell User Profile Using Add-Content | medium | 91801 |
| `102652` | 10 | `T1574.011` T1574.011 | Abuse of Service Permissions to Hide Services Via Set-Service - PS | high | 91801 |
| `102653` | 9 | `T1112` T1112 | Registry Modification Attempt Via VBScript - PowerShell | medium | 91801 |
| `102654` | 9 | `T1546.003` T1546.003 | Powershell WMI Persistence | medium | 91801 |
| `102655` | 10 | `T1053.002` T1053.002 | Interactive AT Job | high | 61603 |
| `102656` | 9 | `T1070` Indicator Removal | Potential Ransomware or Unauthorized MBR Tampering Via Bcdedit.EXE | medium | 61603 |
| `102657` | 9 | `T1197` T1197 | File Download Via Bitsadmin | medium | 61603 |
| `102658` | 10 | `T1197` T1197 | Suspicious Download From Direct IP Via Bitsadmin | high | 61603 |
| `102659` | 10 | `T1197` T1197 | Suspicious Download From File-Sharing Website Via Bitsadmin | high | 61603 |
| `102660` | 10 | `T1197` T1197 | File With Suspicious Extension Downloaded Via Bitsadmin | high | 61603 |
| `102661` | 10 | `T1197` T1197 | File Download Via Bitsadmin To A Suspicious Target Folder | high | 61603 |
| `102662` | 9 | `T1197` T1197 | Monitoring For Persistence Via BITS | medium | 61603 |
| `102663` | 9 | `T1176.001` T1176.001 | Chromium Browser Instance Executed With Custom Extension | medium | 61603 |
| `102664` | 10 | `T1176.001` T1176.001 | Suspicious Chromium Browser Instance Executed With Custom Extension | high | 61603 |
| `102665` | 10 | `T1546.008` T1546.008 | Persistence Via Sticky Key Backdoor | high | 61603 |
| `102666` | 10 | `T1543.003` T1543.003 | Devcon Execution Disabling VMware VMCI Device | high | 61603 |
| `102667` | 10 | `T1133` T1133 | Unusual Child Process of dns.exe | high | 61603 |
| `102668` | 10 | `T1685.001` T1685.001 | Security Event Logging Disabled via MiniNt Registry Key - Process | high | 61603 |
| `102669` | 10 | `T1615` T1615 | HackTool - SharpUp PrivEsc Tool Execution | high | 61603 |
| `102670` | 10 | `T1615` T1615 | HackTool - SharpUp PrivEsc Tool Execution | high | 61603 |
| `102671` | 10 | `T1615` T1615 | HackTool - SharpUp PrivEsc Tool Execution | high | 61603 |
| `102672` | 9 | `T1505.003` T1505.003 | IIS Native-Code Module Command Line Installation | medium | 61603 |
| `102673` | 10 | `T1505.004` T1505.004 | Suspicious IIS Module Registration | high | 61603 |
| `102674` | 9 | `T1203` T1203 | Potentially Suspicious Child Process of KeyScrambler.exe | medium | 61603 |
| `102675` | 9 | `T1136.001` T1136.001 | New User Created Via Net.EXE | medium | 61603 |
| `102676` | 10 | `T1136.001` T1136.001 | New User Created Via Net.EXE With Never Expire Option | high | 61603 |
| `102677` | 10 | `T1574.011` T1574.011 | Abuse of Service Permissions to Hide Services Via Set-Service | high | 61603 |
| `102678` | 9 | - | Unsigned AppX Installation Attempt Using Add-AppxPackage | medium | 61603 |
| `102679` | 9 | `T1505.002` T1505.002 | MSExchange Transport Agent Installation | medium | 61603 |
| `102680` | 10 | `T1543.003` T1543.003 | PUA - Kernel Driver Utility (KDU) Execution | high | 61603 |
| `102681` | 9 | `T1082` System Information Discovery | PUA - System Informer Execution | medium | 61603 |
| `102682` | 9 | `T1082` System Information Discovery | PUA - System Informer Execution | medium | 61603 |
| `102683` | 9 | `T1082` System Information Discovery | PUA - System Informer Execution | medium | 61603 |
| `102684` | 9 | `T1082` System Information Discovery | PUA - System Informer Execution | medium | 61603 |
| `102685` | 9 | `T1082` System Information Discovery | PUA - System Informer Execution | medium | 61603 |
| `102686` | 9 | `T1556.002` T1556.002 | Dropping Of Password Filter DLL | medium | 61603 |
| `102687` | 9 | `T1112` T1112 | Potentially Suspicious Desktop Background Change Using Reg.EXE | medium | 61603 |
| `102688` | 9 | `T1112` T1112 | Potential Suspicious Registry File Imported Via Reg.EXE | medium | 61603 |
| `102689` | 10 | `T1112` T1112 | RestrictedAdminMode Registry Value Tampering - ProcCreation | high | 61603 |
| `102690` | 10 | `T1112` T1112 | Enable LM Hash Storage - ProcCreation | high | 61603 |
| `102691` | 10 | `T1021.001` T1021.001 | Potential Tampering With RDP Related Registry Keys Via Reg.EXE | high | 61603 |
| `102692` | 9 | `T1546.002` T1546.002 | Suspicious ScreenSave Change by Reg.exe | medium | 61603 |
| `102693` | 10 | `T1112` T1112 | Reg Add Suspicious Paths | high | 61603 |
| `102694` | 9 | `T1112` T1112 | Imports Registry Key From a File | medium | 61603 |
| `102695` | 10 | `T1112` T1112 | Imports Registry Key From an ADS | high | 61603 |
| `102696` | 10 | `T1112` T1112 | Suspicious Registry Modification From ADS Via Regini.EXE | high | 61603 |
| `102697` | 10 | `T1546.008` T1546.008 | Suspicious Debugger Registration Cmdline | high | 61603 |
| `102698` | 10 | `T1574.011` T1574.011 | Potential Privilege Escalation via Service Permissions Weakness | high | 61603 |
| `102699` | 9 | - | Persistence Via TypedPaths - CommandLine | medium | 61603 |
| `102700` | 9 | `T1133` T1133 | Remote Access Tool - ScreenConnect Installation Execution | medium | 61603 |
| `102701` | 10 | `T1112` T1112 | ShimCache Flush | high | 61603 |
| `102702` | 10 | `T1574.011` T1574.011 | Possible Privilege Escalation via Weak Service Permissions | high | 61603 |
| `102703` | 9 | `T1543.003` T1543.003 | New Kernel Driver Via SC.EXE | medium | 61603 |
| `102704` | 10 | `T1574.011` T1574.011 | Service DACL Abuse To Hide Services Via Sc.EXE | high | 61603 |
| `102705` | 9 | `T1574.011` T1574.011 | Service Security Descriptor Tampering Via Sc.EXE | medium | 61603 |
| `102706` | 10 | `T1543.003` T1543.003 | Suspicious Service Path Modification | high | 61603 |
| `102707` | 9 | `T1546.011` T1546.011 | Potential Shim Database Persistence via Sdbinst.EXE | medium | 61603 |
| `102708` | 9 | `T1546.011` T1546.011 | Uncommon Extension Shim Database Installation Via Sdbinst.EXE | medium | 61603 |
| `102709` | 9 | `T1211` T1211 | Writing Of Malicious Files To The Fonts Folder | medium | 61603 |
| `102710` | 10 | `T1112` T1112 | Non-privileged Usage of Reg or Powershell | high | 61603 |
| `102711` | 10 | - | Suspicious Process Execution From Fake Recycle.Bin Folder | high | 61603 |
| `102712` | 10 | `T1543.003` T1543.003 | Suspicious New Service Creation | high | 61603 |
| `102713` | 10 | `T1543.003` T1543.003 | Suspicious New Service Creation | high | 61603 |
| `102714` | 10 | `T1547.001` T1547.001 | User Shell Folders Registry Modification via CommandLine | high | 61603 |
| `102715` | 9 | `T1112` T1112 | Registry Modification Attempt Via VBScript | medium | 61603 |
| `102716` | 9 | `T1112` T1112 | Suspicious VBoxDrvInst.exe Parameters | medium | 61603 |
| `102717` | 10 | `T1505.003` T1505.003 | Chopper Webshell Process Pattern | high | 61603 |
| `102718` | 10 | `T1505.003` T1505.003 | Webshell Hacking Activity Patterns | high | 61603 |
| `102719` | 10 | `T1505.003` T1505.003 | Webshell Hacking Activity Patterns | high | 61603 |
| `102720` | 10 | `T1505.003` T1505.003 | Webshell Hacking Activity Patterns | high | 61603 |
| `102721` | 10 | `T1505.003` T1505.003 | Webshell Detection With Command Line Keywords | high | 61603 |
| `102722` | 10 | `T1505.003` T1505.003 | Webshell Detection With Command Line Keywords | high | 61603 |
| `102723` | 10 | `T1505.003` T1505.003 | Webshell Detection With Command Line Keywords | high | 61603 |
| `102724` | 10 | `T1505.003` T1505.003 | Suspicious Process By Web Server Process | high | 61603 |
| `102725` | 10 | `T1505.003` T1505.003 | Suspicious Process By Web Server Process | high | 61603 |
| `102726` | 10 | `T1505.003` T1505.003 | Suspicious Process By Web Server Process | high | 61603 |
| `102727` | 10 | `T1505.003` T1505.003 | Webshell Tool Reconnaissance Activity | high | 61603 |
| `102728` | 10 | `T1505.003` T1505.003 | Webshell Tool Reconnaissance Activity | high | 61603 |
| `102729` | 10 | `T1505.003` T1505.003 | Webshell Tool Reconnaissance Activity | high | 61603 |
| `102730` | 9 | `T1546.003` T1546.003 | WMI Persistence - Script Event Consumer | medium | 61603 |
| `102731` | 9 | `T1047` T1047 | Registry Manipulation via WMI Stdregprov | medium | 61603 |
| `102732` | 10 | `T1542.001` T1542.001 | UEFI Persistence Via Wpbbin - ProcessCreation | high | 61603 |
| `102733` | 9 | - | Potential Persistence Via Disk Cleanup Handler - Registry | medium | 61614 |
| `102734` | 10 | `T1070` Indicator Removal | Terminal Server Client Connection History Cleared - Registry | high | 61614 |
| `102735` | 10 | `T1070` Indicator Removal | Terminal Server Client Connection History Cleared - Registry | high | 61614 |
| `102736` | 9 | `T1112` T1112 | Removal of Potential COM Hijacking Registry Keys | medium | 61614 |
| `102737` | 12 | `T1136.001` T1136.001 | Creation of a Local Hidden User Account by Registry | high | 61615 |
| `102738` | 10 | `T1685.001` T1685.001 | Disable Security Events Logging Adding Reg Key MiniNt | high | 61615 |
| `102739` | 10 | `T1685.001` T1685.001 | Disable Security Events Logging Adding Reg Key MiniNt | high | 61615 |
| `102740` | 10 | `T1112` T1112 | Wdigest CredGuard Registry Modification | high | 61615 |
| `102741` | 10 | `T1112` T1112 | Registry Entries For Azorult Malware | high | 61615 |
| `102742` | 10 | `T1112` T1112 | Potential Qakbot Registry Activity | high | 61615 |
| `102743` | 9 | `T1546.002` T1546.002 | Path To Screensaver Binary Modified | medium | 61615 |
| `102744` | 10 | `T1685` T1685 | NetNTLM Downgrade Attack - Registry | high | 61615 |
| `102745` | 9 | `T1137.002` T1137.002 | Office Application Startup - Office Test | medium | 61615 |
| `102746` | 10 | `T1112` T1112 | RedMimicry Winnti Playbook Registry Manipulation | high | 61615 |
| `102747` | 9 | `T1112` T1112 | Run Once Task Configuration in Registry | medium | 61615 |
| `102748` | 10 | `T1548.002` T1548.002 | Shell Open Registry Keys Manipulation | high | 61615 |
| `102749` | 9 | `T1112` T1112 | Registry Tampering by Potentially Suspicious Processes | medium | 61615 |
| `102750` | 9 | - | Add Debugger Entry To AeDebug For Persistence | medium | 61615 |
| `102751` | 9 | `T1112` T1112 | Allow RDP Remote Assistance Feature | medium | 61615 |
| `102752` | 9 | `T1112` T1112 | New BgInfo.EXE Custom DB Path Registry Configuration | medium | 61615 |
| `102753` | 9 | `T1112` T1112 | New BgInfo.EXE Custom VBScript Registry Configuration | medium | 61615 |
| `102754` | 9 | `T1112` T1112 | New BgInfo.EXE Custom WMI Query Registry Configuration | medium | 61615 |
| `102755` | 9 | `T1137` T1137 | IE Change Domain Zone | medium | 61615 |
| `102756` | 9 | `T1112` T1112 | ClickOnce Trust Prompt Tampering | medium | 61615 |
| `102757` | 13 | `T1021.002` T1021.002 | Potential CobaltStrike Service Installations - Registry | high | 61615 |
| `102758` | 10 | `T1546` T1546 | COM Hijack via Sdclt | high | 61615 |
| `102759` | 9 | `T1564` T1564 | CrashControl CrashDump Disabled | medium | 61615 |
| `102760` | 10 | `T1685.001` T1685.001 | Security Event Logging Disabled via MiniNt Registry Key - Registry Set | high | 61615 |
| `102761` | 10 | `T1112` T1112 | Service Binary in Suspicious Folder | high | 61615 |
| `102762` | 10 | `T1112` T1112 | Service Binary in Suspicious Folder | high | 61615 |
| `102763` | 9 | `T1112` T1112 | Potentially Suspicious Desktop Background Change Via Registry | medium | 61615 |
| `102764` | 9 | `T1112` T1112 | Disable Internal Tools or Feature in Registry | medium | 61615 |
| `102765` | 9 | `T1112` T1112 | Disable Internal Tools or Feature in Registry | medium | 61615 |
| `102766` | 9 | `T1112` T1112 | Disable Windows Security Center Notifications | medium | 61615 |
| `102767` | 9 | `T1112` T1112 | Add DisallowRun Execution to Registry | medium | 61615 |
| `102768` | 9 | - | Persistence Via Disk Cleanup Handler - Autorun | medium | 61615 |
| `102769` | 9 | `T1140` T1140 | DNS-over-HTTPS Enabled by Registry | medium | 61615 |
| `102770` | 9 | `T1140` T1140 | DNS-over-HTTPS Enabled by Registry | medium | 61615 |
| `102771` | 9 | `T1140` T1140 | DNS-over-HTTPS Enabled by Registry | medium | 61615 |
| `102772` | 10 | `T1112` T1112 | ETW Logging Disabled In .NET Processes - Sysmon Registry | high | 61615 |
| `102773` | 10 | `T1112` T1112 | ETW Logging Disabled In .NET Processes - Sysmon Registry | high | 61615 |
| `102774` | 9 | `T1574.012` T1574.012 | Enabling COR Profiler Environment Variables | medium | 61615 |
| `102775` | 9 | `T1574.012` T1574.012 | Enabling COR Profiler Environment Variables | medium | 61615 |
| `102776` | 10 | `T1112` T1112 | Change User Account Associated with the FAX Service | high | 61615 |
| `102777` | 10 | `T1112` T1112 | Change the Fax Dll | high | 61615 |
| `102778` | 10 | - | Add Debugger Entry To Hangs Key For Persistence | high | 61615 |
| `102779` | 10 | - | Persistence Via Hhctrl.ocx | high | 61615 |
| `102780` | 9 | `T1137` T1137 | Registry Modification to Hidden File Extension | medium | 61615 |
| `102781` | 9 | `T1137` T1137 | Registry Modification to Hidden File Extension | medium | 61615 |
| `102782` | 9 | `T1112` T1112 | Registry Hide Function from User | medium | 61615 |
| `102783` | 9 | `T1112` T1112 | Registry Hide Function from User | medium | 61615 |
| `102784` | 10 | `T1112` T1112 | RestrictedAdminMode Registry Value Tampering | high | 61615 |
| `102785` | 10 | `T1112` T1112 | NET NGenAssemblyUsageLog Registry Key Tamper | high | 61615 |
| `102786` | 10 | `T1112` T1112 | Trust Access Disable For VBApplications | high | 61615 |
| `102787` | 10 | `T1112` T1112 | Outlook EnableUnsafeClientMailRules Setting Enabled - Registry | high | 61615 |
| `102788` | 9 | `T1137` T1137 | Outlook Security Settings Updated - Registry | medium | 61615 |
| `102789` | 10 | `T1112` T1112 | Macro Enabled In A Potentially Suspicious Document | high | 61615 |
| `102790` | 10 | `T1112` T1112 | Uncommon Microsoft Office Trusted Location Added | high | 61615 |
| `102791` | 10 | `T1112` T1112 | Office Macros Warning Disabled | high | 61615 |
| `102792` | 9 | - | Potential Persistence Via New AMSI Providers - Registry | medium | 61615 |
| `102793` | 10 | - | Potential Persistence Via AutodialDLL | high | 61615 |
| `102794` | 10 | - | Potential Persistence Via CHM Helper DLL | high | 61615 |
| `102795` | 9 | `T1112` T1112 | Potential Persistence Via Custom Protocol Handler | medium | 61615 |
| `102796` | 9 | `T1112` T1112 | Potential Persistence Via Event Viewer Events.asp | medium | 61615 |
| `102797` | 9 | - | Register New IFiltre For Persistence | medium | 61615 |
| `102798` | 9 | - | Register New IFiltre For Persistence | medium | 61615 |
| `102799` | 10 | - | Potential Persistence Via LSA Extensions | high | 61615 |
| `102800` | 10 | - | Potential Persistence Via Mpnotify | high | 61615 |
| `102801` | 10 | - | Potential Persistence Via MyComputer Registry Keys | high | 61615 |
| `102802` | 10 | - | Potential Persistence Via DLLPathOverride | high | 61615 |
| `102803` | 9 | `T1137.006` T1137.006 | Potential Persistence Via Visual Studio Tools for Office | medium | 61615 |
| `102804` | 10 | `T1112` T1112 | Potential Persistence Via Outlook Home Page | high | 61615 |
| `102805` | 10 | `T1112` T1112 | Potential Persistence Via Outlook Today Page | high | 61615 |
| `102806` | 10 | - | Potential Persistence Via TypedPaths | high | 61615 |
| `102807` | 10 | `T1137.006` T1137.006 | Potential Persistence Via Excel Add-in - Registry | high | 61615 |
| `102808` | 10 | `T1112` T1112 | Registry Modification for OCI DLL Redirection | high | 61615 |
| `102809` | 10 | `T1564.001` T1564.001 | PowerShell Logging Disabled Via Registry Key Tampering | high | 61615 |
| `102810` | 9 | - | Potential SentinelOne Shell Context Menu Scan Command Tampering | medium | 61615 |
| `102811` | 9 | `T1543.003` T1543.003 | ServiceDll Hijack | medium | 61615 |
| `102812` | 9 | `T1112` T1112 | Registry Explorer Policy Modification | medium | 61615 |
| `102813` | 9 | `T1553.003` T1553.003 | Persistence Via New SIP Provider | medium | 61615 |
| `102814` | 9 | `T1112` T1112 | Activate Suppression of Windows Security Center Notifications | medium | 61615 |
| `102815` | 10 | `T1574` T1574 | Suspicious Printer Driver Empty Manufacturer | high | 61615 |
| `102816` | 10 | `T1547.001` T1547.001 | Modify User Shell Folders Startup Value | high | 61615 |
| `102817` | 10 | - | Suspicious Environment Variable Has Been Registered | high | 61615 |
| `102818` | 10 | `T1112` T1112 | Enable LM Hash Storage | high | 61615 |
| `102819` | 9 | `T1112` T1112 | RDP Sensitive Settings Changed to Zero | medium | 61615 |
| `102820` | 10 | `T1112` T1112 | RDP Sensitive Settings Changed | high | 61615 |
| `102821` | 10 | `T1547.003` T1547.003 | New TimeProviders Registered With Uncommon DLL Name | high | 61615 |
| `102822` | 10 | `T1112` T1112 | Wdigest Enable UseLogonCredential | high | 61615 |
| `102823` | 9 | - | Enable Local Manifest Installation With Winget | medium | 61615 |
| `102824` | 9 | `T1112` T1112 | Winlogon AllowMultipleTSSessions Enable | medium | 61615 |

### Privilege Escalation (TA0004) — 371 rules

| Rule ID | Level | Technique | Description | Confidence | Parent SID |
|---------|-------|-----------|-------------|------------|------------|
| `103000` | 8 | `T1078` Valid Accounts | Special privilege assignment | low | 60100 |
| `103001` | 10 | `T1134.001` T1134.001 | Potential Access Token Abuse | medium | 60100 |
| `103002` | 11 | - | DiagTrackEoP Default Login Username | high | 60100 |
| `103003` | 10 | `T1133` T1133 | External Remote RDP Logon from Public IP | medium | 60100 |
| `103004` | 11 | `T1133` T1133 | External Remote SMB Logon from Public IP | high | 60100 |
| `103005` | 10 | `T1078` Valid Accounts | Failed Logon From Public IP | medium | 60100 |
| `103006` | 11 | `T1548` Abuse Elevation Control Mechanism | Potential Privilege Escalation via Local Kerberos Relay over LDAP | high | 60100 |
| `103007` | 11 | `T1098` T1098 | Powerview Add-DomainObjectAcl DCSync AD Extend Right | high | 60100 |
| `103008` | 11 | - | ADCS Certificate Template Configuration Vulnerability with Risky EKU | high | 60100 |
| `103009` | 11 | `T1098` T1098 | Enabled User Right in AD to Control User Objects | high | 60100 |
| `103010` | 11 | `T1098` T1098 | Active Directory User Backdoors | high | 60100 |
| `103011` | 10 | `T1053.002` T1053.002 | Remote Task Creation via ATSVC Named Pipe | medium | 60100 |
| `103012` | 10 | `T1484.001` T1484.001 | Windows Default Domain GPO Modification | medium | 60100 |
| `103013` | 11 | `T1053.005` T1053.005 | Persistence and Execution at Scale via GPO Scheduled Task | high | 60100 |
| `103014` | 11 | `T1053.005` T1053.005 | Persistence and Execution at Scale via GPO Scheduled Task | high | 60100 |
| `103015` | 11 | `T1134` Access Token Manipulation | HackTool - NoFilter Execution | high | 60100 |
| `103016` | 11 | `T1134` Access Token Manipulation | HackTool - NoFilter Execution | high | 60100 |
| `103017` | 14 | `T1134.001` T1134.001 | Meterpreter or Cobalt Strike Getsystem Service Installation - Security | high | 60100 |
| `103018` | 10 | `T1547.009` T1547.009 | Windows Network Access Suspicious desktop.ini Action | medium | 60100 |
| `103019` | 10 | `T1548` Abuse Elevation Control Mechanism | SCM Database Privileged Operation | medium | 60100 |
| `103020` | 10 | `T1543.003` T1543.003 | Remote Access Tool Services Have Been Installed - Security | medium | 60100 |
| `103021` | 10 | `T1098` T1098 | A New Trust Was Created To A Domain | medium | 60100 |
| `103022` | 11 | `T1098` T1098 | Password Change on Directory Service Restore Mode (DSRM) Account | high | 60100 |
| `103023` | 10 | `T1484.001` T1484.001 | Group Policy Abuse for Privilege Addition | medium | 60100 |
| `103024` | 10 | `T1078` Valid Accounts | Suspicious Remote Logon with Explicit Credentials | medium | 60100 |
| `103025` | 11 | `T1574.001` T1574.001 | DHCP Server Loaded the CallOut DLL | high | 60106 |
| `103026` | 11 | `T1574.001` T1574.001 | DHCP Server Error Failed Loading the CallOut DLL | high | 60106 |
| `103027` | 10 | - | Certificate Use With No Strong Mapping | medium | 60106 |
| `103028` | 11 | `T1548` Abuse Elevation Control Mechanism | Vulnerable Netlogon Secure Channel Connection Allowed | high | 60106 |
| `103029` | 14 | `T1134.001` T1134.001 | Meterpreter or Cobalt Strike Getsystem Service Installation - System | high | 60106 |
| `103030` | 10 | `T1543.003` T1543.003 | Remote Access Tool Services Have Been Installed - System | medium | 60106 |
| `103031` | 11 | `T1055.012` T1055.012 | HackTool - CACTUSTORCH Remote Thread Creation | high | 61610 |
| `103032` | 13 | `T1055.001` T1055.001 | HackTool - Potential CobaltStrike Process Injection | high | 61610 |
| `103033` | 11 | `T1055` Process Injection | Rare Remote Thread Creation By Uncommon Source Image | high | 61610 |
| `103034` | 10 | `T1055` Process Injection | Remote Thread Creation By Uncommon Source Image | medium | 61610 |
| `103035` | 10 | `T1055.003` T1055.003 | Remote Thread Creation In Uncommon Target Image | medium | 61610 |
| `103036` | 10 | `T1547.009` T1547.009 | New Custom Shim Database Created | medium | 61613 |
| `103037` | 10 | `T1546.002` T1546.002 | Suspicious Screensaver Binary File Creation | medium | 61613 |
| `103038` | 11 | `T1547.009` T1547.009 | Creation Exe for Service with Unquoted Path | high | 61613 |
| `103039` | 10 | `T1547.009` T1547.009 | Desktop.INI Created by Uncommon Process | medium | 61613 |
| `103040` | 10 | `T1566` Phishing | Potential Initial Access via DLL Search Order Hijacking | medium | 61613 |
| `103041` | 11 | `T1547.001` T1547.001 | File Creation In Suspicious Directory By Msdt.EXE | high | 61613 |
| `103042` | 10 | `T1137` T1137 | New Outlook Macro Created | medium | 61613 |
| `103043` | 11 | `T1137` T1137 | Suspicious Outlook Macro Created | high | 61613 |
| `103044` | 11 | `T1547.001` T1547.001 | Potential Startup Shortcut Persistence Via PowerShell.EXE | high | 61613 |
| `103045` | 11 | `T1547` Boot or Logon Autostart Execution | Potential RipZip Attack on Startup Folder | high | 61613 |
| `103046` | 10 | `T1547.001` T1547.001 | Startup Folder File Write | medium | 61613 |
| `103047` | 10 | `T1055` Process Injection | Created Files by Microsoft Sync Center | medium | 61613 |
| `103048` | 11 | `T1546` T1546 | Suspicious Get-Variable.exe Creation | high | 61613 |
| `103049` | 11 | `T1204.002` T1204.002 | Suspicious Startup Folder Persistence | high | 61613 |
| `103050` | 11 | `T1053` Scheduled Task/Job | Suspicious Scheduled Task Write to System32 Tasks | high | 61613 |
| `103051` | 10 | `T1547.015` T1547.015 | Windows Terminal Profile Settings Modification By Uncommon Process | medium | 61613 |
| `103052` | 11 | - | LiveKD Kernel Memory Dump File Created | high | 61613 |
| `103053` | 10 | - | LiveKD Driver Creation | medium | 61613 |
| `103054` | 11 | - | LiveKD Driver Creation By Uncommon Process | high | 61613 |
| `103055` | 11 | `T1548.002` T1548.002 | UAC Bypass Using Consent and Comctl32 - File | high | 61613 |
| `103056` | 11 | `T1548.002` T1548.002 | UAC Bypass Using .NET Code Profiler on MMC | high | 61613 |
| `103057` | 11 | - | UAC Bypass Using EventVwr | high | 61613 |
| `103058` | 11 | `T1548.002` T1548.002 | UAC Bypass Using IEInstal - File | high | 61613 |
| `103059` | 11 | `T1548.002` T1548.002 | UAC Bypass Using MSConfig Token Modification - File | high | 61613 |
| `103060` | 11 | `T1548.002` T1548.002 | UAC Bypass Using NTFS Reparse Point - File | high | 61613 |
| `103061` | 11 | `T1548.002` T1548.002 | UAC Bypass Abusing Winsat Path Parsing - File | high | 61613 |
| `103062` | 11 | `T1548.002` T1548.002 | UAC Bypass Using Windows Media Player - File | high | 61613 |
| `103063` | 11 | `T1548.002` T1548.002 | UAC Bypass Using Windows Media Player - File | high | 61613 |
| `103064` | 10 | `T1574.001` T1574.001 | Creation of WerFault.exe/Wer.dll in Unusual Folder | medium | 61613 |
| `103065` | 11 | `T1547.001` T1547.001 | WinRAR Creating Files in Startup Locations | high | 61613 |
| `103066` | 11 | `T1546.003` T1546.003 | WMI Persistence - Script Event Consumer File Write | high | 61613 |
| `103067` | 10 | `T1546.002` T1546.002 | Writing Local Admin Share | medium | 61613 |
| `103068` | 11 | `T1574.001` T1574.001 | Aruba Network Service Potential DLL Sideloading | high | 61609 |
| `103069` | 10 | `T1218` T1218 | Potential DLL Sideloading Using Coregen.exe | medium | 61609 |
| `103070` | 10 | `T1574.001` T1574.001 | Potential DLL Sideloading Of DbgModel.DLL | medium | 61609 |
| `103071` | 10 | `T1574.001` T1574.001 | Potential DLL Sideloading Of MpSvc.DLL | medium | 61609 |
| `103072` | 10 | `T1574.001` T1574.001 | Potential DLL Sideloading Of MsCorSvc.DLL | medium | 61609 |
| `103073` | 10 | `T1574.001` T1574.001 | Potential Python DLL SideLoading | medium | 61609 |
| `103074` | 11 | `T1574.001` T1574.001 | Fax Service DLL Search Order Hijack | high | 61609 |
| `103075` | 11 | `T1574.001` T1574.001 | Potential DLL Sideloading Via VMware Xfer | high | 61609 |
| `103076` | 11 | `T1574.001` T1574.001 | Potential Mpclient.DLL Sideloading | high | 61609 |
| `103077` | 10 | `T1574.001` T1574.001 | Unsigned Module Loaded by ClickOnce Application | medium | 61609 |
| `103078` | 11 | `T1574.001` T1574.001 | Suspicious Unsigned Thor Scanner Execution | high | 61609 |
| `103079` | 11 | `T1548.002` T1548.002 | UAC Bypass Using Iscsicpl - ImageLoad | high | 61609 |
| `103080` | 11 | `T1546.003` T1546.003 | WMI Persistence - Command Line Event Consumer | high | 61609 |
| `103081` | 11 | `T1055` Process Injection | Network Connection Initiated Via Notepad.EXE | high | 61605 |
| `103082` | 10 | `T1055` Process Injection | Microsoft Sync Center Suspicious Network Connections | medium | 61605 |
| `103083` | 13 | `T1055` Process Injection | CobaltStrike Named Pipe | high | 61619 |
| `103084` | 13 | `T1055` Process Injection | CobaltStrike Named Pipe | high | 61619 |
| `103085` | 13 | `T1055` Process Injection | CobaltStrike Named Pipe | high | 61619 |
| `103086` | 13 | `T1055` Process Injection | CobaltStrike Named Pipe | high | 61619 |
| `103087` | 13 | `T1055` Process Injection | CobaltStrike Named Pipe | high | 61619 |
| `103088` | 13 | `T1055` Process Injection | CobaltStrike Named Pipe | high | 61619 |
| `103089` | 13 | `T1055` Process Injection | CobaltStrike Named Pipe | high | 61619 |
| `103090` | 13 | `T1055` Process Injection | CobaltStrike Named Pipe | high | 61619 |
| `103091` | 13 | `T1055` Process Injection | CobaltStrike Named Pipe | high | 61619 |
| `103092` | 13 | `T1055` Process Injection | CobaltStrike Named Pipe | high | 61619 |
| `103093` | 13 | `T1055` Process Injection | CobaltStrike Named Pipe | high | 61619 |
| `103094` | 13 | `T1055` Process Injection | CobaltStrike Named Pipe Pattern Regex | high | 61619 |
| `103095` | 13 | `T1055` Process Injection | CobaltStrike Named Pipe Pattern Regex | high | 61619 |
| `103096` | 13 | `T1055` Process Injection | CobaltStrike Named Pipe Pattern Regex | high | 61619 |
| `103097` | 13 | `T1055` Process Injection | CobaltStrike Named Pipe Pattern Regex | high | 61619 |
| `103098` | 13 | `T1055` Process Injection | CobaltStrike Named Pipe Pattern Regex | high | 61619 |
| `103099` | 13 | `T1055` Process Injection | CobaltStrike Named Pipe Pattern Regex | high | 61619 |
| `103100` | 13 | `T1055` Process Injection | CobaltStrike Named Pipe Pattern Regex | high | 61619 |
| `103101` | 13 | `T1055` Process Injection | CobaltStrike Named Pipe Pattern Regex | high | 61619 |
| `103102` | 13 | `T1055` Process Injection | CobaltStrike Named Pipe Pattern Regex | high | 61619 |
| `103103` | 13 | `T1055` Process Injection | CobaltStrike Named Pipe Pattern Regex | high | 61619 |
| `103104` | 13 | `T1055` Process Injection | CobaltStrike Named Pipe Pattern Regex | high | 61619 |
| `103105` | 13 | `T1055` Process Injection | CobaltStrike Named Pipe Pattern Regex | high | 61619 |
| `103106` | 13 | `T1055` Process Injection | CobaltStrike Named Pipe Pattern Regex | high | 61619 |
| `103107` | 13 | `T1055` Process Injection | CobaltStrike Named Pipe Pattern Regex | high | 61619 |
| `103108` | 13 | `T1055` Process Injection | CobaltStrike Named Pipe Pattern Regex | high | 61619 |
| `103109` | 13 | `T1055` Process Injection | CobaltStrike Named Pipe Pattern Regex | high | 61619 |
| `103110` | 13 | `T1055` Process Injection | CobaltStrike Named Pipe Pattern Regex | high | 61619 |
| `103111` | 13 | `T1055` Process Injection | CobaltStrike Named Pipe Pattern Regex | high | 61619 |
| `103112` | 13 | `T1055` Process Injection | CobaltStrike Named Pipe Pattern Regex | high | 61619 |
| `103113` | 13 | `T1055` Process Injection | CobaltStrike Named Pipe Patterns | high | 61619 |
| `103114` | 13 | `T1055` Process Injection | CobaltStrike Named Pipe Patterns | high | 61619 |
| `103115` | 13 | `T1055` Process Injection | CobaltStrike Named Pipe Patterns | high | 61619 |
| `103116` | 11 | `T1055` Process Injection | HackTool - CoercedPotato Named Pipe Creation | high | 61619 |
| `103117` | 11 | - | HackTool - DiagTrackEoP Default Named Pipe | high | 61619 |
| `103118` | 11 | `T1055` Process Injection | HackTool - EfsPotato Named Pipe Creation | high | 61619 |
| `103119` | 11 | `T1528` T1528 | HackTool - Koh Default Named Pipe | high | 61619 |
| `103120` | 12 | `T1055` Process Injection | Malicious Named Pipe Created | high | 61619 |
| `103121` | 10 | `T1078` Valid Accounts | Suspicious Computer Machine Password by PowerShell | medium | 91801 |
| `103122` | 10 | `T1053.005` T1053.005 | Powershell Create Scheduled Task | medium | 91801 |
| `103123` | 10 | `T1053.005` T1053.005 | Powershell Create Scheduled Task | medium | 91801 |
| `103124` | 10 | `T1574.012` T1574.012 | Registry-Free Process Scope COR_PROFILER | medium | 91801 |
| `103125` | 10 | `T1078.002` T1078.002 | DMSA Service Account Created in Specific OUs - PowerShell | medium | 91801 |
| `103126` | 10 | `T1574.011` T1574.011 | Service Registry Permissions Weakness Check | medium | 91801 |
| `103127` | 10 | `T1098` T1098 | Powershell LocalAccount Manipulation | medium | 91801 |
| `103128` | 10 | `T1484.001` T1484.001 | Modify Group Policy Settings - ScriptBlockLogging | medium | 91801 |
| `103129` | 11 | `T1055` Process Injection | PowerShell ShellCode | high | 91801 |
| `103130` | 10 | `T1546.015` T1546.015 | Suspicious GetTypeFromCLSID ShellExecute | medium | 91801 |
| `103131` | 10 | `T1547.004` T1547.004 | Winlogon Helper DLL | medium | 91801 |
| `103132` | 11 | `T1548` Abuse Elevation Control Mechanism | Credential Dumping Attempt Via Svchost | high | 61612 |
| `103133` | 10 | `T1548.002` T1548.002 | Function Call From Undocumented COM Interface EditionUpgradeManager | medium | 61612 |
| `103134` | 11 | `T1548.002` T1548.002 | UAC Bypass Using WOW64 Logger DLL Hijack | high | 61612 |
| `103135` | 11 | `T1547.001` T1547.001 | Suspicious Autorun Registry Modified via WMI | high | 61603 |
| `103136` | 11 | `T1546.001` T1546.001 | Change Default File Association To Executable Via Assoc | high | 61603 |
| `103137` | 11 | `T1546.008` T1546.008 | Potential Privilege Escalation Using Symlink Between Osk and Cmd | high | 61603 |
| `103138` | 11 | `T1546.008` T1546.008 | Sticky Key Like Backdoor Execution | high | 61603 |
| `103139` | 11 | `T1218.002` T1218.002 | Control Panel Items | high | 61603 |
| `103140` | 10 | `T1078.002` T1078.002 | New DMSA Service Account Created in Specific OUs | medium | 61603 |
| `103141` | 11 | `T1055.001` T1055.001 | ManageEngine Endpoint Central Dctask64.EXE Potential Abuse | high | 61603 |
| `103142` | 10 | `T1574.001` T1574.001 | Potential DLL Sideloading Via DeviceEnroller.EXE | medium | 61603 |
| `103143` | 11 | `T1548.002` T1548.002 | PowerShell Web Access Feature Enabled Via DISM | high | 61603 |
| `103144` | 11 | `T1574.001` T1574.001 | DLL Sideloading by VMware Xfer Utility | high | 61603 |
| `103145` | 11 | `T1055` Process Injection | Dllhost.EXE Execution Anomaly | high | 61603 |
| `103146` | 11 | `T1574.001` T1574.001 | New DNS ServerLevelPluginDll Installed Via Dnscmd.EXE | high | 61603 |
| `103147` | 11 | `T1548.002` T1548.002 | Potentially Suspicious Event Viewer Child Process | high | 61603 |
| `103148` | 11 | `T1548.002` T1548.002 | Explorer NOUACCHECK Flag | high | 61603 |
| `103149` | 11 | `T1574.001` T1574.001 | Suspicious GUP Usage | high | 61603 |
| `103150` | 11 | `T1055` Process Injection | HackTool - CoercedPotato Execution | high | 61603 |
| `103151` | 11 | `T1055` Process Injection | HackTool - CoercedPotato Execution | high | 61603 |
| `103152` | 11 | `T1055` Process Injection | HackTool - CoercedPotato Execution | high | 61603 |
| `103153` | 11 | `T1047` T1047 | HackTool - CrackMapExec Execution Patterns | high | 61603 |
| `103154` | 11 | `T1055` Process Injection | HackTool - DInjector PowerShell Cradle Execution | high | 61603 |
| `103155` | 12 | `T1548.002` T1548.002 | HackTool - Empire PowerShell UAC Bypass | high | 61603 |
| `103156` | 11 | `T1055.012` T1055.012 | HackTool - HollowReaper Execution | high | 61603 |
| `103157` | 10 | `T1134.001` T1134.001 | HackTool - Impersonate Execution | medium | 61603 |
| `103158` | 11 | - | HackTool - LocalPotato Execution | high | 61603 |
| `103159` | 11 | - | HackTool - LocalPotato Execution | high | 61603 |
| `103160` | 11 | - | HackTool - LocalPotato Execution | high | 61603 |
| `103161` | 14 | `T1134.001` T1134.001 | Potential Meterpreter/CobaltStrike Activity | high | 61603 |
| `103162` | 11 | `T1134.004` T1134.004 | HackTool - PPID Spoofing SelectMyParent Tool Execution | high | 61603 |
| `103163` | 11 | `T1134.004` T1134.004 | HackTool - PPID Spoofing SelectMyParent Tool Execution | high | 61603 |
| `103164` | 11 | `T1134.004` T1134.004 | HackTool - PPID Spoofing SelectMyParent Tool Execution | high | 61603 |
| `103165` | 11 | `T1134.004` T1134.004 | HackTool - PPID Spoofing SelectMyParent Tool Execution | high | 61603 |
| `103166` | 11 | `T1134.004` T1134.004 | HackTool - PPID Spoofing SelectMyParent Tool Execution | high | 61603 |
| `103167` | 11 | `T1134.001` T1134.001 | HackTool - SharpDPAPI Execution | high | 61603 |
| `103168` | 11 | `T1134.001` T1134.001 | HackTool - SharpImpersonation Execution | high | 61603 |
| `103169` | 11 | `T1134.001` T1134.001 | HackTool - SharpImpersonation Execution | high | 61603 |
| `103170` | 11 | `T1134.001` T1134.001 | HackTool - SharpImpersonation Execution | high | 61603 |
| `103171` | 11 | `T1134.001` T1134.001 | HackTool - SharpImpersonation Execution | high | 61603 |
| `103172` | 11 | `T1134.001` T1134.001 | HackTool - SharpImpersonation Execution | high | 61603 |
| `103173` | 11 | `T1053` Scheduled Task/Job | HackTool - SharPersist Execution | high | 61603 |
| `103174` | 11 | `T1053` Scheduled Task/Job | HackTool - SharPersist Execution | high | 61603 |
| `103175` | 11 | `T1053` Scheduled Task/Job | HackTool - SharPersist Execution | high | 61603 |
| `103176` | 11 | `T1053` Scheduled Task/Job | HackTool - SharPersist Execution | high | 61603 |
| `103177` | 11 | `T1053` Scheduled Task/Job | HackTool - SharPersist Execution | high | 61603 |
| `103178` | 11 | `T1053` Scheduled Task/Job | HackTool - SharPersist Execution | high | 61603 |
| `103179` | 11 | `T1068` Exploitation for Privilege Escalation | HKTL - SharpSuccessor Privilege Escalation Tool Execution | high | 61603 |
| `103180` | 11 | `T1068` Exploitation for Privilege Escalation | HKTL - SharpSuccessor Privilege Escalation Tool Execution | high | 61603 |
| `103181` | 11 | `T1068` Exploitation for Privilege Escalation | HKTL - SharpSuccessor Privilege Escalation Tool Execution | high | 61603 |
| `103182` | 11 | `T1068` Exploitation for Privilege Escalation | HKTL - SharpSuccessor Privilege Escalation Tool Execution | high | 61603 |
| `103183` | 11 | `T1068` Exploitation for Privilege Escalation | HackTool - SysmonEOP Execution | high | 61603 |
| `103184` | 11 | `T1068` Exploitation for Privilege Escalation | HackTool - SysmonEOP Execution | high | 61603 |
| `103185` | 11 | `T1548.002` T1548.002 | HackTool - UACMe Akagi Execution | high | 61603 |
| `103186` | 11 | `T1548.002` T1548.002 | HackTool - UACMe Akagi Execution | high | 61603 |
| `103187` | 11 | `T1548.002` T1548.002 | HackTool - UACMe Akagi Execution | high | 61603 |
| `103188` | 11 | `T1548.002` T1548.002 | HackTool - UACMe Akagi Execution | high | 61603 |
| `103189` | 11 | `T1548.002` T1548.002 | HackTool - UACMe Akagi Execution | high | 61603 |
| `103190` | 11 | `T1548.002` T1548.002 | HackTool - UACMe Akagi Execution | high | 61603 |
| `103191` | 11 | `T1082` System Information Discovery | HackTool - winPEAS Execution | high | 61603 |
| `103192` | 11 | `T1082` System Information Discovery | HackTool - winPEAS Execution | high | 61603 |
| `103193` | 11 | `T1082` System Information Discovery | HackTool - winPEAS Execution | high | 61603 |
| `103194` | 11 | `T1082` System Information Discovery | HackTool - winPEAS Execution | high | 61603 |
| `103195` | 11 | `T1082` System Information Discovery | HackTool - winPEAS Execution | high | 61603 |
| `103196` | 11 | `T1082` System Information Discovery | HackTool - winPEAS Execution | high | 61603 |
| `103197` | 10 | - | Windows Kernel Debugger Execution | medium | 61603 |
| `103198` | 10 | - | Windows Kernel Debugger Execution | medium | 61603 |
| `103199` | 11 | `T1055.001` T1055.001 | Mavinject Inject DLL Into Running Process | high | 61603 |
| `103200` | 11 | `T1574.008` T1574.008 | Using SettingSyncHost.exe as LOLBin | high | 61603 |
| `103201` | 10 | `T1547` Boot or Logon Autostart Execution | Suspicious Driver Install by pnputil.exe | medium | 61603 |
| `103202` | 11 | `T1547` Boot or Logon Autostart Execution | Suspicious GrpConv Execution | high | 61603 |
| `103203` | 10 | `T1055.001` T1055.001 | Potential DLL Injection Or Execution Using Tracker.exe | medium | 61603 |
| `103204` | 10 | `T1484.001` T1484.001 | Windows Default Domain GPO Modification via GPME | medium | 61603 |
| `103205` | 11 | `T1574.001` T1574.001 | Potential Mpclient.DLL Sideloading Via Defender Binaries | high | 61603 |
| `103206` | 11 | `T1055` Process Injection | Potential Process Injection Via Msra.EXE | high | 61603 |
| `103207` | 10 | `T1546.007` T1546.007 | Potential Persistence Via Netsh Helper DLL | medium | 61603 |
| `103208` | 11 | `T1543.003` T1543.003 | Suspicious Service DACL Modification Via Set-Service Cmdlet | high | 61603 |
| `103209` | 11 | `T1134.002` T1134.002 | PUA - AdvancedRun Suspicious Execution | high | 61603 |
| `103210` | 10 | `T1547.001` T1547.001 | Potential Persistence Attempt Via Run Keys Using Reg.EXE | medium | 61603 |
| `103211` | 10 | `T1547.001` T1547.001 | Direct Autorun Keys Modification | medium | 61603 |
| `103212` | 10 | `T1484.001` T1484.001 | Modify Group Policy Settings | medium | 61603 |
| `103213` | 10 | `T1574.011` T1574.011 | Changing Existing Service ImagePath Value Via Reg.EXE | medium | 61603 |
| `103214` | 11 | `T1548` Abuse Elevation Control Mechanism | Regedit as Trusted Installer | high | 61603 |
| `103215` | 10 | `T1574` T1574 | DLL Execution Via Register-cimprovider.exe | medium | 61603 |
| `103216` | 11 | `T1037.001` T1037.001 | Potential Persistence Via Logon Scripts - CommandLine | high | 61603 |
| `103217` | 10 | `T1574` T1574 | Regsvr32 DLL Execution With Uncommon Extension | medium | 61603 |
| `103218` | 11 | `T1036` T1036 | Renamed ZOHO Dctask64 Execution | high | 61603 |
| `103219` | 11 | `T1055.001` T1055.001 | Renamed Mavinject.EXE Execution | high | 61603 |
| `103220` | 11 | `T1574.001` T1574.001 | Renamed Vmnat.exe Execution | high | 61603 |
| `103221` | 11 | `T1055` Process Injection | Suspicious Rundll32 Invoking Inline VBScript | high | 61603 |
| `103222` | 11 | `T1212` T1212 | Suspicious NTLM Authentication on the Printer Spooler Service | high | 61603 |
| `103223` | 11 | `T1546.015` T1546.015 | Rundll32 Registered COM Objects | high | 61603 |
| `103224` | 11 | `T1543.003` T1543.003 | Allow Service Access Using Security Descriptor Tampering Via Sc.EXE | high | 61603 |
| `103225` | 11 | `T1543.003` T1543.003 | Deny Service Access Using Security Descriptor Tampering Via Sc.EXE | high | 61603 |
| `103226` | 10 | `T1543.003` T1543.003 | Potential Persistence Attempt Via Existing Service Tampering | medium | 61603 |
| `103227` | 11 | `T1053.005` T1053.005 | Suspicious Schtasks Execution AppData Folder | high | 61603 |
| `103228` | 11 | `T1053.005` T1053.005 | Suspicious Modification Of Scheduled Tasks | high | 61603 |
| `103229` | 11 | `T1053.005` T1053.005 | Suspicious Scheduled Task Creation Involving Temp Folder | high | 61603 |
| `103230` | 10 | `T1053.005` T1053.005 | Scheduled Task Creation with Curl and PowerShell Execution Combo | medium | 61603 |
| `103231` | 10 | `T1053.005` T1053.005 | Schedule Task Creation From Env Variable Or Potentially Suspicious ... | medium | 61603 |
| `103232` | 11 | `T1053.005` T1053.005 | Schtasks From Suspicious Folders | high | 61603 |
| `103233` | 10 | `T1053.005` T1053.005 | Suspicious Scheduled Task Name As GUID | medium | 61603 |
| `103234` | 11 | `T1053.005` T1053.005 | Potential SSH Tunnel Persistence Install Using A Scheduled Task | high | 61603 |
| `103235` | 10 | `T1053.005` T1053.005 | Potential Persistence Via Microsoft Compatibility Appraiser | medium | 61603 |
| `103236` | 11 | `T1053.005` T1053.005 | Potential Persistence Via Powershell Search Order Hijacking - Task | high | 61603 |
| `103237` | 10 | `T1053.005` T1053.005 | Scheduled Task Executing Payload from Registry | medium | 61603 |
| `103238` | 11 | `T1053.005` T1053.005 | Scheduled Task Executing Encoded Payload from Registry | high | 61603 |
| `103239` | 11 | `T1053.005` T1053.005 | Suspicious Schtasks Schedule Types | high | 61603 |
| `103240` | 10 | `T1053.005` T1053.005 | Suspicious Schtasks Schedule Type With High Privileges | medium | 61603 |
| `103241` | 10 | `T1036.005` T1036.005 | Suspicious Scheduled Task Creation via Masqueraded XML File | medium | 61603 |
| `103242` | 11 | `T1053.005` T1053.005 | Suspicious Command Patterns In Scheduled Task Creation | high | 61603 |
| `103243` | 11 | `T1053.005` T1053.005 | Schtasks Creation Or Modification With SYSTEM Privileges | high | 61603 |
| `103244` | 12 | `T1053.005` T1053.005 | Scheduled Task Creation Masquerading as System Processes | high | 61603 |
| `103245` | 10 | `T1548.002` T1548.002 | Sdclt Child Processes | medium | 61603 |
| `103246` | 10 | `T1574.005` T1574.005 | Setup16.EXE Execution With Custom .Lst File | medium | 61603 |
| `103247` | 12 | `T1548` Abuse Elevation Control Mechanism | Abused Debug Privilege by Arbitrary Parent Processes | high | 61603 |
| `103248` | 10 | `T1098` T1098 | User Added to Local Administrators Group | medium | 61603 |
| `103249` | 11 | `T1098` T1098 | User Added To Highly Privileged Group | high | 61603 |
| `103250` | 10 | `T1548.002` T1548.002 | Always Install Elevated Windows Installer | medium | 61603 |
| `103251` | 10 | `T1548.002` T1548.002 | Always Install Elevated Windows Installer | medium | 61603 |
| `103252` | 11 | `T1134.002` T1134.002 | Suspicious Child Process Created as System | high | 61603 |
| `103253` | 10 | `T1548.002` T1548.002 | Always Install Elevated MSI Spawned Cmd And Powershell | medium | 61603 |
| `103254` | 10 | `T1059` Command and Scripting Interpreter | Elevated System Shell Spawned From Uncommon Parent Location | medium | 61603 |
| `103255` | 10 | - | Suspicious RunAs-Like Flag Combination | medium | 61603 |
| `103256` | 10 | `T1548.002` T1548.002 | Registry Modification of MS-settings Protocol Handler | medium | 61603 |
| `103257` | 10 | `T1055` Process Injection | Process Creation Using Sysnative Folder | medium | 61603 |
| `103258` | 11 | `T1574.001` T1574.001 | Tasks Folder Evasion | high | 61603 |
| `103259` | 10 | `T1055` Process Injection | Suspicious Userinit Child Process | medium | 61603 |
| `103260` | 11 | `T1055` Process Injection | Suspect Svchost Activity | high | 61603 |
| `103261` | 11 | `T1036.005` T1036.005 | Uncommon Svchost Command Line Parameter | high | 61603 |
| `103262` | 10 | `T1543.003` T1543.003 | Sysinternals PsService Execution | medium | 61603 |
| `103263` | 10 | `T1543.003` T1543.003 | Sysinternals PsService Execution | medium | 61603 |
| `103264` | 10 | `T1543.003` T1543.003 | Sysinternals PsSuspend Execution | medium | 61603 |
| `103265` | 10 | `T1543.003` T1543.003 | Sysinternals PsSuspend Execution | medium | 61603 |
| `103266` | 11 | `T1548.002` T1548.002 | UAC Bypass Using ChangePK and SLUI | high | 61603 |
| `103267` | 11 | `T1548.002` T1548.002 | UAC Bypass Using Disk Cleanup | high | 61603 |
| `103268` | 11 | `T1548.002` T1548.002 | Bypass UAC via CMSTP | high | 61603 |
| `103269` | 11 | `T1548.002` T1548.002 | UAC Bypass Tools Using ComputerDefaults | high | 61603 |
| `103270` | 11 | `T1548.002` T1548.002 | UAC Bypass Using Consent and Comctl32 - Process | high | 61603 |
| `103271` | 11 | `T1548.002` T1548.002 | UAC Bypass Using DismHost | high | 61603 |
| `103272` | 11 | - | UAC Bypass Using Event Viewer RecentViews | high | 61603 |
| `103273` | 11 | `T1548.002` T1548.002 | Bypass UAC via Fodhelper.exe | high | 61603 |
| `103274` | 10 | `T1548` Abuse Elevation Control Mechanism | UAC Bypass via Windows Firewall Snap-In Hijack | medium | 61603 |
| `103275` | 11 | `T1548.002` T1548.002 | UAC Bypass via ICMLuaUtil | high | 61603 |
| `103276` | 11 | `T1548.002` T1548.002 | UAC Bypass Using IEInstal - Process | high | 61603 |
| `103277` | 11 | `T1548.002` T1548.002 | UAC Bypass Using MSConfig Token Modification - Process | high | 61603 |
| `103278` | 11 | `T1548.002` T1548.002 | UAC Bypass Using NTFS Reparse Point - Process | high | 61603 |
| `103279` | 11 | `T1548.002` T1548.002 | UAC Bypass Using NTFS Reparse Point - Process | high | 61603 |
| `103280` | 11 | `T1548.002` T1548.002 | UAC Bypass Using PkgMgr and DISM | high | 61603 |
| `103281` | 10 | `T1548.002` T1548.002 | Potential UAC Bypass Via Sdclt.EXE | medium | 61603 |
| `103282` | 11 | `T1548.002` T1548.002 | TrustedPath UAC Bypass Pattern | high | 61603 |
| `103283` | 11 | `T1548.002` T1548.002 | UAC Bypass Abusing Winsat Path Parsing - Process | high | 61603 |
| `103284` | 11 | `T1548.002` T1548.002 | UAC Bypass Using Windows Media Player - Process | high | 61603 |
| `103285` | 11 | `T1548.002` T1548.002 | UAC Bypass Using Windows Media Player - Process | high | 61603 |
| `103286` | 11 | `T1548.002` T1548.002 | Bypass UAC via WSReset.exe | high | 61603 |
| `103287` | 11 | `T1548.002` T1548.002 | UAC Bypass WSReset | high | 61603 |
| `103288` | 11 | `T1037.001` T1037.001 | Uncommon Userinit Child Process | high | 61603 |
| `103289` | 11 | `T1055` Process Injection | Suspicious Child Process Of Wermgr.EXE | high | 61603 |
| `103290` | 11 | `T1033` T1033 | Whoami.EXE Execution From Privileged Process | high | 61603 |
| `103291` | 11 | `T1033` T1033 | Security Privileges Enumeration Via Whoami.EXE | high | 61603 |
| `103292` | 11 | `T1546.003` T1546.003 | WMI Backdoor Exchange Transport Agent | high | 61603 |
| `103293` | 10 | `T1047` T1047 | Password Set to Never Expire via WMI | medium | 61603 |
| `103294` | 11 | `T1546.003` T1546.003 | New ActiveScriptEventConsumer Created Via Wmic.EXE | high | 61603 |
| `103295` | 11 | `T1574.001` T1574.001 | Xwizard.EXE Execution From Non-Default Location | high | 61603 |
| `103296` | 10 | `T1055.012` T1055.012 | Potential Process Hollowing Activity | medium | 61627 |
| `103297` | 11 | `T1548.002` T1548.002 | UAC Bypass Via Wsreset | high | 61615 |
| `103298` | 11 | `T1547.001` T1547.001 | Narrator's Feedback-Hub Persistence | high | 61615 |
| `103299` | 11 | `T1547.001` T1547.001 | Narrator's Feedback-Hub Persistence | high | 61615 |
| `103300` | 10 | `T1546.009` T1546.009 | New DLL Added to AppCertDlls Registry Key | medium | 61615 |
| `103301` | 10 | `T1546.009` T1546.009 | New DLL Added to AppCertDlls Registry Key | medium | 61615 |
| `103302` | 10 | `T1546.010` T1546.010 | New DLL Added to AppInit_DLLs Registry Key | medium | 61615 |
| `103303` | 11 | `T1547` Boot or Logon Autostart Execution | Registry Persistence Mechanisms in Recycle Bin | high | 61615 |
| `103304` | 11 | `T1547` Boot or Logon Autostart Execution | Registry Persistence Mechanisms in Recycle Bin | high | 61615 |
| `103305` | 11 | `T1547` Boot or Logon Autostart Execution | WINEKEY Registry Modification | high | 61615 |
| `103306` | 11 | `T1547.005` T1547.005 | Security Support Provider (SSP) Added to LSA Configuration | high | 61615 |
| `103307` | 11 | `T1546.008` T1546.008 | Sticky Key Like Backdoor Usage - Registry | high | 61615 |
| `103308` | 10 | `T1218` T1218 | Atbroker Registry Change | medium | 61615 |
| `103309` | 11 | `T1547.001` T1547.001 | Suspicious Run Key from Download | high | 61615 |
| `103310` | 12 | `T1547.008` T1547.008 | DLL Load via LSASS | high | 61615 |
| `103311` | 10 | `T1547.010` T1547.010 | Add Port Monitor Persistence in Registry | medium | 61615 |
| `103312` | 10 | `T1547.001` T1547.001 | Classes Autorun Keys Modification | medium | 61615 |
| `103313` | 10 | `T1547.001` T1547.001 | Common Autorun Keys Modification | medium | 61615 |
| `103314` | 10 | `T1547.001` T1547.001 | CurrentControlSet Autorun Keys Modification | medium | 61615 |
| `103315` | 10 | `T1547.001` T1547.001 | CurrentVersion Autorun Keys Modification | medium | 61615 |
| `103316` | 10 | `T1547.001` T1547.001 | CurrentVersion NT Autorun Keys Modification | medium | 61615 |
| `103317` | 10 | `T1547.001` T1547.001 | Internet Explorer Autorun Keys Modification | medium | 61615 |
| `103318` | 10 | `T1547.001` T1547.001 | Office Autorun Keys Modification | medium | 61615 |
| `103319` | 10 | `T1547.001` T1547.001 | Session Manager Autorun Keys Modification | medium | 61615 |
| `103320` | 10 | `T1547.001` T1547.001 | System Scripts Autorun Keys Modification | medium | 61615 |
| `103321` | 10 | `T1547.001` T1547.001 | WinSock2 Autorun Keys Modification | medium | 61615 |
| `103322` | 10 | `T1547.001` T1547.001 | Wow6432Node CurrentVersion Autorun Keys Modification | medium | 61615 |
| `103323` | 10 | `T1547.001` T1547.001 | Wow6432Node Classes Autorun Keys Modification | medium | 61615 |
| `103324` | 10 | `T1547.001` T1547.001 | Wow6432Node Windows NT CurrentVersion Autorun Keys Modification | medium | 61615 |
| `103325` | 11 | `T1548.002` T1548.002 | Bypass UAC Using DelegateExecute | high | 61615 |
| `103326` | 11 | `T1547.010` T1547.010 | Bypass UAC Using Event Viewer | high | 61615 |
| `103327` | 11 | `T1548.002` T1548.002 | Bypass UAC Using SilentCleanup Task | high | 61615 |
| `103328` | 11 | `T1547.010` T1547.010 | Default RDP Port Changed to Non Standard Port | high | 61615 |
| `103329` | 10 | `T1574` T1574 | Potential Registry Persistence Attempt Via DbgManagedDebugger | medium | 61615 |
| `103330` | 11 | `T1574.001` T1574.001 | DHCP Callout DLL Installation | high | 61615 |
| `103331` | 11 | `T1547.001` T1547.001 | Windows Event Log Access Tampering Via Registry | high | 61615 |
| `103332` | 11 | `T1547.001` T1547.001 | Windows Event Log Access Tampering Via Registry | high | 61615 |
| `103333` | 11 | `T1574.001` T1574.001 | New DNS ServerLevelPluginDll Installed | high | 61615 |
| `103334` | 11 | `T1546.007` T1546.007 | New Netsh Helper DLL Registered From A Suspicious Location | high | 61615 |
| `103335` | 10 | `T1546.007` T1546.007 | Potential Persistence Via Netsh Helper DLL - Registry | medium | 61615 |
| `103336` | 11 | `T1137` T1137 | Potential Persistence Via Outlook LoadMacroProviderOnBoot Setting | high | 61615 |
| `103337` | 11 | `T1137` T1137 | Outlook Macro Execution Without Warning Setting Enabled | high | 61615 |
| `103338` | 10 | `T1546.011` T1546.011 | Potential Persistence Via AppCompat RegisterAppRestart Layer | medium | 61615 |
| `103339` | 11 | `T1546.012` T1546.012 | Potential Persistence Via App Paths Default Property | high | 61615 |
| `103340` | 10 | `T1546.015` T1546.015 | Potential Persistence Using DebugPath | medium | 61615 |
| `103341` | 10 | `T1546.015` T1546.015 | Potential Persistence Using DebugPath | medium | 61615 |
| `103342` | 11 | `T1546.015` T1546.015 | COM Object Hijacking Via Modification Of Default System CLSID Defau... | high | 61615 |
| `103343` | 10 | `T1546.015` T1546.015 | Potential COM Object Hijacking Via TreatAs Subkey - Registry | medium | 61615 |
| `103344` | 11 | `T1546.015` T1546.015 | Potential PSFactoryBuffer COM Hijacking | high | 61615 |
| `103345` | 11 | `T1546.012` T1546.012 | Potential Persistence Via GlobalFlags | high | 61615 |
| `103346` | 11 | `T1546.012` T1546.012 | Potential Persistence Via GlobalFlags | high | 61615 |
| `103347` | 10 | `T1037.001` T1037.001 | Potential Persistence Via Logon Scripts - Registry | medium | 61615 |
| `103348` | 10 | `T1546.015` T1546.015 | Potential Persistence Via Scrobj.dll COM Hijacking | medium | 61615 |
| `103349` | 10 | `T1546.011` T1546.011 | Potential Persistence Via Shim Database Modification | medium | 61615 |
| `103350` | 11 | `T1546.011` T1546.011 | Suspicious Shim Database Patching Activity | high | 61615 |
| `103351` | 11 | `T1546.011` T1546.011 | Potential Persistence Via Shim Database In Uncommon Location | high | 61615 |
| `103352` | 10 | `T1547.001` T1547.001 | Suspicious PowerShell In Registry Run Keys | medium | 61615 |
| `103353` | 11 | `T1547.001` T1547.001 | Registry Persistence via Explorer Run Key | high | 61615 |
| `103354` | 11 | `T1547.001` T1547.001 | New RUN Key Pointing to Suspicious Folder | high | 61615 |
| `103355` | 10 | `T1548.002` T1548.002 | Suspicious Shell Open Command Registry Modification | medium | 61615 |
| `103356` | 11 | `T1053` Scheduled Task/Job | Scheduled TaskCache Change by Uncommon Program | high | 61615 |
| `103357` | 11 | `T1053.005` T1053.005 | Potential Registry Persistence Attempt Via Windows Telemetry | high | 61615 |
| `103358` | 10 | `T1546.015` T1546.015 | COM Hijacking via TreatAs | medium | 61615 |
| `103359` | 11 | `T1548.002` T1548.002 | UAC Bypass via Event Viewer | high | 61615 |
| `103360` | 11 | `T1548.002` T1548.002 | UAC Bypass via Sdclt | high | 61615 |
| `103361` | 11 | `T1548.002` T1548.002 | UAC Bypass via Sdclt | high | 61615 |
| `103362` | 11 | `T1548.002` T1548.002 | UAC Bypass Abusing Winsat Path Parsing - Registry | high | 61615 |
| `103363` | 11 | `T1548.002` T1548.002 | UAC Bypass Using Windows Media Player - Registry | high | 61615 |
| `103364` | 10 | `T1548.002` T1548.002 | UAC Disabled | medium | 61615 |
| `103365` | 10 | `T1548.002` T1548.002 | UAC Notification Disabled | medium | 61615 |
| `103366` | 10 | `T1548.002` T1548.002 | UAC Secure Desktop Prompt Disabled | medium | 61615 |
| `103367` | 11 | `T1547.001` T1547.001 | VBScript Payload Stored in Registry | high | 61615 |
| `103368` | 11 | `T1547.004` T1547.004 | Winlogon Notify Key Logon Persistence | high | 61615 |
| `103369` | 10 | `T1546.003` T1546.003 | WMI Event Subscription | medium | 61621 |
| `103370` | 11 | `T1047` T1047 | Suspicious Encoded Scripts in a WMI Consumer | high | 61621 |

### Defense Evasion (TA0005) — 35 rules

| Rule ID | Level | Technique | Description | Confidence | Parent SID |
|---------|-------|-----------|-------------|------------|------------|
| `104000` | 9 | `T1574.002` T1574.002 | DLL loaded from suspicious path | medium | 61609 |
| `104001` | 10 | `T1218.011` T1218.011 | Suspicious process: rundll32 | high | 61603 |
| `104002` | 9 | `T1218.011` T1218.011 | File created by rundll32 | medium | 61613 |
| `104003` | 9 | `T1574.002` T1574.002 | DLL loaded from suspicious path | medium | 61609 |
| `104004` | 10 | `T1197` T1197 | Suspicious process: bitsadmin | high | 61603 |
| `104005` | 10 | `T1218.010` T1218.010 | Suspicious process: regsvr32 | high | 61603 |
| `104006` | 10 | `T1218.010` T1218.010 | DLL sideloading by regsvr32 | high | 61609 |
| `104007` | 10 | `T1218.010` T1218.010 | Network connection by regsvr32 | high | 61605 |
| `104008` | 10 | `T1140` T1140 | Suspicious process: certutil | high | 61603 |
| `104009` | 9 | `T1140` T1140 | File created by certutil | medium | 61613 |
| `104010` | 10 | `T1218.004` T1218.004 | Suspicious process: installutil | high | 61603 |
| `104011` | 10 | `T1218.005` T1218.005 | Suspicious process: mshta | high | 61603 |
| `104012` | 10 | `T1218.005` T1218.005 | DLL sideloading by mshta | high | 61609 |
| `104013` | 10 | `T1218.005` T1218.005 | Network connection by mshta | high | 61605 |
| `104014` | 10 | `T1218.005` T1218.005 | Network connection by mshta | high | 61605 |
| `104015` | 10 | `T1218.003` T1218.003 | Suspicious process: cmstp | high | 61603 |
| `104016` | 10 | `T1218.011` T1218.011 | DLL sideloading by rundll32 | high | 61609 |
| `104017` | 10 | `T1218.011` T1218.011 | Network connection by rundll32 | high | 61605 |
| `104018` | 10 | `T1140` T1140 | Network connection by certutil | high | 61605 |
| `104019` | 9 | `T1574.002` T1574.002 | DLL loaded from suspicious path | medium | 61609 |
| `104020` | 10 | `T1218.011` T1218.011 | Network connection by rundll32 | high | 61605 |
| `104021` | 9 | `T1574.002` T1574.002 | DLL loaded from suspicious path | medium | 61609 |
| `104022` | 9 | `T1112` T1112 | Registry persistence via shell | medium | 61615 |
| `104023` | 9 | `T1112` T1112 | Registry persistence via shell | medium | 61614 |
| `104024` | 10 | `T1218.007` T1218.007 | DLL sideloading by msiexec | high | 61609 |
| `104025` | 10 | `T1218.011` T1218.011 | Network connection by rundll32 | high | 61605 |
| `104026` | 10 | `T1218.010` T1218.010 | Network connection by regsvr32 | high | 61605 |
| `104027` | 10 | `T1218.005` T1218.005 | Network connection by mshta | high | 61605 |
| `104028` | 10 | `T1218.005` T1218.005 | Network connection by mshta | high | 61605 |
| `104029` | 9 | `T1574.002` T1574.002 | DLL loaded from suspicious path | medium | 61609 |
| `104030` | 9 | `T1036` T1036 | Account renamed | medium | 60100 |
| `104031` | 9 | `T1562.001` T1562.001 | Suspicious PowerShell: set-mppreference -disablerealtimemonitoring | medium | 91801 |
| `104032` | 9 | `T1112` T1112 | Registry persistence via currentversion\explorer\shell | medium | 61614 |
| `104033` | 9 | `T1027` Obfuscated Files or Information | Suspicious PowerShell: invoke-obfuscation | medium | 91801 |
| `104034` | 10 | `T1218.004` T1218.004 | DLL sideloading by installutil | high | 61609 |

### Credential Access (TA0006) — 286 rules

| Rule ID | Level | Technique | Description | Confidence | Parent SID |
|---------|-------|-----------|-------------|------------|------------|
| `105000` | 11 | `T1003.002` T1003.002 | Suspicious command: reg save | medium | 61603 |
| `105001` | 12 | `T1003.001` T1003.001 | LSASS memory access | high | 61612 |
| `105002` | 12 | `T1003.001` T1003.001 | Suspicious process: procdump | high | 61603 |
| `105003` | 11 | `T1003.001` T1003.001 | Suspicious command: procdump | medium | 61603 |
| `105004` | 11 | `T1003.003` T1003.003 | Suspicious command: ntdsutil | medium | 61603 |
| `105005` | 9 | `T1110` Brute Force | Failed logon attempt | low | 60100 |
| `105006` | 12 | `T1003.001` T1003.001 | Remote thread injection into LSASS | high | 61610 |
| `105007` | 12 | `T1003.001` T1003.001 | LSASS memory access | high | 61612 |
| `105008` | 11 | `T1003.001` T1003.001 | Suspicious PowerShell: minidump | medium | 91801 |
| `105009` | 12 | `T1003.001` T1003.001 | LSASS memory access | high | 61612 |
| `105010` | 12 | `T1003.001` T1003.001 | LSASS memory access | high | 61612 |
| `105011` | 12 | `T1003.001` T1003.001 | LSASS memory access | high | 61612 |
| `105012` | 11 | `T1003.001` T1003.001 | File created by procdump | medium | 61613 |
| `105013` | 11 | `T1003.001` T1003.001 | Suspicious command: dumpert | medium | 61603 |
| `105014` | 11 | `T1003.001` T1003.001 | Suspicious command: comsvcs.dll | medium | 61603 |
| `105015` | 11 | `T1003.001` T1003.001 | Suspicious command: minidump | medium | 61603 |
| `105016` | 12 | `T1003.001` T1003.001 | LSASS memory access | high | 61612 |
| `105017` | 12 | `T1003.001` T1003.001 | LSASS memory access | high | 61612 |
| `105018` | 13 | `T1003` OS Credential Dumping | Suspicious service: mimikatz driver (mimidrv) | high | 60106 |
| `105019` | 13 | `T1003` OS Credential Dumping | PowerShell module: invoke-mimikatz | medium | 91801 |
| `105020` | 13 | `T1003.001` T1003.001 | PowerShell module: sekurlsa:: | medium | 91801 |
| `105021` | 13 | `T1003` OS Credential Dumping | Suspicious process: mimikatz | high | 61603 |
| `105022` | 11 | `T1003.001` T1003.001 | Suspicious PowerShell: comsvcs.dll | medium | 91801 |
| `105023` | 13 | `T1003` OS Credential Dumping | Suspicious PowerShell: invoke-mimikatz | medium | 91801 |
| `105024` | 12 | `T1003.006` T1003.006 | Active Directory Replication from Non Machine Account | high | 60100 |
| `105025` | 13 | `T1003.006` T1003.006 | Mimikatz DC Sync | high | 60100 |
| `105026` | 12 | `T1003.004` T1003.004 | DPAPI Domain Backup Key Extraction | high | 60100 |
| `105027` | 11 | `T1003.004` T1003.004 | DPAPI Domain Master Key Backup Attempt | medium | 60100 |
| `105028` | 12 | `T1003.002` T1003.002 | Possible Impacket SecretDump Remote Activity | high | 60100 |
| `105029` | 11 | `T1558.003` T1558.003 | Kerberoasting Activity - Initial Query | medium | 60100 |
| `105030` | 12 | `T1003.001` T1003.001 | LSASS Access From Non System Account | medium | 60100 |
| `105031` | 12 | `T1003.001` T1003.001 | Credential Dumping Tools Service Execution - Security | high | 60100 |
| `105032` | 12 | `T1003` OS Credential Dumping | WCE wceaux.dll Access | high | 60100 |
| `105033` | 12 | `T1187` T1187 | Possible PetitPotam Coerce Authentication Attempt | high | 60100 |
| `105034` | 12 | `T1187` T1187 | PetitPotam Suspicious Kerberos TGT Request | high | 60100 |
| `105035` | 11 | `T1207` T1207 | Possible DC Shadow Attack | medium | 60100 |
| `105036` | 11 | `T1207` T1207 | Possible DC Shadow Attack | medium | 60100 |
| `105037` | 12 | `T1558` Steal or Forge Kerberos Tickets | Replay Attack Detected | high | 60100 |
| `105038` | 11 | `T1003` OS Credential Dumping | File Access Of Signal Desktop Sensitive Data | medium | 60100 |
| `105039` | 12 | `T1212` T1212 | Kerberos Manipulation | high | 60100 |
| `105040` | 12 | `T1003.001` T1003.001 | Password Dumper Activity on LSASS | high | 60100 |
| `105041` | 12 | `T1003.001` T1003.001 | Potentially Suspicious AccessMask Requested From LSASS | medium | 60100 |
| `105042` | 12 | `T1003.001` T1003.001 | Potentially Suspicious AccessMask Requested From LSASS | medium | 60100 |
| `105043` | 11 | `T1558.003` T1558.003 | Suspicious Kerberos RC4 Ticket Encryption | medium | 60100 |
| `105044` | 12 | `T1528` T1528 | Suspicious Teams Application Related ObjectAcess Event | high | 60100 |
| `105045` | 12 | `T1003.002` T1003.002 | Transferring Files with Credential Data via Network Shares | medium | 60100 |
| `105046` | 12 | `T1558.003` T1558.003 | User Couldn't Call a Privileged Service 'LsaRegisterLogonProcess' | high | 60100 |
| `105047` | 12 | `T1003.002` T1003.002 | Critical Hive In Suspicious Location Access Bits Cleared | high | 60106 |
| `105048` | 11 | `T1003.002` T1003.002 | Crash Dump Created By Operating System | medium | 60106 |
| `105049` | 12 | `T1003.001` T1003.001 | Credential Dumping Tools Service Execution - System | high | 60106 |
| `105050` | 12 | `T1555.005` T1555.005 | Remote Thread Created In KeePass.EXE | high | 61610 |
| `105051` | 12 | - | Remote Thread Creation In Mstsc.Exe From Suspicious Location | high | 61610 |
| `105052` | 12 | `T1003.001` T1003.001 | Potential Credential Dumping Attempt Via PowerShell Remote Thread | high | 61610 |
| `105053` | 12 | `T1003.001` T1003.001 | Password Dumper Remote Thread in LSASS | high | 61610 |
| `105054` | 12 | `T1599.001` T1599.001 | WinDivert Driver Load | high | 61608 |
| `105055` | 12 | `T1599.001` T1599.001 | WinDivert Driver Load | high | 61608 |
| `105056` | 11 | `T1003` OS Credential Dumping | Credential Manager Access By Uncommon Applications | medium | 61613 |
| `105057` | 11 | `T1555.004` T1555.004 | Access To Windows Credential History File By Uncommon Applications | medium | 61613 |
| `105058` | 11 | `T1003` OS Credential Dumping | Access To Crypto Currency Wallets By Uncommon Applications | medium | 61613 |
| `105059` | 11 | `T1555.004` T1555.004 | Access To Windows DPAPI Master Keys By Uncommon Applications | medium | 61613 |
| `105060` | 11 | `T1552.006` T1552.006 | Access To Potentially Sensitive Sysvol Files By Uncommon Applications | medium | 61613 |
| `105061` | 11 | `T1528` T1528 | Microsoft Teams Sensitive File Access By Uncommon Applications | medium | 61613 |
| `105062` | 12 | `T1003.001` T1003.001 | Cred Dump Tools Dropped Files | high | 61613 |
| `105063` | 12 | `T1003.001` T1003.001 | Cred Dump Tools Dropped Files | high | 61613 |
| `105064` | 12 | `T1003.001` T1003.001 | HackTool - CrackMapExec File Indicators | high | 61613 |
| `105065` | 12 | `T1003.001` T1003.001 | HackTool - Dumpert Process Dumper Default File | high | 61613 |
| `105066` | 12 | `T1552.001` T1552.001 | HackTool - Typical HiveNightmare SAM File Export | high | 61613 |
| `105067` | 12 | `T1552.001` T1552.001 | HackTool - Typical HiveNightmare SAM File Export | high | 61613 |
| `105068` | 13 | `T1558` Steal or Forge Kerberos Tickets | HackTool - Mimikatz Kirbi File Creation | high | 61613 |
| `105069` | 12 | - | HackTool - NPPSpy Hacktool Usage | high | 61613 |
| `105070` | 12 | `T1003.002` T1003.002 | HackTool - QuarksPwDump Dump File | high | 61613 |
| `105071` | 12 | `T1003` OS Credential Dumping | HackTool - Potential Remote Credential Dumping Activity Via CrackMa... | high | 61613 |
| `105072` | 12 | `T1003.001` T1003.001 | HackTool - SafetyKatz Dump Indicator | high | 61613 |
| `105073` | 12 | `T1003.001` T1003.001 | HackTool - Impacket File Indicators | high | 61613 |
| `105074` | 12 | `T1003.001` T1003.001 | LSASS Process Memory Dump Files | high | 61613 |
| `105075` | 12 | `T1003.001` T1003.001 | LSASS Process Memory Dump Files | high | 61613 |
| `105076` | 12 | `T1003.001` T1003.001 | LSASS Process Memory Dump Files | high | 61613 |
| `105077` | 12 | `T1003.001` T1003.001 | LSASS Process Memory Dump Files | high | 61613 |
| `105078` | 12 | `T1003.001` T1003.001 | LSASS Process Memory Dump Files | high | 61613 |
| `105079` | 12 | `T1003.001` T1003.001 | LSASS Process Dump Artefact In CrashDumps Folder | high | 61613 |
| `105080` | 12 | `T1003.001` T1003.001 | WerFault LSASS Process Memory Dump | high | 61613 |
| `105081` | 12 | `T1003.003` T1003.003 | NTDS.DIT Creation By Uncommon Parent Process | high | 61613 |
| `105082` | 12 | `T1003.002` T1003.002 | NTDS.DIT Creation By Uncommon Process | high | 61613 |
| `105083` | 12 | `T1003.003` T1003.003 | NTDS Exfiltration Filename Patterns | high | 61613 |
| `105084` | 12 | `T1003.002` T1003.002 | Potential SAM Database Dump | high | 61613 |
| `105085` | 12 | `T1003.002` T1003.002 | Potential SAM Database Dump | high | 61613 |
| `105086` | 12 | `T1555` T1555 | DPAPI Backup Keys And Certificate Export Activity IOC | high | 61613 |
| `105087` | 12 | `T1003.001` T1003.001 | LSASS Process Memory Dump Creation Via Taskmgr.EXE | high | 61613 |
| `105088` | 12 | `T1003.001` T1003.001 | Suspicious Renamed Comsvcs DLL Loaded By Rundll32 | high | 61609 |
| `105089` | 11 | `T1056.002` T1056.002 | CredUI.DLL Loaded By Uncommon Process | medium | 61609 |
| `105090` | 12 | `T1003.001` T1003.001 | Suspicious Unsigned Dbghelp/Dbgcore DLL Loaded | high | 61609 |
| `105091` | 12 | `T1218` T1218 | Time Travel Debugging Utility Usage - Image | high | 61609 |
| `105092` | 12 | `T1003.001` T1003.001 | Unsigned Image Loaded Into LSASS Process | medium | 61609 |
| `105093` | 12 | `T1003` OS Credential Dumping | Suspicious Loading of Dbgcore/Dbghelp DLLs from Uncommon Location | high | 61609 |
| `105094` | 11 | `T1558` Steal or Forge Kerberos Tickets | Uncommon Outbound Kerberos Connection | medium | 61605 |
| `105095` | 13 | `T1003.001` T1003.001 | HackTool - Credential Dumping Tools Named Pipe Created | high | 61619 |
| `105096` | 12 | `T1003.003` T1003.003 | Suspicious Get-ADDBAccount Usage | high | 91801 |
| `105097` | 11 | `T1555.003` T1555.003 | Access to Browser Login Data | medium | 91801 |
| `105098` | 12 | `T1003.003` T1003.003 | Create Volume Shadow Copy with Powershell | high | 91801 |
| `105099` | 11 | `T1555` T1555 | Dump Credentials from Windows Credential Manager With PowerShell | medium | 91801 |
| `105100` | 11 | `T1555` T1555 | Dump Credentials from Windows Credential Manager With PowerShell | medium | 91801 |
| `105101` | 11 | `T1555` T1555 | Dump Credentials from Windows Credential Manager With PowerShell | medium | 91801 |
| `105102` | 11 | `T1555` T1555 | Enumerate Credentials from Windows Credential Manager With PowerShell | medium | 91801 |
| `105103` | 11 | `T1552.004` T1552.004 | Certificate Exported Via PowerShell - ScriptBlock | medium | 91801 |
| `105104` | 11 | `T1003.006` T1003.006 | Suspicious Get-ADReplAccount | medium | 91801 |
| `105105` | 12 | `T1003` OS Credential Dumping | HackTool - Rubeus Execution - ScriptBlock | high | 91801 |
| `105106` | 12 | `T1046` T1046 | HackTool - WinPwn Execution - ScriptBlock | high | 91801 |
| `105107` | 11 | `T1056.001` T1056.001 | Powershell Keylogging | medium | 91801 |
| `105108` | 11 | `T1056.001` T1056.001 | Powershell Keylogging | medium | 91801 |
| `105109` | 12 | `T1003` OS Credential Dumping | Live Memory Dump Using Powershell | high | 91801 |
| `105110` | 11 | `T1040` T1040 | Potential Packet Capture Activity Via Start-NetEventSession - Scrip... | medium | 91801 |
| `105111` | 13 | `T1003` OS Credential Dumping | Potential Invoke-Mimikatz PowerShell Script | high | 91801 |
| `105112` | 13 | `T1003` OS Credential Dumping | Potential Invoke-Mimikatz PowerShell Script | high | 91801 |
| `105113` | 13 | `T1003` OS Credential Dumping | Potential Invoke-Mimikatz PowerShell Script | high | 91801 |
| `105114` | 12 | `T1059.001` T1059.001 | PowerShell Credential Prompt | high | 91801 |
| `105115` | 12 | `T1558.003` T1558.003 | Suspicious Kerberos Ticket Request via PowerShell Script - ScriptBlock | high | 91801 |
| `105116` | 11 | `T1552.001` T1552.001 | Extracting Information with PowerShell | medium | 91801 |
| `105117` | 12 | `T1003.001` T1003.001 | PowerShell Get-Process LSASS in ScriptBlock | high | 91801 |
| `105118` | 12 | - | Veeam Backup Servers Credential Dumping Script Execution | high | 91801 |
| `105119` | 13 | `T1003.001` T1003.001 | HackTool - Generic Process Access | high | 61612 |
| `105120` | 12 | `T1003.001` T1003.001 | HackTool - Generic Process Access | high | 61612 |
| `105121` | 12 | `T1003.001` T1003.001 | Lsass Memory Dump via Comsvcs DLL | high | 61612 |
| `105122` | 12 | `T1003.001` T1003.001 | LSASS Memory Access by Tool With Dump Keyword In Name | high | 61612 |
| `105123` | 12 | `T1003.001` T1003.001 | Potential Credential Dumping Activity Via LSASS | medium | 61612 |
| `105124` | 12 | `T1003.001` T1003.001 | Credential Dumping Activity By Python Based Tool | high | 61612 |
| `105125` | 12 | `T1003.001` T1003.001 | Remote LSASS Process Access Through Windows Remote Management | high | 61612 |
| `105126` | 12 | `T1003.001` T1003.001 | Suspicious LSASS Access Via MalSecLogon | high | 61612 |
| `105127` | 12 | `T1003.001` T1003.001 | Potentially Suspicious GrantedAccess Flags On LSASS | medium | 61612 |
| `105128` | 12 | `T1003.001` T1003.001 | Credential Dumping Attempt Via WerFault | high | 61612 |
| `105129` | 12 | `T1003.001` T1003.001 | LSASS Access From Potentially White-Listed Processes | high | 61612 |
| `105130` | 12 | `T1003.001` T1003.001 | Suspicious Process Access to LSASS with Dbgcore/Dbghelp DLLs | high | 61612 |
| `105131` | 12 | `T1185` T1185 | Potential Data Stealing Via Chromium Headless Debugging | high | 61603 |
| `105132` | 11 | `T1185` T1185 | Browser Started with Remote Debugging | medium | 61603 |
| `105133` | 11 | `T1185` T1185 | Browser Started with Remote Debugging | medium | 61603 |
| `105134` | 12 | `T1218.011` T1218.011 | Process Access via TrolleyExpress Exclusion | high | 61603 |
| `105135` | 12 | - | Copy .DMP/.DUMP Files From Remote Share Via Cmd.EXE | high | 61603 |
| `105136` | 12 | `T1003.002` T1003.002 | VolumeShadowCopy Symlink Creation Via Mklink | high | 61603 |
| `105137` | 11 | `T1003.005` T1003.005 | New Generic Credentials Added Via Cmdkey.EXE | medium | 61603 |
| `105138` | 12 | `T1003.005` T1003.005 | Potential Reconnaissance For Cached Credentials Via Cmdkey.EXE | high | 61603 |
| `105139` | 12 | `T1036` T1036 | CreateDump Process Dump | high | 61603 |
| `105140` | 12 | `T1003.001` T1003.001 | Potential Windows Defender AV Bypass Via Dump64.EXE Rename | high | 61603 |
| `105141` | 11 | `T1036` T1036 | DumpMinitool Execution | medium | 61603 |
| `105142` | 12 | `T1036` T1036 | Suspicious DumpMinitool Execution | high | 61603 |
| `105143` | 11 | `T1003` OS Credential Dumping | Esentutl Gather Credentials | medium | 61603 |
| `105144` | 12 | `T1003.002` T1003.002 | Copying Sensitive Files with Credential Data | high | 61603 |
| `105145` | 11 | `T1218` T1218 | Remote File Download Via Findstr.EXE | medium | 61603 |
| `105146` | 12 | `T1552.006` T1552.006 | Findstr GPP Passwords | high | 61603 |
| `105147` | 12 | `T1552.006` T1552.006 | LSASS Process Reconnaissance Via Findstr.EXE | high | 61603 |
| `105148` | 11 | `T1552.006` T1552.006 | Permission Misconfiguration Reconnaissance Via Findstr.EXE | medium | 61603 |
| `105149` | 12 | `T1003.001` T1003.001 | HackTool - CrackMapExec Process Patterns | high | 61603 |
| `105150` | 12 | `T1003.001` T1003.001 | HackTool - CrackMapExec Process Patterns | high | 61603 |
| `105151` | 12 | `T1003.001` T1003.001 | HackTool - CrackMapExec Process Patterns | high | 61603 |
| `105152` | 12 | `T1003.001` T1003.001 | HackTool - CreateMiniDump Execution | high | 61603 |
| `105153` | 12 | `T1003.001` T1003.001 | HackTool - CreateMiniDump Execution | high | 61603 |
| `105154` | 12 | `T1003.001` T1003.001 | HackTool - Doppelanger LSASS Dumper Execution | high | 61603 |
| `105155` | 12 | `T1003.001` T1003.001 | HackTool - Doppelanger LSASS Dumper Execution | high | 61603 |
| `105156` | 12 | `T1003.001` T1003.001 | HackTool - Dumpert Process Dumper Execution | high | 61603 |
| `105157` | 12 | `T1003.001` T1003.001 | HackTool - Dumpert Process Dumper Execution | high | 61603 |
| `105158` | 12 | `T1588.002` T1588.002 | Hacktool Execution - Imphash | high | 61603 |
| `105159` | 12 | `T1588.002` T1588.002 | Hacktool Execution - PE Metadata | high | 61603 |
| `105160` | 12 | `T1003.001` T1003.001 | HackTool - HandleKatz LSASS Dumper Execution | high | 61603 |
| `105161` | 12 | `T1003.001` T1003.001 | HackTool - HandleKatz LSASS Dumper Execution | high | 61603 |
| `105162` | 12 | `T1003.001` T1003.001 | HackTool - HandleKatz LSASS Dumper Execution | high | 61603 |
| `105163` | 12 | `T1110.002` T1110.002 | HackTool - Hashcat Password Cracker Execution | high | 61603 |
| `105164` | 12 | `T1110.002` T1110.002 | HackTool - Hashcat Password Cracker Execution | high | 61603 |
| `105165` | 12 | `T1110` Brute Force | HackTool - Hydra Password Bruteforce Execution | high | 61603 |
| `105166` | 12 | `T1003.001` T1003.001 | HackTool - Inveigh Execution | high | 61603 |
| `105167` | 12 | `T1003.001` T1003.001 | HackTool - Inveigh Execution | high | 61603 |
| `105168` | 12 | `T1003.001` T1003.001 | HackTool - Inveigh Execution | high | 61603 |
| `105169` | 12 | `T1003.001` T1003.001 | HackTool - Inveigh Execution | high | 61603 |
| `105170` | 12 | `T1558.003` T1558.003 | HackTool - KrbRelay Execution | high | 61603 |
| `105171` | 12 | `T1558.003` T1558.003 | HackTool - KrbRelay Execution | high | 61603 |
| `105172` | 12 | `T1558.003` T1558.003 | HackTool - KrbRelay Execution | high | 61603 |
| `105173` | 12 | `T1558.003` T1558.003 | HackTool - KrbRelay Execution | high | 61603 |
| `105174` | 12 | `T1558.003` T1558.003 | HackTool - KrbRelay Execution | high | 61603 |
| `105175` | 12 | `T1558.003` T1558.003 | HackTool - RemoteKrbRelay Execution | high | 61603 |
| `105176` | 12 | `T1558.003` T1558.003 | HackTool - KrbRelayUp Execution | high | 61603 |
| `105177` | 12 | `T1558.003` T1558.003 | HackTool - KrbRelayUp Execution | high | 61603 |
| `105178` | 12 | `T1558.003` T1558.003 | HackTool - KrbRelayUp Execution | high | 61603 |
| `105179` | 12 | `T1558.003` T1558.003 | HackTool - KrbRelayUp Execution | high | 61603 |
| `105180` | 12 | `T1558.003` T1558.003 | HackTool - KrbRelayUp Execution | high | 61603 |
| `105181` | 11 | - | HackTool - LaZagne Execution | medium | 61603 |
| `105182` | 11 | - | HackTool - LaZagne Execution | medium | 61603 |
| `105183` | 13 | `T1003.001` T1003.001 | HackTool - Mimikatz Execution | high | 61603 |
| `105184` | 13 | `T1003.001` T1003.001 | HackTool - Mimikatz Execution | high | 61603 |
| `105185` | 13 | `T1003.001` T1003.001 | HackTool - Mimikatz Execution | high | 61603 |
| `105186` | 12 | `T1003.002` T1003.002 | HackTool - Pypykatz Credentials Dumping Activity | high | 61603 |
| `105187` | 12 | `T1003.002` T1003.002 | HackTool - Quarks PwDump Execution | high | 61603 |
| `105188` | 12 | `T1003.002` T1003.002 | HackTool - Quarks PwDump Execution | high | 61603 |
| `105189` | 12 | `T1003` OS Credential Dumping | HackTool - Rubeus Execution | high | 61603 |
| `105190` | 12 | `T1003` OS Credential Dumping | HackTool - Rubeus Execution | high | 61603 |
| `105191` | 12 | `T1003` OS Credential Dumping | HackTool - Rubeus Execution | high | 61603 |
| `105192` | 12 | `T1003` OS Credential Dumping | HackTool - Rubeus Execution | high | 61603 |
| `105193` | 12 | `T1003.001` T1003.001 | HackTool - SafetyKatz Execution | high | 61603 |
| `105194` | 12 | `T1003.001` T1003.001 | HackTool - SafetyKatz Execution | high | 61603 |
| `105195` | 12 | `T1003.001` T1003.001 | HackTool - SafetyKatz Execution | high | 61603 |
| `105196` | 12 | `T1555` T1555 | HackTool - SecurityXploded Execution | high | 61603 |
| `105197` | 12 | `T1555` T1555 | HackTool - SecurityXploded Execution | high | 61603 |
| `105198` | 12 | `T1555` T1555 | HackTool - SecurityXploded Execution | high | 61603 |
| `105199` | 12 | `T1003.001` T1003.001 | HackTool - Windows Credential Editor (WCE) Execution | high | 61603 |
| `105200` | 12 | `T1003.001` T1003.001 | HackTool - Windows Credential Editor (WCE) Execution | high | 61603 |
| `105201` | 12 | `T1046` T1046 | HackTool - WinPwn Execution | high | 61603 |
| `105202` | 12 | `T1003.001` T1003.001 | HackTool - WSASS Execution | high | 61603 |
| `105203` | 12 | `T1003.001` T1003.001 | HackTool - WSASS Execution | high | 61603 |
| `105204` | 12 | `T1003.001` T1003.001 | HackTool - WSASS Execution | high | 61603 |
| `105205` | 12 | `T1036` T1036 | HackTool - XORDump Execution | high | 61603 |
| `105206` | 12 | `T1036` T1036 | HackTool - XORDump Execution | high | 61603 |
| `105207` | 12 | `T1003` OS Credential Dumping | Microsoft IIS Service Account Password Dumped | high | 61603 |
| `105208` | 12 | `T1003` OS Credential Dumping | Microsoft IIS Connection Strings Decryption | high | 61603 |
| `105209` | 11 | `T1003.001` T1003.001 | Dumping Process via Sqldumper.exe | medium | 61603 |
| `105210` | 12 | `T1218` T1218 | Time Travel Debugging Utility Usage | high | 61603 |
| `105211` | 12 | `T1003` OS Credential Dumping | Potential Credential Dumping Via LSASS Process Clone | high | 61603 |
| `105212` | 11 | `T1003.003` T1003.003 | Suspicious Usage Of Active Directory Diagnostic Tool (ntdsutil.exe) | medium | 61603 |
| `105213` | 11 | `T1003.003` T1003.003 | Invocation of Active Directory Diagnostic Tool (ntdsutil.exe) | medium | 61603 |
| `105214` | 11 | `T1552.001` T1552.001 | Potential PowerShell Console History Access Attempt via History File | medium | 61603 |
| `105215` | 11 | `T1552.004` T1552.004 | Certificate Exported Via PowerShell | medium | 61603 |
| `105216` | 12 | `T1552.004` T1552.004 | PowerShell Get-Process LSASS | high | 61603 |
| `105217` | 12 | `T1558.003` T1558.003 | Suspicious Kerberos Ticket Request via CLI | high | 61603 |
| `105218` | 12 | `T1003.002` T1003.002 | PowerShell SAM Copy | high | 61603 |
| `105219` | 12 | `T1003.003` T1003.003 | Sensitive File Dump Via Print.EXE | high | 61603 |
| `105220` | 12 | `T1003.003` T1003.003 | PUA - DIT Snapshot Viewer | high | 61603 |
| `105221` | 12 | `T1003.003` T1003.003 | PUA - DIT Snapshot Viewer | high | 61603 |
| `105222` | 12 | `T1003` OS Credential Dumping | PUA - Memory Dump Mount Via MemProcFS | high | 61603 |
| `105223` | 11 | `T1056.002` T1056.002 | PUA - Mouse Lock Execution | medium | 61603 |
| `105224` | 11 | `T1056.002` T1056.002 | PUA - Mouse Lock Execution | medium | 61603 |
| `105225` | 11 | `T1056.002` T1056.002 | PUA - Mouse Lock Execution | medium | 61603 |
| `105226` | 11 | `T1555.003` T1555.003 | PUA - WebBrowserPassView Execution | medium | 61603 |
| `105227` | 11 | `T1555.003` T1555.003 | PUA - WebBrowserPassView Execution | medium | 61603 |
| `105228` | 12 | `T1003.001` T1003.001 | Process Memory Dump via RdrLeakDiag.EXE | high | 61603 |
| `105229` | 12 | `T1003.002` T1003.002 | Dumping of Sensitive Hives Via Reg.EXE | high | 61603 |
| `105230` | 11 | `T1552.002` T1552.002 | Enumeration for Credentials in Registry | medium | 61603 |
| `105231` | 11 | `T1552.002` T1552.002 | Enumeration for 3rd Party Creds From CLI | medium | 61603 |
| `105232` | 12 | `T1552.002` T1552.002 | Registry Export of Third-Party Credentials | high | 61603 |
| `105233` | 12 | `T1003` OS Credential Dumping | Potential Credential Dumping Attempt Using New NetworkProvider - CLI | high | 61603 |
| `105234` | 12 | `T1528` T1528 | Renamed BrowserCore.EXE Execution | high | 61603 |
| `105235` | 12 | `T1036` T1036 | Renamed CreateDump Utility Execution | high | 61603 |
| `105236` | 12 | `T1036` T1036 | Renamed CreateDump Utility Execution | high | 61603 |
| `105237` | 12 | `T1036` T1036 | Renamed CreateDump Utility Execution | high | 61603 |
| `105238` | 11 | `T1003` OS Credential Dumping | Capture Credentials with Rpcping.exe | medium | 61603 |
| `105239` | 12 | `T1555.004` T1555.004 | Suspicious Key Manager Access | high | 61603 |
| `105240` | 12 | `T1036` T1036 | Process Memory Dump Via Comsvcs.DLL | high | 61603 |
| `105241` | 12 | `T1555` T1555 | Suspicious Serv-U Process Pattern | high | 61603 |
| `105242` | 11 | `T1558.003` T1558.003 | Potential SPN Enumeration Via Setspn.EXE | medium | 61603 |
| `105243` | 12 | `T1539` T1539 | SQLite Chromium Profile Data DB Access | high | 61603 |
| `105244` | 12 | `T1539` T1539 | SQLite Firefox Profile Data DB Access | high | 61603 |
| `105245` | 11 | `T1555.003` T1555.003 | Potential Browser Data Stealing | medium | 61603 |
| `105246` | 11 | `T1552` T1552 | Potentially Suspicious EventLog Recon Activity Using Log Query Util... | medium | 61603 |
| `105247` | 11 | `T1552` T1552 | Potentially Suspicious EventLog Recon Activity Using Log Query Util... | medium | 61603 |
| `105248` | 11 | `T1528` T1528 | Potentially Suspicious JWT Token Search Via CLI | medium | 61603 |
| `105249` | 12 | `T1003.001` T1003.001 | LSASS Dump Keyword In CommandLine | high | 61603 |
| `105250` | 12 | `T1003.001` T1003.001 | LSASS Dump Keyword In CommandLine | high | 61603 |
| `105251` | 12 | `T1003.001` T1003.001 | LSASS Dump Keyword In CommandLine | high | 61603 |
| `105252` | 12 | `T1003.001` T1003.001 | LSASS Dump Keyword In CommandLine | high | 61603 |
| `105253` | 11 | `T1040` T1040 | Potential Network Sniffing Activity Using Network Tools | medium | 61603 |
| `105254` | 11 | `T1040` T1040 | Potential Network Sniffing Activity Using Network Tools | medium | 61603 |
| `105255` | 12 | `T1003.003` T1003.003 | Suspicious Process Patterns NTDS.DIT Exfil | high | 61603 |
| `105256` | 12 | `T1003.003` T1003.003 | Suspicious Process Patterns NTDS.DIT Exfil | high | 61603 |
| `105257` | 12 | `T1003.003` T1003.003 | Suspicious Process Patterns NTDS.DIT Exfil | high | 61603 |
| `105258` | 12 | `T1003.003` T1003.003 | Suspicious Process Patterns NTDS.DIT Exfil | high | 61603 |
| `105259` | 12 | `T1003.003` T1003.003 | Suspicious Process Patterns NTDS.DIT Exfil | high | 61603 |
| `105260` | 12 | `T1003.003` T1003.003 | Suspicious Process Patterns NTDS.DIT Exfil | high | 61603 |
| `105261` | 12 | `T1003.003` T1003.003 | Suspicious Process Patterns NTDS.DIT Exfil | high | 61603 |
| `105262` | 11 | `T1552.004` T1552.004 | Private Keys Reconnaissance Via CommandLine Tools | medium | 61603 |
| `105263` | 12 | `T1552` T1552 | Script Interpreter Spawning Credential Scanner - Windows | high | 61603 |
| `105264` | 11 | `T1003` OS Credential Dumping | Shadow Copies Creation Using Operating Systems Utilities | medium | 61603 |
| `105265` | 12 | `T1134` Access Token Manipulation | Suspicious SYSTEM User Process Creation | high | 61603 |
| `105266` | 11 | `T1552.006` T1552.006 | Suspicious SYSVOL Domain Group Policy Access | medium | 61603 |
| `105267` | 11 | `T1036` T1036 | Procdump Execution | medium | 61603 |
| `105268` | 12 | `T1036` T1036 | Potential SysInternals ProcDump Evasion | high | 61603 |
| `105269` | 12 | `T1036` T1036 | Potential SysInternals ProcDump Evasion | high | 61603 |
| `105270` | 12 | `T1036` T1036 | Potential SysInternals ProcDump Evasion | high | 61603 |
| `105271` | 12 | `T1036` T1036 | Potential LSASS Process Dump Via Procdump | high | 61603 |
| `105272` | 11 | `T1003` OS Credential Dumping | Loaded Module Enumeration Via Tasklist.EXE | medium | 61603 |
| `105273` | 11 | `T1528` T1528 | Potentially Suspicious Command Targeting Teams Sensitive Files | medium | 61603 |
| `105274` | 11 | `T1555.004` T1555.004 | Windows Credential Manager Access via VaultCmd | medium | 61603 |
| `105275` | 12 | `T1003.003` T1003.003 | Sensitive File Dump Via Wbadmin.EXE | high | 61603 |
| `105276` | 12 | `T1003.003` T1003.003 | Sensitive File Recovery From Backup Via Wbadmin.EXE | high | 61603 |
| `105277` | 12 | `T1003.001` T1003.001 | Potential Credential Dumping Via WER | high | 61603 |
| `105278` | 12 | `T1685` T1685 | PPL Tampering Via WerFaultSecure | high | 61603 |
| `105279` | 12 | `T1003.002` T1003.002 | Esentutl Volume Shadow Copy Service Keys | high | 61615 |
| `105280` | 12 | `T1003.001` T1003.001 | Windows Credential Editor Registry | high | 61615 |
| `105281` | 12 | `T1003.001` T1003.001 | Potential Credential Dumping Via LSASS SilentProcessExit Technique | high | 61615 |
| `105282` | 12 | `T1556` T1556 | Directory Service Restore Mode(DSRM) Registry Value Tampering | high | 61615 |
| `105283` | 12 | `T1003.001` T1003.001 | Lsass Full Dump Request Via DumpType Registry Settings | high | 61615 |
| `105284` | 11 | `T1003` OS Credential Dumping | Potential Credential Dumping Attempt Using New NetworkProvider - REG | medium | 61615 |
| `105285` | 12 | `T1003` OS Credential Dumping | Potentially Suspicious ODBC Driver Registered | high | 61615 |

### Discovery (TA0007) — 136 rules

| Rule ID | Level | Technique | Description | Confidence | Parent SID |
|---------|-------|-----------|-------------|------------|------------|
| `106000` | 6 | `T1087.001` T1087.001 | Suspicious command: net user | medium | 61603 |
| `106001` | 6 | `T1012` T1012 | Azure AD Health Monitoring Agent Registry Keys Access | medium | 60100 |
| `106002` | 6 | `T1012` T1012 | Azure AD Health Service Agents Registry Keys Access | medium | 60100 |
| `106003` | 7 | `T1087.002` T1087.002 | AD Privileged Users or Groups Reconnaissance | high | 60100 |
| `106004` | 6 | `T1087.002` T1087.002 | Potential AD User Enumeration From Non-Machine Account | medium | 60100 |
| `106005` | 7 | `T1087` Account Discovery | Hacktool Ruler | high | 60100 |
| `106006` | 6 | `T1201` T1201 | Password Policy Enumerated | medium | 60100 |
| `106007` | 6 | `T1040` T1040 | Windows Pcap Drivers | medium | 60100 |
| `106008` | 7 | `T1012` T1012 | SAM Registry Hive Handle Request | high | 60100 |
| `106009` | 6 | `T1010` T1010 | SCM Database Handle Failure | medium | 60100 |
| `106010` | 7 | `T1087.002` T1087.002 | Reconnaissance Activity | high | 60100 |
| `106011` | 7 | `T1012` T1012 | SysKey Registry Keys Access | high | 60100 |
| `106012` | 6 | `T1046` T1046 | Advanced IP Scanner - File Event | medium | 61613 |
| `106013` | 11 | `T1087.001` T1087.001 | BloodHound Collection Files | high | 61613 |
| `106014` | 6 | - | GatherNetworkInfo.VBS Reconnaissance Script Output | medium | 61613 |
| `106015` | 6 | `T1087.002` T1087.002 | ADExplorer Writing Complete AD Snapshot Into .dat File | medium | 61613 |
| `106016` | 6 | `T1087` Account Discovery | Uncommon Connection to Active Directory Web Services | medium | 61605 |
| `106017` | 6 | `T1016` T1016 | Suspicious Network Connection to IP Lookup Service APIs | medium | 61605 |
| `106018` | 6 | `T1046` T1046 | Python Initiated Connection | medium | 61605 |
| `106019` | 6 | - | Potential Active Directory Enumeration Using AD Module - PsModule | medium | 91801 |
| `106020` | 6 | - | Potential Active Directory Enumeration Using AD Module - PsScript | medium | 91801 |
| `106021` | 6 | - | Potential Active Directory Enumeration Using AD Module - PsScript | medium | 91801 |
| `106022` | 7 | `T1059.001` T1059.001 | PowerShell ADRecon Execution | high | 91801 |
| `106023` | 6 | `T1033` T1033 | Get-ADUser Enumeration Using UserAccountControl Flags | medium | 91801 |
| `106024` | 6 | `T1033` T1033 | Computer Discovery And Export Via Get-ADComputer Cmdlet - PowerShell | medium | 91801 |
| `106025` | 6 | `T1497.001` T1497.001 | Powershell Detect Virtualization Environment | medium | 91801 |
| `106026` | 6 | `T1018` T1018 | DirectorySearcher Powershell Exploitation | medium | 91801 |
| `106027` | 6 | `T1518.001` T1518.001 | Security Software Discovery Via Powershell Script | medium | 91801 |
| `106028` | 6 | - | PowerShell Hotfix Enumeration | medium | 91801 |
| `106029` | 6 | `T1018` T1018 | Potential Unconstrained Delegation Discovery Via Get-ADComputer - S... | medium | 91801 |
| `106030` | 6 | `T1083` File and Directory Discovery | Powershell Sensitive File Discovery | medium | 91801 |
| `106031` | 6 | `T1518` T1518 | Detected Windows Software Discovery - PowerShell | medium | 91801 |
| `106032` | 6 | `T1083` File and Directory Discovery | Powershell Directory Enumeration | medium | 91801 |
| `106033` | 6 | `T1033` T1033 | User Discovery And Export Via Get-ADUser Cmdlet - PowerShell | medium | 91801 |
| `106034` | 6 | `T1614.001` T1614.001 | Console CodePage Lookup Via CHCP | medium | 61603 |
| `106035` | 6 | - | Potential Discovery Activity Via Dnscmd.EXE | medium | 61603 |
| `106036` | 7 | - | Potential Recon Activity Using DriverQuery.EXE | high | 61603 |
| `106037` | 6 | - | DriverQuery.EXE Execution | medium | 61603 |
| `106038` | 6 | `T1482` T1482 | Domain Trust Discovery Via Dsquery | medium | 61603 |
| `106039` | 7 | `T1082` System Information Discovery | Suspicious Kernel Dump Using Dtrace | high | 61603 |
| `106040` | 7 | `T1082` System Information Discovery | Suspicious Kernel Dump Using Dtrace | high | 61603 |
| `106041` | 7 | `T1135` T1135 | File Explorer Folder Opened Using Explorer Folder Shortcut Via Shell | high | 61603 |
| `106042` | 6 | `T1057` T1057 | Recon Command Output Piped To Findstr.EXE | medium | 61603 |
| `106043` | 6 | `T1518.001` T1518.001 | Security Tools Keyword Lookup Via Findstr.EXE | medium | 61603 |
| `106044` | 7 | `T1518.001` T1518.001 | Sysmon Discovery Via Default Driver Altitude Using Findstr.EXE | high | 61603 |
| `106045` | 6 | `T1615` T1615 | Gpresult Display Group Policy Information | medium | 61603 |
| `106046` | 11 | `T1087.001` T1087.001 | HackTool - Bloodhound/Sharphound Execution | high | 61603 |
| `106047` | 11 | `T1087.001` T1087.001 | HackTool - Bloodhound/Sharphound Execution | high | 61603 |
| `106048` | 11 | `T1087.001` T1087.001 | HackTool - Bloodhound/Sharphound Execution | high | 61603 |
| `106049` | 11 | `T1087.001` T1087.001 | HackTool - Bloodhound/Sharphound Execution | high | 61603 |
| `106050` | 11 | `T1087.001` T1087.001 | HackTool - Bloodhound/Sharphound Execution | high | 61603 |
| `106051` | 11 | `T1087.001` T1087.001 | HackTool - Bloodhound/Sharphound Execution | high | 61603 |
| `106052` | 11 | `T1087.001` T1087.001 | HackTool - Bloodhound/Sharphound Execution | high | 61603 |
| `106053` | 7 | `T1649` T1649 | HackTool - Certify Execution | high | 61603 |
| `106054` | 11 | `T1649` T1649 | HackTool - Certipy Execution | high | 61603 |
| `106055` | 7 | `T1018` T1018 | HackTool - NetExec Execution | high | 61603 |
| `106056` | 6 | - | HackTool - SharpLDAPmonitor Execution | medium | 61603 |
| `106057` | 6 | - | HackTool - SharpLDAPmonitor Execution | medium | 61603 |
| `106058` | 6 | - | HackTool - SharpLDAPmonitor Execution | medium | 61603 |
| `106059` | 7 | `T1033` T1033 | HackTool - SharpLdapWhoami Execution | high | 61603 |
| `106060` | 7 | `T1033` T1033 | HackTool - SharpLdapWhoami Execution | high | 61603 |
| `106061` | 7 | `T1033` T1033 | HackTool - SharpLdapWhoami Execution | high | 61603 |
| `106062` | 7 | `T1033` T1033 | HackTool - SharpLdapWhoami Execution | high | 61603 |
| `106063` | 7 | `T1049` T1049 | HackTool - SharpView Execution | high | 61603 |
| `106064` | 7 | `T1049` T1049 | HackTool - SharpView Execution | high | 61603 |
| `106065` | 7 | `T1049` T1049 | HackTool - SharpView Execution | high | 61603 |
| `106066` | 7 | `T1087` Account Discovery | HackTool - SOAPHound Execution | high | 61603 |
| `106067` | 7 | `T1482` T1482 | HackTool - TruffleSnout Execution | high | 61603 |
| `106068` | 7 | `T1482` T1482 | HackTool - TruffleSnout Execution | high | 61603 |
| `106069` | 6 | `T1615` T1615 | Potential Reconnaissance Activity Via GatherNetworkInfo.VBS | medium | 61603 |
| `106070` | 6 | `T1087.001` T1087.001 | Suspicious Group And Account Reconnaissance Activity Using Net.EXE | medium | 61603 |
| `106071` | 6 | `T1040` T1040 | New Network Trace Capture Started Via Netsh.EXE | medium | 61603 |
| `106072` | 6 | `T1040` T1040 | Harvesting Of Wifi Credentials Via Netsh.EXE | medium | 61603 |
| `106073` | 6 | `T1016` T1016 | Potential Recon Activity Via Nltest.EXE | medium | 61603 |
| `106074` | 7 | `T1087` Account Discovery | Network Reconnaissance Activity | high | 61603 |
| `106075` | 6 | `T1040` T1040 | PktMon.EXE Execution | medium | 61603 |
| `106076` | 6 | `T1040` T1040 | PktMon.EXE Execution | medium | 61603 |
| `106077` | 6 | - | Potential Active Directory Enumeration Using AD Module - ProcCreation | medium | 61603 |
| `106078` | 6 | `T1033` T1033 | Computer Discovery And Export Via Get-ADComputer Cmdlet | medium | 61603 |
| `106079` | 6 | `T1087.001` T1087.001 | Suspicious Reconnaissance Activity Using Get-LocalGroupMember Cmdlet | medium | 61603 |
| `106080` | 6 | `T1033` T1033 | User Discovery And Export Via Get-ADUser Cmdlet | medium | 61603 |
| `106081` | 7 | `T1087.002` T1087.002 | PUA - Suspicious ActiveDirectory Enumeration Via AdFind.EXE | high | 61603 |
| `106082` | 7 | `T1087.002` T1087.002 | PUA - Suspicious ActiveDirectory Enumeration Via AdFind.EXE | high | 61603 |
| `106083` | 7 | `T1087.002` T1087.002 | PUA - Suspicious ActiveDirectory Enumeration Via AdFind.EXE | high | 61603 |
| `106084` | 6 | `T1087.002` T1087.002 | PUA - AdFind.EXE Execution | medium | 61603 |
| `106085` | 6 | `T1087.002` T1087.002 | PUA - AdFind.EXE Execution | medium | 61603 |
| `106086` | 6 | `T1087.002` T1087.002 | PUA - AdFind.EXE Execution | medium | 61603 |
| `106087` | 7 | `T1018` T1018 | PUA - AdFind Suspicious Execution | high | 61603 |
| `106088` | 6 | `T1046` T1046 | PUA - Advanced IP Scanner Execution | medium | 61603 |
| `106089` | 6 | `T1046` T1046 | PUA - Advanced IP Scanner Execution | medium | 61603 |
| `106090` | 6 | `T1046` T1046 | PUA - Advanced IP Scanner Execution | medium | 61603 |
| `106091` | 6 | `T1046` T1046 | PUA - Advanced IP Scanner Execution | medium | 61603 |
| `106092` | 6 | `T1046` T1046 | PUA - Advanced Port Scanner Execution | medium | 61603 |
| `106093` | 6 | `T1046` T1046 | PUA - Advanced Port Scanner Execution | medium | 61603 |
| `106094` | 6 | `T1046` T1046 | PUA - Advanced Port Scanner Execution | medium | 61603 |
| `106095` | 6 | `T1046` T1046 | PUA - Advanced Port Scanner Execution | medium | 61603 |
| `106096` | 7 | `T1590.001` T1590.001 | PUA - Crassus Execution | high | 61603 |
| `106097` | 7 | `T1590.001` T1590.001 | PUA - Crassus Execution | high | 61603 |
| `106098` | 7 | `T1590.001` T1590.001 | PUA - Crassus Execution | high | 61603 |
| `106099` | 6 | `T1046` T1046 | PUA - SoftPerfect Netscan Execution | medium | 61603 |
| `106100` | 6 | `T1046` T1046 | PUA - SoftPerfect Netscan Execution | medium | 61603 |
| `106101` | 6 | `T1046` T1046 | PUA - SoftPerfect Netscan Execution | medium | 61603 |
| `106102` | 6 | `T1046` T1046 | PUA - NimScan Execution | medium | 61603 |
| `106103` | 6 | `T1046` T1046 | PUA - NimScan Execution | medium | 61603 |
| `106104` | 6 | `T1046` T1046 | PUA - Nmap/Zenmap Execution | medium | 61603 |
| `106105` | 6 | `T1046` T1046 | PUA - Nmap/Zenmap Execution | medium | 61603 |
| `106106` | 6 | `T1622` T1622 | PUA - Process Hacker Execution | medium | 61603 |
| `106107` | 6 | `T1622` T1622 | PUA - Process Hacker Execution | medium | 61603 |
| `106108` | 6 | `T1622` T1622 | PUA - Process Hacker Execution | medium | 61603 |
| `106109` | 6 | `T1622` T1622 | PUA - Process Hacker Execution | medium | 61603 |
| `106110` | 6 | `T1622` T1622 | PUA - Process Hacker Execution | medium | 61603 |
| `106111` | 6 | `T1622` T1622 | PUA - Process Hacker Execution | medium | 61603 |
| `106112` | 7 | `T1526` T1526 | PUA - Seatbelt Execution | high | 61603 |
| `106113` | 6 | `T1083` File and Directory Discovery | PUA - TruffleHog Execution | medium | 61603 |
| `106114` | 6 | `T1012` T1012 | Potential Configuration And Service Reconnaissance Via Reg.EXE | medium | 61603 |
| `106115` | 6 | `T1518` T1518 | Detected Windows Software Discovery | medium | 61603 |
| `106116` | 6 | `T1614.001` T1614.001 | System Language Discovery via Reg.Exe | medium | 61603 |
| `106117` | 7 | `T1018` T1018 | Renamed AdFind Execution | high | 61603 |
| `106118` | 7 | `T1018` T1018 | Renamed AdFind Execution | high | 61603 |
| `106119` | 7 | `T1018` T1018 | Renamed AdFind Execution | high | 61603 |
| `106120` | 7 | `T1033` T1033 | Renamed Whoami Execution | high | 61603 |
| `106121` | 7 | `T1615` T1615 | Suspicious Reconnaissance Activity Via GatherNetworkInfo.VBS | high | 61603 |
| `106122` | 6 | - | Obfuscated IP Download Activity | medium | 61603 |
| `106123` | 6 | - | Obfuscated IP Via CLI | medium | 61603 |
| `106124` | 7 | `T1033` T1033 | WhoAmI as Parameter | high | 61603 |
| `106125` | 6 | `T1069.001` T1069.001 | Permission Check Via Accesschk.EXE | medium | 61603 |
| `106126` | 6 | `T1087.002` T1087.002 | Active Directory Database Snapshot Via ADExplorer | medium | 61603 |
| `106127` | 7 | `T1087.002` T1087.002 | Suspicious Active Directory Database Snapshot Via ADExplorer | high | 61603 |
| `106128` | 6 | `T1087` Account Discovery | Suspicious Use of PsLogList | medium | 61603 |
| `106129` | 7 | `T1124` T1124 | Use of W32tm as Timer | high | 61603 |
| `106130` | 6 | `T1033` T1033 | Enumerate All Information With Whoami.EXE | medium | 61603 |
| `106131` | 6 | `T1033` T1033 | Group Membership Reconnaissance Via Whoami.EXE | medium | 61603 |
| `106132` | 6 | `T1033` T1033 | Whoami.EXE Execution With Output Option | medium | 61603 |
| `106133` | 6 | `T1033` T1033 | Whoami.EXE Execution Anomaly | medium | 61603 |
| `106134` | 6 | `T1047` T1047 | Computer System Reconnaissance Via Wmic.EXE | medium | 61603 |
| `106135` | 6 | `T1082` System Information Discovery | Uncommon System Information Discovery Via Wmic.EXE | medium | 61603 |

### Lateral Movement (TA0008) — 74 rules

| Rule ID | Level | Technique | Description | Confidence | Parent SID |
|---------|-------|-----------|-------------|------------|------------|
| `107000` | 8 | `T1078` Valid Accounts | Explicit credential logon | low | 60100 |
| `107001` | 8 | `T1021.001` T1021.001 | Remote logon (type 3) | low | 60100 |
| `107002` | 8 | `T1021.001` T1021.001 | Remote logon (type 10) | low | 60100 |
| `107003` | 11 | `T1021.002` T1021.002 | Suspicious named pipe: \ntsvcs | high | 61620 |
| `107004` | 11 | `T1021.002` T1021.002 | Suspicious named pipe: \scerpc | high | 61620 |
| `107005` | 11 | `T1021.002` T1021.002 | Suspicious process: psexesvc | high | 61603 |
| `107006` | 11 | `T1021.002` T1021.002 | Suspicious process: psexec | high | 61603 |
| `107007` | 11 | `T1021.002` T1021.002 | Suspicious named pipe: \psexe | high | 61619 |
| `107008` | 11 | `T1021.002` T1021.002 | Suspicious named pipe: \psexe | high | 61620 |
| `107009` | 10 | `T1021.002` T1021.002 | File created by psexec | medium | 61613 |
| `107010` | 10 | `T1021.002` T1021.002 | DNS query by psexec | medium | 61624 |
| `107011` | 11 | `T1021.002` T1021.002 | Suspicious service: PSEXESVC | high | 60106 |
| `107012` | 11 | `T1550.002` T1550.002 | Successful Overpass the Hash Attempt | high | 60100 |
| `107013` | 10 | `T1550.002` T1550.002 | Pass the Hash Activity 2 | medium | 60100 |
| `107014` | 10 | `T1550.002` T1550.002 | Pass the Hash Activity 2 | medium | 60100 |
| `107015` | 11 | `T1021.001` T1021.001 | RDP Login from Localhost | high | 60100 |
| `107016` | 10 | `T1021.002` T1021.002 | DCERPC SMB Spoolss Named Pipe | medium | 60100 |
| `107017` | 11 | `T1021.002` T1021.002 | DCOM InternetExplorer.Application Iertutil DLL Hijack - Security | high | 60100 |
| `107018` | 11 | `T1021.002` T1021.002 | Impacket PsExec Execution | high | 60100 |
| `107019` | 11 | `T1021.002` T1021.002 | First Time Seen Remote Named Pipe | high | 60100 |
| `107020` | 11 | `T1021.002` T1021.002 | Metasploit SMB Authentication | high | 60100 |
| `107021` | 11 | `T1021.002` T1021.002 | Metasploit SMB Authentication | high | 60100 |
| `107022` | 11 | `T1021.002` T1021.002 | Metasploit Or Impacket Service Installation Via SMB PsExec | high | 60100 |
| `107023` | 10 | `T1021.001` T1021.001 | Denied Access To Remote Desktop | medium | 60100 |
| `107024` | 11 | `T1021.002` T1021.002 | Protected Storage Service Access | high | 60100 |
| `107025` | 11 | `T1558.003` T1558.003 | Register new Logon Process by Rubeus | high | 60100 |
| `107026` | 11 | `T1021.002` T1021.002 | SMB Create Remote File Admin Share | high | 60100 |
| `107027` | 10 | `T1558.003` T1558.003 | Uncommon Outbound Kerberos Connection - Security | medium | 60100 |
| `107028` | 11 | `T1021.002` T1021.002 | Suspicious PsExec Execution | high | 60100 |
| `107029` | 10 | `T1021.002` T1021.002 | Remote Service Activity via SVCCTL Named Pipe | medium | 60100 |
| `107030` | 10 | `T1550.002` T1550.002 | NTLMv1 Logon Between Client and Server | medium | 60106 |
| `107031` | 11 | `T1210` T1210 | Zerologon Exploitation Using Well-known Tools | high | 60106 |
| `107032` | 11 | `T1021.002` T1021.002 | smbexec.py Service Installation | high | 60106 |
| `107033` | 11 | `T1021.002` T1021.002 | Potential DCOM InternetExplorer.Application DLL Hijack | high | 61613 |
| `107034` | 11 | `T1136.002` T1136.002 | PSEXEC Remote Execution File Artefact | high | 61613 |
| `107035` | 11 | `T1047` T1047 | Wmiexec Default Output File | high | 61613 |
| `107036` | 11 | `T1047` T1047 | Wmiexec Default Output File | high | 61613 |
| `107037` | 11 | `T1047` T1047 | Wmiexec Default Output File | high | 61613 |
| `107038` | 11 | `T1021.002` T1021.002 | Potential DCOM InternetExplorer.Application DLL Hijack - Image Load | high | 61609 |
| `107039` | 10 | `T1546.003` T1546.003 | WMI ActiveScriptEventConsumers Activity Via Scrcons.EXE DLL Load | medium | 61609 |
| `107040` | 11 | `T1218` T1218 | BaaUpdate.exe Suspicious DLL Load | high | 61609 |
| `107041` | 11 | `T1021.001` T1021.001 | Outbound RDP Connections Over Non-Standard Tools | high | 61605 |
| `107042` | 10 | `T1021.002` T1021.002 | PUA - CSExec Default Named Pipe | medium | 61619 |
| `107043` | 10 | `T1021.002` T1021.002 | PUA - RemCom Default Named Pipe | medium | 61619 |
| `107044` | 11 | - | HackTool - Evil-WinRm Execution - PowerShell Module | high | 91801 |
| `107045` | 10 | `T1021.006` T1021.006 | Enable Windows Remote Management | medium | 91801 |
| `107046` | 10 | `T1021.006` T1021.006 | Execute Invoke-command on Remote Host | medium | 91801 |
| `107047` | 10 | `T1021.002` T1021.002 | Suspicious New-PSDrive to Admin Share | medium | 91801 |
| `107048` | 11 | `T1218` T1218 | Suspicious BitLocker Access Agent Update Utility Execution | high | 61603 |
| `107049` | 10 | `T1072` T1072 | Suspicious Csi.exe Usage | medium | 61603 |
| `107050` | 10 | `T1021.006` T1021.006 | HackTool - WinRM Access Via Evil-WinRM | medium | 61603 |
| `107051` | 11 | `T1021.002` T1021.002 | HackTool - SharpMove Tool Execution | high | 61603 |
| `107052` | 11 | - | HackTool - Wmiexec Default Powershell Command | high | 61603 |
| `107053` | 10 | `T1210` T1210 | Suspicious SysAidServer Child | medium | 61603 |
| `107054` | 11 | `T1021.003` T1021.003 | MMC Spawning Windows Shell | high | 61603 |
| `107055` | 11 | `T1563.002` T1563.002 | Potential MSTSC Shadowing Activity | high | 61603 |
| `107056` | 10 | `T1021.001` T1021.001 | New Remote Desktop Connection Initiated Via Mstsc.EXE | medium | 61603 |
| `107057` | 11 | - | Mstsc.EXE Execution From Uncommon Parent | high | 61603 |
| `107058` | 10 | `T1021.002` T1021.002 | Windows Admin Share Mount Via Net.EXE | medium | 61603 |
| `107059` | 11 | `T1021.002` T1021.002 | Windows Internet Hosted WebDav Share Mount Via Net.EXE | high | 61603 |
| `107060` | 10 | `T1090` T1090 | New Port Forwarding Rule Added Via Netsh.EXE | medium | 61603 |
| `107061` | 11 | `T1090` T1090 | RDP Port Forwarding Rule Added Via Netsh.EXE | high | 61603 |
| `107062` | 11 | `T1021.003` T1021.003 | Potential Excel.EXE DCOM Lateral Movement Via ActivateMicrosoftApp | high | 61603 |
| `107063` | 10 | `T1021.001` T1021.001 | RDP Enable or Disable via Win32_TerminalServiceSetting WMI Class | medium | 61603 |
| `107064` | 11 | `T1021.002` T1021.002 | Rundll32 Execution Without Parameters | high | 61603 |
| `107065` | 11 | `T1021.003` T1021.003 | Suspicious Speech Runtime Binary Child Process | high | 61603 |
| `107066` | 10 | `T1039` T1039 | Copy From Or To Admin Share Or Sysvol Folder | medium | 61603 |
| `107067` | 11 | `T1021` Remote Services | Privilege Escalation via Named Pipe Impersonation | high | 61603 |
| `107068` | 10 | `T1021` Remote Services | Potential Remote Desktop Tunneling | medium | 61603 |
| `107069` | 11 | `T1563.002` T1563.002 | Suspicious RDP Redirect Using TSCON | high | 61603 |
| `107070` | 11 | `T1021.005` T1021.005 | Suspicious UltraVNC Execution | high | 61603 |
| `107071` | 11 | `T1021.006` T1021.006 | Winrs Local Command Execution | high | 61603 |
| `107072` | 10 | `T1021.006` T1021.006 | Potential Lateral Movement via Windows Remote Shell | medium | 61603 |
| `107073` | 10 | `T1090` T1090 | New PortProxy Registry Entry Added | medium | 61615 |

### Collection (TA0009) — 50 rules

| Rule ID | Level | Technique | Description | Confidence | Parent SID |
|---------|-------|-----------|-------------|------------|------------|
| `108000` | 8 | `T1557.001` T1557.001 | RottenPotato Like Attack Pattern | high | 60100 |
| `108001` | 7 | `T1123` T1123 | Processes Accessing the Microphone and Webcam | medium | 60100 |
| `108002` | 8 | `T1557.003` T1557.003 | Potential Kerberos Coercion by Spoofing SPNs via DNS Manipulation | high | 60100 |
| `108003` | 8 | `T1557.003` T1557.003 | Potential Kerberos Coercion by Spoofing SPNs via DNS Manipulation | high | 60100 |
| `108004` | 7 | `T1039` T1039 | Suspicious Access to Sensitive File Extensions | medium | 60100 |
| `108005` | 8 | `T1557.001` T1557.001 | Local Privilege Escalation Indicator TabTip | high | 60106 |
| `108006` | 7 | `T1195.002` T1195.002 | Notepad++ Updater DNS Query to Uncommon Domains | medium | 61624 |
| `108007` | 8 | `T1557.001` T1557.001 | Suspicious DNS Query Indicating Kerberos Coercion via DNS Object SP... | high | 61624 |
| `108008` | 8 | `T1195.002` T1195.002 | Uncommon File Created by Notepad++ Updater Gup.EXE | high | 61613 |
| `108009` | 7 | `T1005` T1005 | ADFS Database Named Pipe Connection By Uncommon Tool | medium | 61619 |
| `108010` | 7 | `T1115` T1115 | PowerShell Get Clipboard | medium | 91801 |
| `108011` | 7 | `T1074.001` T1074.001 | Zip A Folder With PowerShell For Staging In Temp  - PowerShell Module | medium | 91801 |
| `108012` | 7 | `T1119` T1119 | Automated Collection Command PowerShell | medium | 91801 |
| `108013` | 7 | `T1113` T1113 | Windows Screen Capture with CopyFromScreen | medium | 91801 |
| `108014` | 7 | `T1056.001` T1056.001 | Potential Keylogger Activity | medium | 91801 |
| `108015` | 7 | `T1114.001` T1114.001 | Powershell Local Email Collection | medium | 91801 |
| `108016` | 7 | `T1119` T1119 | Recon Information for Export with PowerShell | medium | 91801 |
| `108017` | 7 | `T1074.001` T1074.001 | Zip A Folder With PowerShell For Staging In Temp - PowerShell Script | medium | 91801 |
| `108018` | 7 | `T1560.001` T1560.001 | 7Zip Compressing Dump Files | medium | 61603 |
| `108019` | 7 | `T1560.001` T1560.001 | Compress Data and Lock With Password for Exfiltration With 7-ZIP | medium | 61603 |
| `108020` | 7 | `T1005` T1005 | Esentutl Steals Browser Information | medium | 61603 |
| `108021` | 8 | `T1195.002` T1195.002 | Suspicious Child Process of Notepad++ Updater - GUP.Exe | high | 61603 |
| `108022` | 8 | `T1557.001` T1557.001 | HackTool - ADCSPwn Execution | high | 61603 |
| `108023` | 8 | `T1557.001` T1557.001 | HackTool - Impacket Tools Execution | high | 61603 |
| `108024` | 13 | `T1557.001` T1557.001 | HackTool - Impacket Tools Execution | high | 61603 |
| `108025` | 8 | `T1557.001` T1557.001 | Potential SMB Relay Attack Tool Execution | high | 61603 |
| `108026` | 8 | `T1557.001` T1557.001 | Potential SMB Relay Attack Tool Execution | high | 61603 |
| `108027` | 8 | `T1557.001` T1557.001 | Potential SMB Relay Attack Tool Execution | high | 61603 |
| `108028` | 8 | `T1557.001` T1557.001 | Attempts of Kerberos Coercion Via DNS SPN Spoofing | high | 61603 |
| `108029` | 8 | `T1560.001` T1560.001 | Suspicious Manipulation Of Default Accounts Via Net.EXE | high | 61603 |
| `108030` | 7 | `T1123` T1123 | Audio Capture via PowerShell | medium | 61603 |
| `108031` | 7 | `T1115` T1115 | PowerShell Get-Clipboard Cmdlet Via CLI | medium | 61603 |
| `108032` | 7 | `T1074.001` T1074.001 | Folder Compress To Potentially Suspicious Output Via Compress-Archi... | medium | 61603 |
| `108033` | 7 | `T1113` T1113 | Screen Capture Activity Via Psr.EXE | medium | 61603 |
| `108034` | 8 | `T1560.001` T1560.001 | Rar Usage with Password and Compression Level | high | 61603 |
| `108035` | 7 | `T1113` T1113 | Windows Recall Feature Enabled Via Reg.EXE | medium | 61603 |
| `108036` | 7 | - | Renamed Remote Utilities RAT (RURAT) Execution | medium | 61603 |
| `108037` | 7 | `T1685.001` T1685.001 | Potential Suspicious Activity Using SeCEdit | medium | 61603 |
| `108038` | 7 | `T1123` T1123 | Audio Capture via SoundRecorder | medium | 61603 |
| `108039` | 7 | `T1005` T1005 | Veeam Backup Database Suspicious Query | medium | 61603 |
| `108040` | 8 | `T1005` T1005 | VeeamBackup Database Credentials Dump Via Sqlcmd.EXE | high | 61603 |
| `108041` | 7 | `T1119` T1119 | Automated Collection Command Prompt | medium | 61603 |
| `108042` | 7 | `T1119` T1119 | Recon Information for Export with Command Prompt | medium | 61603 |
| `108043` | 7 | `T1560.001` T1560.001 | Winrar Compressing Dump Files | medium | 61603 |
| `108044` | 7 | `T1560.001` T1560.001 | WinRAR Execution in Non-Standard Folder | medium | 61603 |
| `108045` | 7 | `T1560.001` T1560.001 | Compress Data and Lock With Password for Exfiltration With WINZIP | medium | 61603 |
| `108046` | 7 | `T1113` T1113 | Windows Recall Feature Enabled - DisableAIDataAnalysis Value Deleted | medium | 61614 |
| `108047` | 8 | `T1125` T1125 | Suspicious Camera and Microphone Access | high | 61615 |
| `108048` | 7 | `T1113` T1113 | Periodic Backup For System Registry Hives Enabled | medium | 61615 |
| `108049` | 7 | `T1113` T1113 | Windows Recall Feature Enabled - Registry | medium | 61615 |

### Command and Control (TA0011) — 187 rules

| Rule ID | Level | Technique | Description | Confidence | Parent SID |
|---------|-------|-----------|-------------|------------|------------|
| `109000` | 9 | `T1105` Ingress Tool Transfer | Executable dropped in downloads | medium | 61613 |
| `109001` | 9 | `T1105` Ingress Tool Transfer | Executable dropped in appdata | medium | 61613 |
| `109002` | 9 | `T1105` Ingress Tool Transfer | Executable dropped in temp | medium | 61613 |
| `109003` | 9 | `T1105` Ingress Tool Transfer | Executable dropped in programdata | medium | 61613 |
| `109004` | 9 | `T1105` Ingress Tool Transfer | Executable dropped in public | medium | 61613 |
| `109005` | 10 | `T1090.001` T1090.001 | RDP over Reverse SSH Tunnel WFP | high | 60100 |
| `109006` | 10 | `T1001.003` T1001.003 | Suspicious LDAP-Attributes Used | high | 60100 |
| `109007` | 10 | `T1027` Obfuscated Files or Information | Password Protected ZIP File Opened (Suspicious Filenames) | high | 60100 |
| `109008` | 9 | `T1219.002` T1219.002 | Mesh Agent Service Installation | medium | 60106 |
| `109009` | 9 | `T1219.002` T1219.002 | TacticalRMM Service Installation | medium | 60106 |
| `109010` | 9 | `T1105` Ingress Tool Transfer | AppX Package Installation Attempts Via AppInstaller.EXE | medium | 61624 |
| `109011` | 9 | `T1071.001` T1071.001 | Cloudflared Tunnels Related DNS Requests | medium | 61624 |
| `109012` | 9 | `T1071.004` T1071.004 | DNS Query To Common Malware Hosting and Shortener Services | medium | 61624 |
| `109013` | 9 | `T1071.001` T1071.001 | DNS Query To Devtunnels Domain | medium | 61624 |
| `109014` | 9 | `T1219.002` T1219.002 | DNS Query To AzureWebsites.NET By Non-Browser Process | medium | 61624 |
| `109015` | 10 | `T1071.004` T1071.004 | DNS Query by Finger Utility | high | 61624 |
| `109016` | 13 | `T1071.004` T1071.004 | Suspicious Cobalt Strike DNS Beaconing - Sysmon | high | 61624 |
| `109017` | 13 | `T1071.004` T1071.004 | Suspicious Cobalt Strike DNS Beaconing - Sysmon | high | 61624 |
| `109018` | 9 | `T1219.002` T1219.002 | DNS Query To Remote Access Software Domain From Non-Browser App | medium | 61624 |
| `109019` | 9 | `T1219.002` T1219.002 | DNS Query To Remote Access Software Domain From Non-Browser App | medium | 61624 |
| `109020` | 9 | `T1219.002` T1219.002 | TeamViewer Domain Query By Non-TeamViewer Application | medium | 61624 |
| `109021` | 10 | `T1090.003` T1090.003 | DNS Query Tor .Onion Address - Sysmon | high | 61624 |
| `109022` | 9 | `T1071.001` T1071.001 | DNS Query To Visual Studio Code Tunnels Domain | medium | 61624 |
| `109023` | 9 | `T1001.003` T1001.003 | ADSI-Cache File Creation By Uncommon Tool | medium | 61613 |
| `109024` | 9 | `T1219.002` T1219.002 | Anydesk Temporary Artefact | medium | 61613 |
| `109025` | 10 | `T1219.002` T1219.002 | Suspicious Binary Writes Via AnyDesk | high | 61613 |
| `109026` | 10 | `T1127` T1127 | Suspicious File Created by ArcSOC.exe | high | 61613 |
| `109027` | 9 | `T1105` Ingress Tool Transfer | Potentially Suspicious File Creation by OpenEDR's ITSMService | medium | 61613 |
| `109028` | 9 | `T1219.002` T1219.002 | GoToAssist Temporary Installation Artefact | medium | 61613 |
| `109029` | 10 | `T1219.002` T1219.002 | HackTool - Inveigh Execution Artefacts | high | 61613 |
| `109030` | 10 | `T1219.002` T1219.002 | HackTool - RemoteKrbRelay SMB Relay Secrets Dump Module Indicators | high | 61613 |
| `109031` | 9 | `T1219.002` T1219.002 | Installation of TeamViewer Desktop | medium | 61613 |
| `109032` | 9 | `T1219.002` T1219.002 | ScreenConnect Temporary Installation Artefact | medium | 61613 |
| `109033` | 10 | `T1105` Ingress Tool Transfer | Suspicious Desktopimgdownldr Target File | high | 61613 |
| `109034` | 10 | `T1218` T1218 | Legitimate Application Writing Files In Uncommon Location | high | 61613 |
| `109035` | 9 | `T1219.002` T1219.002 | TeamViewer Remote Session | medium | 61613 |
| `109036` | 9 | `T1219.002` T1219.002 | TeamViewer Remote Session | medium | 61613 |
| `109037` | 10 | `T1219.002` T1219.002 | Hijack Legit RDP Session to Move Laterally | high | 61613 |
| `109038` | 9 | - | Visual Studio Code Tunnel Remote File Creation | medium | 61613 |
| `109039` | 10 | - | Renamed VsCode Code Tunnel Execution - File Indicator | high | 61613 |
| `109040` | 10 | `T1071` Application Layer Protocol | HackTool - SILENTTRINITY Stager DLL Load | high | 61609 |
| `109041` | 10 | `T1105` Ingress Tool Transfer | Uncommon Network Connection Initiated By Certutil.EXE | high | 61605 |
| `109042` | 9 | `T1102` T1102 | Network Connection Initiated To AzureWebsites.NET By Non-Browser Pr... | medium | 61605 |
| `109043` | 10 | `T1102` T1102 | New Connection Initiated To Potential Dead Drop Resolver Domain | high | 61605 |
| `109044` | 10 | `T1105` Ingress Tool Transfer | Suspicious Dropbox API Usage | high | 61605 |
| `109045` | 9 | `T1102` T1102 | Suspicious Non-Browser Network Communication With Google API | medium | 61605 |
| `109046` | 10 | `T1572` T1572 | Communication To LocaltoNet Tunneling Service Initiated | high | 61605 |
| `109047` | 9 | `T1041` T1041 | Network Communication Initiated To Portmap.IO Domain | medium | 61605 |
| `109048` | 9 | `T1102` T1102 | Suspicious Non-Browser Network Communication With Telegram API | medium | 61605 |
| `109049` | 10 | `T1071.004` T1071.004 | Network Connection Initiated via Finger.EXE | high | 61605 |
| `109050` | 10 | `T1105` Ingress Tool Transfer | Network Connection Initiated By IMEWDBLD.EXE | high | 61605 |
| `109051` | 9 | - | Office Application Initiated Network Connection Over Uncommon Ports | medium | 61605 |
| `109052` | 10 | `T1572` T1572 | RDP Over Reverse SSH Tunnel | high | 61605 |
| `109053` | 10 | `T1572` T1572 | RDP to HTTP or HTTPS Target Ports | high | 61605 |
| `109054` | 10 | `T1105` Ingress Tool Transfer | Network Communication Initiated To File Sharing Domains From Proces... | high | 61605 |
| `109055` | 10 | `T1105` Ingress Tool Transfer | Network Connection Initiated From Process Located In Potentially Su... | high | 61605 |
| `109056` | 9 | - | Suspicious Wordpad Outbound Connections | medium | 61605 |
| `109057` | 9 | `T1105` Ingress Tool Transfer | Local Network Connection Initiated By Script Interpreter | medium | 61605 |
| `109058` | 10 | `T1105` Ingress Tool Transfer | Outbound Network Connection Initiated By Script Interpreter | high | 61605 |
| `109059` | 9 | `T1095` T1095 | Netcat The Powershell Version | medium | 91801 |
| `109060` | 9 | `T1105` Ingress Tool Transfer | Potential COM Objects Download Cradles Usage - PS Script | medium | 91801 |
| `109061` | 9 | `T1132.001` T1132.001 | Suspicious FromBase64String Usage On Gzip Archive - Ps Script | medium | 91801 |
| `109062` | 9 | `T1071.001` T1071.001 | Change User Agents with WebRequest | medium | 91801 |
| `109063` | 9 | `T1090` T1090 | Suspicious TCP Tunnel Via PowerShell Script | medium | 91801 |
| `109064` | 9 | `T1571` T1571 | Testing Usage of Uncommonly Used Port | medium | 91801 |
| `109065` | 10 | `T1105` Ingress Tool Transfer | File Download with Headless Browser | high | 61603 |
| `109066` | 9 | `T1105` Ingress Tool Transfer | File Download From Browser Process Via Inline URL | medium | 61603 |
| `109067` | 10 | `T1090.003` T1090.003 | Tor Client/Browser Execution | high | 61603 |
| `109068` | 10 | `T1090.003` T1090.003 | Tor Client/Browser Execution | high | 61603 |
| `109069` | 10 | `T1090.003` T1090.003 | Tor Client/Browser Execution | high | 61603 |
| `109070` | 9 | `T1105` Ingress Tool Transfer | File Download via CertOC.EXE | medium | 61603 |
| `109071` | 10 | `T1105` Ingress Tool Transfer | File Download From IP Based URL Via CertOC.EXE | high | 61603 |
| `109072` | 10 | `T1105` Ingress Tool Transfer | Suspicious CertReq Command to Download | high | 61603 |
| `109073` | 9 | `T1027` Obfuscated Files or Information | Suspicious Download Via Certutil.EXE | medium | 61603 |
| `109074` | 10 | `T1027` Obfuscated Files or Information | Suspicious File Downloaded From Direct IP Via Certutil.EXE | high | 61603 |
| `109075` | 10 | `T1027` Obfuscated Files or Information | Suspicious File Downloaded From File-Sharing Website Via Certutil.EXE | high | 61603 |
| `109076` | 9 | `T1090.001` T1090.001 | Cloudflared Portable Execution | medium | 61603 |
| `109077` | 9 | `T1090.001` T1090.001 | Cloudflared Quick Tunnel Execution | medium | 61603 |
| `109078` | 9 | `T1102` T1102 | Cloudflared Tunnel Connections Cleanup | medium | 61603 |
| `109079` | 9 | `T1102` T1102 | Cloudflared Tunnel Execution | medium | 61603 |
| `109080` | 10 | `T1218` T1218 | Curl Download And Execute Combination | high | 61603 |
| `109081` | 9 | `T1105` Ingress Tool Transfer | Potential Download/Upload Activity Using Type Command | medium | 61603 |
| `109082` | 9 | `T1105` Ingress Tool Transfer | Potential Download/Upload Activity Using Type Command | medium | 61603 |
| `109083` | 10 | `T1105` Ingress Tool Transfer | Suspicious Curl.EXE Download | high | 61603 |
| `109084` | 9 | `T1105` Ingress Tool Transfer | Remote File Download Via Desktopimgdownldr Utility | medium | 61603 |
| `109085` | 10 | `T1105` Ingress Tool Transfer | Suspicious Desktopimgdownldr Command | high | 61603 |
| `109086` | 10 | `T1105` Ingress Tool Transfer | Finger.EXE Execution | high | 61603 |
| `109087` | 10 | `T1105` Ingress Tool Transfer | Finger.EXE Execution | high | 61603 |
| `109088` | 9 | `T1105` Ingress Tool Transfer | Arbitrary File Download Via GfxDownloadWrapper.EXE | medium | 61603 |
| `109089` | 9 | `T1102.002` T1102.002 | Github Self-Hosted Runner Execution | medium | 61603 |
| `109090` | 10 | `T1105` Ingress Tool Transfer | File Download Using Notepad++ GUP Utility | high | 61603 |
| `109091` | 10 | `T1090` T1090 | HackTool - Htran/NATBypass Execution | high | 61603 |
| `109092` | 10 | `T1090` T1090 | HackTool - Htran/NATBypass Execution | high | 61603 |
| `109093` | 10 | `T1090.001` T1090.001 | HackTool - SharpChisel Execution | high | 61603 |
| `109094` | 10 | `T1090.001` T1090.001 | HackTool - SharpChisel Execution | high | 61603 |
| `109095` | 10 | `T1071` Application Layer Protocol | HackTool - SILENTTRINITY Stager Execution | high | 61603 |
| `109096` | 10 | `T1105` Ingress Tool Transfer | File Download And Execution Via IEExec.EXE | high | 61603 |
| `109097` | 10 | `T1102` T1102 | Suspicious Child Process Of Manage Engine ServiceDesk | high | 61603 |
| `109098` | 9 | `T1218` T1218 | Import LDAP Data Interchange Format File Via Ldifde.EXE | medium | 61603 |
| `109099` | 9 | `T1105` Ingress Tool Transfer | Suspicious Diantz Download and Compress Into a CAB File | medium | 61603 |
| `109100` | 9 | `T1105` Ingress Tool Transfer | Suspicious Extrac32 Execution | medium | 61603 |
| `109101` | 10 | `T1105` Ingress Tool Transfer | PrintBrm ZIP Creation of Extraction | high | 61603 |
| `109102` | 9 | `T1105` Ingress Tool Transfer | Replace.exe Usage | medium | 61603 |
| `109103` | 10 | `T1218` T1218 | File Download Via Windows Defender MpCmpRun.EXE | high | 61603 |
| `109104` | 9 | `T1218.007` T1218.007 | MsiExec Web Install | medium | 61603 |
| `109105` | 10 | `T1219.002` T1219.002 | Suspicious Mstsc.EXE Execution With Local RDP File | high | 61603 |
| `109106` | 10 | `T1572` T1572 | Suspicious Plink Port Forwarding | high | 61603 |
| `109107` | 10 | `T1572` T1572 | Potential RDP Tunneling Via Plink | high | 61603 |
| `109108` | 9 | `T1132.001` T1132.001 | Gzip Archive Decode Via PowerShell | medium | 61603 |
| `109109` | 9 | `T1105` Ingress Tool Transfer | Potential COM Objects Download Cradles Usage - Process Creation | medium | 61603 |
| `109110` | 9 | `T1059.001` T1059.001 | Potential DLL File Download Via PowerShell Invoke-WebRequest | medium | 61603 |
| `109111` | 9 | `T1132.001` T1132.001 | Suspicious FromBase64String Usage On Gzip Archive - Process Creation | medium | 61603 |
| `109112` | 9 | `T1105` Ingress Tool Transfer | Suspicious Invoke-WebRequest Execution With DirectIP | medium | 61603 |
| `109113` | 10 | `T1105` Ingress Tool Transfer | Suspicious Invoke-WebRequest Execution | high | 61603 |
| `109114` | 10 | `T1572` T1572 | PUA - 3Proxy Execution | high | 61603 |
| `109115` | 10 | `T1572` T1572 | PUA - 3Proxy Execution | high | 61603 |
| `109116` | 10 | `T1572` T1572 | PUA - 3Proxy Execution | high | 61603 |
| `109117` | 10 | `T1090.001` T1090.001 | PUA - Chisel Tunneling Tool Execution | high | 61603 |
| `109118` | 10 | `T1090` T1090 | PUA - Fast Reverse Proxy (FRP) Execution | high | 61603 |
| `109119` | 10 | `T1090` T1090 | PUA - Fast Reverse Proxy (FRP) Execution | high | 61603 |
| `109120` | 10 | `T1090` T1090 | PUA - Fast Reverse Proxy (FRP) Execution | high | 61603 |
| `109121` | 10 | `T1090` T1090 | PUA- IOX Tunneling Tool Execution | high | 61603 |
| `109122` | 10 | `T1090` T1090 | PUA- IOX Tunneling Tool Execution | high | 61603 |
| `109123` | 10 | `T1090` T1090 | PUA- IOX Tunneling Tool Execution | high | 61603 |
| `109124` | 10 | `T1095` T1095 | PUA - Netcat Suspicious Execution | high | 61603 |
| `109125` | 10 | `T1095` T1095 | PUA - Netcat Suspicious Execution | high | 61603 |
| `109126` | 10 | `T1572` T1572 | PUA - Ngrok Execution | high | 61603 |
| `109127` | 10 | `T1572` T1572 | PUA - Ngrok Execution | high | 61603 |
| `109128` | 10 | `T1572` T1572 | PUA - Ngrok Execution | high | 61603 |
| `109129` | 10 | `T1572` T1572 | PUA - Ngrok Execution | high | 61603 |
| `109130` | 10 | `T1105` Ingress Tool Transfer | PUA - Nimgrab Execution | high | 61603 |
| `109131` | 10 | `T1105` Ingress Tool Transfer | PUA - Nimgrab Execution | high | 61603 |
| `109132` | 10 | `T1090` T1090 | PUA - NPS Tunneling Tool Execution | high | 61603 |
| `109133` | 10 | `T1090` T1090 | PUA - NPS Tunneling Tool Execution | high | 61603 |
| `109134` | 10 | `T1090` T1090 | PUA - NPS Tunneling Tool Execution | high | 61603 |
| `109135` | 10 | `T1090` T1090 | PUA - NPS Tunneling Tool Execution | high | 61603 |
| `109136` | 9 | `T1090` T1090 | Potentially Suspicious Usage Of Qemu | medium | 61603 |
| `109137` | 9 | `T1219.002` T1219.002 | Remote Access Tool - AnyDesk Execution | medium | 61603 |
| `109138` | 9 | `T1219.002` T1219.002 | Remote Access Tool - AnyDesk Execution | medium | 61603 |
| `109139` | 9 | `T1219.002` T1219.002 | Remote Access Tool - AnyDesk Execution | medium | 61603 |
| `109140` | 9 | `T1219.002` T1219.002 | Remote Access Tool - AnyDesk Execution | medium | 61603 |
| `109141` | 9 | `T1219.002` T1219.002 | Remote Access Tool - AnyDesk Piped Password Via CLI | medium | 61603 |
| `109142` | 10 | `T1219.002` T1219.002 | Remote Access Tool - AnyDesk Silent Installation | high | 61603 |
| `109143` | 10 | `T1219.002` T1219.002 | Remote Access Tool - Anydesk Execution From Suspicious Folder | high | 61603 |
| `109144` | 9 | `T1219.002` T1219.002 | Remote Access Tool - GoToAssist Execution | medium | 61603 |
| `109145` | 9 | `T1219.002` T1219.002 | Remote Access Tool - GoToAssist Execution | medium | 61603 |
| `109146` | 9 | `T1219.002` T1219.002 | Remote Access Tool - GoToAssist Execution | medium | 61603 |
| `109147` | 9 | `T1219.002` T1219.002 | Remote Access Tool - LogMeIn Execution | medium | 61603 |
| `109148` | 9 | `T1219.002` T1219.002 | Remote Access Tool - LogMeIn Execution | medium | 61603 |
| `109149` | 9 | `T1219.002` T1219.002 | Remote Access Tool - LogMeIn Execution | medium | 61603 |
| `109150` | 9 | `T1219.002` T1219.002 | Remote Access Tool - Potential MeshAgent Execution - Windows | medium | 61603 |
| `109151` | 9 | `T1219.002` T1219.002 | Remote Access Tool - MeshAgent Command Execution via MeshCentral | medium | 61603 |
| `109152` | 9 | `T1219.002` T1219.002 | Remote Access Tool - NetSupport Execution | medium | 61603 |
| `109153` | 9 | `T1219.002` T1219.002 | Remote Access Tool - NetSupport Execution | medium | 61603 |
| `109154` | 9 | `T1219.002` T1219.002 | Remote Access Tool - NetSupport Execution | medium | 61603 |
| `109155` | 9 | `T1219.002` T1219.002 | Remote Access Tool - NetSupport Execution | medium | 61603 |
| `109156` | 10 | `T1219.002` T1219.002 | Remote Access Tool - Renamed MeshAgent Execution - Windows | high | 61603 |
| `109157` | 9 | `T1219.002` T1219.002 | Remote Access Tool - ScreenConnect Execution | medium | 61603 |
| `109158` | 9 | `T1219.002` T1219.002 | Remote Access Tool - ScreenConnect Execution | medium | 61603 |
| `109159` | 9 | `T1219.002` T1219.002 | Remote Access Tool - ScreenConnect Execution | medium | 61603 |
| `109160` | 9 | `T1219.002` T1219.002 | Remote Access Tool - ScreenConnect Potential Suspicious Remote Comm... | medium | 61603 |
| `109161` | 9 | `T1219.002` T1219.002 | Remote Access Tool - Simple Help Execution | medium | 61603 |
| `109162` | 9 | `T1219` T1219 | Remote Access Tool - TacticalRMM Agent Registration to Potentially ... | medium | 61603 |
| `109163` | 9 | `T1219.002` T1219.002 | Remote Access Tool - UltraViewer Execution | medium | 61603 |
| `109164` | 9 | `T1219.002` T1219.002 | Remote Access Tool - UltraViewer Execution | medium | 61603 |
| `109165` | 9 | `T1219.002` T1219.002 | Remote Access Tool - UltraViewer Execution | medium | 61603 |
| `109166` | 10 | `T1090.001` T1090.001 | Renamed Cloudflared.EXE Execution | high | 61603 |
| `109167` | 10 | `T1090.001` T1090.001 | Renamed Cloudflared.EXE Execution | high | 61603 |
| `109168` | 10 | `T1090.001` T1090.001 | Renamed Cloudflared.EXE Execution | high | 61603 |
| `109169` | 10 | `T1090.001` T1090.001 | Renamed Cloudflared.EXE Execution | high | 61603 |
| `109170` | 9 | `T1572` T1572 | Port Forwarding Activity Via SSH.EXE | medium | 61603 |
| `109171` | 10 | `T1572` T1572 | Potential RDP Tunneling Via SSH | high | 61603 |
| `109172` | 9 | `T1219.002` T1219.002 | Potential Amazon SSM Agent Hijacking | medium | 61603 |
| `109173` | 10 | `T1105` Ingress Tool Transfer | Suspicious Download from Office Domain | high | 61603 |
| `109174` | 10 | `T1219` T1219 | Suspicious Velociraptor Child Process | high | 61603 |
| `109175` | 10 | `T1219.002` T1219.002 | Suspicious TSCON Start as SYSTEM | high | 61603 |
| `109176` | 9 | `T1219.002` T1219.002 | Use of UltraVNC Remote Access Software | medium | 61603 |
| `109177` | 9 | `T1219.002` T1219.002 | Use of UltraVNC Remote Access Software | medium | 61603 |
| `109178` | 9 | `T1219.002` T1219.002 | Use of UltraVNC Remote Access Software | medium | 61603 |
| `109179` | 9 | `T1219.002` T1219.002 | Use of UltraVNC Remote Access Software | medium | 61603 |
| `109180` | 9 | `T1071.001` T1071.001 | Visual Studio Code Tunnel Execution | medium | 61603 |
| `109181` | 9 | `T1071.001` T1071.001 | Visual Studio Code Tunnel Execution | medium | 61603 |
| `109182` | 9 | `T1071.001` T1071.001 | Visual Studio Code Tunnel Execution | medium | 61603 |
| `109183` | 9 | `T1071.001` T1071.001 | Visual Studio Code Tunnel Shell Execution | medium | 61603 |
| `109184` | 10 | `T1071.001` T1071.001 | Renamed Visual Studio Code Tunnel Execution | high | 61603 |
| `109185` | 9 | `T1071.001` T1071.001 | Visual Studio Code Tunnel Service Installation | medium | 61603 |
| `109186` | 10 | `T1105` Ingress Tool Transfer | Lolbas OneDriveStandaloneUpdater.exe Proxy Download | high | 61615 |

### Exfiltration (TA0010) — 33 rules

| Rule ID | Level | Technique | Description | Confidence | Parent SID |
|---------|-------|-----------|-------------|------------|------------|
| `110000` | 12 | `T1048` T1048 | Tap Driver Installation | medium | 60106 |
| `110001` | 13 | `T1567.002` T1567.002 | DNS Query for Anonfiles.com Domain - Sysmon | high | 61624 |
| `110002` | 12 | `T1567.002` T1567.002 | DNS Query To MEGA Hosting Website | medium | 61624 |
| `110003` | 12 | `T1567.002` T1567.002 | Rclone Config File Creation | medium | 61613 |
| `110004` | 12 | `T1567` T1567 | Network Connection Initiated To BTunnels Domains | medium | 61605 |
| `110005` | 12 | `T1567` T1567 | Network Connection Initiated To Cloudflared Tunnels Domains | medium | 61605 |
| `110006` | 12 | `T1567.001` T1567.001 | Network Connection Initiated To DevTunnels Domain | medium | 61605 |
| `110007` | 13 | `T1567` T1567 | Process Initiated Network Connection To Ngrok Domain | high | 61605 |
| `110008` | 13 | `T1567` T1567 | Communication To Ngrok Tunneling Service Initiated | high | 61605 |
| `110009` | 12 | `T1567` T1567 | Network Connection Initiated To Visual Studio Code Tunnels Domain | medium | 61605 |
| `110010` | 12 | `T1048.003` T1048.003 | Suspicious Outbound SMTP Connections | medium | 61605 |
| `110011` | 12 | - | Potential Data Exfiltration Via Audio File | medium | 91801 |
| `110012` | 12 | `T1048.003` T1048.003 | PowerShell ICMP Exfiltration | medium | 91801 |
| `110013` | 13 | `T1048` T1048 | Powershell DNSExfiltration | high | 91801 |
| `110014` | 13 | - | Suspicious PowerShell Mailbox Export to Share - PS | high | 91801 |
| `110015` | 12 | `T1020` T1020 | PowerShell Script With File Hostname Resolving Capabilities | medium | 91801 |
| `110016` | 12 | `T1567` T1567 | Arbitrary File Download Via ConfigSecurityPolicy.EXE | medium | 61603 |
| `110017` | 12 | `T1087.002` T1087.002 | Active Directory Structure Export Via Csvde.EXE | medium | 61603 |
| `110018` | 13 | `T1048.001` T1048.001 | DNS Exfiltration and Tunneling Tools Execution | high | 61603 |
| `110019` | 13 | `T1048.001` T1048.001 | DNS Exfiltration and Tunneling Tools Execution | high | 61603 |
| `110020` | 12 | - | Active Directory Structure Export Via Ldifde.EXE | medium | 61603 |
| `110021` | 12 | `T1567` T1567 | LOLBAS Data Exfiltration by DataSvcUtil.exe | medium | 61603 |
| `110022` | 13 | - | Email Exifiltration Via Powershell | high | 61603 |
| `110023` | 13 | - | Suspicious PowerShell Mailbox Export to Share | high | 61603 |
| `110024` | 13 | `T1567.002` T1567.002 | PUA - Rclone Execution | high | 61603 |
| `110025` | 13 | `T1048` T1048 | PUA - Restic Backup Tool Execution | high | 61603 |
| `110026` | 13 | `T1048` T1048 | PUA - Restic Backup Tool Execution | high | 61603 |
| `110027` | 13 | `T1048` T1048 | PUA - Restic Backup Tool Execution | high | 61603 |
| `110028` | 13 | `T1012` T1012 | Exports Critical Registry Keys To a File | high | 61603 |
| `110029` | 12 | `T1048.003` T1048.003 | WebDav Client Execution Via Rundll32.EXE | medium | 61603 |
| `110030` | 13 | `T1048.003` T1048.003 | Suspicious WebDav Client Execution Via Rundll32.EXE | high | 61603 |
| `110031` | 13 | `T1048` T1048 | Suspicious Redirection to Local Admin Share | high | 61603 |
| `110032` | 12 | `T1048` T1048 | Tap Installer Execution | medium | 61603 |

### Impact (TA0040) — 43 rules

| Rule ID | Level | Technique | Description | Confidence | Parent SID |
|---------|-------|-----------|-------------|------------|------------|
| `111000` | 13 | `T1490` T1490 | Suspicious command: shadow copy | medium | 61603 |
| `111001` | 13 | `T1489` Service Stop | Suspicious PowerShell: stop-service | medium | 91801 |
| `111002` | 13 | `T1070.004` T1070.004 | Potential Secure Deletion with SDelete | medium | 60100 |
| `111003` | 13 | `T1557` T1557 | ISATAP Router Address Was Set | medium | 60106 |
| `111004` | 14 | `T1499.001` T1499.001 | NTFS Vulnerability Exploitation | high | 60106 |
| `111005` | 13 | `T1490` T1490 | Backup Files Deleted | medium | 61625 |
| `111006` | 13 | `T1486` Data Encrypted for Impact | Suspicious Appended Extension | medium | 61613 |
| `111007` | 14 | `T1486` Data Encrypted for Impact | Load Of RstrtMgr.DLL By A Suspicious Process | high | 61609 |
| `111008` | 14 | `T1490` T1490 | Suspicious Volume Shadow Copy VSS_PS.dll Load | high | 61609 |
| `111009` | 14 | `T1490` T1490 | Suspicious Volume Shadow Copy Vssapi.dll Load | high | 61609 |
| `111010` | 13 | `T1490` T1490 | Potentially Suspicious Volume Shadow Copy Vsstrace.dll Load | medium | 61609 |
| `111011` | 14 | `T1496` T1496 | Network Communication With Crypto Mining Pool | high | 61605 |
| `111012` | 14 | `T1490` T1490 | Delete Volume Shadow Copies Via WMI With PowerShell | high | 91801 |
| `111013` | 14 | `T1565` T1565 | Powershell Add Name Resolution Policy Table Rule | high | 91801 |
| `111014` | 13 | `T1531` T1531 | Remove Account From Domain Admin Group | medium | 91801 |
| `111015` | 14 | `T1490` T1490 | Deletion of Volume Shadow Copies via WMI with PowerShell - PS Script | high | 91801 |
| `111016` | 14 | `T1490` T1490 | Boot Configuration Tampering Via Bcdedit.EXE | high | 61603 |
| `111017` | 13 | `T1485` Data Destruction | Deleted Data Overwritten Via Cipher.EXE | medium | 61603 |
| `111018` | 14 | `T1490` T1490 | Copy From VolumeShadowCopy Via Cmd.EXE | high | 61603 |
| `111019` | 14 | `T1070` Indicator Removal | Fsutil Suspicious Invocation | high | 61603 |
| `111020` | 13 | `T1486` Data Encrypted for Impact | Portable Gpg.EXE Execution | medium | 61603 |
| `111021` | 14 | `T1490` T1490 | Deletion of Volume Shadow Copies via WMI with PowerShell | high | 61603 |
| `111022` | 13 | `T1490` T1490 | Windows Recovery Environment Disabled Via Reagentc | medium | 61603 |
| `111023` | 14 | `T1486` Data Encrypted for Impact | Suspicious Reg Add BitLocker | high | 61603 |
| `111024` | 14 | `T1490` T1490 | System Restore Registry Modification via CommandLine | high | 61603 |
| `111025` | 14 | `T1486` Data Encrypted for Impact | Renamed Gpg.EXE Execution | high | 61603 |
| `111026` | 14 | `T1485` Data Destruction | Renamed Sysinternals Sdelete Execution | high | 61603 |
| `111027` | 14 | `T1489` Service Stop | Delete Important Scheduled Task | high | 61603 |
| `111028` | 14 | `T1489` Service Stop | Delete All Scheduled Tasks | high | 61603 |
| `111029` | 14 | `T1489` Service Stop | Disable Important Scheduled Task | high | 61603 |
| `111030` | 13 | `T1529` T1529 | Suspicious Execution of Shutdown | medium | 61603 |
| `111031` | 13 | `T1529` T1529 | Suspicious Execution of Shutdown to Log Out | medium | 61603 |
| `111032` | 14 | `T1496` T1496 | Potential Crypto Mining Activity | high | 61603 |
| `111033` | 14 | `T1490` T1490 | Sensitive File Access Via Volume Shadow Copy Backup | high | 61603 |
| `111034` | 14 | `T1489` Service Stop | Suspicious Windows Service Tampering | high | 61603 |
| `111035` | 14 | `T1070` Indicator Removal | Shadow Copies Deletion Using Operating Systems Utilities | high | 61603 |
| `111036` | 14 | `T1485` Data Destruction | Potential File Overwrite Via Sysinternals SDelete | high | 61603 |
| `111037` | 14 | `T1490` T1490 | All Backups Deleted Via Wbadmin.EXE | high | 61603 |
| `111038` | 13 | `T1490` T1490 | Windows Backup Deleted Via Wbadmin.EXE | medium | 61603 |
| `111039` | 13 | `T1490` T1490 | File Recovery From Backup Via Wbadmin.EXE | medium | 61603 |
| `111040` | 14 | `T1490` T1490 | Registry Disable System Restore | high | 61615 |
| `111041` | 13 | `T1490` T1490 | New Root or CA or AuthRoot Certificate to Store | medium | 61615 |
| `111042` | 14 | `T1491.001` T1491.001 | Potential Ransomware Activity Using LegalNotice Message | high | 61615 |

## Exported Rule Files

Rules are exported in three parallel views. Each view contains the same rules, organized differently:

### `database/rules/by_tactic/`
_One XML file per MITRE ATT&CK tactic. Best for broad deployment._

| File | Rules |
|------|-------|
| `collection.xml` | 50 |
| `command_and_control.xml` | 182 |
| `credential_access.xml` | 262 |
| `defense_evasion.xml` | 35 |
| `discovery.xml` | 135 |
| `execution.xml` | 981 |
| `exfiltration.xml` | 33 |
| `impact.xml` | 41 |
| `initial_access.xml` | 32 |
| `lateral_movement.xml` | 62 |
| `persistence.xml` | 305 |
| `privilege_escalation.xml` | 370 |

### `database/rules/by_technique/`
_One XML file per MITRE technique. Best for selective/granular deployment._

| File | Rules |
|------|-------|
| `T1001.003_unknown.xml` | 2 |
| `T1003.001_unknown.xml` | 78 |
| `T1003.002_unknown.xml` | 16 |
| `T1003.003_unknown.xml` | 18 |
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
| `T1021.002_unknown.xml` | 28 |
| `T1021.003_unknown.xml` | 4 |
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
| `T1036.003_unknown.xml` | 17 |
| `T1036.005_unknown.xml` | 8 |
| `T1036.007_unknown.xml` | 5 |
| `T1036_unknown.xml` | 43 |
| `T1037.001_unknown.xml` | 3 |
| `T1039_data_from_network_shared.xml` | 2 |
| `T1040_unknown.xml` | 8 |
| `T1041_exfil_over_c2.xml` | 1 |
| `T1046_unknown.xml` | 19 |
| `T1047_unknown.xml` | 34 |
| `T1048.001_unknown.xml` | 2 |
| `T1048.003_unknown.xml` | 4 |
| `T1048_exfil_over_alt_protocol.xml` | 8 |
| `T1049_unknown.xml` | 3 |
| `T1053.002_unknown.xml` | 2 |
| `T1053.005_unknown.xml` | 27 |
| `T1053_scheduled_task.xml` | 8 |
| `T1055.001_unknown.xml` | 5 |
| `T1055.003_unknown.xml` | 1 |
| `T1055.012_unknown.xml` | 3 |
| `T1055_process_injection.xml` | 54 |
| `T1056.001_unknown.xml` | 3 |
| `T1056.002_unknown.xml` | 4 |
| `T1057_unknown.xml` | 1 |
| `T1059.001_unknown.xml` | 108 |
| `T1059.003_unknown.xml` | 12 |
| `T1059.005_unknown.xml` | 8 |
| `T1059.006_unknown.xml` | 2 |
| `T1059.007_unknown.xml` | 1 |
| `T1059_command_scripting.xml` | 67 |
| `T1068_exploitation_for_privesc.xml` | 8 |
| `T1069.001_unknown.xml` | 1 |
| `T1070.003_unknown.xml` | 7 |
| `T1070.004_unknown.xml` | 7 |
| `T1070.005_unknown.xml` | 1 |
| `T1070.006_unknown.xml` | 1 |
| `T1070_indicator_removal.xml` | 24 |
| `T1071.001_unknown.xml` | 11 |
| `T1071.004_unknown.xml` | 5 |
| `T1071_application_layer_protocol.xml` | 2 |
| `T1072_unknown.xml` | 8 |
| `T1074.001_unknown.xml` | 3 |
| `T1078.002_unknown.xml` | 2 |
| `T1078_valid_accounts.xml` | 7 |
| `T1082_system_info_discovery.xml` | 18 |
| `T1083_file_directory_discovery.xml` | 3 |
| `T1087.001_unknown.xml` | 10 |
| `T1087.002_unknown.xml` | 13 |
| `T1087_account_discovery.xml` | 5 |
| `T1090.001_unknown.xml` | 10 |
| `T1090.003_unknown.xml` | 4 |
| `T1090_unknown.xml` | 17 |
| `T1095_unknown.xml` | 3 |
| `T1098_unknown.xml` | 8 |
| `T1102.002_unknown.xml` | 1 |
| `T1102_unknown.xml` | 7 |
| `T1105_ingress_tool_transfer.xml` | 37 |
| `T1106_unknown.xml` | 7 |
| `T1110.002_unknown.xml` | 2 |
| `T1110_brute_force.xml` | 1 |
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
| `T1197_unknown.xml` | 6 |
| `T1200_unknown.xml` | 1 |
| `T1201_unknown.xml` | 1 |
| `T1202_unknown.xml` | 17 |
| `T1203_unknown.xml` | 6 |
| `T1204.001_unknown.xml` | 1 |
| `T1204.002_unknown.xml` | 15 |
| `T1204.004_unknown.xml` | 2 |
| `T1204_user_execution.xml` | 2 |
| `T1207_unknown.xml` | 2 |
| `T1210_unknown.xml` | 3 |
| `T1211_unknown.xml` | 1 |
| `T1212_unknown.xml` | 2 |
| `T1216.001_unknown.xml` | 2 |
| `T1216_unknown.xml` | 10 |
| `T1218.001_unknown.xml` | 2 |
| `T1218.002_unknown.xml` | 1 |
| `T1218.003_unknown.xml` | 4 |
| `T1218.004_unknown.xml` | 2 |
| `T1218.005_unknown.xml` | 4 |
| `T1218.007_unknown.xml` | 7 |
| `T1218.008_unknown.xml` | 8 |
| `T1218.009_unknown.xml` | 3 |
| `T1218.010_unknown.xml` | 9 |
| `T1218.011_unknown.xml` | 26 |
| `T1218_unknown.xml` | 105 |
| `T1219.002_unknown.xml` | 52 |
| `T1219_unknown.xml` | 2 |
| `T1220_unknown.xml` | 3 |
| `T1222.001_unknown.xml` | 2 |
| `T1222_unknown.xml` | 1 |
| `T1482_unknown.xml` | 6 |
| `T1484.001_unknown.xml` | 6 |
| `T1485_data_destruction.xml` | 3 |
| `T1486_data_encrypted_for_impact.xml` | 5 |
| `T1489_service_stop.xml` | 4 |
| `T1490_unknown.xml` | 17 |
| `T1491.001_unknown.xml` | 1 |
| `T1496_unknown.xml` | 2 |
| `T1497.001_unknown.xml` | 1 |
| `T1499.001_unknown.xml` | 1 |
| `T1505.002_unknown.xml` | 1 |
| `T1505.003_unknown.xml` | 18 |
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
| `T1543_create_modify_service.xml` | 7 |
| `T1546.001_unknown.xml` | 1 |
| `T1546.002_unknown.xml` | 4 |
| `T1546.003_unknown.xml` | 9 |
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
| `T1554_unknown.xml` | 2 |
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
| `T1560.001_unknown.xml` | 7 |
| `T1562.001_unknown.xml` | 1 |
| `T1563.002_unknown.xml` | 2 |
| `T1564.001_unknown.xml` | 4 |
| `T1564.002_unknown.xml` | 1 |
| `T1564.003_unknown.xml` | 5 |
| `T1564.004_unknown.xml` | 18 |
| `T1564.006_unknown.xml` | 1 |
| `T1564_unknown.xml` | 4 |
| `T1565_unknown.xml` | 1 |
| `T1566.001_unknown.xml` | 10 |
| `T1566_phishing.xml` | 3 |
| `T1567.001_unknown.xml` | 1 |
| `T1567.002_unknown.xml` | 4 |
| `T1567_exfil_over_web_service.xml` | 7 |
| `T1569.002_unknown.xml` | 17 |
| `T1569_system_services.xml` | 2 |
| `T1571_unknown.xml` | 3 |
| `T1572_unknown.xml` | 14 |
| `T1574.001_unknown.xml` | 69 |
| `T1574.002_unknown.xml` | 5 |
| `T1574.005_unknown.xml` | 1 |
| `T1574.007_unknown.xml` | 1 |
| `T1574.008_unknown.xml` | 1 |
| `T1574.011_unknown.xml` | 9 |
| `T1574.012_unknown.xml` | 3 |
| `T1574_unknown.xml` | 4 |
| `T1587.001_unknown.xml` | 7 |
| `T1587_unknown.xml` | 3 |
| `T1588.002_unknown.xml` | 3 |
| `T1590.001_unknown.xml` | 3 |
| `T1590_unknown.xml` | 1 |
| `T1593.003_unknown.xml` | 1 |
| `T1595_unknown.xml` | 13 |
| `T1599.001_unknown.xml` | 2 |
| `T1614.001_unknown.xml` | 2 |
| `T1615_unknown.xml` | 6 |
| `T1620_unknown.xml` | 1 |
| `T1622_unknown.xml` | 6 |
| `T1649_unknown.xml` | 2 |
| `T1685.001_unknown.xml` | 18 |
| `T1685.005_unknown.xml` | 8 |
| `T1685_unknown.xml` | 75 |
| `T1686.003_unknown.xml` | 7 |
| `T1689_unknown.xml` | 1 |
| `unknown_collection.xml` | 1 |
| `unknown_command_and_control.xml` | 4 |
| `unknown_credential_access.xml` | 6 |
| `unknown_discovery.xml` | 14 |
| `unknown_execution.xml` | 126 |
| `unknown_exfiltration.xml` | 5 |
| `unknown_initial_access.xml` | 4 |
| `unknown_lateral_movement.xml` | 3 |
| `unknown_persistence.xml` | 36 |
| `unknown_privilege_escalation.xml` | 15 |

### `database/rules/by_source/`
_Grouped by Windows event source (Sysmon, Security, PowerShell, System). Aligns with Wazuh decoder structure._

| File | Rules |
|------|-------|
| `powershell.xml` | 204 |
| `security.xml` | 138 |
| `sysmon.xml` | 2053 |
| `system.xml` | 58 |

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
