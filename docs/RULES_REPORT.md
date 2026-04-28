# Wazuh Rule Database Report

> Generated: 2026-04-28 23:55 UTC
> Pipeline version: 1.0.0

## Overview

| Metric | Value |
|--------|-------|
| Total rules generated | **793** |
| EVTX files processed | 140 |
| EVTX sources used | 1 |
| MITRE tactics covered | 9 / 12 |
| MITRE techniques covered | 9 |
| Rule ID range | 100000 - 120000 |

## Alert Level Distribution

| Level | Wazuh Severity | Count | Percentage |
|-------|----------------|-------|------------|
| 4 | System low | 2 | 0.3%  |
| 6 | Low relevance | 7 | 0.9%  |
| 7 | Bad word matching | 13 | 1.6%  |
| 8 | First time seen | 551 | 69.5% ██████████████████████████████████ |
| 9 | Error from invalid source | 105 | 13.2% ██████ |
| 10 | Multiple user-generated errors | 55 | 6.9% ███ |
| 11 | Integrity checking warning | 26 | 3.3% █ |
| 12 | High importance event | 19 | 2.4% █ |
| 13 | Unusual error (high importance) | 15 | 1.9%  |

## Detection Confidence Distribution

| Confidence | Count | Description |
|------------|-------|-------------|
| high | 103 | Exact tool/process name match |
| medium | 662 | Command-line pattern or behavioral indicator |
| low | 28 | Heuristic / generic event |

## Rules by MITRE ATT&CK Tactic

### Initial Access (TA0001) — 1 rules

| Rule ID | Level | Technique | Description | Confidence | Parent SID |
|---------|-------|-----------|-------------|------------|------------|
| `100000` | 6 | `T1566` Phishing | Failed logon attempt | low | 60100 |

### Execution (TA0002) — 582 rules

| Rule ID | Level | Technique | Description | Confidence | Parent SID |
|---------|-------|-----------|-------------|------------|------------|
| `101000` | 9 | `T1059` Command and Scripting Interpreter | Suspicious process: rundll32 | high | 61603 |
| `101001` | 9 | `T1059` Command and Scripting Interpreter | Suspicious process: bitsadmin | high | 61603 |
| `101002` | 8 | `T1059` Command and Scripting Interpreter | Suspicious command: reg save | medium | 61603 |
| `101003` | 9 | `T1059` Command and Scripting Interpreter | Suspicious process: wmic | high | 61603 |
| `101004` | 9 | `T1059` Command and Scripting Interpreter | Suspicious process: regsvr32 | high | 61603 |
| `101005` | 9 | `T1059` Command and Scripting Interpreter | Suspicious process: certutil | high | 61603 |
| `101006` | 9 | `T1059` Command and Scripting Interpreter | Suspicious process: procdump | high | 61603 |
| `101007` | 9 | `T1059` Command and Scripting Interpreter | Suspicious process: installutil | high | 61603 |
| `101008` | 9 | `T1059` Command and Scripting Interpreter | Suspicious process: mshta | high | 61603 |
| `101009` | 8 | `T1059` Command and Scripting Interpreter | Suspicious command: iex( | medium | 61603 |
| `101010` | 9 | `T1059` Command and Scripting Interpreter | Suspicious process: cmstp | high | 61603 |
| `101011` | 9 | `T1059` Command and Scripting Interpreter | Network connection by rundll32 | high | 61605 |
| `101012` | 9 | `T1059` Command and Scripting Interpreter | Network connection by mshta | high | 61605 |
| `101013` | 9 | `T1059` Command and Scripting Interpreter | Network connection by mshta | high | 61605 |
| `101014` | 9 | `T1059` Command and Scripting Interpreter | Network connection by regsvr32 | high | 61605 |
| `101015` | 9 | `T1059` Command and Scripting Interpreter | Network connection by wmic | high | 61605 |
| `101016` | 9 | `T1059` Command and Scripting Interpreter | Network connection by wmic | high | 61605 |
| `101017` | 8 | `T1059` Command and Scripting Interpreter | Suspicious command: bypass | medium | 61603 |
| `101018` | 9 | `T1059` Command and Scripting Interpreter | Network connection by mshta | high | 61605 |
| `101019` | 9 | `T1059` Command and Scripting Interpreter | Suspicious process: psexec | high | 61603 |
| `101020` | 8 | `T1059` Command and Scripting Interpreter | DNS query by psexec | medium | 61624 |
| `101021` | 8 | `T1059` Command and Scripting Interpreter | Suspicious PowerShell: downloadstring | medium | 91801 |
| `101022` | 8 | `T1059` Command and Scripting Interpreter | Suspicious PowerShell: iex( | medium | 91801 |
| `101023` | 13 | `T1059` Command and Scripting Interpreter | Suspicious PowerShell: invoke-mimikatz | medium | 91801 |
| `101024` | 8 | `T1059` Command and Scripting Interpreter | Suspicious PowerShell: invoke-expression | medium | 91801 |
| `101025` | 8 | `T1059` Command and Scripting Interpreter | Suspicious PowerShell: bypass | medium | 91801 |
| `101026` | 8 | `T1059` Command and Scripting Interpreter | Suspicious PowerShell: -nop  | medium | 91801 |
| `101027` | 8 | `T1059` Command and Scripting Interpreter | Executable dropped in downloads | medium | 61613 |
| `101028` | 8 | `T1059` Command and Scripting Interpreter | Executable dropped in appdata | medium | 61613 |
| `101030` | 8 | `T1059` Command and Scripting Interpreter | Executable dropped in temp | medium | 61613 |
| `101037` | 8 | `T1059` Command and Scripting Interpreter | Suspicious command: procdump | medium | 61603 |
| `101038` | 8 | `T1059` Command and Scripting Interpreter | Suspicious command: ntdsutil | medium | 61603 |
| `101043` | 9 | `T1059` Command and Scripting Interpreter | DLL sideloading by msiexec | high | 61609 |
| `101045` | 8 | `T1059` Command and Scripting Interpreter | DLL loaded from suspicious path | medium | 61609 |
| `101048` | 8 | `T1059` Command and Scripting Interpreter | Executable dropped in programdata | medium | 61613 |
| `101055` | 8 | `T1059` Command and Scripting Interpreter | Suspicious command: shadow copy | medium | 61603 |
| `101057` | 8 | `T1059` Command and Scripting Interpreter | Scheduled task created | medium | 60100 |
| `101060` | 9 | `T1059` Command and Scripting Interpreter | Suspicious named pipe: \psexe | high | 61619 |
| `101061` | 9 | `T1059` Command and Scripting Interpreter | Suspicious named pipe: \psexe | high | 61620 |
| `101063` | 6 | `T1059` Command and Scripting Interpreter | Special privilege assignment | low | 60100 |
| `101064` | 6 | `T1059` Command and Scripting Interpreter | Remote logon (type 3) | low | 60100 |
| `101067` | 8 | `T1059` Command and Scripting Interpreter | PowerShell module: downloadstring | medium | 91801 |
| `101068` | 8 | `T1059` Command and Scripting Interpreter | PowerShell module: iex( | medium | 91801 |
| `101069` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101070` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101071` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101072` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101073` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101074` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101075` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101076` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101077` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101078` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101079` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101080` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101081` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101082` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101083` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101084` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101085` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101086` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101087` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101088` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101089` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101090` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101091` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101092` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101093` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101094` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101095` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101096` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101097` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101098` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101099` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101100` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101101` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101102` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101103` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101104` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101105` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101106` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101107` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101108` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101109` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101110` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101111` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101112` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101113` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101114` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101115` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101116` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101117` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101118` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101119` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101120` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101121` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101122` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101123` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101124` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101125` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101126` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101127` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101128` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101129` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101130` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101131` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101132` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101133` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101134` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101135` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101136` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101137` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101138` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101139` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101140` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101141` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101142` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101143` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101144` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101145` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101146` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101147` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101148` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101149` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101150` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101151` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101152` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101153` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101154` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101155` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101156` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101157` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101158` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101159` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101160` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101161` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101162` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101163` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101164` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101165` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101166` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101167` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101168` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101169` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101170` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101171` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101172` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101173` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101174` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101175` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101176` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101177` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101178` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101179` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101180` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101181` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101182` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101183` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101184` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101185` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101186` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101187` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101188` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101189` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101190` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101191` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101192` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101193` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101194` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101195` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101196` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101197` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101198` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101199` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101200` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101201` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101202` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101203` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101204` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101205` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101206` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101207` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101208` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101209` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101210` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101211` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101212` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101213` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101214` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101215` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101216` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101217` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101218` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101219` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101220` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101221` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101222` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101223` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101224` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101225` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101226` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101227` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101228` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101229` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101230` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101231` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101232` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101233` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101234` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101235` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101236` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101237` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101238` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101239` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101240` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101241` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101242` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101243` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101244` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101245` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101246` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101247` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101248` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101249` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101250` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101251` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101252` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101253` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101254` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101255` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101256` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101257` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101258` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101259` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101260` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101261` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101262` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101263` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101264` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101265` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101266` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101267` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101268` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101269` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101270` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101271` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101272` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101273` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101274` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101275` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101276` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101277` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101278` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101279` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101280` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101281` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101282` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101283` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101284` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101285` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101286` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101287` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101288` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101289` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101290` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101291` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101292` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101293` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101294` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101295` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101296` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101297` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101298` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101299` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101300` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101301` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101302` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101303` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101304` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101305` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101306` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101307` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101308` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101309` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101310` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101311` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101312` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101313` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101314` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101315` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101316` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101317` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101318` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101319` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101320` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101321` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101322` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101323` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101324` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101325` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101326` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101327` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101328` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101329` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101330` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101331` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101332` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101333` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101334` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101335` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101336` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101337` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101338` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101339` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101340` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101341` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101342` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101343` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101344` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101345` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101346` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101347` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101348` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101349` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101350` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101351` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101352` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101353` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101354` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101355` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101356` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101357` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101358` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101359` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101360` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101361` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101362` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101363` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101364` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101365` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101366` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101367` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101368` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101369` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101370` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101371` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101372` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101373` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101374` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101375` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101376` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101377` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101378` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101379` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101380` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101381` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101382` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101383` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101384` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101385` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101386` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101387` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101388` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101389` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101390` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101391` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101392` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101393` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101394` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101395` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101396` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101397` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101398` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101399` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101400` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101401` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101402` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101403` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101404` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101405` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101406` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101407` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101408` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101409` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101410` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101411` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101412` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101413` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101414` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101415` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101416` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101417` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101418` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101419` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101420` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101421` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101422` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101423` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101424` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101425` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101426` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101427` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101428` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101429` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101430` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101431` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101432` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101433` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101434` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101435` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101436` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101437` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101438` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101439` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101440` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101441` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101442` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101443` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101444` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101445` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101446` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101447` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101448` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101449` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101450` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101451` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101452` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101453` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101454` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101455` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101456` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101457` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101458` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101459` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101460` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101461` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101462` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101463` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101464` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101465` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101466` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101467` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101468` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101469` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101470` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101471` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101472` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101473` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101474` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101475` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101476` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101477` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101478` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101479` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101480` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101481` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101482` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101483` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101484` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101485` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101486` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101487` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101488` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101489` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101490` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101491` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101492` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101493` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101494` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101495` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101496` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101497` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101498` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101499` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101500` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101501` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101502` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101503` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101504` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101505` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101506` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101507` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101508` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101509` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101510` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101511` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101512` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101513` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101514` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101515` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101516` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101517` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101518` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101519` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101520` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101521` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101522` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101523` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101524` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101525` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101526` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101527` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101528` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101529` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101530` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101531` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101532` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101533` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101534` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101535` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101536` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101537` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101538` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101539` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101540` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101541` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101542` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101543` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101544` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101545` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101546` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101547` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101548` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101549` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101550` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101551` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101552` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101553` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101554` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101555` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: cmd.exe /c | medium | 60106 |
| `101556` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: powershell | medium | 60106 |
| `101557` | 8 | `T1059` Command and Scripting Interpreter | WMI event subscription (EventID 20) | medium | 61622 |
| `101558` | 8 | `T1059` Command and Scripting Interpreter | WMI event subscription (EventID 19) | medium | 61621 |
| `101559` | 6 | `T1059` Command and Scripting Interpreter | Explicit credential logon | low | 60100 |
| `101560` | 8 | `T1059` Command and Scripting Interpreter | PowerShell module: bypass | medium | 91801 |
| `101561` | 8 | `T1059` Command and Scripting Interpreter | PowerShell module: invoke-expression | medium | 91801 |
| `101562` | 8 | `T1059` Command and Scripting Interpreter | PowerShell module: procdump | medium | 91801 |
| `101563` | 8 | `T1059` Command and Scripting Interpreter | PowerShell module: -nop  | medium | 91801 |
| `101564` | 8 | `T1059` Command and Scripting Interpreter | PowerShell module: -w hidden | medium | 91801 |
| `101565` | 9 | `T1059` Command and Scripting Interpreter | Suspicious process: psexesvc | high | 61603 |
| `101568` | 8 | `T1059` Command and Scripting Interpreter | Suspicious PowerShell: -w hidden | medium | 91801 |
| `101569` | 8 | `T1059` Command and Scripting Interpreter | Suspicious command: invoke-expression | medium | 61603 |
| `101570` | 8 | `T1059` Command and Scripting Interpreter | Suspicious command: -nop  | medium | 61603 |
| `101571` | 8 | `T1059` Command and Scripting Interpreter | Suspicious command: -w hidden | medium | 61603 |
| `101573` | 13 | `T1059` Command and Scripting Interpreter | PowerShell module: sekurlsa:: | medium | 91801 |
| `101574` | 13 | `T1059` Command and Scripting Interpreter | Suspicious PowerShell: sekurlsa:: | medium | 91801 |
| `101575` | 13 | `T1059` Command and Scripting Interpreter | Suspicious command: sekurlsa:: | medium | 61603 |
| `101576` | 13 | `T1059` Command and Scripting Interpreter | Suspicious command: lsadump:: | medium | 61603 |
| `101577` | 13 | `T1059` Command and Scripting Interpreter | PowerShell module: lsadump:: | medium | 91801 |
| `101578` | 13 | `T1059` Command and Scripting Interpreter | Suspicious PowerShell: lsadump:: | medium | 91801 |
| `101579` | 13 | `T1059` Command and Scripting Interpreter | PowerShell module: invoke-mimikatz | medium | 91801 |
| `101580` | 8 | `T1059` Command and Scripting Interpreter | PowerShell module: kerberos:: | medium | 91801 |
| `101582` | 8 | `T1059` Command and Scripting Interpreter | Suspicious PowerShell: kerberos:: | medium | 91801 |
| `101583` | 8 | `T1059` Command and Scripting Interpreter | PowerShell module: net user | medium | 91801 |
| `101584` | 8 | `T1059` Command and Scripting Interpreter | Suspicious PowerShell: net user | medium | 91801 |
| `101585` | 8 | `T1059` Command and Scripting Interpreter | Suspicious command: dumpert | medium | 61603 |
| `101586` | 13 | `T1059` Command and Scripting Interpreter | Suspicious process: mimikatz | high | 61603 |
| `101587` | 8 | `T1059` Command and Scripting Interpreter | Suspicious PowerShell: stop-service | medium | 91801 |
| `101588` | 8 | `T1059` Command and Scripting Interpreter | PowerShell module: stop-service | medium | 91801 |
| `101589` | 9 | `T1059` Command and Scripting Interpreter | Suspicious process: seatbelt | high | 61603 |
| `101590` | 8 | `T1059` Command and Scripting Interpreter | PowerShell module: invoke-wmimethod | medium | 91801 |
| `101591` | 9 | `T1059` Command and Scripting Interpreter | Suspicious named pipe: \ntsvcs | high | 61619 |
| `101592` | 9 | `T1059` Command and Scripting Interpreter | Suspicious named pipe: \scerpc | high | 61619 |
| `101593` | 8 | `T1059` Command and Scripting Interpreter | Suspicious service path: programdata\ | medium | 60106 |
| `101594` | 8 | `T1059` Command and Scripting Interpreter | PowerShell module: net localgroup | medium | 91801 |
| `101595` | 8 | `T1059` Command and Scripting Interpreter | PowerShell module: reg save | medium | 91801 |
| `101596` | 9 | `T1059` Command and Scripting Interpreter | Suspicious process: rubeus | high | 61603 |
| `101597` | 8 | `T1059` Command and Scripting Interpreter | Suspicious command: net user | medium | 61603 |
| `101598` | 8 | `T1059` Command and Scripting Interpreter | Suspicious command: comsvcs.dll | medium | 61603 |
| `101599` | 8 | `T1059` Command and Scripting Interpreter | Suspicious command: minidump | medium | 61603 |
| `101600` | 8 | `T1059` Command and Scripting Interpreter | PowerShell module: comsvcs.dll | medium | 91801 |
| `101601` | 8 | `T1059` Command and Scripting Interpreter | PowerShell module: minidump | medium | 91801 |
| `101602` | 9 | `T1059` Command and Scripting Interpreter | Suspicious process: nanodump | high | 61603 |
| `101603` | 8 | `T1059` Command and Scripting Interpreter | Suspicious command: nanodump | medium | 61603 |
| `101604` | 8 | `T1059` Command and Scripting Interpreter | Suspicious PowerShell: minidump | medium | 91801 |
| `101605` | 8 | `T1059` Command and Scripting Interpreter | Suspicious PowerShell: out-minidump | medium | 91801 |
| `101606` | 8 | `T1059` Command and Scripting Interpreter | PowerShell module: invoke-webrequest | medium | 91801 |
| `101607` | 8 | `T1059` Command and Scripting Interpreter | PowerShell module: out-minidump | medium | 91801 |
| `101608` | 8 | `T1059` Command and Scripting Interpreter | Suspicious PowerShell: procdump | medium | 91801 |
| `101609` | 8 | `T1059` Command and Scripting Interpreter | Suspicious command: sharpdump | medium | 61603 |
| `101614` | 8 | `T1059` Command and Scripting Interpreter | Suspicious PowerShell: invoke-obfuscation | medium | 91801 |
| `101615` | 8 | `T1059` Command and Scripting Interpreter | DLL loaded from suspicious path | medium | 61609 |

### Persistence (TA0003) — 70 rules

| Rule ID | Level | Technique | Description | Confidence | Parent SID |
|---------|-------|-----------|-------------|------------|------------|
| `102000` | 9 | `T1547` Boot or Logon Autostart Execution | Registry persistence via currentversion\run | medium | 61615 |
| `102001` | 9 | `T1547` Boot or Logon Autostart Execution | Registry persistence via currentversion\run | medium | 61614 |
| `102002` | 9 | `T1547` Boot or Logon Autostart Execution | Registry persistence via currentversion\runonce | medium | 61615 |
| `102003` | 9 | `T1547` Boot or Logon Autostart Execution | Registry persistence via currentversion\runonce | medium | 61614 |
| `102004` | 9 | `T1547` Boot or Logon Autostart Execution | Registry persistence via userinit | medium | 61615 |
| `102005` | 9 | `T1547` Boot or Logon Autostart Execution | Registry persistence via shell | medium | 61615 |
| `102006` | 9 | `T1547` Boot or Logon Autostart Execution | Registry persistence via shell | medium | 61614 |
| `102007` | 10 | `T1547` Boot or Logon Autostart Execution | Suspicious process: psexesvc | high | 61603 |
| `102008` | 10 | `T1547` Boot or Logon Autostart Execution | Suspicious process: rundll32 | high | 61603 |
| `102009` | 9 | `T1547` Boot or Logon Autostart Execution | Registry persistence via winlogon\ | medium | 61615 |
| `102010` | 10 | `T1547` Boot or Logon Autostart Execution | Suspicious process: regsvr32 | high | 61603 |
| `102011` | 10 | `T1547` Boot or Logon Autostart Execution | Network connection by regsvr32 | high | 61605 |
| `102012` | 10 | `T1547` Boot or Logon Autostart Execution | Suspicious process: wmic | high | 61603 |
| `102013` | 10 | `T1547` Boot or Logon Autostart Execution | Suspicious service: PSEXESVC | high | 60106 |
| `102014` | 13 | `T1547` Boot or Logon Autostart Execution | Suspicious service: mimikatz driver (mimidrv) | high | 60106 |
| `102017` | 9 | `T1547` Boot or Logon Autostart Execution | DLL loaded from suspicious path | medium | 61609 |
| `102022` | 9 | `T1547` Boot or Logon Autostart Execution | WMI event subscription (EventID 19) | medium | 61621 |
| `102023` | 9 | `T1547` Boot or Logon Autostart Execution | WMI event subscription (EventID 20) | medium | 61622 |
| `102024` | 9 | `T1547` Boot or Logon Autostart Execution | WMI event subscription (EventID 21) | medium | 61623 |
| `102025` | 9 | `T1547` Boot or Logon Autostart Execution | File created by certutil | medium | 61613 |
| `102029` | 7 | `T1547` Boot or Logon Autostart Execution | Member added to group | low | 60100 |
| `102030` | 9 | `T1547` Boot or Logon Autostart Execution | Executable dropped in programdata | medium | 61613 |
| `102031` | 9 | `T1547` Boot or Logon Autostart Execution | Executable dropped in downloads | medium | 61613 |
| `102032` | 9 | `T1547` Boot or Logon Autostart Execution | DLL loaded from suspicious path | medium | 61609 |
| `102033` | 9 | `T1547` Boot or Logon Autostart Execution | Executable dropped in temp | medium | 61613 |
| `102036` | 9 | `T1547` Boot or Logon Autostart Execution | Executable dropped in appdata | medium | 61613 |
| `102041` | 9 | `T1547` Boot or Logon Autostart Execution | WMI event subscription (EventID 20) | medium | 61622 |
| `102042` | 9 | `T1547` Boot or Logon Autostart Execution | WMI event subscription (EventID 21) | medium | 61623 |
| `102043` | 9 | `T1547` Boot or Logon Autostart Execution | WMI event subscription (EventID 19) | medium | 61621 |
| `102044` | 9 | `T1547` Boot or Logon Autostart Execution | WMI event subscription (EventID 20) | medium | 61622 |
| `102045` | 9 | `T1547` Boot or Logon Autostart Execution | WMI event subscription (EventID 21) | medium | 61623 |
| `102046` | 9 | `T1547` Boot or Logon Autostart Execution | Scheduled task created | medium | 60100 |
| `102047` | 9 | `T1547` Boot or Logon Autostart Execution | User account created | medium | 60100 |
| `102048` | 7 | `T1547` Boot or Logon Autostart Execution | Remote logon (type 3) | low | 60100 |
| `102049` | 9 | `T1547` Boot or Logon Autostart Execution | Account renamed | medium | 60100 |
| `102052` | 9 | `T1547` Boot or Logon Autostart Execution | Registry persistence via currentversion\explorer\shell | medium | 61614 |
| `102055` | 9 | `T1547` Boot or Logon Autostart Execution | WMI event subscription (EventID 19) | medium | 61621 |
| `102056` | 9 | `T1547` Boot or Logon Autostart Execution | WMI event subscription (EventID 20) | medium | 61622 |
| `102057` | 9 | `T1547` Boot or Logon Autostart Execution | File created by mshta | medium | 61613 |
| `102058` | 9 | `T1547` Boot or Logon Autostart Execution | File created by psexec | medium | 61613 |
| `102059` | 9 | `T1547` Boot or Logon Autostart Execution | WMI event subscription (EventID 19) | medium | 61621 |
| `102060` | 9 | `T1547` Boot or Logon Autostart Execution | WMI event subscription (EventID 20) | medium | 61622 |
| `102061` | 9 | `T1547` Boot or Logon Autostart Execution | WMI event subscription (EventID 21) | medium | 61623 |
| `102062` | 7 | `T1547` Boot or Logon Autostart Execution | Special privilege assignment | low | 60100 |
| `102063` | 9 | `T1547` Boot or Logon Autostart Execution | PowerShell module: invoke-expression | medium | 91801 |
| `102064` | 10 | `T1547` Boot or Logon Autostart Execution | Suspicious named pipe: \ntsvcs | high | 61619 |
| `102065` | 10 | `T1547` Boot or Logon Autostart Execution | Suspicious named pipe: \scerpc | high | 61619 |
| `102066` | 9 | `T1547` Boot or Logon Autostart Execution | Suspicious service path: powershell | medium | 60106 |
| `102067` | 9 | `T1547` Boot or Logon Autostart Execution | File created by rubeus | medium | 61613 |
| `102068` | 9 | `T1547` Boot or Logon Autostart Execution | Suspicious service path: powershell | medium | 60106 |
| `102069` | 9 | `T1547` Boot or Logon Autostart Execution | WMI event subscription (EventID 19) | medium | 61621 |
| `102070` | 9 | `T1547` Boot or Logon Autostart Execution | WMI event subscription (EventID 20) | medium | 61622 |
| `102071` | 9 | `T1547` Boot or Logon Autostart Execution | WMI event subscription (EventID 21) | medium | 61623 |
| `102072` | 10 | `T1547` Boot or Logon Autostart Execution | Suspicious service: qfhaer | high | 60106 |
| `102073` | 10 | `T1547` Boot or Logon Autostart Execution | Suspicious service: rtcpef | high | 60106 |
| `102074` | 9 | `T1547` Boot or Logon Autostart Execution | File created by nanodump | medium | 61613 |
| `102075` | 9 | `T1547` Boot or Logon Autostart Execution | File created by procdump | medium | 61613 |
| `102076` | 7 | `T1547` Boot or Logon Autostart Execution | Security group created | low | 60100 |
| `102077` | 7 | `T1547` Boot or Logon Autostart Execution | Security group changed | low | 60100 |
| `102078` | 9 | `T1547` Boot or Logon Autostart Execution | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102079` | 9 | `T1547` Boot or Logon Autostart Execution | Suspicious service path: powershell | medium | 60106 |
| `102080` | 9 | `T1547` Boot or Logon Autostart Execution | Suspicious service path: powershell | medium | 60106 |
| `102081` | 9 | `T1547` Boot or Logon Autostart Execution | Suspicious service path: powershell | medium | 60106 |
| `102082` | 9 | `T1547` Boot or Logon Autostart Execution | Suspicious service path: powershell | medium | 60106 |
| `102083` | 9 | `T1547` Boot or Logon Autostart Execution | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102084` | 9 | `T1547` Boot or Logon Autostart Execution | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102085` | 9 | `T1547` Boot or Logon Autostart Execution | Suspicious service path: powershell | medium | 60106 |
| `102086` | 9 | `T1547` Boot or Logon Autostart Execution | Suspicious service path: cmd.exe /c | medium | 60106 |
| `102087` | 9 | `T1547` Boot or Logon Autostart Execution | Suspicious service path: powershell | medium | 60106 |
| `102088` | 9 | `T1547` Boot or Logon Autostart Execution | Suspicious service path: cmd.exe /c | medium | 60106 |

### Privilege Escalation (TA0004) — 18 rules

| Rule ID | Level | Technique | Description | Confidence | Parent SID |
|---------|-------|-----------|-------------|------------|------------|
| `103000` | 11 | `T1548` Abuse Elevation Control Mechanism | Suspicious process: rundll32 | high | 61603 |
| `103001` | 10 | `T1548` Abuse Elevation Control Mechanism | Suspicious command: bypass | medium | 61603 |
| `103002` | 11 | `T1548` Abuse Elevation Control Mechanism | Suspicious process: cmstp | high | 61603 |
| `103003` | 11 | `T1548` Abuse Elevation Control Mechanism | Suspicious process: psexec | high | 61603 |
| `103004` | 11 | `T1548` Abuse Elevation Control Mechanism | Suspicious process: psexesvc | high | 61603 |
| `103005` | 10 | `T1548` Abuse Elevation Control Mechanism | DLL loaded from suspicious path | medium | 61609 |
| `103006` | 8 | `T1548` Abuse Elevation Control Mechanism | Special privilege assignment | low | 60100 |
| `103007` | 8 | `T1548` Abuse Elevation Control Mechanism | Remote logon (type 3) | low | 60100 |
| `103008` | 10 | `T1548` Abuse Elevation Control Mechanism | Scheduled task created | medium | 60100 |
| `103009` | 8 | `T1548` Abuse Elevation Control Mechanism | Explicit credential logon | low | 60100 |
| `103010` | 10 | `T1548` Abuse Elevation Control Mechanism | Executable dropped in temp | medium | 61613 |
| `103011` | 10 | `T1548` Abuse Elevation Control Mechanism | Executable dropped in appdata | medium | 61613 |
| `103012` | 10 | `T1548` Abuse Elevation Control Mechanism | DLL loaded from suspicious path | medium | 61609 |
| `103014` | 10 | `T1548` Abuse Elevation Control Mechanism | Account renamed | medium | 60100 |
| `103018` | 11 | `T1548` Abuse Elevation Control Mechanism | Suspicious named pipe: \psexe | high | 61619 |
| `103020` | 11 | `T1548` Abuse Elevation Control Mechanism | Suspicious named pipe: \psexe | high | 61620 |
| `103021` | 10 | `T1548` Abuse Elevation Control Mechanism | Executable dropped in public | medium | 61613 |
| `103022` | 10 | `T1548` Abuse Elevation Control Mechanism | DLL loaded from suspicious path | medium | 61609 |

### Defense Evasion (TA0005) — 37 rules

| Rule ID | Level | Technique | Description | Confidence | Parent SID |
|---------|-------|-----------|-------------|------------|------------|
| `104000` | 10 | `T1055` Process Injection | Suspicious process: rundll32 | high | 61603 |
| `104001` | 10 | `T1055` Process Injection | Network connection by rundll32 | high | 61605 |
| `104002` | 10 | `T1055` Process Injection | Suspicious process: regsvr32 | high | 61603 |
| `104003` | 9 | `T1055` Process Injection | Suspicious command: bypass | medium | 61603 |
| `104004` | 9 | `T1055` Process Injection | Suspicious command: -nop  | medium | 61603 |
| `104005` | 9 | `T1055` Process Injection | Suspicious PowerShell: set-mppreference -disablerealtimemonitoring | medium | 91801 |
| `104006` | 9 | `T1055` Process Injection | Suspicious PowerShell: bypass | medium | 91801 |
| `104007` | 9 | `T1055` Process Injection | DLL loaded from suspicious path | medium | 61609 |
| `104008` | 9 | `T1055` Process Injection | DLL loaded from suspicious path | medium | 61609 |
| `104010` | 10 | `T1055` Process Injection | DLL sideloading by mshta | high | 61609 |
| `104012` | 9 | `T1055` Process Injection | User account created | medium | 60100 |
| `104013` | 9 | `T1055` Process Injection | Executable dropped in downloads | medium | 61613 |
| `104014` | 9 | `T1055` Process Injection | DLL loaded from suspicious path | medium | 61609 |
| `104015` | 7 | `T1055` Process Injection | Remote logon (type 3) | low | 60100 |
| `104018` | 9 | `T1055` Process Injection | DLL loaded from suspicious path | medium | 61609 |
| `104019` | 9 | `T1055` Process Injection | Executable dropped in programdata | medium | 61613 |
| `104020` | 9 | `T1055` Process Injection | Executable dropped in appdata | medium | 61613 |
| `104022` | 9 | `T1055` Process Injection | Account renamed | medium | 60100 |
| `104025` | 13 | `T1055` Process Injection | PowerShell module: invoke-mimikatz | medium | 91801 |
| `104026` | 9 | `T1055` Process Injection | PowerShell module: invoke-expression | medium | 91801 |
| `104027` | 9 | `T1055` Process Injection | PowerShell module: downloadstring | medium | 91801 |
| `104028` | 13 | `T1055` Process Injection | PowerShell module: sekurlsa:: | medium | 91801 |
| `104029` | 9 | `T1055` Process Injection | Executable dropped in temp | medium | 61613 |
| `104030` | 7 | `T1055` Process Injection | Special privilege assignment | low | 60100 |
| `104033` | 10 | `T1055` Process Injection | DLL sideloading by psexec | high | 61609 |
| `104034` | 10 | `T1055` Process Injection | DLL sideloading by psexesvc | high | 61609 |
| `104035` | 9 | `T1055` Process Injection | DLL loaded from suspicious path | medium | 61609 |
| `104036` | 10 | `T1055` Process Injection | DLL sideloading by certutil | high | 61609 |
| `104037` | 10 | `T1055` Process Injection | DLL sideloading by bitsadmin | high | 61609 |
| `104038` | 10 | `T1055` Process Injection | Process tampering (Image is locked for access) | high | 61627 |
| `104039` | 10 | `T1055` Process Injection | DLL sideloading by seatbelt | high | 61609 |
| `104040` | 10 | `T1055` Process Injection | DLL sideloading by installutil | high | 61609 |
| `104041` | 10 | `T1055` Process Injection | DLL sideloading by wmic | high | 61609 |
| `104042` | 10 | `T1055` Process Injection | DLL sideloading by rubeus | high | 61609 |
| `104043` | 10 | `T1055` Process Injection | DLL sideloading by nanodump | high | 61609 |
| `104044` | 10 | `T1055` Process Injection | DLL sideloading by procdump | high | 61609 |
| `104045` | 13 | `T1055` Process Injection | DLL sideloading by mimikatz | high | 61609 |

### Credential Access (TA0006) — 34 rules

| Rule ID | Level | Technique | Description | Confidence | Parent SID |
|---------|-------|-----------|-------------|------------|------------|
| `105000` | 12 | `T1003` OS Credential Dumping | LSASS memory access | high | 61612 |
| `105001` | 9 | `T1003` OS Credential Dumping | Failed logon attempt | low | 60100 |
| `105002` | 12 | `T1003` OS Credential Dumping | Remote thread injection into LSASS | high | 61610 |
| `105003` | 12 | `T1003` OS Credential Dumping | LSASS memory access | high | 61612 |
| `105004` | 11 | `T1003` OS Credential Dumping | Suspicious command: -nop  | medium | 61603 |
| `105005` | 12 | `T1003` OS Credential Dumping | LSASS memory access | high | 61612 |
| `105006` | 12 | `T1003` OS Credential Dumping | LSASS memory access | high | 61612 |
| `105007` | 12 | `T1003` OS Credential Dumping | LSASS memory access | high | 61612 |
| `105008` | 12 | `T1003` OS Credential Dumping | Suspicious process: rundll32 | high | 61603 |
| `105009` | 12 | `T1003` OS Credential Dumping | LSASS memory access | high | 61612 |
| `105010` | 12 | `T1003` OS Credential Dumping | LSASS memory access | high | 61612 |
| `105011` | 13 | `T1003` OS Credential Dumping | Suspicious process: mimikatz | high | 61603 |
| `105014` | 11 | `T1003` OS Credential Dumping | DLL loaded from suspicious path | medium | 61609 |
| `105017` | 11 | `T1003` OS Credential Dumping | Suspicious PowerShell: minidump | medium | 91801 |
| `105018` | 9 | `T1003` OS Credential Dumping | Remote logon (type 3) | low | 60100 |
| `105023` | 9 | `T1003` OS Credential Dumping | Special privilege assignment | low | 60100 |
| `105024` | 11 | `T1003` OS Credential Dumping | File created by procdump | medium | 61613 |
| `105025` | 11 | `T1003` OS Credential Dumping | Suspicious command: dumpert | medium | 61603 |
| `105028` | 11 | `T1003` OS Credential Dumping | Suspicious command: comsvcs.dll | medium | 61603 |
| `105029` | 11 | `T1003` OS Credential Dumping | Suspicious command: minidump | medium | 61603 |
| `105033` | 11 | `T1003` OS Credential Dumping | Suspicious PowerShell: comsvcs.dll | medium | 91801 |
| `105034` | 11 | `T1003` OS Credential Dumping | Suspicious PowerShell: invoke-wmimethod | medium | 91801 |
| `105035` | 11 | `T1003` OS Credential Dumping | Suspicious PowerShell: stop-service | medium | 91801 |
| `105036` | 9 | `T1003` OS Credential Dumping | Explicit credential logon | low | 60100 |
| `105037` | 12 | `T1003` OS Credential Dumping | LSASS memory access | high | 61612 |
| `105038` | 12 | `T1003` OS Credential Dumping | LSASS memory access | high | 61612 |
| `105039` | 12 | `T1003` OS Credential Dumping | LSASS memory access | high | 61612 |
| `105040` | 12 | `T1003` OS Credential Dumping | LSASS memory access | high | 61612 |
| `105041` | 12 | `T1003` OS Credential Dumping | LSASS memory access | high | 61612 |
| `105042` | 12 | `T1003` OS Credential Dumping | LSASS memory access | high | 61612 |
| `105043` | 12 | `T1003` OS Credential Dumping | LSASS memory access | high | 61612 |
| `105044` | 12 | `T1003` OS Credential Dumping | LSASS memory access | high | 61612 |
| `105045` | 12 | `T1003` OS Credential Dumping | LSASS memory access | high | 61612 |
| `105046` | 12 | `T1003` OS Credential Dumping | LSASS memory access | high | 61612 |

### Discovery (TA0007) — 7 rules

| Rule ID | Level | Technique | Description | Confidence | Parent SID |
|---------|-------|-----------|-------------|------------|------------|
| `106000` | 6 | `T1087` Account Discovery | Suspicious PowerShell: invoke-expression | medium | 91801 |
| `106001` | 6 | `T1087` Account Discovery | Suspicious PowerShell: invoke-webrequest | medium | 91801 |
| `106002` | 6 | `T1087` Account Discovery | Suspicious PowerShell: bypass | medium | 91801 |
| `106003` | 7 | `T1087` Account Discovery | Suspicious named pipe: \ntsvcs | high | 61620 |
| `106004` | 7 | `T1087` Account Discovery | Suspicious named pipe: \scerpc | high | 61620 |
| `106005` | 4 | `T1087` Account Discovery | Special privilege assignment | low | 60100 |
| `106006` | 4 | `T1087` Account Discovery | Remote logon (type 3) | low | 60100 |

### Lateral Movement (TA0008) — 24 rules

| Rule ID | Level | Technique | Description | Confidence | Parent SID |
|---------|-------|-----------|-------------|------------|------------|
| `107000` | 11 | `T1021` Remote Services | Suspicious process: mshta | high | 61603 |
| `107001` | 11 | `T1021` Remote Services | Network connection by mshta | high | 61605 |
| `107002` | 10 | `T1021` Remote Services | Suspicious command: -nop  | medium | 61603 |
| `107003` | 10 | `T1021` Remote Services | Suspicious command: -w hidden | medium | 61603 |
| `107004` | 10 | `T1021` Remote Services | Suspicious command: net user | medium | 61603 |
| `107005` | 11 | `T1021` Remote Services | Suspicious process: rundll32 | high | 61603 |
| `107006` | 11 | `T1021` Remote Services | Suspicious process: psexesvc | high | 61603 |
| `107007` | 10 | `T1021` Remote Services | Suspicious PowerShell: bypass | medium | 91801 |
| `107008` | 8 | `T1021` Remote Services | Remote logon (type 3) | low | 60100 |
| `107009` | 8 | `T1021` Remote Services | Special privilege assignment | low | 60100 |
| `107012` | 10 | `T1021` Remote Services | Scheduled task created | medium | 60100 |
| `107013` | 8 | `T1021` Remote Services | Explicit credential logon | low | 60100 |
| `107014` | 11 | `T1021` Remote Services | Suspicious named pipe: \ntsvcs | high | 61620 |
| `107018` | 10 | `T1021` Remote Services | Executable dropped in programdata | medium | 61613 |
| `107019` | 10 | `T1021` Remote Services | Executable dropped in appdata | medium | 61613 |
| `107023` | 10 | `T1021` Remote Services | DLL loaded from suspicious path | medium | 61609 |
| `107025` | 10 | `T1021` Remote Services | DLL loaded from suspicious path | medium | 61609 |
| `107026` | 10 | `T1021` Remote Services | Executable dropped in temp | medium | 61613 |
| `107027` | 8 | `T1021` Remote Services | Failed logon attempt | low | 60100 |
| `107028` | 11 | `T1021` Remote Services | Suspicious named pipe: \psexe | high | 61619 |
| `107029` | 11 | `T1021` Remote Services | Suspicious named pipe: \psexe | high | 61620 |
| `107030` | 11 | `T1021` Remote Services | Suspicious named pipe: \ntsvcs | high | 61619 |
| `107031` | 11 | `T1021` Remote Services | Suspicious named pipe: \scerpc | high | 61619 |
| `107032` | 11 | `T1021` Remote Services | Suspicious named pipe: \scerpc | high | 61620 |

### Command and Control (TA0011) — 20 rules

| Rule ID | Level | Technique | Description | Confidence | Parent SID |
|---------|-------|-----------|-------------|------------|------------|
| `109000` | 10 | `T1071` Application Layer Protocol | Network connection by regsvr32 | high | 61605 |
| `109001` | 10 | `T1071` Application Layer Protocol | Network connection by mshta | high | 61605 |
| `109002` | 10 | `T1071` Application Layer Protocol | Network connection by mshta | high | 61605 |
| `109003` | 10 | `T1071` Application Layer Protocol | Network connection by wmic | high | 61605 |
| `109004` | 10 | `T1071` Application Layer Protocol | Network connection by rundll32 | high | 61605 |
| `109005` | 10 | `T1071` Application Layer Protocol | Network connection by certutil | high | 61605 |
| `109012` | 7 | `T1071` Application Layer Protocol | Explicit credential logon | low | 60100 |
| `109013` | 7 | `T1071` Application Layer Protocol | Special privilege assignment | low | 60100 |
| `109014` | 7 | `T1071` Application Layer Protocol | Remote logon (type 3) | low | 60100 |
| `109015` | 7 | `T1071` Application Layer Protocol | Remote logon (type 10) | low | 60100 |
| `109016` | 9 | `T1071` Application Layer Protocol | DNS query by psexec | medium | 61624 |
| `109017` | 10 | `T1071` Application Layer Protocol | Network connection by psexec | high | 61605 |
| `109018` | 10 | `T1071` Application Layer Protocol | Network connection by installutil | high | 61605 |
| `109019` | 9 | `T1071` Application Layer Protocol | DNS query by installutil | medium | 61624 |
| `109020` | 10 | `T1071` Application Layer Protocol | Network connection by regsvr32 | high | 61605 |
| `109021` | 10 | `T1071` Application Layer Protocol | Network connection by rubeus | high | 61605 |
| `109022` | 9 | `T1071` Application Layer Protocol | DNS query by rubeus | medium | 61624 |
| `109023` | 9 | `T1071` Application Layer Protocol | DNS query by wmic | medium | 61624 |
| `109024` | 10 | `T1071` Application Layer Protocol | Network connection by wmic | high | 61605 |
| `109025` | 13 | `T1071` Application Layer Protocol | DNS query by mimikatz | medium | 61624 |

## Exported Rule Files

Rules are exported in three parallel views. Each view contains the same rules, organized differently:

### `database/rules/by_tactic/`
_One XML file per MITRE ATT&CK tactic. Best for broad deployment._

| File | Rules |
|------|-------|
| `command_and_control.xml` | 14 |
| `credential_access.xml` | 22 |
| `defense_evasion.xml` | 30 |
| `discovery.xml` | 4 |
| `execution.xml` | 555 |
| `initial_access.xml` | 1 |
| `lateral_movement.xml` | 16 |
| `persistence.xml` | 55 |
| `privilege_escalation.xml` | 13 |

### `database/rules/by_technique/`
_One XML file per MITRE technique. Best for selective/granular deployment._

| File | Rules |
|------|-------|
| `T1003_credential_dumping.xml` | 22 |
| `T1021_remote_services.xml` | 16 |
| `T1055_process_injection.xml` | 30 |
| `T1059_command_scripting.xml` | 555 |
| `T1071_application_layer_protocol.xml` | 14 |
| `T1087_account_discovery.xml` | 4 |
| `T1547_boot_autostart.xml` | 55 |
| `T1548_abuse_elevation.xml` | 13 |
| `T1566_phishing.xml` | 1 |

### `database/rules/by_source/`
_Grouped by Windows event source (Sysmon, Security, PowerShell, System). Aligns with Wazuh decoder structure._

| File | Rules |
|------|-------|
| `powershell.xml` | 39 |
| `security.xml` | 35 |
| `sysmon.xml` | 131 |
| `system.xml` | 504 |

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
