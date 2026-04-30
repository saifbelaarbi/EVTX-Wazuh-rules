# Wazuh Rule Database Report

> Generated: 2026-04-30 14:20 UTC
> Pipeline version: 1.0.0

## Overview

| Metric | Value |
|--------|-------|
| Total rules generated | **1570** |
| EVTX-derived rules | 793 |
| Sigma-converted rules | 777 |
| EVTX sample files processed | 140 |
| Sigma rule files processed | 641 |
| EVTX source repositories used | 5 |
| MITRE tactics covered | 12 / 12 |
| MITRE techniques covered | 91 |
| Rule ID range | 100000 - 120000 |

## Origin Breakdown

| Origin | Rules | Tactics | Techniques | Validation |
|--------|-------|---------|------------|------------|
| EVTX-derived | 793 | 9 | 9 | 98/793 passed (12.4%) |
| Sigma-converted | 777 | 6 | 91 | not run |

## Validation Summary

| Scope | Tested | Passed | Failed | Pass Rate |
|-------|--------|--------|--------|-----------|
| Combined | 793 | 98 | 695 | 12.4% |
| EVTX-derived | 793 | 98 | 695 | 12.4% |
| Sigma-converted | 0 | 0 | 0 | 0.0% |

## Alert Level Distribution

| Level | Wazuh Severity | Count | Percentage |
|-------|----------------|-------|------------|
| 4 | System low | 2 | 0.1%  |
| 6 | Low relevance | 7 | 0.4%  |
| 7 | Bad word matching | 63 | 4.0% ## |
| 8 | First time seen | 574 | 36.6% ################## |
| 9 | Error from invalid source | 414 | 26.4% ############# |
| 10 | Multiple user-generated errors | 318 | 20.3% ########## |
| 11 | Integrity checking warning | 35 | 2.2% # |
| 12 | High importance event | 43 | 2.7% # |
| 13 | Unusual error (high importance) | 85 | 5.4% ## |
| 14 | High importance security event | 29 | 1.8%  |

## Detection Confidence Distribution

| Confidence | Count | Description |
|------------|-------|-------------|
| high | 880 | Exact tool or process indicator |
| medium | 662 | Command-line pattern or behavioral indicator |
| low | 28 | Heuristic or generic event |

## Rules by MITRE ATT&CK Tactic

### Initial Access (TA0001) - 1 rules

| Rule ID | Level | Technique | Description | Confidence | Parent SID |
|---------|-------|-----------|-------------|------------|------------|
| `100000` | 6 | `T1566` Phishing | Failed logon attempt | low | 60100 |

### Execution (TA0002) - 965 rules

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
| `101617` | 9 | - | DiagTrackEoP Default Login Username | high | 60100 |
| `101618` | 9 | `T1550` T1550 | Successful Overpass the Hash Attempt | high | 60100 |
| `101619` | 9 | `T1021` Remote Services | RDP Login from Localhost | high | 60100 |
| `101620` | 9 | `T1548` Abuse Elevation Control Mechanism | Potential Privilege Escalation via Local Kerberos Relay over LDAP | high | 60100 |
| `101621` | 9 | `T1562` T1562 | Windows Filtering Platform Blocked Connection From EDR Agent Binary | high | 60100 |
| `101622` | 9 | `T1222` T1222 | AD Object WriteDAC Access | high | 60100 |
| `101623` | 9 | `T1003` OS Credential Dumping | Active Directory Replication from Non Machine Account | high | 60100 |
| `101624` | 9 | - | ADCS Certificate Template Configuration Vulnerability with Risky EKU | high | 60100 |
| `101625` | 9 | `T1562` T1562 | Weak Encryption Enabled and Kerberoast | high | 60100 |
| `101626` | 9 | `T1070` Indicator Removal | Security Eventlog Cleared | high | 60100 |
| `101627` | 9 | `T1070` Indicator Removal | Security Eventlog Cleared | high | 60100 |
| `101628` | 9 | `T1021` Remote Services | DCOM InternetExplorer.Application Iertutil DLL Hijack - Security | high | 60100 |
| `101629` | 13 | `T1003` OS Credential Dumping | Mimikatz DC Sync | high | 60100 |
| `101630` | 9 | `T1562` T1562 | Important Windows Event Auditing Disabled | high | 60100 |
| `101631` | 9 | `T1562` T1562 | Important Windows Event Auditing Disabled | high | 60100 |
| `101632` | 9 | `T1003` OS Credential Dumping | DPAPI Domain Backup Key Extraction | high | 60100 |
| `101633` | 9 | `T1053` Scheduled Task/Job | Persistence and Execution at Scale via GPO Scheduled Task | high | 60100 |
| `101634` | 9 | `T1053` Scheduled Task/Job | Persistence and Execution at Scale via GPO Scheduled Task | high | 60100 |
| `101635` | 9 | `T1562` T1562 | HackTool - EDRSilencer Execution - Filter Added | high | 60100 |
| `101636` | 9 | `T1134` Access Token Manipulation | HackTool - NoFilter Execution | high | 60100 |
| `101637` | 9 | `T1134` Access Token Manipulation | HackTool - NoFilter Execution | high | 60100 |
| `101638` | 9 | `T1021` Remote Services | Impacket PsExec Execution | high | 60100 |
| `101639` | 9 | `T1003` OS Credential Dumping | Possible Impacket SecretDump Remote Activity | high | 60100 |
| `101640` | 9 | `T1027` Obfuscated Files or Information | Invoke-Obfuscation CLIP+ Launcher - Security | high | 60100 |
| `101641` | 9 | `T1027` Obfuscated Files or Information | Invoke-Obfuscation Obfuscated IEX Invocation - Security | high | 60100 |
| `101642` | 9 | `T1027` Obfuscated Files or Information | Invoke-Obfuscation STDIN+ Launcher - Security | high | 60100 |
| `101643` | 9 | `T1027` Obfuscated Files or Information | Invoke-Obfuscation VAR+ Launcher - Security | high | 60100 |
| `101644` | 9 | `T1027` Obfuscated Files or Information | Invoke-Obfuscation Via Stdin - Security | high | 60100 |
| `101645` | 9 | `T1027` Obfuscated Files or Information | Invoke-Obfuscation Via Use Clip - Security | high | 60100 |
| `101646` | 9 | `T1027` Obfuscated Files or Information | Invoke-Obfuscation Via Use MSHTA - Security | high | 60100 |
| `101647` | 9 | `T1027` Obfuscated Files or Information | Invoke-Obfuscation Via Use Rundll32 - Security | high | 60100 |
| `101648` | 9 | `T1027` Obfuscated Files or Information | Invoke-Obfuscation VAR++ LAUNCHER OBFUSCATION - Security | high | 60100 |
| `101649` | 9 | `T1021` Remote Services | First Time Seen Remote Named Pipe | high | 60100 |
| `101650` | 9 | `T1003` OS Credential Dumping | Credential Dumping Tools Service Execution - Security | high | 60100 |
| `101651` | 9 | `T1003` OS Credential Dumping | WCE wceaux.dll Access | high | 60100 |
| `101652` | 9 | `T1021` Remote Services | Metasploit SMB Authentication | high | 60100 |
| `101653` | 9 | `T1021` Remote Services | Metasploit SMB Authentication | high | 60100 |
| `101654` | 9 | `T1021` Remote Services | Metasploit Or Impacket Service Installation Via SMB PsExec | high | 60100 |
| `101655` | 14 | `T1134` Access Token Manipulation | Meterpreter or Cobalt Strike Getsystem Service Installation - Security | high | 60100 |
| `101656` | 9 | `T1187` T1187 | Possible PetitPotam Coerce Authentication Attempt | high | 60100 |
| `101657` | 9 | `T1187` T1187 | PetitPotam Suspicious Kerberos TGT Request | high | 60100 |
| `101658` | 9 | `T1569` System Services | PowerShell Scripts Installed as Services - Security | high | 60100 |
| `101659` | 9 | `T1021` Remote Services | Protected Storage Service Access | high | 60100 |
| `101660` | 9 | `T1090` T1090 | RDP over Reverse SSH Tunnel WFP | high | 60100 |
| `101661` | 9 | `T1558` Steal or Forge Kerberos Tickets | Register new Logon Process by Rubeus | high | 60100 |
| `101662` | 9 | `T1059` Command and Scripting Interpreter | Remote PowerShell Sessions Network Connections (WinRM) | high | 60100 |
| `101663` | 9 | `T1558` Steal or Forge Kerberos Tickets | Replay Attack Detected | high | 60100 |
| `101664` | 9 | `T1021` Remote Services | SMB Create Remote File Admin Share | high | 60100 |
| `101665` | 9 | `T1212` T1212 | Kerberos Manipulation | high | 60100 |
| `101666` | 9 | `T1001` T1001 | Suspicious LDAP-Attributes Used | high | 60100 |
| `101667` | 12 | `T1003` OS Credential Dumping | Password Dumper Activity on LSASS | high | 60100 |
| `101668` | 9 | `T1027` Obfuscated Files or Information | Password Protected ZIP File Opened (Suspicious Filenames) | high | 60100 |
| `101669` | 9 | `T1027` Obfuscated Files or Information | Password Protected ZIP File Opened (Email Attachment) | high | 60100 |
| `101670` | 9 | `T1021` Remote Services | Suspicious PsExec Execution | high | 60100 |
| `101671` | 9 | `T1053` Scheduled Task/Job | Suspicious Scheduled Task Creation | high | 60100 |
| `101672` | 9 | `T1053` Scheduled Task/Job | Important Scheduled Task Deleted/Disabled | high | 60100 |
| `101673` | 9 | `T1053` Scheduled Task/Job | Suspicious Scheduled Task Update | high | 60100 |
| `101674` | 9 | `T1528` T1528 | Suspicious Teams Application Related ObjectAcess Event | high | 60100 |
| `101675` | 9 | `T1558` Steal or Forge Kerberos Tickets | User Couldn't Call a Privileged Service 'LsaRegisterLogonProcess' | high | 60100 |
| `101676` | 9 | `T1047` T1047 | T1047 Wmiprvse Wbemcomn DLL Hijack | high | 60100 |
| `101677` | 9 | `T1562` T1562 | Sysmon Application Crashed | high | 60106 |
| `101678` | 9 | `T1070` Indicator Removal | Important Windows Eventlog Cleared | high | 60106 |
| `101679` | 9 | `T1003` OS Credential Dumping | Critical Hive In Suspicious Location Access Bits Cleared | high | 60106 |
| `101680` | 9 | `T1210` T1210 | Zerologon Exploitation Using Well-known Tools | high | 60106 |
| `101681` | 9 | `T1548` Abuse Elevation Control Mechanism | Vulnerable Netlogon Secure Channel Connection Allowed | high | 60106 |
| `101682` | 9 | `T1021` Remote Services | smbexec.py Service Installation | high | 60106 |
| `101683` | 9 | `T1027` Obfuscated Files or Information | Invoke-Obfuscation CLIP+ Launcher - System | high | 60106 |
| `101684` | 9 | `T1027` Obfuscated Files or Information | Invoke-Obfuscation Obfuscated IEX Invocation - System | high | 60106 |
| `101685` | 9 | `T1027` Obfuscated Files or Information | Invoke-Obfuscation STDIN+ Launcher - System | high | 60106 |
| `101686` | 9 | `T1027` Obfuscated Files or Information | Invoke-Obfuscation VAR+ Launcher - System | high | 60106 |
| `101687` | 9 | `T1027` Obfuscated Files or Information | Invoke-Obfuscation Via Stdin - System | high | 60106 |
| `101688` | 9 | `T1027` Obfuscated Files or Information | Invoke-Obfuscation Via Use Clip - System | high | 60106 |
| `101689` | 9 | `T1027` Obfuscated Files or Information | Invoke-Obfuscation Via Use MSHTA - System | high | 60106 |
| `101690` | 9 | `T1027` Obfuscated Files or Information | Invoke-Obfuscation Via Use Rundll32 - System | high | 60106 |
| `101691` | 9 | `T1027` Obfuscated Files or Information | Invoke-Obfuscation VAR++ LAUNCHER OBFUSCATION - System | high | 60106 |
| `101692` | 9 | `T1003` OS Credential Dumping | Credential Dumping Tools Service Execution - System | high | 60106 |
| `101693` | 14 | `T1134` Access Token Manipulation | Meterpreter or Cobalt Strike Getsystem Service Installation - System | high | 60106 |
| `101694` | 9 | `T1569` System Services | PowerShell Scripts Installed as Services | high | 60106 |
| `101695` | 9 | `T1569` System Services | HackTool Service Registration or Execution | high | 60106 |
| `101696` | 9 | - | Important Windows Service Terminated With Error | high | 60106 |
| `101697` | 9 | - | Important Windows Service Terminated Unexpectedly | high | 60106 |
| `101698` | 9 | `T1055` Process Injection | HackTool - CACTUSTORCH Remote Thread Creation | high | 61610 |
| `101699` | 13 | `T1055` Process Injection | HackTool - Potential CobaltStrike Process Injection | high | 61610 |
| `101700` | 9 | `T1555` T1555 | Remote Thread Created In KeePass.EXE | high | 61610 |
| `101701` | 9 | - | Remote Thread Creation In Mstsc.Exe From Suspicious Location | high | 61610 |
| `101702` | 12 | `T1003` OS Credential Dumping | Potential Credential Dumping Attempt Via PowerShell Remote Thread | high | 61610 |
| `101703` | 12 | `T1003` OS Credential Dumping | Password Dumper Remote Thread in LSASS | high | 61610 |
| `101704` | 9 | `T1055` Process Injection | Rare Remote Thread Creation By Uncommon Source Image | high | 61610 |
| `101705` | 9 | `T1127` T1127 | Remote Thread Creation Ttdinject.exe Proxy | high | 61610 |
| `101706` | 9 | `T1564` T1564 | Suspicious File Download From File Sharing Websites -  File Stream | high | 61617 |
| `101707` | 9 | `T1564` T1564 | HackTool Named File Stream Created | high | 61617 |
| `101708` | 9 | `T1564` T1564 | Exports Registry Key To an Alternate Data Stream | high | 61617 |
| `101709` | 9 | `T1564` T1564 | Unusual File Download from Direct IP Address | high | 61617 |
| `101710` | 9 | - | Potentially Suspicious File Download From ZIP TLD | high | 61617 |
| `101711` | 9 | `T1071` Application Layer Protocol | DNS Query by Finger Utility | high | 61624 |
| `101712` | 13 | `T1071` Application Layer Protocol | Suspicious Cobalt Strike DNS Beaconing - Sysmon | high | 61624 |
| `101713` | 13 | `T1071` Application Layer Protocol | Suspicious Cobalt Strike DNS Beaconing - Sysmon | high | 61624 |
| `101714` | 9 | `T1090` T1090 | DNS Query Tor .Onion Address - Sysmon | high | 61624 |
| `101715` | 9 | `T1070` Indicator Removal | Exchange PowerShell Cmdlet History Deleted | high | 61625 |
| `101716` | 9 | `T1070` Indicator Removal | Prefetch File Deleted | high | 61625 |
| `101717` | 9 | `T1219` T1219 | Suspicious Binary Writes Via AnyDesk | high | 61613 |
| `101718` | 9 | `T1003` OS Credential Dumping | Cred Dump Tools Dropped Files | high | 61613 |
| `101719` | 9 | `T1003` OS Credential Dumping | Cred Dump Tools Dropped Files | high | 61613 |
| `101720` | 9 | `T1059` Command and Scripting Interpreter | WScript or CScript Dropper - File | high | 61613 |
| `101721` | 9 | `T1021` Remote Services | Potential DCOM InternetExplorer.Application DLL Hijack | high | 61613 |
| `101722` | 9 | `T1003` OS Credential Dumping | HackTool - CrackMapExec File Indicators | high | 61613 |
| `101723` | 9 | `T1003` OS Credential Dumping | HackTool - Dumpert Process Dumper Default File | high | 61613 |
| `101724` | 9 | `T1552` T1552 | HackTool - Typical HiveNightmare SAM File Export | high | 61613 |
| `101725` | 9 | `T1552` T1552 | HackTool - Typical HiveNightmare SAM File Export | high | 61613 |
| `101726` | 9 | `T1219` T1219 | HackTool - Inveigh Execution Artefacts | high | 61613 |
| `101727` | 9 | `T1219` T1219 | HackTool - RemoteKrbRelay SMB Relay Secrets Dump Module Indicators | high | 61613 |
| `101728` | 13 | `T1558` Steal or Forge Kerberos Tickets | HackTool - Mimikatz Kirbi File Creation | high | 61613 |
| `101729` | 9 | `T1021` Remote Services | HackTool - NetExec File Indicators | high | 61613 |
| `101730` | 9 | `T1021` Remote Services | HackTool - NetExec File Indicators | high | 61613 |
| `101731` | 9 | - | HackTool - NPPSpy Hacktool Usage | high | 61613 |
| `101732` | 9 | `T1003` OS Credential Dumping | HackTool - QuarksPwDump Dump File | high | 61613 |
| `101733` | 9 | `T1003` OS Credential Dumping | HackTool - Potential Remote Credential Dumping Activity Via CrackMa... | high | 61613 |
| `101734` | 9 | `T1003` OS Credential Dumping | HackTool - SafetyKatz Dump Indicator | high | 61613 |
| `101735` | 9 | `T1003` OS Credential Dumping | HackTool - Impacket File Indicators | high | 61613 |
| `101736` | 9 | `T1566` Phishing | ISO File Created Within Temp Folders | high | 61613 |
| `101737` | 9 | `T1566` Phishing | ISO File Created Within Temp Folders | high | 61613 |
| `101738` | 12 | `T1003` OS Credential Dumping | LSASS Process Memory Dump Files | high | 61613 |
| `101739` | 12 | `T1003` OS Credential Dumping | LSASS Process Memory Dump Files | high | 61613 |
| `101740` | 12 | `T1003` OS Credential Dumping | LSASS Process Memory Dump Files | high | 61613 |
| `101741` | 12 | `T1003` OS Credential Dumping | LSASS Process Memory Dump Files | high | 61613 |
| `101742` | 12 | `T1003` OS Credential Dumping | LSASS Process Memory Dump Files | high | 61613 |
| `101743` | 12 | `T1003` OS Credential Dumping | LSASS Process Dump Artefact In CrashDumps Folder | high | 61613 |
| `101744` | 12 | `T1003` OS Credential Dumping | WerFault LSASS Process Memory Dump | high | 61613 |
| `101745` | 9 | `T1059` Command and Scripting Interpreter | Adwind RAT / JRAT File Artifact | high | 61613 |
| `101746` | 9 | `T1059` Command and Scripting Interpreter | Adwind RAT / JRAT File Artifact | high | 61613 |
| `101747` | 9 | `T1195` T1195 | Octopus Scanner Malware | high | 61613 |
| `101748` | 9 | - | Uncommon File Creation By Mysql Daemon Process | high | 61613 |
| `101749` | 9 | `T1218` T1218 | Suspicious DotNET CLR Usage Log Artifact | high | 61613 |
| `101750` | 9 | - | Suspicious File Creation In Uncommon AppData Folder | high | 61613 |
| `101751` | 9 | `T1003` OS Credential Dumping | NTDS.DIT Creation By Uncommon Parent Process | high | 61613 |
| `101752` | 9 | `T1003` OS Credential Dumping | NTDS.DIT Creation By Uncommon Process | high | 61613 |
| `101753` | 9 | `T1003` OS Credential Dumping | NTDS Exfiltration Filename Patterns | high | 61613 |
| `101754` | 9 | `T1566` Phishing | Office Macro File Creation From Suspicious Process | high | 61613 |
| `101755` | 9 | - | Suspicious File Created Via OneNote Application | high | 61613 |
| `101756` | 9 | `T1566` Phishing | Suspicious File Created in Outlook Temporary Directory | high | 61613 |
| `101757` | 9 | `T1204` User Execution | File With Uncommon Extension Created By An Office Application | high | 61613 |
| `101758` | 9 | `T1587` T1587 | Uncommon File Created In Office Startup Folder | high | 61613 |
| `101759` | 9 | `T1059` Command and Scripting Interpreter | PCRE.NET Package Temp Files | high | 61613 |
| `101760` | 13 | `T1059` Command and Scripting Interpreter | Malicious PowerShell Scripts - FileCreation | high | 61613 |
| `101761` | 9 | `T1059` Command and Scripting Interpreter | Malicious PowerShell Scripts - FileCreation | high | 61613 |
| `101762` | 9 | - | .RDP File Created By Uncommon Application | high | 61613 |
| `101763` | 9 | `T1027` Obfuscated Files or Information | Potential Winnti Dropper Activity | high | 61613 |
| `101764` | 9 | - | PDF File Created By RegEdit.EXE | high | 61613 |
| `101765` | 9 | `T1003` OS Credential Dumping | Potential SAM Database Dump | high | 61613 |
| `101766` | 9 | `T1003` OS Credential Dumping | Potential SAM Database Dump | high | 61613 |
| `101767` | 9 | `T1059` Command and Scripting Interpreter | Windows Shell/Scripting Application File Write to Suspicious Folder | high | 61613 |
| `101768` | 9 | `T1059` Command and Scripting Interpreter | Windows Shell/Scripting Application File Write to Suspicious Folder | high | 61613 |
| `101769` | 12 | `T1036` T1036 | Windows Binaries Write Suspicious Extensions | high | 61613 |
| `101770` | 9 | `T1036` T1036 | Windows Binaries Write Suspicious Extensions | high | 61613 |
| `101771` | 9 | `T1564` T1564 | Suspicious Creation with Colorcpl | high | 61613 |
| `101772` | 9 | `T1105` Ingress Tool Transfer | Suspicious Desktopimgdownldr Target File | high | 61613 |
| `101773` | 9 | `T1036` T1036 | Suspicious Double Extension Files | high | 61613 |
| `101774` | 9 | `T1036` T1036 | Suspicious Double Extension Files | high | 61613 |
| `101775` | 9 | `T1555` T1555 | DPAPI Backup Keys And Certificate Export Activity IOC | high | 61613 |
| `101776` | 9 | `T1564` T1564 | Suspicious Executable File Creation | high | 61613 |
| `101777` | 9 | `T1218` T1218 | Legitimate Application Dropped Archive | high | 61613 |
| `101778` | 9 | `T1218` T1218 | Legitimate Application Dropped Executable | high | 61613 |
| `101779` | 9 | `T1218` T1218 | Legitimate Application Writing Files In Uncommon Location | high | 61613 |
| `101780` | 9 | `T1218` T1218 | Legitimate Application Dropped Script | high | 61613 |
| `101781` | 9 | `T1204` User Execution | Suspicious Binaries and Scripts in Public Folder | high | 61613 |
| `101782` | 9 | `T1036` T1036 | Potential File Extension Spoofing Using Right-to-Left Override | high | 61613 |
| `101783` | 9 | `T1204` User Execution | Suspicious Startup Folder Persistence | high | 61613 |
| `101784` | 9 | `T1059` Command and Scripting Interpreter | Suspicious Interactive PowerShell as SYSTEM | high | 61613 |
| `101785` | 9 | - | LiveKD Kernel Memory Dump File Created | high | 61613 |
| `101786` | 9 | - | LiveKD Driver Creation By Uncommon Process | high | 61613 |
| `101787` | 9 | `T1136` T1136 | PSEXEC Remote Execution File Artefact | high | 61613 |
| `101788` | 12 | `T1003` OS Credential Dumping | LSASS Process Memory Dump Creation Via Taskmgr.EXE | high | 61613 |
| `101789` | 9 | `T1219` T1219 | Hijack Legit RDP Session to Move Laterally | high | 61613 |
| `101790` | 9 | `T1548` Abuse Elevation Control Mechanism | UAC Bypass Using Consent and Comctl32 - File | high | 61613 |
| `101791` | 9 | `T1548` Abuse Elevation Control Mechanism | UAC Bypass Using .NET Code Profiler on MMC | high | 61613 |
| `101792` | 9 | - | UAC Bypass Using EventVwr | high | 61613 |
| `101793` | 9 | `T1548` Abuse Elevation Control Mechanism | UAC Bypass Using IDiagnostic Profile - File | high | 61613 |
| `101794` | 9 | `T1548` Abuse Elevation Control Mechanism | UAC Bypass Using IEInstal - File | high | 61613 |
| `101795` | 9 | `T1548` Abuse Elevation Control Mechanism | UAC Bypass Using MSConfig Token Modification - File | high | 61613 |
| `101796` | 9 | `T1548` Abuse Elevation Control Mechanism | UAC Bypass Using NTFS Reparse Point - File | high | 61613 |
| `101797` | 9 | `T1548` Abuse Elevation Control Mechanism | UAC Bypass Abusing Winsat Path Parsing - File | high | 61613 |
| `101798` | 9 | `T1548` Abuse Elevation Control Mechanism | UAC Bypass Using Windows Media Player - File | high | 61613 |
| `101799` | 9 | `T1548` Abuse Elevation Control Mechanism | UAC Bypass Using Windows Media Player - File | high | 61613 |
| `101800` | 9 | - | Renamed VsCode Code Tunnel Execution - File Indicator | high | 61613 |
| `101801` | 9 | `T1047` T1047 | Wmiexec Default Output File | high | 61613 |
| `101802` | 9 | `T1047` T1047 | Wmiexec Default Output File | high | 61613 |
| `101803` | 9 | `T1047` T1047 | Wmiexec Default Output File | high | 61613 |
| `101804` | 9 | `T1047` T1047 | Wmiprvse Wbemcomn DLL Hijack - File | high | 61613 |
| `101805` | 9 | `T1218` T1218 | DLL Loaded From Suspicious Location Via Cmspt.EXE | high | 61609 |
| `101806` | 9 | `T1003` OS Credential Dumping | Suspicious Renamed Comsvcs DLL Loaded By Rundll32 | high | 61609 |
| `101807` | 9 | `T1003` OS Credential Dumping | Suspicious Unsigned Dbghelp/Dbgcore DLL Loaded | high | 61609 |
| `101808` | 9 | `T1059` Command and Scripting Interpreter | PCRE.NET Package Image Load | high | 61609 |
| `101809` | 9 | `T1202` T1202 | Diagnostic Library Sdiageng.DLL Loaded By Msdt.EXE | high | 61609 |
| `101810` | 9 | `T1218` T1218 | Time Travel Debugging Utility Usage - Image | high | 61609 |
| `101811` | 9 | `T1562` T1562 | HackTool - SharpEvtMute DLL Load | high | 61609 |
| `101812` | 9 | `T1071` Application Layer Protocol | HackTool - SILENTTRINITY Stager DLL Load | high | 61609 |
| `101813` | 9 | `T1021` Remote Services | Potential DCOM InternetExplorer.Application DLL Hijack - Image Load | high | 61609 |
| `101814` | 9 | `T1204` User Execution | GAC DLL Loaded Via Office Applications | high | 61609 |
| `101815` | 9 | `T1204` User Execution | VBA DLL Loaded Via Office Application | high | 61609 |
| `101816` | 9 | `T1059` Command and Scripting Interpreter | Abusable DLL Potential Sideloading From Suspicious Location | high | 61609 |
| `101817` | 9 | `T1218` T1218 | BaaUpdate.exe Suspicious DLL Load | high | 61609 |
| `101818` | 9 | `T1055` Process Injection | DotNet CLR DLL Loaded By Scripting Applications | high | 61609 |
| `101819` | 9 | `T1548` Abuse Elevation Control Mechanism | UAC Bypass Using Iscsicpl - ImageLoad | high | 61609 |
| `101820` | 9 | `T1003` OS Credential Dumping | Suspicious Loading of Dbgcore/Dbghelp DLLs from Uncommon Location | high | 61609 |
| `101821` | 9 | `T1047` T1047 | Wmiprvse Wbemcomn DLL Hijack | high | 61609 |
| `101822` | 9 | `T1218` T1218 | Network Connection Initiated By AddinUtil.EXE | high | 61605 |
| `101823` | 9 | `T1105` Ingress Tool Transfer | Uncommon Network Connection Initiated By Certutil.EXE | high | 61605 |
| `101824` | 9 | `T1218` T1218 | Outbound Network Connection Initiated By Cmstp.EXE | high | 61605 |
| `101825` | 9 | `T1071` Application Layer Protocol | Outbound Network Connection Initiated By Microsoft Dialer | high | 61605 |
| `101826` | 9 | `T1102` T1102 | New Connection Initiated To Potential Dead Drop Resolver Domain | high | 61605 |
| `101827` | 9 | `T1572` T1572 | Communication To LocaltoNet Tunneling Service Initiated | high | 61605 |
| `101828` | 9 | `T1203` T1203 | Network Connection Initiated By Eqnedt32.EXE | high | 61605 |
| `101829` | 9 | `T1071` Application Layer Protocol | Network Connection Initiated via Finger.EXE | high | 61605 |
| `101830` | 9 | `T1105` Ingress Tool Transfer | Network Connection Initiated By IMEWDBLD.EXE | high | 61605 |
| `101831` | 9 | `T1055` Process Injection | Network Connection Initiated Via Notepad.EXE | high | 61605 |
| `101832` | 9 | `T1021` Remote Services | Outbound RDP Connections Over Non-Standard Tools | high | 61605 |
| `101833` | 9 | `T1572` T1572 | RDP Over Reverse SSH Tunnel | high | 61605 |
| `101834` | 9 | `T1572` T1572 | RDP to HTTP or HTTPS Target Ports | high | 61605 |
| `101835` | 9 | `T1127` T1127 | Silenttrinity Stager Msbuild Activity | high | 61605 |
| `101836` | 9 | - | Suspicious Network Connection Binary No CommandLine | high | 61605 |
| `101837` | 9 | `T1105` Ingress Tool Transfer | Network Communication Initiated To File Sharing Domains From Proces... | high | 61605 |
| `101838` | 9 | `T1105` Ingress Tool Transfer | Network Connection Initiated From Process Located In Potentially Su... | high | 61605 |
| `101839` | 9 | `T1059` Command and Scripting Interpreter | Potential Remote PowerShell Session Initiated | high | 61605 |
| `101840` | 9 | `T1105` Ingress Tool Transfer | Outbound Network Connection Initiated By Script Interpreter | high | 61605 |
| `101841` | 13 | `T1055` Process Injection | CobaltStrike Named Pipe | high | 61619 |
| `101842` | 13 | `T1055` Process Injection | CobaltStrike Named Pipe | high | 61619 |
| `101843` | 13 | `T1055` Process Injection | CobaltStrike Named Pipe | high | 61619 |
| `101844` | 13 | `T1055` Process Injection | CobaltStrike Named Pipe | high | 61619 |
| `101845` | 13 | `T1055` Process Injection | CobaltStrike Named Pipe | high | 61619 |
| `101846` | 13 | `T1055` Process Injection | CobaltStrike Named Pipe | high | 61619 |
| `101847` | 13 | `T1055` Process Injection | CobaltStrike Named Pipe | high | 61619 |
| `101848` | 13 | `T1055` Process Injection | CobaltStrike Named Pipe | high | 61619 |
| `101849` | 13 | `T1055` Process Injection | CobaltStrike Named Pipe | high | 61619 |
| `101850` | 13 | `T1055` Process Injection | CobaltStrike Named Pipe | high | 61619 |
| `101851` | 13 | `T1055` Process Injection | CobaltStrike Named Pipe | high | 61619 |
| `101852` | 13 | `T1055` Process Injection | CobaltStrike Named Pipe Pattern Regex | high | 61619 |
| `101853` | 13 | `T1055` Process Injection | CobaltStrike Named Pipe Pattern Regex | high | 61619 |
| `101854` | 13 | `T1055` Process Injection | CobaltStrike Named Pipe Pattern Regex | high | 61619 |
| `101855` | 13 | `T1055` Process Injection | CobaltStrike Named Pipe Pattern Regex | high | 61619 |
| `101856` | 13 | `T1055` Process Injection | CobaltStrike Named Pipe Pattern Regex | high | 61619 |
| `101857` | 13 | `T1055` Process Injection | CobaltStrike Named Pipe Pattern Regex | high | 61619 |
| `101858` | 13 | `T1055` Process Injection | CobaltStrike Named Pipe Pattern Regex | high | 61619 |
| `101859` | 13 | `T1055` Process Injection | CobaltStrike Named Pipe Pattern Regex | high | 61619 |
| `101860` | 13 | `T1055` Process Injection | CobaltStrike Named Pipe Pattern Regex | high | 61619 |
| `101861` | 13 | `T1055` Process Injection | CobaltStrike Named Pipe Pattern Regex | high | 61619 |
| `101862` | 13 | `T1055` Process Injection | CobaltStrike Named Pipe Pattern Regex | high | 61619 |
| `101863` | 13 | `T1055` Process Injection | CobaltStrike Named Pipe Pattern Regex | high | 61619 |
| `101864` | 13 | `T1055` Process Injection | CobaltStrike Named Pipe Pattern Regex | high | 61619 |
| `101865` | 13 | `T1055` Process Injection | CobaltStrike Named Pipe Pattern Regex | high | 61619 |
| `101866` | 13 | `T1055` Process Injection | CobaltStrike Named Pipe Pattern Regex | high | 61619 |
| `101867` | 13 | `T1055` Process Injection | CobaltStrike Named Pipe Pattern Regex | high | 61619 |
| `101868` | 13 | `T1055` Process Injection | CobaltStrike Named Pipe Pattern Regex | high | 61619 |
| `101869` | 13 | `T1055` Process Injection | CobaltStrike Named Pipe Pattern Regex | high | 61619 |
| `101870` | 13 | `T1055` Process Injection | CobaltStrike Named Pipe Pattern Regex | high | 61619 |
| `101871` | 13 | `T1055` Process Injection | CobaltStrike Named Pipe Patterns | high | 61619 |
| `101872` | 13 | `T1055` Process Injection | CobaltStrike Named Pipe Patterns | high | 61619 |
| `101873` | 13 | `T1055` Process Injection | CobaltStrike Named Pipe Patterns | high | 61619 |
| `101874` | 9 | `T1055` Process Injection | HackTool - CoercedPotato Named Pipe Creation | high | 61619 |
| `101875` | 9 | - | HackTool - DiagTrackEoP Default Named Pipe | high | 61619 |
| `101876` | 9 | `T1055` Process Injection | HackTool - EfsPotato Named Pipe Creation | high | 61619 |
| `101877` | 13 | `T1003` OS Credential Dumping | HackTool - Credential Dumping Tools Named Pipe Created | high | 61619 |
| `101878` | 9 | `T1528` T1528 | HackTool - Koh Default Named Pipe | high | 61619 |
| `101879` | 12 | `T1055` Process Injection | Malicious Named Pipe Created | high | 61619 |
| `101880` | 9 | `T1059` Command and Scripting Interpreter | PowerShell Called from an Executable Version Mismatch | high | 91801 |
| `101881` | 9 | `T1059` Command and Scripting Interpreter | Bad Opsec Powershell Code Artifacts | high | 91801 |
| `101882` | 13 | `T1059` Command and Scripting Interpreter | Malicious PowerShell Scripts - PoshModule | high | 91801 |
| `101883` | 9 | `T1059` Command and Scripting Interpreter | Malicious PowerShell Scripts - PoshModule | high | 91801 |
| `101884` | 9 | `T1003` OS Credential Dumping | Suspicious Get-ADDBAccount Usage | high | 91801 |
| `101885` | 9 | - | HackTool - Evil-WinRm Execution - PowerShell Module | high | 91801 |
| `101886` | 9 | `T1027` Obfuscated Files or Information | Invoke-Obfuscation CLIP+ Launcher - PowerShell Module | high | 91801 |
| `101887` | 9 | `T1027` Obfuscated Files or Information | Invoke-Obfuscation Obfuscated IEX Invocation - PowerShell Module | high | 91801 |
| `101888` | 9 | `T1027` Obfuscated Files or Information | Invoke-Obfuscation STDIN+ Launcher - PowerShell Module | high | 91801 |
| `101889` | 9 | `T1027` Obfuscated Files or Information | Invoke-Obfuscation VAR+ Launcher - PowerShell Module | high | 91801 |
| `101890` | 9 | `T1027` Obfuscated Files or Information | Invoke-Obfuscation Via Stdin - PowerShell Module | high | 91801 |
| `101891` | 9 | `T1027` Obfuscated Files or Information | Invoke-Obfuscation Via Use Clip - PowerShell Module | high | 91801 |
| `101892` | 9 | `T1027` Obfuscated Files or Information | Invoke-Obfuscation Via Use MSHTA - PowerShell Module | high | 91801 |
| `101893` | 9 | `T1027` Obfuscated Files or Information | Invoke-Obfuscation Via Use Rundll32 - PowerShell Module | high | 91801 |
| `101894` | 9 | `T1027` Obfuscated Files or Information | Invoke-Obfuscation VAR++ LAUNCHER OBFUSCATION - PowerShell Module | high | 91801 |
| `101895` | 13 | `T1482` T1482 | Malicious PowerShell Commandlets - PoshModule | high | 91801 |
| `101896` | 9 | `T1059` Command and Scripting Interpreter | Remote PowerShell Session (PS Module) | high | 91801 |
| `101897` | 9 | `T1218` T1218 | Potential RemoteFXvGPUDisablement.EXE Abuse - PowerShell Module | high | 91801 |
| `101898` | 9 | `T1059` Command and Scripting Interpreter | Suspicious PowerShell Invocations - Generic - PowerShell Module | high | 91801 |
| `101899` | 9 | `T1059` Command and Scripting Interpreter | Suspicious PowerShell Invocations - Specific - PowerShell Module | high | 91801 |
| `101900` | 9 | `T1059` Command and Scripting Interpreter | Suspicious PowerShell Invocations - Specific - PowerShell Module | high | 91801 |
| `101901` | 9 | `T1059` Command and Scripting Interpreter | Suspicious PowerShell Invocations - Specific - PowerShell Module | high | 91801 |
| `101902` | 9 | `T1059` Command and Scripting Interpreter | Suspicious PowerShell Invocations - Specific - PowerShell Module | high | 91801 |
| `101903` | 9 | `T1059` Command and Scripting Interpreter | Suspicious PowerShell Invocations - Specific - PowerShell Module | high | 91801 |
| `101904` | 9 | `T1059` Command and Scripting Interpreter | Suspicious PowerShell Invocations - Specific - PowerShell Module | high | 91801 |
| `101905` | 9 | - | AADInternals PowerShell Cmdlets Execution - PsScript | high | 91801 |
| `101906` | 9 | `T1562` T1562 | AMSI Bypass Pattern Assembly GetType | high | 91801 |
| `101907` | 9 | `T1059` Command and Scripting Interpreter | Silence.EDA Detection | high | 91801 |
| `101908` | 9 | `T1070` Indicator Removal | Clearing Windows Console History | high | 91801 |
| `101909` | 9 | `T1003` OS Credential Dumping | Create Volume Shadow Copy with Powershell | high | 91801 |
| `101910` | 9 | `T1070` Indicator Removal | Disable Powershell Command History | high | 91801 |
| `101911` | 9 | `T1562` T1562 | Disable-WindowsOptionalFeature Command PowerShell | high | 91801 |
| `101912` | 9 | `T1059` Command and Scripting Interpreter | DSInternals Suspicious PowerShell Cmdlets - ScriptBlock | high | 91801 |
| `101913` | 9 | `T1070` Indicator Removal | Disable of ETW Trace - Powershell | high | 91801 |
| `101914` | 9 | `T1070` Indicator Removal | Disable of ETW Trace - Powershell | high | 91801 |
| `101915` | 9 | `T1003` OS Credential Dumping | HackTool - Rubeus Execution - ScriptBlock | high | 91801 |
| `101916` | 9 | `T1027` Obfuscated Files or Information | Invoke-Obfuscation CLIP+ Launcher - PowerShell | high | 91801 |
| `101917` | 9 | `T1027` Obfuscated Files or Information | Invoke-Obfuscation Obfuscated IEX Invocation - PowerShell | high | 91801 |
| `101918` | 9 | `T1027` Obfuscated Files or Information | Invoke-Obfuscation STDIN+ Launcher - Powershell | high | 91801 |
| `101919` | 9 | `T1027` Obfuscated Files or Information | Invoke-Obfuscation VAR+ Launcher - PowerShell | high | 91801 |
| `101920` | 9 | `T1027` Obfuscated Files or Information | Invoke-Obfuscation Via Stdin - Powershell | high | 91801 |
| `101921` | 9 | `T1027` Obfuscated Files or Information | Invoke-Obfuscation Via Use Clip - Powershell | high | 91801 |
| `101922` | 9 | `T1027` Obfuscated Files or Information | Invoke-Obfuscation Via Use MSHTA - PowerShell | high | 91801 |
| `101923` | 9 | `T1027` Obfuscated Files or Information | Invoke-Obfuscation Via Use Rundll32 - PowerShell | high | 91801 |
| `101924` | 9 | `T1027` Obfuscated Files or Information | Invoke-Obfuscation VAR++ LAUNCHER OBFUSCATION - PowerShell | high | 91801 |
| `101925` | 13 | `T1482` T1482 | Malicious PowerShell Commandlets - ScriptBlock | high | 91801 |
| `101926` | 9 | `T1003` OS Credential Dumping | Live Memory Dump Using Powershell | high | 91801 |
| `101927` | 13 | `T1059` Command and Scripting Interpreter | Malicious Nishang PowerShell Commandlets | high | 91801 |
| `101928` | 9 | `T1564` T1564 | NTFS Alternate Data Stream | high | 91801 |
| `101929` | 13 | `T1003` OS Credential Dumping | Potential Invoke-Mimikatz PowerShell Script | high | 91801 |
| `101930` | 13 | `T1003` OS Credential Dumping | Potential Invoke-Mimikatz PowerShell Script | high | 91801 |
| `101931` | 13 | `T1003` OS Credential Dumping | Potential Invoke-Mimikatz PowerShell Script | high | 91801 |
| `101932` | 9 | `T1059` Command and Scripting Interpreter | PowerView PowerShell Cmdlets - ScriptBlock | high | 91801 |
| `101933` | 9 | `T1059` Command and Scripting Interpreter | PowerShell Credential Prompt | high | 91801 |
| `101934` | 9 | `T1059` Command and Scripting Interpreter | PSAsyncShell - Asynchronous TCP Reverse Shell | high | 91801 |
| `101935` | 9 | `T1059` Command and Scripting Interpreter | PowerShell PSAttack | high | 91801 |
| `101936` | 9 | `T1218` T1218 | Potential RemoteFXvGPUDisablement.EXE Abuse - PowerShell ScriptBlock | high | 91801 |
| `101937` | 9 | `T1558` Steal or Forge Kerberos Tickets | Suspicious Kerberos Ticket Request via PowerShell Script - ScriptBlock | high | 91801 |
| `101938` | 9 | `T1222` T1222 | PowerShell Set-Acl On Windows Folder - PsScript | high | 91801 |
| `101939` | 9 | `T1055` Process Injection | PowerShell ShellCode | high | 91801 |
| `101940` | 9 | `T1059` Command and Scripting Interpreter | Malicious ShellIntel PowerShell Commandlets | high | 91801 |
| `101941` | 12 | `T1003` OS Credential Dumping | PowerShell Get-Process LSASS in ScriptBlock | high | 91801 |
| `101942` | 9 | `T1059` Command and Scripting Interpreter | Suspicious PowerShell Invocations - Generic | high | 91801 |
| `101943` | 9 | `T1059` Command and Scripting Interpreter | Suspicious PowerShell Invocations - Specific | high | 91801 |
| `101944` | 9 | `T1059` Command and Scripting Interpreter | Suspicious PowerShell Invocations - Specific | high | 91801 |
| `101945` | 9 | `T1059` Command and Scripting Interpreter | Suspicious PowerShell Invocations - Specific | high | 91801 |
| `101946` | 9 | `T1059` Command and Scripting Interpreter | Suspicious PowerShell Invocations - Specific | high | 91801 |
| `101947` | 9 | `T1059` Command and Scripting Interpreter | Suspicious PowerShell Invocations - Specific | high | 91801 |
| `101948` | 9 | `T1059` Command and Scripting Interpreter | Suspicious PowerShell Invocations - Specific | high | 91801 |
| `101949` | 9 | `T1562` T1562 | Tamper Windows Defender Remove-MpPreference - ScriptBlockLogging | high | 91801 |
| `101950` | 9 | `T1562` T1562 | Tamper Windows Defender - ScriptBlockLogging | high | 91801 |
| `101951` | 9 | - | Veeam Backup Servers Credential Dumping Script Execution | high | 91801 |
| `101952` | 9 | `T1059` Command and Scripting Interpreter | Potential WinAPI Calls Via PowerShell Scripts | high | 91801 |
| `101953` | 9 | `T1059` Command and Scripting Interpreter | Potential WinAPI Calls Via PowerShell Scripts | high | 91801 |
| `101954` | 9 | `T1059` Command and Scripting Interpreter | Potential WinAPI Calls Via PowerShell Scripts | high | 91801 |
| `101955` | 9 | `T1059` Command and Scripting Interpreter | Potential WinAPI Calls Via PowerShell Scripts | high | 91801 |
| `101956` | 9 | `T1047` T1047 | WMImplant Hack Tool | high | 91801 |
| `101957` | 9 | `T1218` T1218 | CMSTP Execution Process Access | high | 61612 |
| `101958` | 13 | `T1106` T1106 | HackTool - CobaltStrike BOF Injection Pattern | high | 61612 |
| `101959` | 13 | `T1003` OS Credential Dumping | HackTool - Generic Process Access | high | 61612 |
| `101960` | 9 | `T1003` OS Credential Dumping | HackTool - Generic Process Access | high | 61612 |
| `101961` | 12 | `T1106` T1106 | HackTool - HandleKatz Duplicating LSASS Handle | high | 61612 |
| `101962` | 9 | `T1204` User Execution | HackTool - LittleCorporal Generated Maldoc Injection | high | 61612 |
| `101963` | 9 | `T1562` T1562 | HackTool - SysmonEnte Execution | high | 61612 |
| `101964` | 12 | `T1003` OS Credential Dumping | Lsass Memory Dump via Comsvcs DLL | high | 61612 |
| `101965` | 12 | `T1003` OS Credential Dumping | LSASS Memory Access by Tool With Dump Keyword In Name | high | 61612 |
| `101966` | 12 | `T1003` OS Credential Dumping | Credential Dumping Activity By Python Based Tool | high | 61612 |
| `101967` | 12 | `T1003` OS Credential Dumping | Remote LSASS Process Access Through Windows Remote Management | high | 61612 |
| `101968` | 12 | `T1003` OS Credential Dumping | Suspicious LSASS Access Via MalSecLogon | high | 61612 |
| `101969` | 12 | `T1003` OS Credential Dumping | Credential Dumping Attempt Via WerFault | high | 61612 |
| `101970` | 12 | `T1003` OS Credential Dumping | LSASS Access From Potentially White-Listed Processes | high | 61612 |
| `101971` | 12 | `T1003` OS Credential Dumping | Suspicious Process Access to LSASS with Dbgcore/Dbghelp DLLs | high | 61612 |
| `101972` | 9 | `T1548` Abuse Elevation Control Mechanism | Credential Dumping Attempt Via Svchost | high | 61612 |
| `101973` | 9 | `T1562` T1562 | Suspicious Svchost Process Access | high | 61612 |
| `101974` | 9 | `T1548` Abuse Elevation Control Mechanism | UAC Bypass Using WOW64 Logger DLL Hijack | high | 61612 |
| `101975` | 9 | `T1562` T1562 | Suspicious Process Access of MsMpEng by WerFaultSecure - EDR-Freeze | high | 61612 |
| `101976` | 9 | `T1218` T1218 | Suspicious AddinUtil.EXE CommandLine Execution | high | 61603 |
| `101977` | 9 | `T1003` OS Credential Dumping | Potential Adplus.EXE Abuse | high | 61603 |
| `101978` | 9 | `T1218` T1218 | Suspicious AgentExecutor PowerShell Execution | high | 61603 |
| `101979` | 9 | `T1562` T1562 | Windows AMSI Related Registry Tampering Via CommandLine | high | 61603 |
| `101980` | 9 | `T1059` Command and Scripting Interpreter | Suspicious ArcSOC.exe Child Process | high | 61603 |
| `101981` | 9 | `T1127` T1127 | Suspicious Child Process of AspNetCompiler | high | 61603 |
| `101982` | 9 | `T1127` T1127 | Potentially Suspicious ASP.NET Compilation Via AspNetCompiler | high | 61603 |
| `101983` | 9 | `T1564` T1564 | Set Suspicious Files as System Files Using Attrib.EXE | high | 61603 |
| `101984` | 9 | `T1562` T1562 | Audit Policy Tampering Via NT Resource Kit Auditpol | high | 61603 |
| `101985` | 9 | `T1562` T1562 | Audit Policy Tampering Via Auditpol | high | 61603 |
| `101986` | 9 | `T1562` T1562 | Windows EventLog Autologger Session Registry Modification Via Comma... | high | 61603 |
| `101987` | 9 | `T1547` Boot or Logon Autostart Execution | Suspicious Autorun Registry Modified via WMI | high | 61603 |
| `101988` | 9 | `T1218` T1218 | Suspicious BitLocker Access Agent Update Utility Execution | high | 61603 |
| `101989` | 9 | `T1059` Command and Scripting Interpreter | Suspicious Child Process Of BgInfo.EXE | high | 61603 |
| `101990` | 9 | `T1105` Ingress Tool Transfer | File Download with Headless Browser | high | 61603 |
| `101991` | 9 | - | Chromium Browser Headless Execution To Mockbin Like Site | high | 61603 |
| `101992` | 9 | `T1090` T1090 | Tor Client/Browser Execution | high | 61603 |
| `101993` | 9 | `T1090` T1090 | Tor Client/Browser Execution | high | 61603 |
| `101994` | 9 | `T1090` T1090 | Tor Client/Browser Execution | high | 61603 |
| `101995` | 9 | `T1036` T1036 | Suspicious Calculator Usage | high | 61603 |
| `101996` | 9 | `T1105` Ingress Tool Transfer | File Download From IP Based URL Via CertOC.EXE | high | 61603 |
| `101997` | 9 | `T1218` T1218 | Suspicious DLL Loaded via CertOC.EXE | high | 61603 |
| `101998` | 9 | `T1105` Ingress Tool Transfer | Suspicious CertReq Command to Download | high | 61603 |
| `101999` | 9 | `T1027` Obfuscated Files or Information | File Decoded From Base64/Hex Via Certutil.EXE | high | 61603 |

### Persistence (TA0003) - 337 rules

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
| `102090` | 10 | `T1098` T1098 | Powerview Add-DomainObjectAcl DCSync AD Extend Right | high | 60100 |
| `102091` | 10 | `T1098` T1098 | Enabled User Right in AD to Control User Objects | high | 60100 |
| `102092` | 10 | `T1098` T1098 | Active Directory User Backdoors | high | 60100 |
| `102093` | 13 | `T1021` Remote Services | CobaltStrike Service Installations - Security | high | 60100 |
| `102094` | 10 | `T1112` T1112 | ETW Logging Disabled In .NET Processes - Registry | high | 60100 |
| `102095` | 10 | `T1112` T1112 | ETW Logging Disabled In .NET Processes - Registry | high | 60100 |
| `102096` | 10 | `T1136` T1136 | Hidden Local User Creation | high | 60100 |
| `102097` | 10 | `T1554` T1554 | HybridConnectionManager Service Installation | high | 60100 |
| `102098` | 10 | `T1562` T1562 | NetNTLM Downgrade Attack | high | 60100 |
| `102099` | 10 | `T1543` Create or Modify System Process | Service Installed By Unusual Client - Security | high | 60100 |
| `102100` | 10 | `T1078` Valid Accounts | Win Susp Computer Name Containing Samtheadmin | high | 60100 |
| `102101` | 10 | `T1078` Valid Accounts | Win Susp Computer Name Containing Samtheadmin | high | 60100 |
| `102102` | 10 | `T1098` T1098 | Password Change on Directory Service Restore Mode (DSRM) Account | high | 60100 |
| `102103` | 10 | `T1136` T1136 | Suspicious Windows ANONYMOUS LOGON Local Account Created | high | 60100 |
| `102104` | 10 | `T1556` T1556 | Possible Shadow Credentials Added | high | 60100 |
| `102105` | 10 | `T1112` T1112 | Sysmon Channel Reference Deletion | high | 60100 |
| `102106` | 10 | `T1112` T1112 | Sysmon Channel Reference Deletion | high | 60100 |
| `102107` | 10 | `T1574` T1574 | DHCP Server Loaded the CallOut DLL | high | 60106 |
| `102108` | 10 | `T1574` T1574 | DHCP Server Error Failed Loading the CallOut DLL | high | 60106 |
| `102109` | 13 | `T1021` Remote Services | CobaltStrike Service Installations - System | high | 60106 |
| `102110` | 10 | `T1543` Create or Modify System Process | KrbRelayUp Service Installation | high | 60106 |
| `102111` | 10 | `T1543` Create or Modify System Process | Moriya Rootkit - System | high | 60106 |
| `102112` | 10 | `T1543` Create or Modify System Process | ProcessHacker Privilege Elevation | high | 60106 |
| `102113` | 10 | `T1543` Create or Modify System Process | Sliver C2 Default Service Installation | high | 60106 |
| `102114` | 10 | `T1543` Create or Modify System Process | Service Installed By Unusual Client - System | high | 60106 |
| `102115` | 10 | `T1543` Create or Modify System Process | Suspicious Service Installation | high | 60106 |
| `102116` | 10 | - | RTCore Suspicious Service Installation | high | 60106 |
| `102117` | 10 | `T1543` Create or Modify System Process | Service Installation with Suspicious Folder Pattern | high | 60106 |
| `102118` | 10 | `T1543` Create or Modify System Process | Suspicious Service Installation Script | high | 60106 |
| `102119` | 10 | - | Potential Suspicious Winget Package Installation | high | 61617 |
| `102120` | 10 | `T1554` T1554 | DNS HybridConnectionManager Service Bus | high | 61624 |
| `102121` | 10 | `T1543` Create or Modify System Process | Malicious Driver Load | high | 61608 |
| `102122` | 10 | `T1543` Create or Modify System Process | PUA - Process Hacker Driver Load | high | 61608 |
| `102123` | 10 | `T1543` Create or Modify System Process | PUA - Process Hacker Driver Load | high | 61608 |
| `102124` | 10 | `T1543` Create or Modify System Process | Driver Load From A Temporary Directory | high | 61608 |
| `102125` | 10 | `T1543` Create or Modify System Process | Vulnerable Driver Load | high | 61608 |
| `102126` | 10 | `T1543` Create or Modify System Process | Vulnerable HackSys Extreme Vulnerable Driver Load | high | 61608 |
| `102127` | 10 | `T1543` Create or Modify System Process | Vulnerable HackSys Extreme Vulnerable Driver Load | high | 61608 |
| `102128` | 10 | `T1543` Create or Modify System Process | Vulnerable WinRing0 Driver Load | high | 61608 |
| `102129` | 10 | `T1543` Create or Modify System Process | Vulnerable WinRing0 Driver Load | high | 61608 |
| `102130` | 10 | `T1133` T1133 | Unusual File Modification by dns.exe | high | 61604 |
| `102131` | 10 | `T1133` T1133 | Unusual File Deletion by Dns.exe | high | 61625 |
| `102132` | 10 | `T1127` T1127 | Suspicious File Created by ArcSOC.exe | high | 61613 |
| `102133` | 10 | `T1547` Boot or Logon Autostart Execution | Creation Exe for Service with Unquoted Path | high | 61613 |
| `102134` | 10 | `T1574` T1574 | DLL Search Order Hijackig Via Additional Space in Path | high | 61613 |
| `102135` | 10 | `T1505` T1505 | Suspicious ASPX File Drop by Exchange | high | 61613 |
| `102136` | 10 | `T1574` T1574 | HackTool - Powerup Write Hijack DLL | high | 61613 |
| `102137` | 10 | `T1574` T1574 | Malicious DLL File Dropped in the Teams or OneDrive Folder | high | 61613 |
| `102138` | 10 | `T1547` Boot or Logon Autostart Execution | File Creation In Suspicious Directory By Msdt.EXE | high | 61613 |
| `102139` | 10 | `T1137` T1137 | Potential Persistence Via Microsoft Office Add-In | high | 61613 |
| `102140` | 10 | `T1137` T1137 | Potential Persistence Via Microsoft Office Add-In | high | 61613 |
| `102141` | 10 | `T1137` T1137 | Potential Persistence Via Microsoft Office Add-In | high | 61613 |
| `102142` | 10 | `T1137` T1137 | Potential Persistence Via Microsoft Office Add-In | high | 61613 |
| `102143` | 10 | `T1137` T1137 | Potential Persistence Via Outlook Form | high | 61613 |
| `102144` | 10 | `T1137` T1137 | Suspicious Outlook Macro Created | high | 61613 |
| `102145` | 10 | `T1137` T1137 | Potential Persistence Via Microsoft Office Startup Folder | high | 61613 |
| `102146` | 10 | `T1547` Boot or Logon Autostart Execution | Potential Startup Shortcut Persistence Via PowerShell.EXE | high | 61613 |
| `102147` | 10 | `T1547` Boot or Logon Autostart Execution | Potential RipZip Attack on Startup Folder | high | 61613 |
| `102148` | 10 | `T1190` Exploit Public-Facing Application | Suspicious MSExchangeMailboxReplication ASPX Write | high | 61613 |
| `102149` | 10 | `T1190` Exploit Public-Facing Application | Suspicious File Write to SharePoint Layouts Directory | high | 61613 |
| `102150` | 10 | `T1546` T1546 | Suspicious Get-Variable.exe Creation | high | 61613 |
| `102151` | 10 | - | Suspicious File Creation Activity From Fake Recycle.Bin Folder | high | 61613 |
| `102152` | 10 | - | Suspicious File Creation Activity From Fake Recycle.Bin Folder | high | 61613 |
| `102153` | 10 | `T1053` Scheduled Task/Job | Suspicious Scheduled Task Write to System32 Tasks | high | 61613 |
| `102154` | 10 | `T1068` Exploitation for Privilege Escalation | Process Explorer Driver Creation By Non-Sysinternals Binary | high | 61613 |
| `102155` | 10 | - | Potential Privilege Escalation Attempt Via .Exe.Local Technique | high | 61613 |
| `102156` | 10 | `T1547` Boot or Logon Autostart Execution | WinRAR Creating Files in Startup Locations | high | 61613 |
| `102157` | 10 | `T1546` T1546 | WMI Persistence - Script Event Consumer File Write | high | 61613 |
| `102158` | 10 | `T1542` T1542 | UEFI Persistence Via Wpbbin - FileCreation | high | 61613 |
| `102159` | 10 | `T1574` T1574 | Potential appverifUI.DLL Sideloading | high | 61609 |
| `102160` | 10 | `T1574` T1574 | Aruba Network Service Potential DLL Sideloading | high | 61609 |
| `102161` | 10 | `T1574` T1574 | Potential DLL Sideloading Via comctl32.dll | high | 61609 |
| `102162` | 10 | `T1574` T1574 | System Control Panel Item Loaded From Uncommon Location | high | 61609 |
| `102163` | 10 | `T1574` T1574 | Potential EACore.DLL Sideloading | high | 61609 |
| `102164` | 10 | `T1574` T1574 | Potential Edputil.DLL Sideloading | high | 61609 |
| `102165` | 10 | `T1574` T1574 | Potential System DLL Sideloading From Non System Locations | high | 61609 |
| `102166` | 10 | `T1574` T1574 | Potential Iviewers.DLL Sideloading | high | 61609 |
| `102167` | 10 | `T1574` T1574 | Potential JLI.dll Side-Loading | high | 61609 |
| `102168` | 10 | `T1574` T1574 | Potential DLL Sideloading Of KeyScramblerIE.DLL Via KeyScrambler.EXE | high | 61609 |
| `102169` | 10 | `T1574` T1574 | Unsigned Mfdetours.DLL Sideloading | high | 61609 |
| `102170` | 10 | `T1574` T1574 | Potential DLL Sideloading Of Non-Existent DLLs From System Folders | high | 61609 |
| `102171` | 10 | `T1574` T1574 | Microsoft Office DLL Sideload | high | 61609 |
| `102172` | 10 | `T1574` T1574 | Potential Rcdll.DLL Sideloading | high | 61609 |
| `102173` | 10 | `T1574` T1574 | Potential RjvPlatform.DLL Sideloading From Non-Default Location | high | 61609 |
| `102174` | 10 | `T1574` T1574 | DLL Sideloading Of ShellChromeAPI.DLL | high | 61609 |
| `102175` | 10 | `T1574` T1574 | Potential SmadHook.DLL Sideloading | high | 61609 |
| `102176` | 10 | `T1574` T1574 | Fax Service DLL Search Order Hijack | high | 61609 |
| `102177` | 10 | `T1574` T1574 | Potential Vcruntime140 DLL Sideloading | high | 61609 |
| `102178` | 10 | `T1574` T1574 | VMMap Unsigned Dbghelp.DLL Potential Sideloading | high | 61609 |
| `102179` | 10 | `T1574` T1574 | Potential DLL Sideloading Via VMware Xfer | high | 61609 |
| `102180` | 10 | `T1574` T1574 | Potential Waveedit.DLL Sideloading | high | 61609 |
| `102181` | 10 | `T1574` T1574 | Potential Mpclient.DLL Sideloading | high | 61609 |
| `102182` | 10 | `T1574` T1574 | Suspicious Unsigned Thor Scanner Execution | high | 61609 |
| `102183` | 10 | `T1548` Abuse Elevation Control Mechanism | UAC Bypass With Fake DLL | high | 61609 |
| `102184` | 10 | `T1574` T1574 | Trusted Path Bypass via Windows Directory Spoofing | high | 61609 |
| `102185` | 10 | `T1546` T1546 | WMI Persistence - Command Line Event Consumer | high | 61609 |
| `102186` | 10 | `T1571` T1571 | Potentially Suspicious Malware Callback Communication | high | 61605 |
| `102187` | 10 | `T1556` T1556 | Powershell Install a DLL in System Directory | high | 91801 |
| `102188` | 10 | `T1137` T1137 | Code Executed Via Office Add-in XLL File | high | 91801 |
| `102189` | 10 | `T1059` Command and Scripting Interpreter | PowerShell Web Access Installation - PsScript | high | 91801 |
| `102190` | 10 | `T1059` Command and Scripting Interpreter | PowerShell Web Access Installation - PsScript | high | 91801 |
| `102191` | 10 | `T1059` Command and Scripting Interpreter | PowerShell Web Access Installation - PsScript | high | 91801 |
| `102192` | 10 | - | Potential Persistence Via Security Descriptors - ScriptBlock | high | 91801 |
| `102193` | 10 | `T1574` T1574 | Suspicious Service DACL Modification Via Set-Service Cmdlet - PS | high | 91801 |
| `102194` | 10 | `T1574` T1574 | Abuse of Service Permissions to Hide Services Via Set-Service - PS | high | 91801 |
| `102195` | 10 | `T1053` Scheduled Task/Job | Interactive AT Job | high | 61603 |
| `102196` | 10 | `T1197` T1197 | Suspicious Download From Direct IP Via Bitsadmin | high | 61603 |
| `102197` | 10 | `T1197` T1197 | Suspicious Download From File-Sharing Website Via Bitsadmin | high | 61603 |
| `102198` | 10 | `T1197` T1197 | File With Suspicious Extension Downloaded Via Bitsadmin | high | 61603 |
| `102199` | 10 | `T1197` T1197 | File Download Via Bitsadmin To A Suspicious Target Folder | high | 61603 |
| `102200` | 10 | `T1176` T1176 | Suspicious Chromium Browser Instance Executed With Custom Extension | high | 61603 |
| `102201` | 10 | `T1546` T1546 | Change Default File Association To Executable Via Assoc | high | 61603 |
| `102202` | 10 | `T1546` T1546 | Potential Privilege Escalation Using Symlink Between Osk and Cmd | high | 61603 |
| `102203` | 10 | `T1546` T1546 | Sticky Key Like Backdoor Execution | high | 61603 |
| `102204` | 10 | `T1546` T1546 | Persistence Via Sticky Key Backdoor | high | 61603 |
| `102205` | 10 | `T1543` Create or Modify System Process | Devcon Execution Disabling VMware VMCI Device | high | 61603 |
| `102206` | 10 | `T1548` Abuse Elevation Control Mechanism | PowerShell Web Access Feature Enabled Via DISM | high | 61603 |
| `102207` | 10 | `T1574` T1574 | DLL Sideloading by VMware Xfer Utility | high | 61603 |
| `102208` | 10 | `T1133` T1133 | Unusual Child Process of dns.exe | high | 61603 |
| `102209` | 10 | `T1574` T1574 | New DNS ServerLevelPluginDll Installed Via Dnscmd.EXE | high | 61603 |
| `102210` | 10 | `T1562` T1562 | Security Event Logging Disabled via MiniNt Registry Key - Process | high | 61603 |
| `102211` | 10 | `T1574` T1574 | Suspicious GUP Usage | high | 61603 |
| `102212` | 10 | `T1047` T1047 | HackTool - CrackMapExec Execution Patterns | high | 61603 |
| `102213` | 10 | `T1615` T1615 | HackTool - SharpUp PrivEsc Tool Execution | high | 61603 |
| `102214` | 10 | `T1615` T1615 | HackTool - SharpUp PrivEsc Tool Execution | high | 61603 |
| `102215` | 10 | `T1615` T1615 | HackTool - SharpUp PrivEsc Tool Execution | high | 61603 |
| `102216` | 10 | `T1505` T1505 | Suspicious IIS Module Registration | high | 61603 |
| `102217` | 10 | - | Suspicious Shells Spawn by Java Utility Keytool | high | 61603 |
| `102218` | 10 | - | Suspicious Processes Spawned by Java.EXE | high | 61603 |
| `102219` | 10 | `T1574` T1574 | Using SettingSyncHost.exe as LOLBin | high | 61603 |
| `102220` | 10 | `T1547` Boot or Logon Autostart Execution | Suspicious GrpConv Execution | high | 61603 |
| `102221` | 10 | `T1574` T1574 | Potential Mpclient.DLL Sideloading Via Defender Binaries | high | 61603 |
| `102222` | 10 | `T1505` T1505 | Suspicious Child Process Of SQL Server | high | 61603 |
| `102223` | 10 | - | Suspicious Child Process Of Veeam Dabatase | high | 61603 |
| `102224` | 10 | `T1136` T1136 | New User Created Via Net.EXE With Never Expire Option | high | 61603 |
| `102225` | 10 | `T1574` T1574 | Abuse of Service Permissions to Hide Services Via Set-Service | high | 61603 |
| `102226` | 10 | `T1543` Create or Modify System Process | Suspicious Service DACL Modification Via Set-Service Cmdlet | high | 61603 |
| `102227` | 10 | `T1543` Create or Modify System Process | PUA - Kernel Driver Utility (KDU) Execution | high | 61603 |
| `102228` | 10 | `T1112` T1112 | RestrictedAdminMode Registry Value Tampering - ProcCreation | high | 61603 |
| `102229` | 10 | `T1112` T1112 | Enable LM Hash Storage - ProcCreation | high | 61603 |
| `102230` | 10 | `T1021` Remote Services | Potential Tampering With RDP Related Registry Keys Via Reg.EXE | high | 61603 |
| `102231` | 10 | `T1112` T1112 | Reg Add Suspicious Paths | high | 61603 |
| `102232` | 10 | `T1112` T1112 | Imports Registry Key From an ADS | high | 61603 |
| `102233` | 10 | `T1112` T1112 | Suspicious Registry Modification From ADS Via Regini.EXE | high | 61603 |
| `102234` | 10 | `T1546` T1546 | Suspicious Debugger Registration Cmdline | high | 61603 |
| `102235` | 10 | `T1037` T1037 | Potential Persistence Via Logon Scripts - CommandLine | high | 61603 |
| `102236` | 10 | `T1574` T1574 | Potential Privilege Escalation via Service Permissions Weakness | high | 61603 |
| `102237` | 10 | `T1574` T1574 | Renamed Vmnat.exe Execution | high | 61603 |
| `102238` | 10 | `T1546` T1546 | Rundll32 Registered COM Objects | high | 61603 |
| `102239` | 10 | `T1112` T1112 | ShimCache Flush | high | 61603 |
| `102240` | 10 | `T1574` T1574 | Possible Privilege Escalation via Weak Service Permissions | high | 61603 |
| `102241` | 10 | `T1543` Create or Modify System Process | Allow Service Access Using Security Descriptor Tampering Via Sc.EXE | high | 61603 |
| `102242` | 10 | `T1543` Create or Modify System Process | Deny Service Access Using Security Descriptor Tampering Via Sc.EXE | high | 61603 |
| `102243` | 10 | `T1574` T1574 | Service DACL Abuse To Hide Services Via Sc.EXE | high | 61603 |
| `102244` | 10 | `T1543` Create or Modify System Process | Suspicious Service Path Modification | high | 61603 |
| `102245` | 10 | `T1053` Scheduled Task/Job | Suspicious Modification Of Scheduled Tasks | high | 61603 |
| `102246` | 10 | `T1053` Scheduled Task/Job | Schtasks From Suspicious Folders | high | 61603 |
| `102247` | 10 | `T1053` Scheduled Task/Job | Potential SSH Tunnel Persistence Install Using A Scheduled Task | high | 61603 |
| `102248` | 10 | `T1053` Scheduled Task/Job | Suspicious Schtasks Schedule Types | high | 61603 |
| `102249` | 10 | `T1053` Scheduled Task/Job | Suspicious Command Patterns In Scheduled Task Creation | high | 61603 |
| `102250` | 10 | `T1098` T1098 | User Added To Highly Privileged Group | high | 61603 |
| `102251` | 10 | `T1133` T1133 | User Added to Remote Desktop Users Group | high | 61603 |
| `102252` | 10 | `T1112` T1112 | Non-privileged Usage of Reg or Powershell | high | 61603 |
| `102253` | 10 | - | Suspicious Process Execution From Fake Recycle.Bin Folder | high | 61603 |
| `102254` | 10 | `T1543` Create or Modify System Process | Suspicious New Service Creation | high | 61603 |
| `102255` | 10 | `T1543` Create or Modify System Process | Suspicious New Service Creation | high | 61603 |
| `102256` | 10 | `T1574` T1574 | Tasks Folder Evasion | high | 61603 |
| `102257` | 10 | `T1219` T1219 | Suspicious Velociraptor Child Process | high | 61603 |
| `102258` | 10 | `T1547` Boot or Logon Autostart Execution | User Shell Folders Registry Modification via CommandLine | high | 61603 |
| `102259` | 10 | `T1037` T1037 | Uncommon Userinit Child Process | high | 61603 |
| `102260` | 10 | `T1505` T1505 | Chopper Webshell Process Pattern | high | 61603 |
| `102261` | 10 | `T1505` T1505 | Webshell Hacking Activity Patterns | high | 61603 |
| `102262` | 10 | `T1505` T1505 | Webshell Hacking Activity Patterns | high | 61603 |
| `102263` | 10 | `T1505` T1505 | Webshell Hacking Activity Patterns | high | 61603 |
| `102264` | 10 | `T1505` T1505 | Webshell Detection With Command Line Keywords | high | 61603 |
| `102265` | 10 | `T1505` T1505 | Webshell Detection With Command Line Keywords | high | 61603 |
| `102266` | 10 | `T1505` T1505 | Webshell Detection With Command Line Keywords | high | 61603 |
| `102267` | 10 | `T1505` T1505 | Suspicious Process By Web Server Process | high | 61603 |
| `102268` | 10 | `T1505` T1505 | Suspicious Process By Web Server Process | high | 61603 |
| `102269` | 10 | `T1505` T1505 | Suspicious Process By Web Server Process | high | 61603 |
| `102270` | 10 | `T1505` T1505 | Webshell Tool Reconnaissance Activity | high | 61603 |
| `102271` | 10 | `T1505` T1505 | Webshell Tool Reconnaissance Activity | high | 61603 |
| `102272` | 10 | `T1505` T1505 | Webshell Tool Reconnaissance Activity | high | 61603 |
| `102273` | 10 | `T1190` Exploit Public-Facing Application | Suspicious Processes Spawned by WinRM | high | 61603 |
| `102274` | 10 | `T1546` T1546 | WMI Backdoor Exchange Transport Agent | high | 61603 |
| `102275` | 10 | `T1546` T1546 | New ActiveScriptEventConsumer Created Via Wmic.EXE | high | 61603 |
| `102276` | 10 | `T1542` T1542 | UEFI Persistence Via Wpbbin - ProcessCreation | high | 61603 |
| `102277` | 10 | `T1574` T1574 | Xwizard.EXE Execution From Non-Default Location | high | 61603 |
| `102278` | 10 | `T1070` Indicator Removal | Terminal Server Client Connection History Cleared - Registry | high | 61614 |
| `102279` | 10 | `T1070` Indicator Removal | Terminal Server Client Connection History Cleared - Registry | high | 61614 |
| `102280` | 12 | `T1136` T1136 | Creation of a Local Hidden User Account by Registry | high | 61615 |
| `102281` | 10 | `T1562` T1562 | Disable Security Events Logging Adding Reg Key MiniNt | high | 61615 |
| `102282` | 10 | `T1562` T1562 | Disable Security Events Logging Adding Reg Key MiniNt | high | 61615 |
| `102283` | 10 | `T1112` T1112 | Wdigest CredGuard Registry Modification | high | 61615 |
| `102284` | 10 | `T1112` T1112 | Registry Entries For Azorult Malware | high | 61615 |
| `102285` | 10 | `T1112` T1112 | Potential Qakbot Registry Activity | high | 61615 |
| `102286` | 10 | `T1547` Boot or Logon Autostart Execution | Narrator's Feedback-Hub Persistence | high | 61615 |
| `102287` | 10 | `T1547` Boot or Logon Autostart Execution | Narrator's Feedback-Hub Persistence | high | 61615 |
| `102288` | 10 | `T1562` T1562 | NetNTLM Downgrade Attack - Registry | high | 61615 |
| `102289` | 10 | `T1547` Boot or Logon Autostart Execution | Registry Persistence Mechanisms in Recycle Bin | high | 61615 |
| `102290` | 10 | `T1547` Boot or Logon Autostart Execution | Registry Persistence Mechanisms in Recycle Bin | high | 61615 |
| `102291` | 10 | `T1112` T1112 | RedMimicry Winnti Playbook Registry Manipulation | high | 61615 |
| `102292` | 10 | `T1547` Boot or Logon Autostart Execution | WINEKEY Registry Modification | high | 61615 |
| `102293` | 10 | `T1548` Abuse Elevation Control Mechanism | Shell Open Registry Keys Manipulation | high | 61615 |
| `102294` | 10 | `T1547` Boot or Logon Autostart Execution | Security Support Provider (SSP) Added to LSA Configuration | high | 61615 |
| `102295` | 10 | `T1546` T1546 | Sticky Key Like Backdoor Usage - Registry | high | 61615 |
| `102296` | 10 | `T1547` Boot or Logon Autostart Execution | Suspicious Run Key from Download | high | 61615 |
| `102297` | 10 | `T1547` Boot or Logon Autostart Execution | Bypass UAC Using Event Viewer | high | 61615 |
| `102298` | 10 | `T1547` Boot or Logon Autostart Execution | Default RDP Port Changed to Non Standard Port | high | 61615 |
| `102299` | 10 | `T1133` T1133 | Running Chrome VPN Extensions via the Registry 2 VPN Extension | high | 61615 |
| `102300` | 13 | `T1021` Remote Services | Potential CobaltStrike Service Installations - Registry | high | 61615 |
| `102301` | 10 | `T1546` T1546 | COM Hijack via Sdclt | high | 61615 |
| `102302` | 10 | `T1562` T1562 | Security Event Logging Disabled via MiniNt Registry Key - Registry Set | high | 61615 |
| `102303` | 10 | `T1112` T1112 | Service Binary in Suspicious Folder | high | 61615 |
| `102304` | 10 | `T1112` T1112 | Service Binary in Suspicious Folder | high | 61615 |
| `102305` | 10 | `T1574` T1574 | DHCP Callout DLL Installation | high | 61615 |
| `102306` | 10 | `T1547` Boot or Logon Autostart Execution | Windows Event Log Access Tampering Via Registry | high | 61615 |
| `102307` | 10 | `T1547` Boot or Logon Autostart Execution | Windows Event Log Access Tampering Via Registry | high | 61615 |
| `102308` | 10 | `T1574` T1574 | New DNS ServerLevelPluginDll Installed | high | 61615 |
| `102309` | 10 | `T1112` T1112 | ETW Logging Disabled In .NET Processes - Sysmon Registry | high | 61615 |
| `102310` | 10 | `T1112` T1112 | ETW Logging Disabled In .NET Processes - Sysmon Registry | high | 61615 |
| `102311` | 10 | `T1556` T1556 | Directory Service Restore Mode(DSRM) Registry Value Tampering | high | 61615 |
| `102312` | 10 | `T1112` T1112 | Change User Account Associated with the FAX Service | high | 61615 |
| `102313` | 10 | `T1112` T1112 | Change the Fax Dll | high | 61615 |
| `102314` | 10 | - | Add Debugger Entry To Hangs Key For Persistence | high | 61615 |
| `102315` | 10 | - | Persistence Via Hhctrl.ocx | high | 61615 |
| `102316` | 10 | `T1112` T1112 | RestrictedAdminMode Registry Value Tampering | high | 61615 |
| `102317` | 10 | `T1112` T1112 | NET NGenAssemblyUsageLog Registry Key Tamper | high | 61615 |
| `102318` | 10 | `T1546` T1546 | New Netsh Helper DLL Registered From A Suspicious Location | high | 61615 |
| `102319` | 10 | `T1003` OS Credential Dumping | Potentially Suspicious ODBC Driver Registered | high | 61615 |
| `102320` | 10 | `T1112` T1112 | Trust Access Disable For VBApplications | high | 61615 |
| `102321` | 10 | `T1137` T1137 | Potential Persistence Via Outlook LoadMacroProviderOnBoot Setting | high | 61615 |
| `102322` | 10 | `T1137` T1137 | Outlook Macro Execution Without Warning Setting Enabled | high | 61615 |
| `102323` | 10 | `T1112` T1112 | Outlook EnableUnsafeClientMailRules Setting Enabled - Registry | high | 61615 |
| `102324` | 10 | `T1112` T1112 | Macro Enabled In A Potentially Suspicious Document | high | 61615 |
| `102325` | 10 | `T1112` T1112 | Uncommon Microsoft Office Trusted Location Added | high | 61615 |
| `102326` | 10 | `T1112` T1112 | Office Macros Warning Disabled | high | 61615 |
| `102327` | 10 | `T1546` T1546 | Potential Persistence Via App Paths Default Property | high | 61615 |
| `102328` | 10 | - | Potential Persistence Via AutodialDLL | high | 61615 |
| `102329` | 10 | - | Potential Persistence Via CHM Helper DLL | high | 61615 |
| `102330` | 10 | `T1546` T1546 | COM Object Hijacking Via Modification Of Default System CLSID Defau... | high | 61615 |
| `102331` | 10 | `T1546` T1546 | Potential PSFactoryBuffer COM Hijacking | high | 61615 |
| `102332` | 10 | `T1546` T1546 | Potential Persistence Via GlobalFlags | high | 61615 |
| `102333` | 10 | `T1546` T1546 | Potential Persistence Via GlobalFlags | high | 61615 |
| `102334` | 10 | - | Potential Persistence Via LSA Extensions | high | 61615 |
| `102335` | 10 | - | Potential Persistence Via Mpnotify | high | 61615 |
| `102336` | 10 | - | Potential Persistence Via MyComputer Registry Keys | high | 61615 |
| `102337` | 10 | - | Potential Persistence Via DLLPathOverride | high | 61615 |
| `102338` | 10 | `T1112` T1112 | Potential Persistence Via Outlook Home Page | high | 61615 |
| `102339` | 10 | `T1112` T1112 | Potential Persistence Via Outlook Today Page | high | 61615 |
| `102340` | 10 | `T1546` T1546 | Suspicious Shim Database Patching Activity | high | 61615 |
| `102341` | 10 | `T1546` T1546 | Potential Persistence Via Shim Database In Uncommon Location | high | 61615 |
| `102342` | 10 | - | Potential Persistence Via TypedPaths | high | 61615 |
| `102343` | 10 | `T1137` T1137 | Potential Persistence Via Excel Add-in - Registry | high | 61615 |
| `102344` | 10 | `T1112` T1112 | Registry Modification for OCI DLL Redirection | high | 61615 |
| `102345` | 10 | `T1564` T1564 | PowerShell Logging Disabled Via Registry Key Tampering | high | 61615 |
| `102346` | 10 | `T1574` T1574 | Suspicious Printer Driver Empty Manufacturer | high | 61615 |
| `102347` | 10 | `T1547` Boot or Logon Autostart Execution | Registry Persistence via Explorer Run Key | high | 61615 |
| `102348` | 10 | `T1547` Boot or Logon Autostart Execution | New RUN Key Pointing to Suspicious Folder | high | 61615 |
| `102349` | 10 | `T1547` Boot or Logon Autostart Execution | Modify User Shell Folders Startup Value | high | 61615 |
| `102350` | 10 | - | Suspicious Environment Variable Has Been Registered | high | 61615 |
| `102351` | 10 | `T1112` T1112 | Enable LM Hash Storage | high | 61615 |
| `102352` | 10 | `T1112` T1112 | RDP Sensitive Settings Changed | high | 61615 |
| `102353` | 10 | `T1547` Boot or Logon Autostart Execution | New TimeProviders Registered With Uncommon DLL Name | high | 61615 |
| `102354` | 10 | `T1547` Boot or Logon Autostart Execution | VBScript Payload Stored in Registry | high | 61615 |
| `102355` | 10 | `T1112` T1112 | Wdigest Enable UseLogonCredential | high | 61615 |
| `102356` | 10 | `T1547` Boot or Logon Autostart Execution | Winlogon Notify Key Logon Persistence | high | 61615 |

### Privilege Escalation (TA0004) - 18 rules

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

### Defense Evasion (TA0005) - 37 rules

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

### Credential Access (TA0006) - 34 rules

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

### Discovery (TA0007) - 66 rules

| Rule ID | Level | Technique | Description | Confidence | Parent SID |
|---------|-------|-----------|-------------|------------|------------|
| `106000` | 6 | `T1087` Account Discovery | Suspicious PowerShell: invoke-expression | medium | 91801 |
| `106001` | 6 | `T1087` Account Discovery | Suspicious PowerShell: invoke-webrequest | medium | 91801 |
| `106002` | 6 | `T1087` Account Discovery | Suspicious PowerShell: bypass | medium | 91801 |
| `106003` | 7 | `T1087` Account Discovery | Suspicious named pipe: \ntsvcs | high | 61620 |
| `106004` | 7 | `T1087` Account Discovery | Suspicious named pipe: \scerpc | high | 61620 |
| `106005` | 4 | `T1087` Account Discovery | Special privilege assignment | low | 60100 |
| `106006` | 4 | `T1087` Account Discovery | Remote logon (type 3) | low | 60100 |
| `106010` | 7 | `T1087` Account Discovery | AD Privileged Users or Groups Reconnaissance | high | 60100 |
| `106011` | 7 | `T1087` Account Discovery | Hacktool Ruler | high | 60100 |
| `106012` | 7 | `T1012` T1012 | SAM Registry Hive Handle Request | high | 60100 |
| `106013` | 7 | `T1087` Account Discovery | Reconnaissance Activity | high | 60100 |
| `106014` | 7 | `T1012` T1012 | SysKey Registry Keys Access | high | 60100 |
| `106015` | 11 | `T1087` Account Discovery | BloodHound Collection Files | high | 61613 |
| `106016` | 7 | `T1059` Command and Scripting Interpreter | PowerShell ADRecon Execution | high | 91801 |
| `106017` | 7 | `T1046` T1046 | HackTool - WinPwn Execution - ScriptBlock | high | 91801 |
| `106018` | 7 | - | Potential Recon Activity Using DriverQuery.EXE | high | 61603 |
| `106019` | 7 | `T1082` System Information Discovery | Suspicious Kernel Dump Using Dtrace | high | 61603 |
| `106020` | 7 | `T1082` System Information Discovery | Suspicious Kernel Dump Using Dtrace | high | 61603 |
| `106021` | 7 | `T1135` T1135 | File Explorer Folder Opened Using Explorer Folder Shortcut Via Shell | high | 61603 |
| `106022` | 7 | `T1518` T1518 | Sysmon Discovery Via Default Driver Altitude Using Findstr.EXE | high | 61603 |
| `106023` | 11 | `T1087` Account Discovery | HackTool - Bloodhound/Sharphound Execution | high | 61603 |
| `106024` | 11 | `T1087` Account Discovery | HackTool - Bloodhound/Sharphound Execution | high | 61603 |
| `106025` | 11 | `T1087` Account Discovery | HackTool - Bloodhound/Sharphound Execution | high | 61603 |
| `106026` | 11 | `T1087` Account Discovery | HackTool - Bloodhound/Sharphound Execution | high | 61603 |
| `106027` | 11 | `T1087` Account Discovery | HackTool - Bloodhound/Sharphound Execution | high | 61603 |
| `106028` | 11 | `T1087` Account Discovery | HackTool - Bloodhound/Sharphound Execution | high | 61603 |
| `106029` | 11 | `T1087` Account Discovery | HackTool - Bloodhound/Sharphound Execution | high | 61603 |
| `106030` | 7 | `T1649` T1649 | HackTool - Certify Execution | high | 61603 |
| `106031` | 11 | `T1649` T1649 | HackTool - Certipy Execution | high | 61603 |
| `106032` | 7 | `T1018` T1018 | HackTool - NetExec Execution | high | 61603 |
| `106033` | 7 | `T1033` T1033 | HackTool - SharpLdapWhoami Execution | high | 61603 |
| `106034` | 7 | `T1033` T1033 | HackTool - SharpLdapWhoami Execution | high | 61603 |
| `106035` | 7 | `T1033` T1033 | HackTool - SharpLdapWhoami Execution | high | 61603 |
| `106036` | 7 | `T1033` T1033 | HackTool - SharpLdapWhoami Execution | high | 61603 |
| `106037` | 7 | `T1049` T1049 | HackTool - SharpView Execution | high | 61603 |
| `106038` | 7 | `T1049` T1049 | HackTool - SharpView Execution | high | 61603 |
| `106039` | 7 | `T1049` T1049 | HackTool - SharpView Execution | high | 61603 |
| `106040` | 7 | `T1087` Account Discovery | HackTool - SOAPHound Execution | high | 61603 |
| `106041` | 7 | `T1482` T1482 | HackTool - TruffleSnout Execution | high | 61603 |
| `106042` | 7 | `T1482` T1482 | HackTool - TruffleSnout Execution | high | 61603 |
| `106043` | 7 | `T1082` System Information Discovery | HackTool - winPEAS Execution | high | 61603 |
| `106044` | 7 | `T1082` System Information Discovery | HackTool - winPEAS Execution | high | 61603 |
| `106045` | 7 | `T1082` System Information Discovery | HackTool - winPEAS Execution | high | 61603 |
| `106046` | 7 | `T1082` System Information Discovery | HackTool - winPEAS Execution | high | 61603 |
| `106047` | 7 | `T1082` System Information Discovery | HackTool - winPEAS Execution | high | 61603 |
| `106048` | 7 | `T1082` System Information Discovery | HackTool - winPEAS Execution | high | 61603 |
| `106049` | 7 | `T1046` T1046 | HackTool - WinPwn Execution | high | 61603 |
| `106050` | 7 | `T1087` Account Discovery | Network Reconnaissance Activity | high | 61603 |
| `106051` | 7 | `T1087` Account Discovery | PUA - Suspicious ActiveDirectory Enumeration Via AdFind.EXE | high | 61603 |
| `106052` | 7 | `T1087` Account Discovery | PUA - Suspicious ActiveDirectory Enumeration Via AdFind.EXE | high | 61603 |
| `106053` | 7 | `T1087` Account Discovery | PUA - Suspicious ActiveDirectory Enumeration Via AdFind.EXE | high | 61603 |
| `106054` | 7 | `T1018` T1018 | PUA - AdFind Suspicious Execution | high | 61603 |
| `106055` | 7 | `T1590` T1590 | PUA - Crassus Execution | high | 61603 |
| `106056` | 7 | `T1590` T1590 | PUA - Crassus Execution | high | 61603 |
| `106057` | 7 | `T1590` T1590 | PUA - Crassus Execution | high | 61603 |
| `106058` | 7 | `T1526` T1526 | PUA - Seatbelt Execution | high | 61603 |
| `106059` | 7 | `T1018` T1018 | Renamed AdFind Execution | high | 61603 |
| `106060` | 7 | `T1018` T1018 | Renamed AdFind Execution | high | 61603 |
| `106061` | 7 | `T1018` T1018 | Renamed AdFind Execution | high | 61603 |
| `106062` | 7 | `T1033` T1033 | Renamed Whoami Execution | high | 61603 |
| `106063` | 7 | `T1615` T1615 | Suspicious Reconnaissance Activity Via GatherNetworkInfo.VBS | high | 61603 |
| `106064` | 7 | `T1033` T1033 | WhoAmI as Parameter | high | 61603 |
| `106065` | 7 | `T1087` Account Discovery | Suspicious Active Directory Database Snapshot Via ADExplorer | high | 61603 |
| `106066` | 7 | `T1124` T1124 | Use of W32tm as Timer | high | 61603 |
| `106067` | 7 | `T1033` T1033 | Whoami.EXE Execution From Privileged Process | high | 61603 |
| `106068` | 7 | `T1033` T1033 | Security Privileges Enumeration Via Whoami.EXE | high | 61603 |

### Lateral Movement (TA0008) - 24 rules

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

### Collection (TA0009) - 24 rules

| Rule ID | Level | Technique | Description | Confidence | Parent SID |
|---------|-------|-----------|-------------|------------|------------|
| `108000` | 8 | `T1557` T1557 | RottenPotato Like Attack Pattern | high | 60100 |
| `108001` | 8 | `T1557` T1557 | Potential Kerberos Coercion by Spoofing SPNs via DNS Manipulation | high | 60100 |
| `108002` | 8 | `T1557` T1557 | Potential Kerberos Coercion by Spoofing SPNs via DNS Manipulation | high | 60100 |
| `108003` | 8 | `T1557` T1557 | Local Privilege Escalation Indicator TabTip | high | 60106 |
| `108004` | 8 | `T1557` T1557 | Suspicious DNS Query Indicating Kerberos Coercion via DNS Object SP... | high | 61624 |
| `108005` | 8 | `T1599` T1599 | WinDivert Driver Load | high | 61608 |
| `108006` | 8 | `T1599` T1599 | WinDivert Driver Load | high | 61608 |
| `108007` | 8 | `T1195` T1195 | Uncommon File Created by Notepad++ Updater Gup.EXE | high | 61613 |
| `108008` | 8 | `T1185` T1185 | Potential Data Stealing Via Chromium Headless Debugging | high | 61603 |
| `108009` | 8 | `T1195` T1195 | Suspicious Child Process of Notepad++ Updater - GUP.Exe | high | 61603 |
| `108010` | 8 | `T1557` T1557 | HackTool - ADCSPwn Execution | high | 61603 |
| `108011` | 8 | `T1557` T1557 | HackTool - Impacket Tools Execution | high | 61603 |
| `108012` | 13 | `T1557` T1557 | HackTool - Impacket Tools Execution | high | 61603 |
| `108013` | 8 | `T1557` T1557 | Potential SMB Relay Attack Tool Execution | high | 61603 |
| `108014` | 8 | `T1557` T1557 | Potential SMB Relay Attack Tool Execution | high | 61603 |
| `108015` | 8 | `T1557` T1557 | Potential SMB Relay Attack Tool Execution | high | 61603 |
| `108016` | 8 | `T1557` T1557 | Attempts of Kerberos Coercion Via DNS SPN Spoofing | high | 61603 |
| `108017` | 8 | `T1560` T1560 | Suspicious Manipulation Of Default Accounts Via Net.EXE | high | 61603 |
| `108018` | 8 | `T1560` T1560 | Rar Usage with Password and Compression Level | high | 61603 |
| `108019` | 8 | `T1005` T1005 | VeeamBackup Database Credentials Dump Via Sqlcmd.EXE | high | 61603 |
| `108020` | 8 | `T1539` T1539 | SQLite Chromium Profile Data DB Access | high | 61603 |
| `108021` | 8 | `T1539` T1539 | SQLite Firefox Profile Data DB Access | high | 61603 |
| `108022` | 8 | `T1552` T1552 | Script Interpreter Spawning Credential Scanner - Windows | high | 61603 |
| `108023` | 8 | `T1125` T1125 | Suspicious Camera and Microphone Access | high | 61615 |

### Command and Control (TA0011) - 20 rules

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

### Exfiltration (TA0010) - 17 rules

| Rule ID | Level | Technique | Description | Confidence | Parent SID |
|---------|-------|-----------|-------------|------------|------------|
| `110000` | 13 | `T1567` T1567 | DNS Query for Anonfiles.com Domain - Sysmon | high | 61624 |
| `110001` | 13 | `T1105` Ingress Tool Transfer | Suspicious Dropbox API Usage | high | 61605 |
| `110002` | 13 | `T1567` T1567 | Process Initiated Network Connection To Ngrok Domain | high | 61605 |
| `110003` | 13 | `T1567` T1567 | Communication To Ngrok Tunneling Service Initiated | high | 61605 |
| `110004` | 13 | `T1048` T1048 | Powershell DNSExfiltration | high | 91801 |
| `110005` | 13 | - | Suspicious PowerShell Mailbox Export to Share - PS | high | 91801 |
| `110006` | 13 | `T1048` T1048 | DNS Exfiltration and Tunneling Tools Execution | high | 61603 |
| `110007` | 13 | `T1048` T1048 | DNS Exfiltration and Tunneling Tools Execution | high | 61603 |
| `110008` | 13 | - | Email Exifiltration Via Powershell | high | 61603 |
| `110009` | 13 | - | Suspicious PowerShell Mailbox Export to Share | high | 61603 |
| `110010` | 13 | `T1567` T1567 | PUA - Rclone Execution | high | 61603 |
| `110011` | 13 | `T1048` T1048 | PUA - Restic Backup Tool Execution | high | 61603 |
| `110012` | 13 | `T1048` T1048 | PUA - Restic Backup Tool Execution | high | 61603 |
| `110013` | 13 | `T1048` T1048 | PUA - Restic Backup Tool Execution | high | 61603 |
| `110014` | 13 | `T1012` T1012 | Exports Critical Registry Keys To a File | high | 61603 |
| `110015` | 13 | `T1048` T1048 | Suspicious WebDav Client Execution Via Rundll32.EXE | high | 61603 |
| `110016` | 13 | `T1048` T1048 | Suspicious Redirection to Local Admin Share | high | 61603 |

### Impact (TA0040) - 27 rules

| Rule ID | Level | Technique | Description | Confidence | Parent SID |
|---------|-------|-----------|-------------|------------|------------|
| `111000` | 14 | `T1499` T1499 | NTFS Vulnerability Exploitation | high | 60106 |
| `111001` | 14 | `T1486` Data Encrypted for Impact | Load Of RstrtMgr.DLL By A Suspicious Process | high | 61609 |
| `111002` | 14 | `T1490` T1490 | Suspicious Volume Shadow Copy VSS_PS.dll Load | high | 61609 |
| `111003` | 14 | `T1490` T1490 | Suspicious Volume Shadow Copy Vssapi.dll Load | high | 61609 |
| `111004` | 14 | `T1496` T1496 | Network Communication With Crypto Mining Pool | high | 61605 |
| `111005` | 14 | `T1490` T1490 | Delete Volume Shadow Copies Via WMI With PowerShell | high | 91801 |
| `111006` | 14 | `T1565` T1565 | Powershell Add Name Resolution Policy Table Rule | high | 91801 |
| `111007` | 14 | `T1490` T1490 | Deletion of Volume Shadow Copies via WMI with PowerShell - PS Script | high | 91801 |
| `111008` | 14 | `T1490` T1490 | Boot Configuration Tampering Via Bcdedit.EXE | high | 61603 |
| `111009` | 14 | `T1490` T1490 | Copy From VolumeShadowCopy Via Cmd.EXE | high | 61603 |
| `111010` | 14 | `T1070` Indicator Removal | Fsutil Suspicious Invocation | high | 61603 |
| `111011` | 14 | `T1490` T1490 | Deletion of Volume Shadow Copies via WMI with PowerShell | high | 61603 |
| `111012` | 14 | `T1486` Data Encrypted for Impact | Suspicious Reg Add BitLocker | high | 61603 |
| `111013` | 14 | `T1490` T1490 | System Restore Registry Modification via CommandLine | high | 61603 |
| `111014` | 14 | `T1486` Data Encrypted for Impact | Renamed Gpg.EXE Execution | high | 61603 |
| `111015` | 14 | `T1485` Data Destruction | Renamed Sysinternals Sdelete Execution | high | 61603 |
| `111016` | 14 | `T1489` Service Stop | Delete Important Scheduled Task | high | 61603 |
| `111017` | 14 | `T1489` Service Stop | Delete All Scheduled Tasks | high | 61603 |
| `111018` | 14 | `T1489` Service Stop | Disable Important Scheduled Task | high | 61603 |
| `111019` | 14 | `T1496` T1496 | Potential Crypto Mining Activity | high | 61603 |
| `111020` | 14 | `T1490` T1490 | Sensitive File Access Via Volume Shadow Copy Backup | high | 61603 |
| `111021` | 14 | `T1489` Service Stop | Suspicious Windows Service Tampering | high | 61603 |
| `111022` | 14 | `T1070` Indicator Removal | Shadow Copies Deletion Using Operating Systems Utilities | high | 61603 |
| `111023` | 14 | `T1485` Data Destruction | Potential File Overwrite Via Sysinternals SDelete | high | 61603 |
| `111024` | 14 | `T1490` T1490 | All Backups Deleted Via Wbadmin.EXE | high | 61603 |
| `111025` | 14 | `T1490` T1490 | Registry Disable System Restore | high | 61615 |
| `111026` | 14 | `T1491` T1491 | Potential Ransomware Activity Using LegalNotice Message | high | 61615 |

## Exported Rule Files

Rules are exported in three parallel views. Each view contains the same rules, organized differently.

### `database/rules/by_tactic/`
_One XML file per MITRE ATT&CK tactic. Best for broad deployment._

| File | Rules |
|------|-------|
| `collection.xml` | 24 |
| `command_and_control.xml` | 14 |
| `credential_access.xml` | 22 |
| `defense_evasion.xml` | 30 |
| `discovery.xml` | 59 |
| `execution.xml` | 383 |
| `exfiltration.xml` | 17 |
| `impact.xml` | 27 |
| `initial_access.xml` | 1 |
| `lateral_movement.xml` | 16 |
| `persistence.xml` | 267 |
| `privilege_escalation.xml` | 13 |

### `database/rules/by_technique/`
_One XML file per MITRE technique. Best for selective deployment._

| File | Rules |
|------|-------|
| `T1001_unknown.xml` | 1 |
| `T1003_credential_dumping.xml` | 56 |
| `T1005_data_from_local_system.xml` | 1 |
| `T1012_unknown.xml` | 3 |
| `T1018_unknown.xml` | 5 |
| `T1021_remote_services.xml` | 20 |
| `T1027_obfuscated_files.xml` | 40 |
| `T1033_unknown.xml` | 8 |
| `T1036_unknown.xml` | 6 |
| `T1037_unknown.xml` | 2 |
| `T1046_unknown.xml` | 2 |
| `T1047_unknown.xml` | 8 |
| `T1048_exfil_over_alt_protocol.xml` | 8 |
| `T1049_unknown.xml` | 3 |
| `T1053_scheduled_task.xml` | 12 |
| `T1055_process_injection.xml` | 42 |
| `T1059_command_scripting.xml` | 50 |
| `T1068_exploitation_for_privesc.xml` | 1 |
| `T1070_indicator_removal.xml` | 13 |
| `T1071_application_layer_protocol.xml` | 6 |
| `T1078_valid_accounts.xml` | 2 |
| `T1082_system_info_discovery.xml` | 8 |
| `T1087_account_discovery.xml` | 17 |
| `T1090_unknown.xml` | 5 |
| `T1098_unknown.xml` | 5 |
| `T1102_unknown.xml` | 1 |
| `T1105_ingress_tool_transfer.xml` | 10 |
| `T1106_unknown.xml` | 2 |
| `T1112_unknown.xml` | 34 |
| `T1124_unknown.xml` | 1 |
| `T1125_unknown.xml` | 1 |
| `T1127_unknown.xml` | 5 |
| `T1133_unknown.xml` | 5 |
| `T1134_access_token_manipulation.xml` | 4 |
| `T1135_unknown.xml` | 1 |
| `T1136_unknown.xml` | 5 |
| `T1137_unknown.xml` | 11 |
| `T1176_unknown.xml` | 1 |
| `T1185_unknown.xml` | 1 |
| `T1187_unknown.xml` | 2 |
| `T1190_exploit_public_app.xml` | 3 |
| `T1195_unknown.xml` | 3 |
| `T1197_unknown.xml` | 4 |
| `T1202_unknown.xml` | 1 |
| `T1203_unknown.xml` | 1 |
| `T1204_user_execution.xml` | 6 |
| `T1210_unknown.xml` | 1 |
| `T1212_unknown.xml` | 1 |
| `T1218_unknown.xml` | 17 |
| `T1219_unknown.xml` | 5 |
| `T1222_unknown.xml` | 2 |
| `T1482_unknown.xml` | 4 |
| `T1485_data_destruction.xml` | 2 |
| `T1486_data_encrypted_for_impact.xml` | 3 |
| `T1489_service_stop.xml` | 4 |
| `T1490_unknown.xml` | 11 |
| `T1491_unknown.xml` | 1 |
| `T1496_unknown.xml` | 2 |
| `T1499_unknown.xml` | 1 |
| `T1505_unknown.xml` | 16 |
| `T1518_unknown.xml` | 1 |
| `T1526_unknown.xml` | 1 |
| `T1528_unknown.xml` | 2 |
| `T1539_unknown.xml` | 2 |
| `T1542_unknown.xml` | 2 |
| `T1543_create_modify_service.xml` | 26 |
| `T1546_unknown.xml` | 21 |
| `T1547_boot_autostart.xml` | 25 |
| `T1548_abuse_elevation.xml` | 17 |
| `T1550_unknown.xml` | 1 |
| `T1552_unknown.xml` | 3 |
| `T1554_unknown.xml` | 2 |
| `T1555_unknown.xml` | 2 |
| `T1556_unknown.xml` | 3 |
| `T1557_unknown.xml` | 12 |
| `T1558_steal_kerberos_ticket.xml` | 5 |
| `T1560_unknown.xml` | 2 |
| `T1562_unknown.xml` | 24 |
| `T1564_unknown.xml` | 9 |
| `T1565_unknown.xml` | 1 |
| `T1566_phishing.xml` | 4 |
| `T1567_exfil_over_web_service.xml` | 4 |
| `T1569_system_services.xml` | 3 |
| `T1571_unknown.xml` | 1 |
| `T1572_unknown.xml` | 3 |
| `T1574_unknown.xml` | 47 |
| `T1587_unknown.xml` | 1 |
| `T1590_unknown.xml` | 3 |
| `T1599_unknown.xml` | 2 |
| `T1615_unknown.xml` | 4 |
| `T1649_unknown.xml` | 2 |
| `unknown_discovery.xml` | 1 |
| `unknown_execution.xml` | 22 |
| `unknown_exfiltration.xml` | 3 |
| `unknown_persistence.xml` | 20 |

### `database/rules/by_source/`
_Grouped by Windows event source to align with Wazuh decoders._

| File | Rules |
|------|-------|
| `other.xml` | 777 |
| `powershell.xml` | 39 |
| `security.xml` | 35 |
| `sysmon.xml` | 131 |
| `system.xml` | 504 |

## Deployment to Wazuh

Copy the desired view's XML files to your Wazuh manager:

```bash
# Option A: Deploy by tactic
sudo cp database/rules/by_tactic/*.xml /var/ossec/etc/rules/

# Option B: Deploy by source
sudo cp database/rules/by_source/*.xml /var/ossec/etc/rules/

# Restart Wazuh manager to load new rules
sudo systemctl restart wazuh-manager

# Verify rules loaded
sudo /var/ossec/bin/wazuh-logtest
```
