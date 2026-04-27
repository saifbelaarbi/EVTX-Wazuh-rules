# Wazuh Rule Database Report

> Generated: 2026-04-27 13:50 UTC
> Pipeline version: 1.0.0

## Overview

| Metric | Value |
|--------|-------|
| Total rules generated | **84** |
| EVTX files processed | 45 |
| EVTX sources used | 1 |
| MITRE tactics covered | 9 / 12 |
| MITRE techniques covered | 9 |
| Rule ID range | 100000 - 120000 |

## Alert Level Distribution

| Level | Wazuh Severity | Count | Percentage |
|-------|----------------|-------|------------|
| 6 | Low relevance | 4 | 4.8% ██ |
| 8 | First time seen | 9 | 10.7% █████ |
| 9 | Error from invalid source | 30 | 35.7% █████████████████ |
| 10 | Multiple user-generated errors | 20 | 23.8% ███████████ |
| 11 | Integrity checking warning | 9 | 10.7% █████ |
| 12 | High importance event | 9 | 10.7% █████ |
| 13 | Unusual error (high importance) | 3 | 3.6% █ |

## Detection Confidence Distribution

| Confidence | Count | Description |
|------------|-------|-------------|
| high | 51 | Exact tool/process name match |
| medium | 31 | Command-line pattern or behavioral indicator |
| low | 2 | Heuristic / generic event |

## Rules by MITRE ATT&CK Tactic

### Initial Access (TA0001) — 1 rules

| Rule ID | Level | Technique | Description | Confidence | Parent SID |
|---------|-------|-----------|-------------|------------|------------|
| `100000` | 6 | `T1566` Phishing | Failed logon attempt | low | 60100 |

### Execution (TA0002) — 27 rules

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

### Persistence (TA0003) — 15 rules

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

### Privilege Escalation (TA0004) — 5 rules

| Rule ID | Level | Technique | Description | Confidence | Parent SID |
|---------|-------|-----------|-------------|------------|------------|
| `103000` | 11 | `T1548` Abuse Elevation Control Mechanism | Suspicious process: rundll32 | high | 61603 |
| `103001` | 10 | `T1548` Abuse Elevation Control Mechanism | Suspicious command: bypass | medium | 61603 |
| `103002` | 11 | `T1548` Abuse Elevation Control Mechanism | Suspicious process: cmstp | high | 61603 |
| `103003` | 11 | `T1548` Abuse Elevation Control Mechanism | Suspicious process: psexec | high | 61603 |
| `103004` | 11 | `T1548` Abuse Elevation Control Mechanism | Suspicious process: psexesvc | high | 61603 |

### Defense Evasion (TA0005) — 7 rules

| Rule ID | Level | Technique | Description | Confidence | Parent SID |
|---------|-------|-----------|-------------|------------|------------|
| `104000` | 10 | `T1055` Process Injection | Suspicious process: rundll32 | high | 61603 |
| `104001` | 10 | `T1055` Process Injection | Network connection by rundll32 | high | 61605 |
| `104002` | 10 | `T1055` Process Injection | Suspicious process: regsvr32 | high | 61603 |
| `104003` | 9 | `T1055` Process Injection | Suspicious command: bypass | medium | 61603 |
| `104004` | 9 | `T1055` Process Injection | Suspicious command: -nop  | medium | 61603 |
| `104005` | 9 | `T1055` Process Injection | Suspicious PowerShell: set-mppreference -disablerealtimemonitoring | medium | 91801 |
| `104006` | 9 | `T1055` Process Injection | Suspicious PowerShell: bypass | medium | 91801 |

### Credential Access (TA0006) — 12 rules

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

### Discovery (TA0007) — 3 rules

| Rule ID | Level | Technique | Description | Confidence | Parent SID |
|---------|-------|-----------|-------------|------------|------------|
| `106000` | 6 | `T1087` Account Discovery | Suspicious PowerShell: invoke-expression | medium | 91801 |
| `106001` | 6 | `T1087` Account Discovery | Suspicious PowerShell: invoke-webrequest | medium | 91801 |
| `106002` | 6 | `T1087` Account Discovery | Suspicious PowerShell: bypass | medium | 91801 |

### Lateral Movement (TA0008) — 8 rules

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

### Command and Control (TA0011) — 6 rules

| Rule ID | Level | Technique | Description | Confidence | Parent SID |
|---------|-------|-----------|-------------|------------|------------|
| `109000` | 10 | `T1071` Application Layer Protocol | Network connection by regsvr32 | high | 61605 |
| `109001` | 10 | `T1071` Application Layer Protocol | Network connection by mshta | high | 61605 |
| `109002` | 10 | `T1071` Application Layer Protocol | Network connection by mshta | high | 61605 |
| `109003` | 10 | `T1071` Application Layer Protocol | Network connection by wmic | high | 61605 |
| `109004` | 10 | `T1071` Application Layer Protocol | Network connection by rundll32 | high | 61605 |
| `109005` | 10 | `T1071` Application Layer Protocol | Network connection by certutil | high | 61605 |

## Exported Rule Files

Rules are exported in three parallel views. Each view contains the same rules, organized differently:

### `database/rules/by_tactic/`
_One XML file per MITRE ATT&CK tactic. Best for broad deployment._

| File | Rules |
|------|-------|
| `command_and_control.xml` | 6 |
| `credential_access.xml` | 12 |
| `defense_evasion.xml` | 7 |
| `discovery.xml` | 3 |
| `execution.xml` | 27 |
| `initial_access.xml` | 1 |
| `lateral_movement.xml` | 8 |
| `persistence.xml` | 15 |
| `privilege_escalation.xml` | 5 |

### `database/rules/by_technique/`
_One XML file per MITRE technique. Best for selective/granular deployment._

| File | Rules |
|------|-------|
| `T1003_credential_dumping.xml` | 12 |
| `T1021_remote_services.xml` | 8 |
| `T1055_process_injection.xml` | 7 |
| `T1059_command_scripting.xml` | 27 |
| `T1071_application_layer_protocol.xml` | 6 |
| `T1087_account_discovery.xml` | 3 |
| `T1547_boot_autostart.xml` | 15 |
| `T1548_abuse_elevation.xml` | 5 |
| `T1566_phishing.xml` | 1 |

### `database/rules/by_source/`
_Grouped by Windows event source (Sysmon, Security, PowerShell, System). Aligns with Wazuh decoder structure._

| File | Rules |
|------|-------|
| `powershell.xml` | 12 |
| `security.xml` | 2 |
| `sysmon.xml` | 68 |
| `system.xml` | 2 |

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
