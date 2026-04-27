# MITRE ATT&CK Coverage Matrix

> 84 rules across 9 tactics

## Coverage Heatmap

| Tactic | ID | Rules | Techniques | Coverage |
|--------|----|-------|------------|----------|
| Initial Access | `TA0001` | 1 | 1 | 🟩 |
| Execution | `TA0002` | 27 | 1 | 🟩🟩🟩🟩🟩🟩🟩🟩🟩🟩🟩🟩🟩🟩🟩🟩🟩🟩🟩🟩 |
| Persistence | `TA0003` | 15 | 1 | 🟩🟩🟩🟩🟩🟩🟩🟩🟩🟩🟩🟩🟩🟩🟩 |
| Privilege Escalation | `TA0004` | 5 | 1 | 🟩🟩🟩🟩🟩 |
| Defense Evasion | `TA0005` | 7 | 1 | 🟩🟩🟩🟩🟩🟩🟩 |
| Credential Access | `TA0006` | 12 | 1 | 🟩🟩🟩🟩🟩🟩🟩🟩🟩🟩🟩🟩 |
| Discovery | `TA0007` | 3 | 1 | 🟩🟩🟩 |
| Lateral Movement | `TA0008` | 8 | 1 | 🟩🟩🟩🟩🟩🟩🟩🟩 |
| Collection | `TA0009` | 0 | 0 |  |
| Command and Control | `TA0011` | 6 | 1 | 🟩🟩🟩🟩🟩🟩 |
| Exfiltration | `TA0010` | 0 | 0 |  |
| Impact | `TA0040` | 0 | 0 |  |

## Technique Detail

### Initial Access

| Technique | Name | Rules | Rule IDs |
|-----------|------|-------|----------|
| `T1566` | Phishing | 1 | `100000` |

### Execution

| Technique | Name | Rules | Rule IDs |
|-----------|------|-------|----------|
| `T1059` | Command and Scripting Interpreter | 27 | `101000`, `101001`, `101002`, `101003`, `101004`, `101005`, `101006`, `101007`, `101008`, `101009`, `101010`, `101011`, `101012`, `101013`, `101014`, `101015`, `101016`, `101017`, `101018`, `101019`, `101020`, `101021`, `101022`, `101023`, `101024`, `101025`, `101026` |

### Persistence

| Technique | Name | Rules | Rule IDs |
|-----------|------|-------|----------|
| `T1547` | Boot or Logon Autostart Execution | 15 | `102000`, `102001`, `102002`, `102003`, `102004`, `102005`, `102006`, `102007`, `102008`, `102009`, `102010`, `102011`, `102012`, `102013`, `102014` |

### Privilege Escalation

| Technique | Name | Rules | Rule IDs |
|-----------|------|-------|----------|
| `T1548` | Abuse Elevation Control Mechanism | 5 | `103000`, `103001`, `103002`, `103003`, `103004` |

### Defense Evasion

| Technique | Name | Rules | Rule IDs |
|-----------|------|-------|----------|
| `T1055` | Process Injection | 7 | `104000`, `104001`, `104002`, `104003`, `104004`, `104005`, `104006` |

### Credential Access

| Technique | Name | Rules | Rule IDs |
|-----------|------|-------|----------|
| `T1003` | OS Credential Dumping | 12 | `105000`, `105001`, `105002`, `105003`, `105004`, `105005`, `105006`, `105007`, `105008`, `105009`, `105010`, `105011` |

### Discovery

| Technique | Name | Rules | Rule IDs |
|-----------|------|-------|----------|
| `T1087` | Account Discovery | 3 | `106000`, `106001`, `106002` |

### Lateral Movement

| Technique | Name | Rules | Rule IDs |
|-----------|------|-------|----------|
| `T1021` | Remote Services | 8 | `107000`, `107001`, `107002`, `107003`, `107004`, `107005`, `107006`, `107007` |

### Command and Control

| Technique | Name | Rules | Rule IDs |
|-----------|------|-------|----------|
| `T1071` | Application Layer Protocol | 6 | `109000`, `109001`, `109002`, `109003`, `109004`, `109005` |

## Coverage Gaps

Tactics with **no rules yet** (opportunities for expansion):

- **Collection** (`TA0009`)
- **Exfiltration** (`TA0010`)
- **Impact** (`TA0040`)
