# Curated Rule Review

Generated: 2026-04-29

## Verdict

This ruleset is a large heuristic draft set, not a production-ready Wazuh ruleset.

What is good:
- It contains many real attacker artifacts and useful seeds for detection engineering.
- It covers the main Windows telemetry surfaces: Sysmon, Security, System, and PowerShell.
- High-signal strings such as `invoke-mimikatz`, `sekurlsa::`, `lsadump::`, `procdump`, `regsvr32`, `mshta`, and LSASS access patterns are worth keeping.

What is not good:
- The EVTX-generated portion has weak validation quality: `98/793` simulated passes, `695/793` simulated failures.
- The generator infers tactic from the sample path and often assigns MITRE techniques from tactic defaults instead of event semantics.
- The same field logic is duplicated across multiple tactics with different ATT&CK labels.
- Many Security log rules are too generic and will be noisy in production.
- Some rules are overfit to single samples and include brittle exact values.

## Evidence Summary

- Broad heuristic matching is implemented in [generator/event_analyzer.py](C:\Users\user\Desktop\TMP\EVTX-Wazuh-rules\generator\event_analyzer.py:68) and [generator/event_analyzer.py](C:\Users\user\Desktop\TMP\EVTX-Wazuh-rules\generator\event_analyzer.py:632).
- Tactic is inferred from source path in [generator/event_analyzer.py](C:\Users\user\Desktop\TMP\EVTX-Wazuh-rules\generator\event_analyzer.py:121).
- MITRE technique defaults are applied by tactic in [generator/rule_builder.py](C:\Users\user\Desktop\TMP\EVTX-Wazuh-rules\generator\rule_builder.py:42).
- Validation mostly checks XML shape, IDs, and syntax in [generator/validator.py](C:\Users\user\Desktop\TMP\EVTX-Wazuh-rules\generator\validator.py:11).

Measured issues:
- `101` cross-tactic duplicate rules with identical field logic and different tactic labels.
- `58` duplicate-logic groups affecting `169` rules.
- Repeated generic detections include:
- `4672` special privilege assignment repeated across 8 tactics.
- `4624` logon type `3` repeated across 8 tactics.
- `rundll32` process match repeated across 6 tactics.

## Keep

These are the strongest rules or rule families. They detect attacker-specific or high-signal behavior and are worth keeping after deduplication.

### Credential dumping and offensive tool artifacts

- PowerShell `sekurlsa::` matches are high signal and should stay: [database/rules/by_source/powershell.xml](C:\Users\user\Desktop\TMP\EVTX-Wazuh-rules\database\rules\by_source\powershell.xml:125)
- PowerShell `lsadump::` matches are high signal and should stay: [database/rules/by_source/powershell.xml](C:\Users\user\Desktop\TMP\EVTX-Wazuh-rules\database\rules\by_source\powershell.xml:139)
- PowerShell `invoke-mimikatz` matches are high signal and should stay: [database/rules/by_source/powershell.xml](C:\Users\user\Desktop\TMP\EVTX-Wazuh-rules\database\rules\by_source\powershell.xml:153)
- PowerShell `minidump` and `comsvcs.dll` script block matches are useful credential-dumping indicators: [database/rules/by_source/powershell.xml](C:\Users\user\Desktop\TMP\EVTX-Wazuh-rules\database\rules\by_source\powershell.xml:3), [database/rules/by_source/powershell.xml](C:\Users\user\Desktop\TMP\EVTX-Wazuh-rules\database\rules\by_source\powershell.xml:67)
- Sysmon command-line matches for `dumpert`, `comsvcs.dll`, and `minidump` are worth keeping: [database/rules/by_source/sysmon.xml](C:\Users\user\Desktop\TMP\EVTX-Wazuh-rules\database\rules\by_source\sysmon.xml:81), [database/rules/by_source/sysmon.xml](C:\Users\user\Desktop\TMP\EVTX-Wazuh-rules\database\rules\by_source\sysmon.xml:95), [database/rules/by_source/sysmon.xml](C:\Users\user\Desktop\TMP\EVTX-Wazuh-rules\database\rules\by_source\sysmon.xml:102)

### WMI persistence indicators

- WMI event subscription activity is a valid persistence surface and worth keeping: [database/rules/by_source/sysmon.xml](C:\Users\user\Desktop\TMP\EVTX-Wazuh-rules\database\rules\by_source\sysmon.xml:41)

### Suspicious PowerShell tradecraft

- `downloadstring`, `iex(`, `-nop`, `-w hidden`, `invoke-expression` are useful medium-signal indicators when treated as execution or defense-evasion patterns rather than precise ATT&CK conclusions: [database/rules/by_source/powershell.xml](C:\Users\user\Desktop\TMP\EVTX-Wazuh-rules\database\rules\by_source\powershell.xml:10), [database/rules/by_source/powershell.xml](C:\Users\user\Desktop\TMP\EVTX-Wazuh-rules\database\rules\by_source\powershell.xml:17), [database/rules/by_source/powershell.xml](C:\Users\user\Desktop\TMP\EVTX-Wazuh-rules\database\rules\by_source\powershell.xml:96), [database/rules/by_source/powershell.xml](C:\Users\user\Desktop\TMP\EVTX-Wazuh-rules\database\rules\by_source\powershell.xml:103), [database/rules/by_source/powershell.xml](C:\Users\user\Desktop\TMP\EVTX-Wazuh-rules\database\rules\by_source\powershell.xml:31)

### LOLBins and suspicious execution paths

- `mshta`, `regsvr32`, `certutil`, `bitsadmin`, `wmic`, `psexec`, `rundll32` are reasonable rule seeds if deduplicated and correctly mapped: see the early execution rules in [database/rules/by_source/sysmon.xml](C:\Users\user\Desktop\TMP\EVTX-Wazuh-rules\database\rules\by_source\sysmon.xml:31)
- Suspicious executable or DLL paths such as `\appdata\`, `\temp\`, `\downloads\`, `\programdata\` are worth keeping as medium-signal enrichment rules: [database/rules/by_source/sysmon.xml](C:\Users\user\Desktop\TMP\EVTX-Wazuh-rules\database\rules\by_source\sysmon.xml:3)

## Fix

These rules are based on real events, but the current implementation or ATT&CK labeling is weak. Keep the detection idea, but rewrite the logic and mapping.

### Generic remote logon detections

- Remote logon type `3` is repeated across multiple tactics and mapped to unrelated ATT&CK techniques, including Command and Control: [database/rules/by_source/security.xml](C:\Users\user\Desktop\TMP\EVTX-Wazuh-rules\database\rules\by_source\security.xml:21)
- This should be one low-priority enrichment rule, not separate rules for credential access, discovery, defense evasion, privilege escalation, and command and control.

### Generic special privilege assignment detections

- Event `4672` is repeated across many tactics with nearly identical logic.
- This should be one contextual rule only, ideally chained with a suspicious logon or process event.

### Scheduled task creation

- Event `4698` is useful, but a bare event ID match is too generic and is currently remapped into multiple tactics: [database/rules/by_source/security.xml](C:\Users\user\Desktop\TMP\EVTX-Wazuh-rules\database\rules\by_source\security.xml:82)
- Improve by matching task content, encoded commands, suspicious parents, or suspicious task paths.

### Service installation rules

- The service-installation family is overfit because it stores an exact `serviceName` from the sample along with a generic path fragment: [database/rules/by_source/system.xml](C:\Users\user\Desktop\TMP\EVTX-Wazuh-rules\database\rules\by_source\system.xml:3)
- These should be rewritten to match only stable suspicious features such as `ImagePath`, temp paths, LOLBins, or known service names.

### PowerShell patterns with wrong ATT&CK mapping

- `invoke-wmimethod` is currently mapped to `T1003` credential dumping, which is not justified by the string alone: [database/rules/by_source/powershell.xml](C:\Users\user\Desktop\TMP\EVTX-Wazuh-rules\database\rules\by_source\powershell.xml:75)
- `stop-service` under credential access is also not defensible by itself and should be reclassified or dropped unless tied to a stronger context: [database/rules/by_source/powershell.xml](C:\Users\user\Desktop\TMP\EVTX-Wazuh-rules\database\rules\by_source\powershell.xml:82)

## Drop

These rules should not be deployed in their current form.

### Wrong ATT&CK mapping from generic Windows events

- Failed logon `4625` mapped to phishing `T1566` should be dropped or reclassified completely: [database/rules/by_tactic/initial_access.xml](C:\Users\user\Desktop\TMP\EVTX-Wazuh-rules\database\rules\by_tactic\initial_access.xml:3)
- User account creation `4720` mapped to process injection `T1055` should be dropped or rewritten from scratch: [database/rules/by_source/security.xml](C:\Users\user\Desktop\TMP\EVTX-Wazuh-rules\database\rules\by_source\security.xml:60)

### Sample-specific exact values

- Any rule whose logic depends on a sample-specific service name blob, generated task name, or sample hostname should be dropped unless rewritten to stable behavioral indicators.
- Example: exact service name content in the `101069` family is not portable: [database/rules/by_source/system.xml](C:\Users\user\Desktop\TMP\EVTX-Wazuh-rules\database\rules\by_source\system.xml:3)

### Pure duplicate logic across tactics

- The same `rundll32` process match appears in execution, credential access, defense evasion, lateral movement, persistence, and privilege escalation with no logic difference.
- The same `4624` logon type `3` and `4672` rules are cloned across tactics.
- These should be collapsed to one rule per detection logic, with one ATT&CK mapping chosen from actual behavior.

## Practical Deployment Guidance

If deploying this ruleset, only start with:
- Exact offensive-tool strings in Sysmon and PowerShell
- Explicit credential-dumping strings
- WMI event subscription rules
- Curated LOLBin execution rules
- Curated suspicious file path rules

Do not deploy as-is:
- Generic `4624`, `4625`, `4672`, `4698`, `4720` rules without stronger context
- Sample-specific service-installation rules
- Cross-tactic duplicates
- Rules whose ATT&CK mapping is clearly source-path-driven rather than event-driven

## Shortlist

Keep first:
- PowerShell `invoke-mimikatz`, `sekurlsa::`, `lsadump::`
- Sysmon `dumpert`, `comsvcs.dll`, `minidump`, `procdump`
- WMI subscription rules
- Curated LOLBin process creation and network rules

Fix next:
- `4624` logon type `3`
- `4672` special privileges
- `4698` scheduled task creation
- `7045` service installation
- Generic PowerShell execution indicators

Drop first:
- `4625` as phishing
- `4720` as process injection
- any rule with sample-specific exact service names or task names
- duplicate logic cloned across tactics
