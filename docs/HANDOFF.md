# Handoff

Generated: 2026-04-29

## What Was Done

- Read the generated Wazuh rule corpus under `database/rules/`.
- Read the generated documentation under `docs/`.
- Read the rule-generation logic in:
- [generator/event_analyzer.py](C:\Users\user\Desktop\TMP\EVTX-Wazuh-rules\generator\event_analyzer.py)
- [generator/rule_builder.py](C:\Users\user\Desktop\TMP\EVTX-Wazuh-rules\generator\rule_builder.py)
- [generator/rule_correlator.py](C:\Users\user\Desktop\TMP\EVTX-Wazuh-rules\generator\rule_correlator.py)
- [generator/alert_leveler.py](C:\Users\user\Desktop\TMP\EVTX-Wazuh-rules\generator\alert_leveler.py)
- [generator/validator.py](C:\Users\user\Desktop\TMP\EVTX-Wazuh-rules\generator\validator.py)
- Read metadata and generated reports, especially:
- [docs/RULES_REPORT.md](C:\Users\user\Desktop\TMP\EVTX-Wazuh-rules\docs\RULES_REPORT.md)
- [docs/COVERAGE_MATRIX.md](C:\Users\user\Desktop\TMP\EVTX-Wazuh-rules\docs\COVERAGE_MATRIX.md)
- [database/metadata/validation_results.json](C:\Users\user\Desktop\TMP\EVTX-Wazuh-rules\database\metadata\validation_results.json)
- [database/metadata/rule_index.json](C:\Users\user\Desktop\TMP\EVTX-Wazuh-rules\database\metadata\rule_index.json)

## Files Added

- [docs/CURATED_RULE_REVIEW.md](C:\Users\user\Desktop\TMP\EVTX-Wazuh-rules\docs\CURATED_RULE_REVIEW.md)
- [docs/HANDOFF.md](C:\Users\user\Desktop\TMP\EVTX-Wazuh-rules\docs\HANDOFF.md)

No existing files were modified.

## Main Findings

- The ruleset is broad, but the EVTX-generated portion is not production-ready as-is.
- The generator is heavily heuristic and relies on substring matching for suspicious processes, command-line fragments, PowerShell content, and a few Windows event IDs.
- Tactic is often inferred from the EVTX sample path, which causes incorrect ATT&CK mapping.
- MITRE technique assignment can default from tactic rather than from event semantics.
- Validation is mostly structural and does not meaningfully validate detection quality.

Measured findings:
- EVTX-generated validation pass rate from `validation_results.json`: `98/793` passed (`12.4%`).
- Cross-tactic duplicate rules with identical field logic but different tactic labels: `101`.
- Duplicate-logic groups identified: `58`, affecting `169` rules.

## Representative Problems

- Failed logon `4625` mapped to phishing `T1566`:
- [database/rules/by_tactic/initial_access.xml](C:\Users\user\Desktop\TMP\EVTX-Wazuh-rules\database\rules\by_tactic\initial_access.xml:3)
- Generic remote logon type `3` mapped to Command and Control `T1071`:
- [database/rules/by_source/security.xml](C:\Users\user\Desktop\TMP\EVTX-Wazuh-rules\database\rules\by_source\security.xml:21)
- User account creation `4720` mapped to process injection `T1055`:
- [database/rules/by_source/security.xml](C:\Users\user\Desktop\TMP\EVTX-Wazuh-rules\database\rules\by_source\security.xml:60)
- Sample-specific service install rule using brittle exact `serviceName` content:
- [database/rules/by_source/system.xml](C:\Users\user\Desktop\TMP\EVTX-Wazuh-rules\database\rules\by_source\system.xml:3)
- `invoke-wmimethod` mapped to credential dumping `T1003`:
- [database/rules/by_source/powershell.xml](C:\Users\user\Desktop\TMP\EVTX-Wazuh-rules\database\rules\by_source\powershell.xml:75)

## High-Value Detections Worth Keeping

- PowerShell credential-dumping strings such as `invoke-mimikatz`, `sekurlsa::`, `lsadump::`
- Sysmon command-line strings such as `dumpert`, `comsvcs.dll`, `minidump`, `procdump`
- WMI subscription activity
- Curated LOLBin usage such as `mshta`, `regsvr32`, `certutil`, `wmic`, `rundll32`
- Suspicious file and DLL path patterns like `\appdata\`, `\temp\`, `\downloads\`, `\programdata\`

## Recommended Next Steps

1. Build a rule-ID-based cleanup plan.
2. Deduplicate identical logic across tactics.
3. Remove obviously wrong ATT&CK mappings.
4. Drop sample-specific brittle rules.
5. Keep and normalize the high-signal offensive-tool and credential-dumping rules.
6. Rework generic Security log rules so they are contextual or correlation-based instead of standalone alerts.

## Suggested Next Task For Another Agent

Create a new document, for example `docs/RULE_CLEANUP_PLAN.md`, containing:
- exact rule IDs to keep
- exact rule IDs to merge
- exact rule IDs to rewrite
- exact rule IDs to drop
- rationale for each bucket

The best starting point is:
- keep the high-signal PowerShell and Sysmon artifact rules
- review all `4624`, `4625`, `4672`, `4698`, `4720`, and `7045` families
- collapse cross-tactic duplicates into one canonical detection per logic pattern
