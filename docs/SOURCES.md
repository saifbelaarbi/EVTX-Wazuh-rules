# EVTX Sources Documentation

This document describes the EVTX sample sources used to generate the Wazuh rule database.

## Source Repositories

| # | Source | Repository | EVTX Files Used | Rules Generated |
|---|--------|------------|-----------------|-----------------|
| 1 | [EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES) | `EVTX-ATTACK-SAMPLES` | 33 | 64 |
| 2 | [EVTX-to-MITRE-Attack](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack) | `EVTX-to-MITRE-Attack` | 11 | 16 |
| 3 | [hayabusa-sample-evtx](https://github.com/Yamato-Security/hayabusa-sample-evtx) | `hayabusa-sample-evtx` | 1 | 4 |
| | **Total** | | **45** | **84** |

## EVTX-ATTACK-SAMPLES
**Repository:** https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES

| Directory | EVTX Files | Rules Generated | Sample Files |
|-----------|------------|-----------------|--------------|
| AutomatedTestingTools | 4 | 23 | `DE_timestomp_and_dll_sideloading_and_RunPersist.evtx`, `rundll32_cmd_schtask.evtx`, `PanacheSysmon_vs_AtomicRedTeam01.evtx` +1 more |
| Credential Access | 6 | 9 | `CA_4624_4625_LogonType2_LogonProc_chrome.evtx`, `CA_sysmon_hashdump_cmd_meterpreter.evtx`, `discovery_sysmon_1_iis_pwd_and_config_discovery_appcmd.evtx` +3 more |
| Defense Evasion | 2 | 4 | `Sysmon 7  Update Session Orchestrator Dll Hijack.evtx`, `de_PsScriptBlockLogging_disabled_sysmon12_13.evtx` |
| Execution | 7 | 9 | `Sysmon_meterpreter_ReflectivePEInjection_to_notepad_.evtx`, `exec_persist_rundll32_mshta_scheduledtask_sysmon_1_3_11.evtx`, `exec_sysmon_1_7_jscript9_defense_evasion.evtx` +4 more |
| Lateral Movement | 5 | 7 | `LM_DCOM_MSHTA_LethalHTA_Sysmon_3_1.evtx`, `LM_sysmon_psexec_smb_meterpreter.evtx`, `LM_typical_IIS_webshell_sysmon_1_10_traces.evtx` +2 more |
| Persistence | 4 | 6 | `persistence_sysmon_11_13_1_shime_appfix.evtx`, `sysmon_13_1_persistence_via_winlogon_shell.evtx`, `sysmon_1_persist_bitsjob_SetNotifyCmdLine.evtx` +1 more |
| Privilege Escalation | 5 | 6 | `privesc_unquoted_svc_sysmon_1_11.evtx`, `sysmon_11_7_1_uacbypass_windirectory_mocking.evtx`, `sysmon_1_13_11_cmstp_ini_uacbypass.evtx` +2 more |

## EVTX-to-MITRE-Attack
**Repository:** https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack

| Directory | EVTX Files | Rules Generated | Sample Files |
|-----------|------------|-----------------|--------------|
| EVTX_full_APT_attack_steps | 1 | 2 | `ID11,13,17,18-PSexec as system execution.evtx` |
| TA0001-Initial access | 1 | 1 | `ID4625-failed login with denied access due to account restriction.evtx` |
| TA0002-Execution | 1 | 2 | `ID4103-4104-Payload download via PowerShell.evtx` |
| TA0003-Persistence | 2 | 2 | `ID7045-7036 PSexec service installation.evtx`, `ID7045-New service for Mimikatz +npcap.evtx` |
| TA0005-Defense Evasion | 3 | 4 | `ID1-CrackMapExec payload execution.evtx`, `ID800-4103-4104 Defender critical features disabled (PowerShell).evtx`, `ID4103-4104-2004-OpenSSH firewall rule activation.evtx` |
| TA0006-Credential Access | 1 | 1 | `ID10-Mimikatz LSASS process dump.evtx` |
| TA0007-Discovery | 1 | 3 | `ID800-4103-4104-Firewall configuration enumerated (PowerShell).evtx` |
| TA0008-Lateral Movement | 1 | 1 | `ID4103-4104-OpenSSH server activation and config.evtx` |

## hayabusa-sample-evtx
**Repository:** https://github.com/Yamato-Security/hayabusa-sample-evtx

| Directory | EVTX Files | Rules Generated | Sample Files |
|-----------|------------|-----------------|--------------|
| DeepBlueCLI | 1 | 4 | `Powershell-Invoke-Obfuscation-many.evtx` |

## Credits

This project relies on the security research community for EVTX samples:

- **SBousseaden** — [EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES) — Windows EVTX samples mapped to MITRE ATT&CK
- **mdecrevoisier** — [EVTX-to-MITRE-Attack](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack) — 270+ EVTX samples with ATT&CK mapping
- **Yamato Security** — [hayabusa-sample-evtx](https://github.com/Yamato-Security/hayabusa-sample-evtx) — Aggregated EVTX sample collection
- **Wazuh Inc.** — [wazuh-ruleset](https://github.com/wazuh/wazuh-ruleset) — Official default Wazuh rules and decoders
