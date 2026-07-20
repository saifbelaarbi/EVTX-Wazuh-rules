# EVTX Sources Documentation

This document describes the EVTX sample sources used to generate the Wazuh rule database.

## Source Repositories

| # | Source | Repository | EVTX Files Used | Rules Generated |
|---|--------|------------|-----------------|-----------------|
| 1 | [EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES) | `EVTX-ATTACK-SAMPLES` | 43 | 99 |
| 2 | [EVTX-to-MITRE-Attack](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack) | `EVTX-to-MITRE-Attack` | 12 | 509 |
| 3 | [Security-Datasets](https://github.com/OTRF/Security-Datasets) | `Security-Datasets` | 1 | 1 |
| 4 | [danderspritz-evtx](https://github.com/fox-it/danderspritz-evtx) | `danderspritz-evtx` | 1 | 2 |
| 5 | [hayabusa-sample-evtx](https://github.com/Yamato-Security/hayabusa-sample-evtx) | `hayabusa-sample-evtx` | 5 | 15 |
| 6 | unknown | `unknown` | 2232 | 2722 |
| | **Total** | | **2294** | **3348** |

## EVTX-ATTACK-SAMPLES
**Repository:** https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES

| Directory | EVTX Files | Rules Generated | Sample Files |
|-----------|------------|-----------------|--------------|
| AutomatedTestingTools | 5 | 46 | `DE_timestomp_and_dll_sideloading_and_RunPersist.evtx`, `rundll32_cmd_schtask.evtx`, `sideloading_injection_persistence_run_key.evtx` +2 more |
| Command and Control | 1 | 4 | `DE_RDP_Tunnel_5156.evtx` |
| Credential Access | 9 | 13 | `CA_4624_4625_LogonType2_LogonProc_chrome.evtx`, `CA_sysmon_hashdump_cmd_meterpreter.evtx`, `Powershell_4104_MiniDumpWriteDump_Lsass.evtx` +6 more |
| Defense Evasion | 6 | 7 | `DE_Fake_ComputerAccount_4720.evtx`, `DE_ProcessHerpaderping_Sysmon_11_10_1_7.evtx`, `Sysmon 7  Update Session Orchestrator Dll Hijack.evtx` +3 more |
| Discovery | 1 | 2 | `Discovery_Remote_System_NamedPipes_Sysmon_18.evtx` |
| Execution | 8 | 9 | `Exec_sysmon_meterpreter_reversetcp_msipackage.evtx`, `Sysmon_meterpreter_ReflectivePEInjection_to_notepad_.evtx`, `exec_sysmon_lobin_regsvr32_sct.evtx` +5 more |
| Lateral Movement | 4 | 4 | `LM_DCOM_MSHTA_LethalHTA_Sysmon_3_1.evtx`, `LM_sysmon_psexec_smb_meterpreter.evtx`, `LM_typical_IIS_webshell_sysmon_1_10_traces.evtx` +1 more |
| Persistence | 4 | 7 | `Network_Service_Guest_added_to_admins_4732.evtx`, `sysmon_13_1_persistence_via_winlogon_shell.evtx`, `sysmon_20_21_1_CommandLineEventConsumer.evtx` +1 more |
| Privilege Escalation | 5 | 7 | `Sysmon_UACME_39.evtx`, `samaccount_spoofing_CVE-2021-42287_CVE-2021-42278_DC_securitylogs.evtx`, `sysmon_privesc_from_admin_to_system_handle_inheritance.evtx` +2 more |

## EVTX-to-MITRE-Attack
**Repository:** https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack

| Directory | EVTX Files | Rules Generated | Sample Files |
|-----------|------------|-----------------|--------------|
| EVTX_full_APT_attack_steps | 1 | 2 | `ID11,13,17,18-PSexec as system execution.evtx` |
| TA0002-Execution | 2 | 492 | `ID4103-4104-Payload download via PowerShell.evtx`, `ID7000,7009,7045-Payload deployed via service - Tchopper.evtx` |
| TA0003-Persistence | 3 | 4 | `ID7045-7036 PSexec service installation.evtx`, `ID7045-New service for Mimikatz +npcap.evtx`, `ID19-20-WMI registration via PowerLurk.evtx` |
| TA0005-Defense Evasion | 3 | 5 | `ID4103-4104-CrackMapExec payload execution.evtx`, `ID800-4103-4104 Defender critical features disabled (PowerShell).evtx`, `ID4103-4104-2004-OpenSSH firewall rule activation.evtx` |
| TA0006-Credential Access | 2 | 4 | `ID10-Mimikatz LSASS process dump.evtx`, `ID800-4103-4104-LSASS dump with LSASSY (PowerShell).evtx` |
| TA0007-Discovery | 1 | 2 | `ID800-4103-4104-Firewall configuration enumerated (PowerShell).evtx` |

## Security-Datasets
**Repository:** https://github.com/OTRF/Security-Datasets

| Directory | EVTX Files | Rules Generated | Sample Files |
|-----------|------------|-----------------|--------------|
| datasets | 1 | 1 | `purplesharp_ad_playbook_I_2020-10-22042947.json` |

## danderspritz-evtx
**Repository:** https://github.com/fox-it/danderspritz-evtx

| Directory | EVTX Files | Rules Generated | Sample Files |
|-----------|------------|-----------------|--------------|
| examples | 1 | 2 | `post-Security.evtx` |

## hayabusa-sample-evtx
**Repository:** https://github.com/Yamato-Security/hayabusa-sample-evtx

| Directory | EVTX Files | Rules Generated | Sample Files |
|-----------|------------|-----------------|--------------|
| DeepBlueCLI | 4 | 14 | `Powershell-Invoke-Obfuscation-many.evtx`, `many-events-system.evtx`, `metasploit-psexec-native-target-system.evtx` +1 more |
| YamatoSecurity | 1 | 1 | `T1218.004_SignedBinaryProxyExecutionInstallUtil_Sysmon.evtx` |

## unknown

| Directory | EVTX Files | Rules Generated | Sample Files |
|-----------|------------|-----------------|--------------|
| (root) | 2232 | 2722 | `win_av_relevant_match.yml`, `win_application_error_lsass_crash.yml`, `win_application_error_msmpeng_crash.yml` +2229 more |

## Credits

This project relies on the security research community for EVTX samples:

- **SBousseaden** — [EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES) — Windows EVTX samples mapped to MITRE ATT&CK
- **mdecrevoisier** — [EVTX-to-MITRE-Attack](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack) — 270+ EVTX samples with ATT&CK mapping
- **Yamato Security** — [hayabusa-sample-evtx](https://github.com/Yamato-Security/hayabusa-sample-evtx) — Aggregated EVTX sample collection
- **OTRF** — [Security-Datasets](https://github.com/OTRF/Security-Datasets) — Pre-recorded adversary simulation data (Mordor)
- **Fox-IT** — [danderspritz-evtx](https://github.com/fox-it/danderspritz-evtx) — DanderSpritz (NSA) detection events
- **SigmaHQ** — [sigma](https://github.com/SigmaHQ/sigma) — Community detection rules in Sigma format
- **Wazuh Inc.** — [wazuh-ruleset](https://github.com/wazuh/wazuh-ruleset) — Official default Wazuh rules and decoders
