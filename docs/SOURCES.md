# EVTX Sources Documentation

This document describes the EVTX sample sources used to generate the Wazuh rule database.

## Source Repositories

| # | Source | Repository | EVTX Files Used | Rules Generated |
|---|--------|------------|-----------------|-----------------|
| 1 | [EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES) | `EVTX-ATTACK-SAMPLES` | 73 | 138 |
| 2 | [EVTX-to-MITRE-Attack](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack) | `EVTX-to-MITRE-Attack` | 25 | 528 |
| 3 | [Security-Datasets](https://github.com/OTRF/Security-Datasets) | `Security-Datasets` | 37 | 109 |
| 4 | [danderspritz-evtx](https://github.com/fox-it/danderspritz-evtx) | `danderspritz-evtx` | 1 | 2 |
| 5 | [hayabusa-sample-evtx](https://github.com/Yamato-Security/hayabusa-sample-evtx) | `hayabusa-sample-evtx` | 4 | 16 |
| | **Total** | | **140** | **793** |

## EVTX-ATTACK-SAMPLES
**Repository:** https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES

| Directory | EVTX Files | Rules Generated | Sample Files |
|-----------|------------|-----------------|--------------|
| AutomatedTestingTools | 6 | 36 | `DE_timestomp_and_dll_sideloading_and_RunPersist.evtx`, `rundll32_cmd_schtask.evtx`, `PanacheSysmon_vs_AtomicRedTeam01.evtx` +3 more |
| Command and Control | 1 | 4 | `DE_RDP_Tunnel_5156.evtx` |
| Credential Access | 12 | 17 | `CA_4624_4625_LogonType2_LogonProc_chrome.evtx`, `CA_sysmon_hashdump_cmd_meterpreter.evtx`, `discovery_sysmon_1_iis_pwd_and_config_discovery_appcmd.evtx` +9 more |
| Defense Evasion | 8 | 11 | `Sysmon 7  Update Session Orchestrator Dll Hijack.evtx`, `de_PsScriptBlockLogging_disabled_sysmon12_13.evtx`, `DE_Fake_ComputerAccount_4720.evtx` +5 more |
| Discovery | 2 | 4 | `Discovery_Remote_System_NamedPipes_Sysmon_18.evtx`, `dicovery_4661_net_group_domain_admins_target.evtx` |
| Execution | 12 | 14 | `Sysmon_meterpreter_ReflectivePEInjection_to_notepad_.evtx`, `exec_persist_rundll32_mshta_scheduledtask_sysmon_1_3_11.evtx`, `exec_sysmon_1_7_jscript9_defense_evasion.evtx` +9 more |
| Lateral Movement | 11 | 15 | `LM_DCOM_MSHTA_LethalHTA_Sysmon_3_1.evtx`, `LM_sysmon_psexec_smb_meterpreter.evtx`, `LM_typical_IIS_webshell_sysmon_1_10_traces.evtx` +8 more |
| Other | 1 | 1 | `APT28-CredentialStealer.evtx` |
| Persistence | 7 | 17 | `persistence_sysmon_11_13_1_shime_appfix.evtx`, `sysmon_13_1_persistence_via_winlogon_shell.evtx`, `sysmon_1_persist_bitsjob_SetNotifyCmdLine.evtx` +4 more |
| Privilege Escalation | 13 | 19 | `privesc_unquoted_svc_sysmon_1_11.evtx`, `sysmon_11_7_1_uacbypass_windirectory_mocking.evtx`, `sysmon_1_13_11_cmstp_ini_uacbypass.evtx` +10 more |

## EVTX-to-MITRE-Attack
**Repository:** https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack

| Directory | EVTX Files | Rules Generated | Sample Files |
|-----------|------------|-----------------|--------------|
| EVTX_full_APT_attack_steps | 5 | 9 | `ID11,13,17,18-PSexec as system execution.evtx`, `ID4688,4698,4699,5145,4624-ATexec remote trask creation (GLOBAL).evtx`, `ID4688,5140,5145-WMIexec execution via SMB (GLOBAL).evtx` +2 more |
| TA0001-Initial access | 1 | 1 | `ID4625-failed login with denied access due to account restriction.evtx` |
| TA0002-Execution | 2 | 492 | `ID4103-4104-Payload download via PowerShell.evtx`, `ID7000,7009,7045-Payload deployed via service - Tchopper.evtx` |
| TA0003-Persistence | 5 | 6 | `ID7045-7036 PSexec service installation.evtx`, `ID7045-New service for Mimikatz +npcap.evtx`, `ID4724-5145-password reset with setNTLM (Mimikatz).evtx` +2 more |
| TA0004-Privilege Escalation | 1 | 1 | `ID4688,4648,4624-Runas execution with different user.evtx` |
| TA0005-Defense Evasion | 6 | 10 | `ID1-CrackMapExec payload execution.evtx`, `ID800-4103-4104 Defender critical features disabled (PowerShell).evtx`, `ID4103-4104-2004-OpenSSH firewall rule activation.evtx` +3 more |
| TA0006-Credential Access | 3 | 5 | `ID10-Mimikatz LSASS process dump.evtx`, `ID800-4103-4104-LSASS dump with LSASSY (PowerShell).evtx`, `ID4625-OpenSSH brutforce with non existing users.evtx` |
| TA0007-Discovery | 1 | 3 | `ID800-4103-4104-Firewall configuration enumerated (PowerShell).evtx` |
| TA0008-Lateral Movement | 1 | 1 | `ID4103-4104-OpenSSH server activation and config.evtx` |

## Security-Datasets
**Repository:** https://github.com/OTRF/Security-Datasets

| Directory | EVTX Files | Rules Generated | Sample Files |
|-----------|------------|-----------------|--------------|
| datasets | 37 | 109 | `purplesharp_ad_playbook_I_2020-10-22042947.json`, `apt29_evals_day1_manual_2020-05-01225525.json`, `apt29_evals_day2_manual_2020-05-02035409.json` +34 more |

## danderspritz-evtx
**Repository:** https://github.com/fox-it/danderspritz-evtx

| Directory | EVTX Files | Rules Generated | Sample Files |
|-----------|------------|-----------------|--------------|
| examples | 1 | 2 | `post-Security.evtx` |

## hayabusa-sample-evtx
**Repository:** https://github.com/Yamato-Security/hayabusa-sample-evtx

| Directory | EVTX Files | Rules Generated | Sample Files |
|-----------|------------|-----------------|--------------|
| DeepBlueCLI | 4 | 16 | `Powershell-Invoke-Obfuscation-many.evtx`, `many-events-system.evtx`, `metasploit-psexec-native-target-system.evtx` +1 more |

## Credits

This project relies on the security research community for EVTX samples:

- **SBousseaden** — [EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES) — Windows EVTX samples mapped to MITRE ATT&CK
- **mdecrevoisier** — [EVTX-to-MITRE-Attack](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack) — 270+ EVTX samples with ATT&CK mapping
- **Yamato Security** — [hayabusa-sample-evtx](https://github.com/Yamato-Security/hayabusa-sample-evtx) — Aggregated EVTX sample collection
- **OTRF** — [Security-Datasets](https://github.com/OTRF/Security-Datasets) — Pre-recorded adversary simulation data (Mordor)
- **Fox-IT** — [danderspritz-evtx](https://github.com/fox-it/danderspritz-evtx) — DanderSpritz (NSA) detection events
- **SigmaHQ** — [sigma](https://github.com/SigmaHQ/sigma) — Community detection rules in Sigma format
- **Wazuh Inc.** — [wazuh-ruleset](https://github.com/wazuh/wazuh-ruleset) — Official default Wazuh rules and decoders
