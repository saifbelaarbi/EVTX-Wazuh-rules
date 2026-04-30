# Rule Source Attribution

This document separates EVTX sample provenance from Sigma rule provenance.

## Overview

| Origin | Input Files | Rules Generated |
|--------|-------------|-----------------|
| EVTX samples | 140 | 793 |
| Sigma rules | 641 | 777 |

## EVTX Source Repositories

| # | Source | Repository | Sample Files Used | Rules Generated |
|---|--------|------------|-------------------|-----------------|
| 1 | [EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES) | `EVTX-ATTACK-SAMPLES` | 73 | 138 |
| 2 | [EVTX-to-MITRE-Attack](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack) | `EVTX-to-MITRE-Attack` | 25 | 528 |
| 3 | [Security-Datasets](https://github.com/OTRF/Security-Datasets) | `Security-Datasets` | 37 | 109 |
| 4 | [danderspritz-evtx](https://github.com/fox-it/danderspritz-evtx) | `danderspritz-evtx` | 1 | 2 |
| 5 | [hayabusa-sample-evtx](https://github.com/Yamato-Security/hayabusa-sample-evtx) | `hayabusa-sample-evtx` | 4 | 16 |
| | **Total** | | **140** | **793** |

## EVTX-ATTACK-SAMPLES
**Repository:** https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES

| Directory | Sample Files | Rules Generated | Sample Inputs |
|-----------|--------------|-----------------|---------------|
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

| Directory | Sample Files | Rules Generated | Sample Inputs |
|-----------|--------------|-----------------|---------------|
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

| Directory | Sample Files | Rules Generated | Sample Inputs |
|-----------|--------------|-----------------|---------------|
| datasets | 37 | 109 | `purplesharp_ad_playbook_I_2020-10-22042947.json`, `apt29_evals_day1_manual_2020-05-01225525.json`, `apt29_evals_day2_manual_2020-05-02035409.json` +34 more |

## danderspritz-evtx
**Repository:** https://github.com/fox-it/danderspritz-evtx

| Directory | Sample Files | Rules Generated | Sample Inputs |
|-----------|--------------|-----------------|---------------|
| examples | 1 | 2 | `post-Security.evtx` |

## hayabusa-sample-evtx
**Repository:** https://github.com/Yamato-Security/hayabusa-sample-evtx

| Directory | Sample Files | Rules Generated | Sample Inputs |
|-----------|--------------|-----------------|---------------|
| DeepBlueCLI | 4 | 16 | `Powershell-Invoke-Obfuscation-many.evtx`, `many-events-system.evtx`, `metasploit-psexec-native-target-system.evtx` +1 more |

## SigmaHQ Input Breakdown

All Sigma-derived rules in this repository come from [SigmaHQ/sigma](https://github.com/SigmaHQ/sigma).

| Category | Sigma Rule Files | Rules Generated |
|----------|------------------|-----------------|
| builtin | 111 | 120 |
| create_remote_thread | 8 | 8 |
| create_stream_hash | 6 | 6 |
| dns_query | 6 | 7 |
| driver_load | 7 | 11 |
| file | 100 | 121 |
| image_load | 47 | 47 |
| network_connection | 24 | 24 |
| pipe_created | 9 | 39 |
| powershell | 73 | 92 |
| process_access | 18 | 19 |
| process_creation | 158 | 201 |
| registry | 74 | 82 |

## Sample Sigma Inputs

| Category | Sample Files |
|----------|--------------|
| builtin | `win_security_diagtrack_eop_default_login_username.yml`, `win_security_overpass_the_hash.yml`, `win_security_rdp_localhost_login.yml` +108 more |
| create_remote_thread | `create_remote_thread_win_hktl_cactustorch.yml`, `create_remote_thread_win_hktl_cobaltstrike.yml`, `create_remote_thread_win_keepass.yml` +5 more |
| create_stream_hash | `create_stream_hash_file_sharing_domains_download_susp_extension.yml`, `create_stream_hash_hktl_generic_download.yml`, `create_stream_hash_regedit_export_to_ads.yml` +3 more |
| dns_query | `dns_query_win_anonymfiles_com.yml`, `dns_query_win_finger.yml`, `dns_query_win_hybridconnectionmgr_servicebus.yml` +3 more |
| driver_load | `driver_load_win_mal_drivers.yml`, `driver_load_win_pua_process_hacker.yml`, `driver_load_win_susp_temp_use.yml` +4 more |
| file | `file_change_win_unusual_modification_by_dns_exe.yml`, `file_delete_win_delete_exchange_powershell_logs.yml`, `file_delete_win_delete_prefetch.yml` +97 more |
| image_load | `image_load_cmstp_load_dll_from_susp_location.yml`, `image_load_dll_comsvcs_load_renamed_version_by_rundll32.yml`, `image_load_dll_dbghelp_dbgcore_unsigned_load.yml` +44 more |
| network_connection | `net_connection_win_addinutil_initiated.yml`, `net_connection_win_certutil_initiated_connection.yml`, `net_connection_win_cmstp_initiated_connection.yml` +21 more |
| pipe_created | `pipe_created_hktl_cobaltstrike.yml`, `pipe_created_hktl_cobaltstrike_re.yml`, `pipe_created_hktl_cobaltstrike_susp_pipe_patterns.yml` +6 more |
| powershell | `posh_pc_delete_volume_shadow_copies.yml`, `posh_pc_exe_calling_ps.yml`, `posh_pm_bad_opsec_artifacts.yml` +70 more |
| process_access | `proc_access_win_cmstp_execution_by_access.yml`, `proc_access_win_hktl_cobaltstrike_bof_injection_pattern.yml`, `proc_access_win_hktl_generic_access.yml` +15 more |
| process_creation | `proc_creation_win_addinutil_suspicious_cmdline.yml`, `proc_creation_win_adplus_memory_dump.yml`, `proc_creation_win_agentexecutor_susp_usage.yml` +155 more |
| registry | `registry_delete_mstsc_history_cleared.yml`, `registry_event_add_local_hidden_user.yml`, `registry_event_disable_security_events_logging_adding_reg_key_minint.yml` +71 more |

## Credits

This project relies on the security research community for EVTX samples and Sigma rules:

- **SBousseaden** - [EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES) - Windows EVTX samples mapped to MITRE ATT&CK
- **mdecrevoisier** - [EVTX-to-MITRE-Attack](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack) - EVTX samples with ATT&CK mapping
- **Yamato Security** - [hayabusa-sample-evtx](https://github.com/Yamato-Security/hayabusa-sample-evtx) - Aggregated EVTX sample collection
- **OTRF** - [Security-Datasets](https://github.com/OTRF/Security-Datasets) - Pre-recorded adversary simulation data
- **Fox-IT** - [danderspritz-evtx](https://github.com/fox-it/danderspritz-evtx) - DanderSpritz detection events
- **SigmaHQ** - [sigma](https://github.com/SigmaHQ/sigma) - Community detection rules in Sigma format
- **Wazuh Inc.** - [wazuh/wazuh-ruleset](https://github.com/wazuh/wazuh-ruleset) - Official default Wazuh rules and decoders
