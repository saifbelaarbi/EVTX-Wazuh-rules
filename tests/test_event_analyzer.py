"""Tests for the event analyzer."""

from generator.event_analyzer import analyze_event, infer_tactic_from_path


def test_infer_tactic_from_path():
    assert infer_tactic_from_path("/data/Credential Access/test.evtx") == "credential_access"
    assert infer_tactic_from_path("/data/Defense Evasion/test.evtx") == "defense_evasion"
    assert infer_tactic_from_path("/data/Lateral Movement/test.evtx") == "lateral_movement"
    assert infer_tactic_from_path("/data/unknown/test.evtx") == ""


def test_analyze_sysmon_process_create_mimikatz():
    event = {
        "event_id": 1,
        "channel": "Microsoft-Windows-Sysmon/Operational",
        "provider_name": "Microsoft-Windows-Sysmon",
        "event_data": {
            "Image": "C:\\Windows\\Temp\\mimikatz.exe",
            "CommandLine": "mimikatz.exe sekurlsa::logonpasswords",
            "ParentImage": "C:\\Windows\\System32\\cmd.exe",
        },
        "_source_file": "/data/Credential Access/mimikatz.evtx",
    }

    patterns = analyze_event(event)
    assert len(patterns) > 0
    assert any("mimikatz" in p.description.lower() for p in patterns)
    assert any(p.confidence == "high" for p in patterns)


def test_analyze_sysmon_lsass_access():
    event = {
        "event_id": 10,
        "channel": "Microsoft-Windows-Sysmon/Operational",
        "provider_name": "Microsoft-Windows-Sysmon",
        "event_data": {
            "SourceImage": "C:\\Windows\\Temp\\procdump.exe",
            "TargetImage": "C:\\Windows\\System32\\lsass.exe",
            "GrantedAccess": "0x1410",
        },
        "_source_file": "/data/Credential Access/lsass_dump.evtx",
    }

    patterns = analyze_event(event)
    assert len(patterns) > 0
    assert any("lsass" in p.description.lower() for p in patterns)


def test_analyze_registry_persistence():
    event = {
        "event_id": 13,
        "channel": "Microsoft-Windows-Sysmon/Operational",
        "provider_name": "Microsoft-Windows-Sysmon",
        "event_data": {
            "TargetObject": "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\malware",
            "Details": "C:\\Windows\\Temp\\backdoor.exe",
        },
        "_source_file": "/data/Persistence/reg_run.evtx",
    }

    patterns = analyze_event(event)
    assert len(patterns) > 0
    assert any(p.tactic == "persistence" for p in patterns)


def test_no_patterns_for_benign_event():
    event = {
        "event_id": 1,
        "channel": "Microsoft-Windows-Sysmon/Operational",
        "provider_name": "Microsoft-Windows-Sysmon",
        "event_data": {
            "Image": "C:\\Windows\\System32\\notepad.exe",
            "CommandLine": "notepad.exe readme.txt",
            "ParentImage": "C:\\Windows\\explorer.exe",
        },
        "_source_file": "/data/test.evtx",
    }

    patterns = analyze_event(event)
    assert len(patterns) == 0
