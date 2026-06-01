"""Tests for the semantic MITRE ATT&CK mapper."""

from generator.mitre_mapper import (
    MitreMapping,
    classify,
    classify_for_pattern,
    normalize_tactic,
)
from generator.event_analyzer import DetectionPattern


def test_normalize_tactic_hyphenated():
    assert normalize_tactic("attack.credential-access") == "credential_access"


def test_normalize_tactic_underscored():
    assert normalize_tactic("credential_access") == "credential_access"


def test_normalize_tactic_spaced():
    assert normalize_tactic("lateral movement") == "lateral_movement"


def test_normalize_tactic_all_six_multiword():
    for raw, expected in [
        ("attack.credential-access", "credential_access"),
        ("attack.lateral-movement", "lateral_movement"),
        ("attack.privilege-escalation", "privilege_escalation"),
        ("attack.defense-evasion", "defense_evasion"),
        ("attack.initial-access", "initial_access"),
        ("attack.command-and-control", "command_and_control"),
    ]:
        assert normalize_tactic(raw) == expected, f"{raw} -> {expected}"


def test_normalize_tactic_unknown():
    assert normalize_tactic("attack.not_a_real_tactic") == ""
    assert normalize_tactic("") == ""


def test_lsass_maps_to_credential_dumping():
    m = classify(event_id=10, channel="Microsoft-Windows-Sysmon/Operational",
                 provider="Microsoft-Windows-Sysmon",
                 indicators=["C:\\Windows\\System32\\lsass.exe"])
    assert m.technique_id == "T1003.001"
    assert m.tactic == "credential_access"


def test_mimikatz_maps_to_credential_dumping():
    m = classify(event_id=1, channel="Microsoft-Windows-Sysmon/Operational",
                 provider="Microsoft-Windows-Sysmon",
                 indicators=["mimikatz.exe"])
    assert m.technique_id == "T1003"
    assert m.tactic == "credential_access"


def test_rundll32_maps_to_defense_evasion():
    m = classify(event_id=1, channel="Microsoft-Windows-Sysmon/Operational",
                 provider="Microsoft-Windows-Sysmon",
                 indicators=["rundll32.exe"])
    assert m.technique_id == "T1218.011"
    assert m.tactic == "defense_evasion"


def test_vssadmin_delete_maps_to_impact():
    m = classify(event_id=1, channel="Microsoft-Windows-Sysmon/Operational",
                 provider="Microsoft-Windows-Sysmon",
                 indicators=["vssadmin delete shadows"])
    assert m.technique_id == "T1490"
    assert m.tactic == "impact"


def test_4625_maps_to_brute_force_not_phishing():
    m = classify(event_id=4625, channel="Security",
                 provider="Microsoft-Windows-Security-Auditing")
    assert m.technique_id == "T1110"
    assert m.tactic == "credential_access"
    assert m.technique_name == "Brute Force"


def test_4624_maps_to_lateral_movement():
    m = classify(event_id=4624, channel="Security",
                 provider="Microsoft-Windows-Security-Auditing")
    assert m.tactic == "lateral_movement"


def test_4720_maps_to_persistence():
    m = classify(event_id=4720, channel="Security",
                 provider="Microsoft-Windows-Security-Auditing")
    assert m.technique_id == "T1136.001"
    assert m.tactic == "persistence"


def test_event_id_default_sysmon_8():
    m = classify(event_id=8, channel="Microsoft-Windows-Sysmon/Operational",
                 provider="Microsoft-Windows-Sysmon")
    assert m.technique_id == "T1055"
    assert m.tactic == "defense_evasion"


def test_path_hint_tactic_fallback():
    m = classify(event_id=99999, channel="Unknown", provider="Unknown",
                 path_hint_tactic="collection")
    assert m.tactic == "collection"
    assert m.technique_id != ""


def test_unknown_no_hint_defaults_to_execution():
    m = classify(event_id=99999, channel="Unknown", provider="Unknown")
    assert m.tactic == "execution"


def test_indicator_priority_over_event_id():
    m = classify(event_id=4625, channel="Security",
                 provider="Microsoft-Windows-Security-Auditing",
                 indicators=["psexec.exe"])
    assert m.tactic == "lateral_movement"
    assert "T1021" in m.technique_id


def test_base_technique_property():
    m = MitreMapping("T1003.001", "LSASS Memory", "credential_access")
    assert m.base_technique == "T1003"


def test_base_technique_no_sub():
    m = MitreMapping("T1003", "OS Credential Dumping", "credential_access")
    assert m.base_technique == "T1003"


def test_classify_for_pattern():
    pattern = DetectionPattern(
        event_id=10,
        channel="Microsoft-Windows-Sysmon/Operational",
        provider_name="Microsoft-Windows-Sysmon",
        field_matches={"win.eventdata.targetImage": "lsass.exe"},
        tactic="discovery",
    )
    m = classify_for_pattern(pattern)
    assert m.technique_id == "T1003.001"
    assert m.tactic == "credential_access"
