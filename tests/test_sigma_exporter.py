"""Tests for back-conversion of EVTX-generated Wazuh rules to Sigma YAML."""

import json

import yaml

from generator.sigma_exporter import (
    export_evtx_rules_to_sigma,
    rule_to_sigma,
    wazuh_field_to_sigma,
)


def test_wazuh_field_to_sigma_known_fields():
    assert wazuh_field_to_sigma("win.eventdata.image") == "Image"
    assert wazuh_field_to_sigma("win.eventdata.commandLine") == "CommandLine"
    assert wazuh_field_to_sigma("win.eventdata.targetFilename") == "TargetFilename"
    assert wazuh_field_to_sigma("win.system.eventID") == "EventID"


def test_wazuh_field_to_sigma_unknown_path_camelcases_last_segment():
    assert wazuh_field_to_sigma("win.eventdata.someNewField") == "SomeNewField"
    assert wazuh_field_to_sigma("data.audit.exe") == "Exe"


def test_rule_to_sigma_produces_valid_dict():
    meta = {
        "technique_name": "Credential dumping via comsvcs",
        "description": "Credential dumping via comsvcs",
        "level": 11,
        "tactic": "credential_access",
        "mitre_ids": ["T1003.001"],
        "source_category": "sysmon",
        "source_evtx": "/data/evtx_samples/foo.evtx",
        "field_matches": {
            "win.eventdata.image": "^C:\\\\windows\\\\system32\\\\rundll32.exe$",
            "win.eventdata.commandLine": "comsvcs.dll|MiniDump",
        },
        "created": "2026-06-02",
    }

    sigma = rule_to_sigma(meta, "100123")

    assert sigma["title"] == "Credential dumping via comsvcs"
    assert sigma["status"] == "experimental"
    assert sigma["author"] == "EVTX-Wazuh-Rules"
    assert sigma["level"] == "high"

    # logsource derived from sysmon category
    assert sigma["logsource"]["product"] == "windows"
    assert sigma["logsource"]["category"] == "process_creation"

    # detection block
    detection = sigma["detection"]
    assert detection["condition"] == "selection"
    selection = detection["selection"]
    assert "Image" in selection
    assert "CommandLine" in selection

    # anchors stripped, \\ unescaped to \, . stays literal
    assert selection["Image"] == "C:\\windows\\system32\\rundll32.exe"
    # value with | becomes a list
    assert selection["CommandLine"] == ["comsvcs.dll", "MiniDump"]

    # tags from mitre ids + tactic (hyphenated)
    assert "attack.t1003.001" in sigma["tags"]
    assert "attack.credential-access" in sigma["tags"]


def test_rule_to_sigma_id_is_deterministic():
    meta = {"technique_name": "x", "level": 5, "field_matches": {}}
    a = rule_to_sigma(meta, "100500")
    b = rule_to_sigma(meta, "100500")
    c = rule_to_sigma(meta, "100501")
    assert a["id"] == b["id"]
    assert a["id"] != c["id"]


def test_level_mapping():
    base = {"technique_name": "t", "field_matches": {}}
    assert rule_to_sigma({**base, "level": 13}, "1")["level"] == "critical"
    assert rule_to_sigma({**base, "level": 15}, "1")["level"] == "critical"
    assert rule_to_sigma({**base, "level": 11}, "1")["level"] == "high"
    assert rule_to_sigma({**base, "level": 8}, "1")["level"] == "medium"
    assert rule_to_sigma({**base, "level": 5}, "1")["level"] == "low"
    assert rule_to_sigma({**base, "level": 3}, "1")["level"] == "low"


def test_logsource_security_and_powershell():
    sec = rule_to_sigma(
        {"technique_name": "t", "level": 8, "source_category": "security", "field_matches": {}},
        "1",
    )
    assert sec["logsource"] == {"product": "windows", "service": "security"}

    ps = rule_to_sigma(
        {"technique_name": "t", "level": 8, "source_category": "powershell", "field_matches": {}},
        "2",
    )
    assert ps["logsource"] == {"product": "windows", "service": "powershell"}


def _write_index(tmp_path, data):
    index_path = tmp_path / "rule_index.json"
    index_path.write_text(json.dumps(data))
    return index_path


def test_export_writes_files_and_returns_count(tmp_path):
    index = {
        "100001": {
            "technique_name": "EVTX rule one",
            "level": 9,
            "tactic": "execution",
            "mitre_ids": ["T1059"],
            "source_category": "sysmon",
            "source_evtx": "/data/samples/a.evtx",
            "field_matches": {"win.eventdata.image": "^foo.exe$"},
        },
        "100002": {
            "technique_name": "EVTX rule two",
            "level": 12,
            "tactic": "persistence",
            "mitre_ids": ["T1547"],
            "source_category": "security",
            "source_evtx": "/data/samples/b.json",
            "field_matches": {"win.system.eventID": "4688"},
        },
    }
    index_path = _write_index(tmp_path, index)
    out_dir = tmp_path / "sigma_out"

    count = export_evtx_rules_to_sigma(index_path=index_path, out_dir=out_dir)

    assert count == 2
    written = sorted(p.name for p in out_dir.glob("*.yml"))
    assert written == ["100001_evtx_rule_one.yml", "100002_evtx_rule_two.yml"]

    loaded = yaml.safe_load((out_dir / "100001_evtx_rule_one.yml").read_text())
    assert loaded["title"] == "EVTX rule one"
    assert loaded["detection"]["selection"]["Image"] == "foo.exe"
    assert loaded["level"] == "medium"


def test_export_skips_sigma_sourced_rules(tmp_path):
    index = {
        "100010": {
            "technique_name": "From EVTX",
            "level": 9,
            "source_category": "sysmon",
            "source_evtx": "/data/samples/real.evtx",
            "field_matches": {"win.eventdata.image": "x"},
        },
        "100011": {
            "technique_name": "From Sigma yml",
            "level": 9,
            "source_category": "sysmon",
            "source_evtx": "/rules/windows/process_creation/foo.yml",
            "field_matches": {"win.eventdata.image": "x"},
        },
        "100012": {
            "technique_name": "From Sigma yaml",
            "level": 9,
            "source_category": "sysmon",
            "source_evtx": "/rules/windows/process_creation/bar.YAML",
            "field_matches": {"win.eventdata.image": "x"},
        },
        "100013": {
            "technique_name": "From Sigma json",
            "level": 9,
            "source_category": "sysmon",
            "source_evtx": "/rules/windows/process_creation/baz.json",
            "sigma_id": "def-456-ghi",
            "field_matches": {"win.eventdata.image": "x"},
        },
        "100014": {
            "technique_name": "Sigma by id",
            "level": 9,
            "source_category": "sysmon",
            "source_evtx": "/data/samples/evtx_file.evtx",
            "sigma_id": "abc-123-def",
            "field_matches": {"win.eventdata.image": "x"},
        },
    }
    index_path = _write_index(tmp_path, index)
    out_dir = tmp_path / "out"

    count = export_evtx_rules_to_sigma(index_path=index_path, out_dir=out_dir)

    assert count == 1
    written = [p.name for p in out_dir.glob("*.yml")]
    assert written == ["100010_from_evtx.yml"]
