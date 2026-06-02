"""Tests for the Sigma converter hardening."""

from unittest import mock

import pytest

from generator.sigma_converter import (
    SigmaConvertError,
    _apply_modifiers,
    _escape_osregex_with_globs,
    _extract_tags,
    _source_category_from_mapping,
    convert_sigma_rule,
)

# ── Tactic normalization ──


def test_extract_tags_hyphenated_credential_access():
    rule = {"tags": ["attack.credential-access", "attack.t1003"]}
    tactic, base_ids, full_ids = _extract_tags(rule)
    assert tactic == "credential_access"
    assert "T1003" in base_ids


def test_extract_tags_hyphenated_lateral_movement():
    rule = {"tags": ["attack.lateral-movement", "attack.t1021.002"]}
    tactic, base_ids, full_ids = _extract_tags(rule)
    assert tactic == "lateral_movement"


def test_extract_tags_all_six_multiword():
    for tag, expected in [
        ("attack.credential-access", "credential_access"),
        ("attack.defense-evasion", "defense_evasion"),
        ("attack.initial-access", "initial_access"),
        ("attack.lateral-movement", "lateral_movement"),
        ("attack.privilege-escalation", "privilege_escalation"),
        ("attack.command-and-control", "command_and_control"),
    ]:
        tactic, _, _ = _extract_tags({"tags": [tag]})
        assert tactic == expected, f"{tag} -> got {tactic}, expected {expected}"


def test_extract_tags_preserves_subtechnique():
    rule = {"tags": ["attack.credential-access", "attack.t1003.001"]}
    _, base_ids, full_ids = _extract_tags(rule)
    assert "T1003.001" in full_ids
    assert "T1003" in base_ids


def test_extract_tags_no_tags_defaults_execution():
    tactic, _, _ = _extract_tags({"tags": []})
    assert tactic == "execution"


# ── Glob translation ──


def test_escape_glob_star():
    assert _escape_osregex_with_globs("foo*bar") == "foo.*bar"


def test_escape_glob_question():
    assert _escape_osregex_with_globs("foo?bar") == "foo.bar"


def test_escape_literal_dot():
    assert _escape_osregex_with_globs("file.exe") == "file\\.exe"


def test_escape_mixed():
    result = _escape_osregex_with_globs("C:\\Windows\\*\\cmd.exe")
    assert ".*" in result
    assert "cmd\\.exe" in result


# ── Modifiers ──


def test_endswith_anchor():
    result = _apply_modifiers("cmd.exe", ["endswith"])
    assert result.endswith("$")
    assert "cmd" in result


def test_startswith_anchor():
    result = _apply_modifiers("C:\\Windows", ["startswith"])
    assert result.startswith("^")


def test_contains_unanchored():
    result = _apply_modifiers("malware", ["contains"])
    assert not result.startswith("^")
    assert not result.endswith("$")
    assert "malware" in result


def test_re_passthrough():
    result = _apply_modifiers("^foo.*bar$", ["re"])
    assert result == "^foo.*bar$"


def test_windash():
    result = _apply_modifiers("-enc", ["windash"])
    assert "[-/]" in result


# ── Source category routing ──


def test_source_category_sysmon():
    mapping = {"parent_sid": 61603, "channel": "sysmon"}
    assert _source_category_from_mapping(mapping) == "sysmon"


def test_source_category_security():
    mapping = {"parent_sid": 60100, "channel": "security"}
    assert _source_category_from_mapping(mapping) == "security"


def test_source_category_powershell():
    mapping = {"parent_sid": 91801, "channel": "powershell"}
    assert _source_category_from_mapping(mapping) == "powershell"


# ── convert_sigma_rule errors ──


def test_unmapped_logsource_raises():
    rule = {
        "logsource": {"category": "totally_unknown_xyz"},
        "detection": {"condition": "selection", "selection": {"Image": "test"}},
    }
    with pytest.raises(SigmaConvertError) as exc_info:
        convert_sigma_rule(rule)
    assert exc_info.value.category == "unmapped_logsource"


def test_no_detection_raises():
    rule = {"logsource": {"category": "process_creation"}}
    with pytest.raises(SigmaConvertError) as exc_info:
        convert_sigma_rule(rule)
    assert exc_info.value.category == "no_detection"


def test_aggregation_condition_raises():
    rule = {
        "logsource": {"category": "process_creation"},
        "detection": {
            "condition": "selection | near other",
            "selection": {"Image": "test"},
        },
    }
    with pytest.raises(SigmaConvertError) as exc_info:
        convert_sigma_rule(rule)
    assert exc_info.value.category == "unsupported_condition"


# ── Aggregation (count) ──


def test_count_aggregation_produces_frequency_rule():
    rule = {
        "title": "Brute force",
        "level": "high",
        "logsource": {"category": "process_creation"},
        "detection": {
            "condition": "selection | count() by User > 5",
            "selection": {"Image": "\\\\net.exe"},
        },
        "tags": ["attack.credential-access", "attack.t1110"],
    }
    with mock.patch("generator.sigma_converter.allocate_id", side_effect=[100001, 100002]):
        results = convert_sigma_rule(rule)
    # base detection rule + frequency correlation rule
    assert len(results) == 2
    from lxml import etree

    freq = next(r for r in results if r["xml_element"].get("frequency"))
    assert freq["xml_element"].get("frequency") == "5"
    xml = etree.tostring(freq["xml_element"], encoding="unicode")
    assert "if_matched_sid" in xml
    assert "same_field" in xml


# ── Negation (suppression) ──


def test_negation_produces_suppression_rule():
    rule = {
        "title": "Suspicious thing",
        "level": "high",
        "logsource": {"category": "process_creation"},
        "detection": {
            "selection": {"Image": "\\\\powershell.exe"},
            "filter": {"User": "SYSTEM"},
            "condition": "selection and not filter",
        },
        "tags": ["attack.execution"],
    }
    with mock.patch("generator.sigma_converter.allocate_id", side_effect=[100001, 100002]):
        results = convert_sigma_rule(rule, with_negation=True)
    assert len(results) == 2
    sup = next(r for r in results if r["level"] == 0)
    from lxml import etree

    xml = etree.tostring(sup["xml_element"], encoding="unicode")
    assert "if_sid" in xml
    assert "100001" in xml  # child references positive rule
    assert "sigma_negation" in xml


def test_negation_off_by_default_drops_filter():
    rule = {
        "title": "Suspicious thing",
        "level": "high",
        "logsource": {"category": "process_creation"},
        "detection": {
            "selection": {"Image": "\\\\powershell.exe"},
            "filter": {"User": "SYSTEM"},
            "condition": "selection and not filter",
        },
        "tags": ["attack.execution"],
    }
    with mock.patch("generator.sigma_converter.allocate_id", side_effect=range(100001, 100010)):
        results = convert_sigma_rule(rule)  # with_negation defaults False
    assert all(r["level"] != 0 for r in results)


# ── Multi-platform field resolution ──


def test_linux_logsource_uses_data_fields():
    from generator.sigma_converter import _resolve_field

    assert _resolve_field("exe", channel="linux") == "data.audit.exe"
    assert _resolve_field("CommandLine", channel="linux").startswith("data.")
    # Windows default unchanged
    assert _resolve_field("Image", channel="").startswith("win.eventdata.")


def test_cloud_logsource_maps_to_wazuh_cloud_fields():
    from generator.sigma_converter import _resolve_field

    assert _resolve_field("eventName", channel="cloud") == "data.aws.eventName"


# ── Successful conversion ──


def test_basic_conversion_produces_rule():
    rule = {
        "title": "Test Rule",
        "id": "abc-123",
        "level": "high",
        "logsource": {"category": "process_creation"},
        "detection": {
            "condition": "selection",
            "selection": {"Image|endswith": "\\mimikatz.exe"},
        },
        "tags": ["attack.credential-access", "attack.t1003"],
    }
    with mock.patch("generator.sigma_converter.allocate_id", return_value=100001):
        results = convert_sigma_rule(rule)

    assert len(results) >= 1
    r = results[0]
    assert r["metadata"]["tactic"] == "credential_access"
    assert "T1003" in r["metadata"]["mitre_ids"]
    assert r["metadata"]["source_category"] == "sysmon"
    assert r["level"] == 11  # high -> 11

    from lxml import etree

    xml_str = etree.tostring(r["xml_element"], encoding="unicode")
    assert "mimikatz" in xml_str
    assert "$" in xml_str  # endswith anchor
