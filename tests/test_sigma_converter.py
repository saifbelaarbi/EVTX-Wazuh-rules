"""Tests for the Sigma converter hardening."""

from unittest import mock

import pytest

from generator.sigma_converter import (
    SigmaConvertError,
    _apply_modifiers,
    _escape_osregex,
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


def test_escape_braces_and_brackets_are_literal():
    # In Wazuh OSRegex ``{ } [ ] ?`` are literal. Escaping them produces an
    # invalid sequence (e.g. ``\{``) that Wazuh rejects with error 5107
    # (CRITICAL — aborts the whole rule file). They must pass through unescaped.
    guid = "{054AAE20-4BEA-4347-8A35-64A533254A9D}"
    assert _escape_osregex(guid) == guid
    assert _escape_osregex("a[b]c?") == "a[b]c?"
    # Backslashes are still doubled (literal backslash); parens still escaped.
    assert _escape_osregex("a\\b") == "a\\\\b"
    assert _escape_osregex("(x)") == "\\(x\\)"


def test_escape_glob_star():
    assert _escape_osregex_with_globs("foo*bar") == "foo\\.*bar"


def test_escape_glob_question():
    assert _escape_osregex_with_globs("foo?bar") == "foo\\.bar"


def test_escape_literal_dot():
    # In OSRegex ``.`` is already literal — no escaping needed
    assert _escape_osregex_with_globs("file.exe") == "file.exe"


def test_escape_mixed():
    # ``C:\Windows\*\cmd.exe`` — backslashes doubled, glob→\\.*,  dot stays literal
    result = _escape_osregex_with_globs("C:\\Windows\\*\\cmd.exe")
    assert "\\.*" in result
    assert "cmd.exe" in result


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
    assert "[-/" in result


def test_cidr_modifier():
    result = _apply_modifiers("10.0.0.0/8", ["cidr"])
    assert result == "^10."


def test_cidr_slash16():
    result = _apply_modifiers("192.168.0.0/16", ["cidr"])
    assert result == "^192.168."


def test_cidr_slash32_exact_match():
    result = _apply_modifiers("192.0.2.5/32", ["cidr"])
    assert result == "^192.0.2.5$"


def test_base64offset_modifier():
    # encodes 'cmd' in 3 offset variants, OR-joined
    result = _apply_modifiers("cmd", ["base64offset", "contains"])
    assert "|" in result
    assert "cmd" not in result  # value is encoded, not literal


def test_numeric_comparator_passthrough():
    # Wazuh can't express inequalities; literal threshold is kept
    result = _apply_modifiers("100", ["gt"])
    assert "100" in result


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
    # count() > 5 means "more than 5", so Wazuh frequency must be 6
    assert freq["xml_element"].get("frequency") == "6"
    xml = etree.tostring(freq["xml_element"], encoding="unicode")
    assert "if_matched_sid" in xml
    assert "same_field" in xml
    # same_field must be element text, not an attribute
    sf = freq["xml_element"].find("same_field")
    assert sf is not None
    assert sf.text is not None
    assert sf.get("name") is None


def test_count_gte_no_off_by_one():
    """count() >= 5 keeps frequency=5 (no adjustment needed)."""
    rule = {
        "title": "GTE test",
        "level": "high",
        "logsource": {"category": "process_creation"},
        "detection": {
            "condition": "selection | count() >= 5",
            "selection": {"Image": "\\\\net.exe"},
        },
        "tags": ["attack.execution"],
    }
    with mock.patch("generator.sigma_converter.allocate_id", side_effect=[100001, 100002]):
        results = convert_sigma_rule(rule)
    freq = next(r for r in results if r["xml_element"].get("frequency"))
    assert freq["xml_element"].get("frequency") == "5"


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


def test_multiple_filters_produce_separate_suppressions():
    """Each negated filter becomes its own suppression rule."""
    rule = {
        "title": "Multi-filter",
        "level": "high",
        "logsource": {"category": "process_creation"},
        "detection": {
            "selection": {"Image": "\\\\cmd.exe"},
            "filter_admin": {"User": "SYSTEM"},
            "filter_path": {"ParentImage": "\\\\explorer.exe"},
            "condition": "selection and not filter_admin and not filter_path",
        },
        "tags": ["attack.execution"],
    }
    with mock.patch("generator.sigma_converter.allocate_id", side_effect=range(100001, 100010)):
        results = convert_sigma_rule(rule, with_negation=True)
    suppressions = [r for r in results if r["level"] == 0]
    assert len(suppressions) == 2
    fields_sets = [set(r["metadata"]["field_matches"].keys()) for r in suppressions]
    assert any("win.eventdata.user" in fs for fs in fields_sets)
    assert any("win.eventdata.parentImage" in fs for fs in fields_sets)


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


# ── keywords detection ──


def test_keywords_map_to_full_log():
    rule = {
        "title": "Keyword rule",
        "level": "high",
        "logsource": {"category": "process_creation"},
        "detection": {
            "keywords": ["mimikatz", "sekurlsa"],
            "condition": "keywords",
        },
        "tags": ["attack.credential-access"],
    }
    with mock.patch("generator.sigma_converter.allocate_id", side_effect=range(100001, 100010)):
        results = convert_sigma_rule(rule)
    from lxml import etree

    xml = " ".join(etree.tostring(r["xml_element"], encoding="unicode") for r in results)
    assert "full_log" in xml
    assert "mimikatz" in xml


# ── Successful conversion ──


def test_linux_process_creation_uses_linux_mapping():
    """Linux Sigma rules with category=process_creation must not use Windows/Sysmon."""
    rule = {
        "title": "Linux suspicious process",
        "level": "high",
        "logsource": {"product": "linux", "category": "process_creation"},
        "detection": {
            "condition": "selection",
            "selection": {"Image": "/usr/bin/nmap"},
        },
        "tags": ["attack.discovery"],
    }
    with mock.patch("generator.sigma_converter.allocate_id", return_value=100001):
        results = convert_sigma_rule(rule)
    r = results[0]
    assert r["metadata"]["source_category"] == "linux"
    # Field should be data.audit.exe, not win.eventdata.image
    from lxml import etree

    xml_str = etree.tostring(r["xml_element"], encoding="unicode")
    assert "data.audit.exe" in xml_str
    assert "win.eventdata" not in xml_str


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
