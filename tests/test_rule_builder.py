"""Tests for the rule builder."""

import json
import tempfile
from pathlib import Path
from unittest import mock

from lxml import etree

from generator.event_analyzer import DetectionPattern
from generator.rule_builder import build_rule, _resolve_parent_sid
from generator import id_manager


def test_resolve_parent_sid_sysmon():
    pattern = DetectionPattern(
        event_id=1,
        channel="Microsoft-Windows-Sysmon/Operational",
        provider_name="Microsoft-Windows-Sysmon",
    )
    assert _resolve_parent_sid(pattern) == 61603


def test_resolve_parent_sid_security():
    pattern = DetectionPattern(
        event_id=4625,
        channel="Security",
        provider_name="Microsoft-Windows-Security-Auditing",
    )
    assert _resolve_parent_sid(pattern) == 60100


def test_build_rule_structure():
    with tempfile.NamedTemporaryFile(suffix=".json", mode="w", delete=False) as f:
        json.dump({}, f)
        tmp_path = Path(f.name)

    with mock.patch.object(id_manager, "ALLOCATIONS_FILE", tmp_path):
        pattern = DetectionPattern(
            event_id=1,
            channel="Microsoft-Windows-Sysmon/Operational",
            provider_name="Microsoft-Windows-Sysmon",
            field_matches={"win.eventdata.image": "mimikatz"},
            tactic="credential_access",
            technique_name="Mimikatz execution",
            description="Mimikatz execution detected",
            confidence="high",
        )

        rule = build_rule(pattern)

        assert rule["id"] >= 105000
        assert rule["id"] <= 105999
        assert rule["xml_element"] is not None

        xml_str = etree.tostring(rule["xml_element"], encoding="unicode")
        assert "if_sid" in xml_str
        assert "61603" in xml_str  # Sysmon process create parent
        assert "mimikatz" in xml_str
        assert "credential_access" in xml_str

    tmp_path.unlink()
