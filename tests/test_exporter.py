"""Tests for the exporter module."""

from lxml import etree

from generator.exporter import (
    _build_xml_group,
    _get_source_category,
    _get_technique_slug,
)


def _make_rule(tactic="credential_access", source_category="sysmon", mitre_ids=None, pattern=None, field_matches=None):
    """Build a minimal rule dict for testing."""
    if mitre_ids is None:
        mitre_ids = ["T1003"]
    rule_elem = etree.Element("rule", id="100001", level="11")
    desc = etree.SubElement(rule_elem, "description")
    desc.text = "Test rule"
    return {
        "id": 100001,
        "level": 11,
        "xml_element": rule_elem,
        "metadata": {
            "tactic": tactic,
            "technique_name": "Test",
            "source_evtx": "",
            "source_category": source_category,
            "parent_sid": 61603,
            "confidence": "high",
            "created": "2026-01-01",
            "field_matches": field_matches or {},
            "mitre_ids": mitre_ids,
        },
        "pattern": pattern,
    }


def test_source_category_sigma_no_pattern():
    """Sigma rules (pattern=None) use metadata.source_category, not 'other'."""
    rule = _make_rule(source_category="security", pattern=None)
    assert _get_source_category(rule) == "security"


def test_source_category_sigma_sysmon():
    rule = _make_rule(source_category="sysmon", pattern=None)
    assert _get_source_category(rule) == "sysmon"


def test_source_category_sigma_powershell():
    rule = _make_rule(source_category="powershell", pattern=None)
    assert _get_source_category(rule) == "powershell"


def test_source_category_fallback_other():
    rule = _make_rule(source_category=None, pattern=None)
    rule["metadata"]["source_category"] = None
    assert _get_source_category(rule) == "other"


def test_technique_slug_with_mitre():
    rule = _make_rule(mitre_ids=["T1003"])
    slug = _get_technique_slug(rule)
    assert slug.startswith("T1003")


def test_technique_slug_without_mitre():
    rule = _make_rule(mitre_ids=[])
    slug = _get_technique_slug(rule)
    assert "unknown" in slug


def test_build_xml_group():
    rule = _make_rule()
    xml_str = _build_xml_group([rule], "test_group")
    assert '<?xml version="1.0"' in xml_str
    assert 'name="test_group,"' in xml_str
    assert "<rule" in xml_str
