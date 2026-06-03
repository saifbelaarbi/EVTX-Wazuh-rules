"""Tests for the composite/chained correlation rule builder."""

import json

import pytest
from lxml import etree

from generator.composite_builder import (
    CompositeRuleSpec,
    build_composite_rule,
    build_from_templates,
    load_templates,
)

COMPOSITE_START = 115000
COMPOSITE_END = 119999


@pytest.fixture
def isolated_allocations(tmp_path, monkeypatch):
    """Point id_manager at a throwaway allocations file so tests never touch
    the real database/metadata/id_allocations.json."""
    from generator import id_manager

    alloc_file = tmp_path / "id_allocations.json"
    alloc_file.write_text(json.dumps({}))
    monkeypatch.setattr(id_manager, "ALLOCATIONS_FILE", alloc_file)
    return alloc_file


def _example_spec() -> CompositeRuleSpec:
    return CompositeRuleSpec(
        name="discovery_then_lateral_movement",
        description="Discovery followed by lateral movement",
        tactic="lateral_movement",
        stages=[
            {"if_sid": 111001},
            {"if_matched_sid": 112501, "same_field": "win.eventdata.user"},
        ],
        frequency=2,
        timeframe=300,
        level=12,
        mitre_ids=["T1021"],
    )


def test_load_templates_parses_yaml_into_specs():
    specs = load_templates()
    assert len(specs) >= 3
    assert all(isinstance(s, CompositeRuleSpec) for s in specs)
    names = {s.name for s in specs}
    assert "discovery_then_lateral_movement" in names
    assert "credential_access_then_exfil" in names
    assert "brute_force_then_logon" in names
    assert "service_install_then_network" in names
    # Stages and mitre ids come through.
    spec = next(s for s in specs if s.name == "discovery_then_lateral_movement")
    assert spec.stages
    assert "T1021" in spec.mitre_ids


def test_load_templates_custom_path(tmp_path):
    custom = tmp_path / "custom.yaml"
    custom.write_text("- name: t\n  description: d\n  tactic: execution\n  stages:\n    - {if_matched_sid: 5}\n")
    specs = load_templates(custom)
    assert len(specs) == 1
    assert specs[0].name == "t"
    assert specs[0].frequency == 2  # default applied


def test_build_composite_rule_xml_shape(isolated_allocations):
    rule = build_composite_rule(_example_spec())

    elem = rule["xml_element"]
    assert elem.tag == "rule"
    assert elem.get("frequency") == "2"
    assert elem.get("timeframe") == "300"
    assert elem.get("level") == "12"

    matched = elem.find("if_matched_sid")
    assert matched is not None
    assert matched.text == "112501"

    same = elem.find("same_field")
    assert same is not None
    assert same.get("name") == "win.eventdata.user"

    group = elem.find("group")
    assert "composite" in group.text

    # Serializes to valid XML.
    xml = etree.tostring(elem)
    assert b"if_matched_sid" in xml


def test_build_composite_rule_id_in_range(isolated_allocations):
    rule = build_composite_rule(_example_spec())
    assert COMPOSITE_START <= rule["id"] <= COMPOSITE_END
    assert rule["level"] == 12
    assert rule["pattern"] is None
    assert rule["metadata"]["tactic"] == "lateral_movement"
    assert rule["metadata"]["mitre_ids"] == ["T1021"]


def test_same_field_omitted_when_absent(isolated_allocations):
    spec = CompositeRuleSpec(
        name="no_same_field",
        description="d",
        tactic="execution",
        stages=[{"if_matched_sid": 100001}],
    )
    rule = build_composite_rule(spec)
    elem = rule["xml_element"]
    assert elem.find("same_field") is None
    assert elem.find("if_matched_sid").text == "100001"


def test_if_sid_chain_emitted(isolated_allocations):
    rule = build_composite_rule(_example_spec())
    elem = rule["xml_element"]
    if_sids = elem.findall("if_sid")
    assert len(if_sids) == 1
    assert if_sids[0].text == "111001"


def test_mitre_ids_emitted(isolated_allocations):
    rule = build_composite_rule(_example_spec())
    mitre = rule["xml_element"].find("mitre")
    assert mitre is not None
    ids = [e.text for e in mitre.findall("id")]
    assert ids == ["T1021"]


def test_build_from_templates_count(isolated_allocations):
    templates = load_templates()
    rules = build_from_templates(templates)
    assert len(rules) == len(templates)
    assert all(COMPOSITE_START <= r["id"] <= COMPOSITE_END for r in rules)
    # Unique ids allocated for each.
    assert len({r["id"] for r in rules}) == len(rules)


def test_build_from_templates_default_loads_yaml(isolated_allocations):
    rules = build_from_templates()
    assert len(rules) == len(load_templates())
