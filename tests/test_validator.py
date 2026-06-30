"""Tests for the rule validator."""

from lxml import etree

from generator.validator import MAX_FIELD_PATTERN_LEN, validate_database, validate_rule


def _make_rule(rule_id=100001, level=10, description="Test rule", if_sid="61600", mitre_id="T1003"):
    elem = etree.Element("rule", id=str(rule_id), level=str(level))
    if if_sid:
        sid = etree.SubElement(elem, "if_sid")
        sid.text = if_sid
    if description:
        desc = etree.SubElement(elem, "description")
        desc.text = description
    if mitre_id:
        mitre = etree.SubElement(elem, "mitre")
        mid = etree.SubElement(mitre, "id")
        mid.text = mitre_id
    group = etree.SubElement(elem, "group")
    group.text = "test,"

    return {"id": rule_id, "level": level, "xml_element": elem, "metadata": {}}


def test_valid_rule():
    rule = _make_rule()
    errors = validate_rule(rule)
    assert len(errors) == 0


def test_missing_description():
    rule = _make_rule(description=None)
    errors = validate_rule(rule)
    assert any("description" in e.lower() for e in errors)


def test_invalid_mitre_id():
    rule = _make_rule(mitre_id="INVALID")
    errors = validate_rule(rule)
    assert any("MITRE" in e for e in errors)


def test_id_out_of_range():
    rule = _make_rule(rule_id=50000)
    errors = validate_rule(rule)
    assert any("range" in e.lower() for e in errors)


def test_level_zero_warning():
    rule = _make_rule(level=0)
    errors = validate_rule(rule)
    assert any("level" in e.lower() for e in errors)


def _write_rule_file(tmp_path, field_pattern):
    xml = (
        '<group name="test,">\n'
        '  <rule id="100001" level="10">\n'
        "    <if_sid>61603</if_sid>\n"
        f'    <field name="win.eventdata.image">{field_pattern}</field>\n'
        "    <description>Test</description>\n"
        "  </rule>\n"
        "</group>\n"
    )
    f = tmp_path / "test.xml"
    f.write_text(xml)
    return tmp_path


def test_overlong_field_pattern_flagged(tmp_path):
    rules_dir = _write_rule_file(tmp_path, "a" * (MAX_FIELD_PATTERN_LEN + 1))
    errors = validate_database(rules_dir)
    assert any("String overflow" in e for e in errors)


def test_normal_field_pattern_ok(tmp_path):
    rules_dir = _write_rule_file(tmp_path, "a" * 100)
    errors = validate_database(rules_dir)
    assert not any("String overflow" in e for e in errors)
