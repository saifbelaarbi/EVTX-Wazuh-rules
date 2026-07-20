"""Tests for the rule validator."""

from lxml import etree

from generator.validator import validate_rule


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


# ── validate_database: dangling parent SIDs ──


def _write_db(tmp_path, xml: str, name="rules.xml"):
    f = tmp_path / name
    f.write_text(xml)
    return tmp_path


def test_database_dangling_parent_sid(tmp_path):
    from generator.validator import validate_database

    _write_db(
        tmp_path,
        """<group name="test,">
  <rule id="100001" level="10">
    <if_sid>109999</if_sid>
    <description>Child of a rule that does not exist</description>
  </rule>
</group>
""",
    )
    errors = validate_database(tmp_path)
    assert any("109999" in e and "does not exist" in e for e in errors)


def test_database_parent_sid_resolved_across_files(tmp_path):
    from generator.validator import validate_database

    (tmp_path / "a.xml").write_text(
        """<group name="test,">
  <rule id="100001" level="10">
    <if_sid>61603</if_sid>
    <description>Parent detection</description>
  </rule>
</group>
"""
    )
    (tmp_path / "b.xml").write_text(
        """<group name="test,">
  <rule id="100002" level="0">
    <if_sid>100001</if_sid>
    <description>Suppression child referencing rule in another file</description>
  </rule>
</group>
"""
    )
    errors = validate_database(tmp_path)
    assert errors == []


def test_database_builtin_parent_sid_not_flagged(tmp_path):
    from generator.validator import validate_database

    _write_db(
        tmp_path,
        """<group name="test,">
  <rule id="100003" level="7">
    <if_sid>61603</if_sid>
    <description>Child of a Wazuh built-in parent</description>
  </rule>
</group>
""",
    )
    errors = validate_database(tmp_path)
    assert errors == []


def test_database_if_matched_sid_checked(tmp_path):
    from generator.validator import validate_database

    _write_db(
        tmp_path,
        """<group name="test,">
  <rule id="100004" level="12" frequency="6" timeframe="300">
    <if_matched_sid>118888</if_matched_sid>
    <description>Frequency rule with dangling base</description>
  </rule>
</group>
""",
    )
    errors = validate_database(tmp_path)
    assert any("118888" in e for e in errors)


def test_database_oversized_field_flagged(tmp_path):
    from generator.validator import validate_database

    huge = "|".join(f"MD5={i:032x}" for i in range(700))  # > 20k chars
    _write_db(
        tmp_path,
        f"""<group name="test,">
  <rule id="100005" level="10">
    <if_sid>61608</if_sid>
    <field name="win.eventdata.hashes">{huge}</field>
    <description>Oversized hash blocklist</description>
  </rule>
</group>
""",
    )
    errors = validate_database(tmp_path)
    assert any("String overflow" in e or "OS_XML buffer" in e for e in errors)


def test_database_load_order_violation_flagged(tmp_path):
    from generator.validator import validate_database

    (tmp_path / "aaa.xml").write_text(
        """<group name="test,">
  <rule id="115000" level="12" frequency="3" timeframe="300">
    <if_matched_sid>112501</if_matched_sid>
    <description>Composite loaded before its parent</description>
  </rule>
</group>
"""
    )
    (tmp_path / "bbb.xml").write_text(
        """<group name="test,">
  <rule id="112501" level="10">
    <if_sid>61603</if_sid>
    <field name="win.eventdata.image">psexec</field>
    <description>Parent defined in later-sorting file</description>
  </rule>
</group>
"""
    )
    errors = validate_database(tmp_path)
    assert any("loads later alphabetically" in e for e in errors)


def test_database_load_order_ok_when_parent_earlier(tmp_path):
    from generator.validator import validate_database

    (tmp_path / "aaa.xml").write_text(
        """<group name="test,">
  <rule id="112501" level="10">
    <if_sid>61603</if_sid>
    <field name="win.eventdata.image">psexec</field>
    <description>Parent in earlier-sorting file</description>
  </rule>
</group>
"""
    )
    (tmp_path / "zz_composites.xml").write_text(
        """<group name="windows,composites,">
  <rule id="115000" level="12" frequency="3" timeframe="300">
    <if_matched_sid>112501</if_matched_sid>
    <description>Composite loads last</description>
  </rule>
</group>
"""
    )
    errors = validate_database(tmp_path)
    assert errors == []


def test_database_same_file_forward_reference_flagged(tmp_path):
    from generator.validator import validate_database

    _write_db(
        tmp_path,
        """<group name="test,">
  <rule id="100001" level="5">
    <if_sid>100099</if_sid>
    <description>Child defined above its parent</description>
  </rule>
  <rule id="100099" level="10">
    <if_sid>61603</if_sid>
    <field name="win.eventdata.image">psexec</field>
    <description>Parent defined below the child</description>
  </rule>
</group>
""",
    )
    errors = validate_database(tmp_path)
    assert any("further down" in e for e in errors)
