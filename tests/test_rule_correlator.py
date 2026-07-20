"""Tests for the rule correlator."""

from generator.rule_correlator import (
    check_duplicate,
    check_overlap,
    correlate,
)


def _make_rule(field_matches, tactic="credential_access"):
    return {
        "metadata": {
            "field_matches": field_matches,
            "tactic": tactic,
            "technique_name": "Test",
        },
        "pattern": None,
    }


def test_exact_duplicate():
    fm = {"win.eventdata.image": "mimikatz"}
    rule = _make_rule(fm, "credential_access")
    index = {"100001": {"field_matches": fm, "tactic": "credential_access"}}
    dup = check_duplicate(rule, index)
    assert dup is not None
    assert dup["type"] == "exact_duplicate"


def test_cross_tactic_not_duplicate_in_current_code():
    """Current check_duplicate requires same tactic — cross-tactic clones pass."""
    fm = {"win.eventdata.image": "mimikatz"}
    rule = _make_rule(fm, "execution")
    index = {"100001": {"field_matches": fm, "tactic": "credential_access"}}
    dup = check_duplicate(rule, index)
    assert dup is None


def test_no_duplicate():
    rule = _make_rule({"win.eventdata.image": "cmd.exe"})
    index = {"100001": {"field_matches": {"win.eventdata.image": "powershell.exe"}, "tactic": "credential_access"}}
    dup = check_duplicate(rule, index)
    assert dup is None


def test_partial_overlap():
    rule = _make_rule(
        {
            "win.eventdata.image": "mimikatz",
            "win.eventdata.commandLine": "sekurlsa",
        }
    )
    index = {
        "100001": {
            "field_matches": {"win.eventdata.image": "mimikatz"},
            "tactic": "credential_access",
        }
    }
    overlaps = check_overlap(rule, index)
    assert len(overlaps) >= 1
    assert overlaps[0]["type"] == "partial_overlap"


def test_correlate_new_unique():
    rule = _make_rule({"win.eventdata.image": "unique_tool_xyz"})
    report = correlate(rule, existing_index={}, default_rules={})
    assert report["recommendation"] == "add"


def test_correlate_exact_dup_skips():
    fm = {"win.eventdata.image": "mimikatz"}
    rule = _make_rule(fm)
    index = {"100001": {"field_matches": fm, "tactic": "credential_access"}}
    report = correlate(rule, existing_index=index, default_rules={})
    assert report["recommendation"] == "skip"


def test_index_memo_invalidated_on_growth():
    """Adding a rule to the index between calls must be picked up (memo keys on length)."""
    fm = {"win.eventdata.image": "late_addition"}
    index = {}
    rule = _make_rule(fm, "credential_access")
    assert check_duplicate(rule, index) is None

    index["100055"] = {"field_matches": fm, "tactic": "credential_access"}
    dup = check_duplicate(rule, index)
    assert dup is not None
    assert dup["rule_id"] == "100055"


def test_overlap_not_reported_when_existing_superset():
    """If an existing rule contains ALL the new rule's fields, it's not a partial overlap."""
    rule = _make_rule({"win.eventdata.image": "mimikatz"})
    index = {
        "100001": {
            "field_matches": {
                "win.eventdata.image": "mimikatz",
                "win.eventdata.commandLine": "sekurlsa",
            },
            "tactic": "credential_access",
        }
    }
    overlaps = check_overlap(rule, index)
    assert overlaps == []


def test_default_coverage_first_default_rule_wins():
    from generator.rule_correlator import check_default_coverage

    rule = _make_rule({"win.eventdata.image": "mimikatz"})
    defaults = {
        "92000": {
            "level": 12,
            "description": "First matching default",
            "fields": {"win.eventdata.image": "\\.*mimikatz\\.*"},
            "source_file": "a.xml",
        },
        "92001": {
            "level": 10,
            "description": "Second matching default",
            "fields": {"win.eventdata.image": "mimikatz.exe or mimikatz"},
            "source_file": "b.xml",
        },
    }
    cov = check_default_coverage(rule, defaults)
    assert cov is not None
    assert cov["default_rule_id"] == "92000"
    assert cov["type"] == "covered_by_default"
