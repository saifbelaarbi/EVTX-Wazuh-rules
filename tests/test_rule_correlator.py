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
    index = {"100001": {"field_matches": {"win.eventdata.image": "powershell.exe"},
                        "tactic": "credential_access"}}
    dup = check_duplicate(rule, index)
    assert dup is None


def test_partial_overlap():
    rule = _make_rule({
        "win.eventdata.image": "mimikatz",
        "win.eventdata.commandLine": "sekurlsa",
    })
    index = {"100001": {
        "field_matches": {"win.eventdata.image": "mimikatz"},
        "tactic": "credential_access",
    }}
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
