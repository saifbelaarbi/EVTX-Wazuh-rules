"""Tests for the logtest validator sample-event resolution."""

from generator.logtest_validator import (
    _flatten_event_fields,
    _literal_from_pattern,
    _match_field,
    _provider_for_parent,
    _resolve_sample_event,
    format_event_for_wazuh,
    simulate_rule_match,
    synthesize_event,
)

# ── _match_field ──


def test_match_field_substring():
    assert _match_field("mimikatz", "C:\\tools\\mimikatz.exe")


def test_match_field_case_insensitive():
    assert _match_field("MIMIKATZ", "c:\\tools\\mimikatz.exe")


def test_match_field_anchored_end():
    assert _match_field("mimikatz\\.exe$", "C:\\tools\\mimikatz.exe")
    assert not _match_field("mimikatz\\.exe$", "mimikatz.exe.bak")


def test_match_field_anchored_start():
    assert _match_field("^C:\\\\tools", "C:\\tools\\something")


def test_match_field_alternation():
    assert _match_field("cmd|powershell", "C:\\Windows\\powershell.exe")
    assert _match_field("cmd|powershell", "cmd.exe")
    assert not _match_field("cmd|powershell", "notepad.exe")


def test_match_field_empty():
    assert _match_field("", "value")  # empty pattern = field exists → matches
    assert not _match_field("", "")
    assert not _match_field("pattern", "")


# ── synthesize_event ──


def test_synthesize_basic():
    fm = {
        "win.eventdata.image": "mimikatz",
        "win.eventdata.commandLine": "sekurlsa",
    }
    event = synthesize_event(fm, "1", "Sysmon", "Microsoft-Windows-Sysmon")
    assert event["_synthetic"] is True
    assert event["event_id"] == "1"
    flat = _flatten_event_fields(event)
    assert "mimikatz" in flat.get("win.eventdata.image", "")
    assert "sekurlsa" in flat.get("win.eventdata.commandLine", "")


def test_synthesize_strips_anchors():
    fm = {"win.eventdata.image": "^start.*end$"}
    event = synthesize_event(fm, "1", "", "")
    assert event["_synthetic"]
    ed = event.get("event_data", {})
    val = list(ed.values())[0]
    assert not val.startswith("^")
    assert not val.endswith("$")


def test_synthesize_event_id_field():
    fm = {"win.system.eventID": "4625"}
    event = synthesize_event(fm, "", "Security", "")
    assert event["event_id"] == "4625"


def test_synthesize_round_trip():
    """A synthesized event should match the field_matches that generated it."""
    fm = {
        "win.eventdata.image": "mimikatz",
        "win.eventdata.commandLine": "sekurlsa::logonpasswords",
    }
    event = synthesize_event(fm, "1", "Sysmon", "Sysmon")
    flat = _flatten_event_fields(event)
    matched, details = simulate_rule_match(fm, flat)
    assert matched, f"Round-trip failed: {details}"


# ── _literal_from_pattern ──


def test_literal_strips_anchors():
    assert _literal_from_pattern("^start$") == "start"


def test_literal_takes_first_alternative():
    assert _literal_from_pattern("foo|bar") == "foo"


def test_literal_replaces_wildcards():
    # In OSRegex, \\.* is zero-or-more any char (the real wildcard)
    result = _literal_from_pattern("foo\\.*bar")
    assert "\\.*" not in result
    # .* is treated as PCRE wildcard for synthesis (Sigma re-modifier patterns)
    assert _literal_from_pattern("foo.*bar") == "fooxbar"


def test_literal_handles_pcre_features():
    # Character classes
    assert _literal_from_pattern("[0-9]{1,3}") == "1"
    assert _literal_from_pattern("[a-zA-Z]") == "a"
    assert _literal_from_pattern("[-/]") == "/"
    # Dollar escape
    assert _literal_from_pattern("\\$") == "$"
    # Non-capturing groups
    assert _literal_from_pattern("(?:foo|bar)") == "foo"
    # PCRE character classes
    assert _literal_from_pattern("\\d") == "1"
    assert _literal_from_pattern("\\s") == " "
    # Empty pattern — returns placeholder since empty field values don't match
    assert _literal_from_pattern("") == "x"
    # .+ and .{n,m}
    assert _literal_from_pattern(".+") == "x"
    assert _literal_from_pattern(".{0,5}") == "x"


# ── _provider_for_parent ──


def test_provider_sysmon():
    ch, prov = _provider_for_parent(61603)
    assert "Sysmon" in prov
    assert "Sysmon" in ch


def test_provider_security():
    ch, prov = _provider_for_parent(60100)
    assert "Security" in ch


def test_provider_powershell():
    ch, prov = _provider_for_parent(91801)
    assert "PowerShell" in ch


def test_provider_unknown():
    ch, prov = _provider_for_parent(99999)
    assert ch == ""


# ── _resolve_sample_event ──


def test_resolve_returns_none_without_fallback(monkeypatch):
    """The resolver must NOT fall back to events[0]; it returns None instead."""
    monkeypatch.setattr("generator.logtest_validator._load_sample_events", lambda: {})
    event, prov = _resolve_sample_event("999999", {"field_matches": {}})
    assert event is None
    assert prov == ""


def test_resolve_uses_stored_event(monkeypatch):
    stored = {"event_id": "1", "channel": "Sysmon", "provider_name": "Sysmon", "event_data": {"Image": "test.exe"}}
    monkeypatch.setattr(
        "generator.logtest_validator._load_sample_events",
        lambda: {"100001": stored},
    )
    event, prov = _resolve_sample_event("100001", {"field_matches": {}})
    assert event is stored
    assert prov == "stored"


def test_resolve_synthesizes_when_no_source(monkeypatch):
    monkeypatch.setattr("generator.logtest_validator._load_sample_events", lambda: {})
    meta = {
        "field_matches": {"win.eventdata.image": "test"},
        "source_evtx": "",
        "parent_sid": 61603,
    }
    event, prov = _resolve_sample_event("100001", meta)
    assert event is not None
    assert prov == "synthetic"
    assert event.get("_synthetic") is True


# ── format_event_for_wazuh ──


def test_format_event_json():
    import json

    event = {
        "provider_name": "Sysmon",
        "event_id": 1,
        "channel": "Microsoft-Windows-Sysmon/Operational",
        "computer": "WS01",
        "event_data": {"Image": "cmd.exe", "CommandLine": "cmd /c whoami"},
    }
    result = format_event_for_wazuh(event)
    parsed = json.loads(result)
    assert parsed["win"]["system"]["eventID"] == "1"
    assert parsed["win"]["eventdata"]["image"] == "cmd.exe"
    assert parsed["win"]["eventdata"]["commandLine"] == "cmd /c whoami"
