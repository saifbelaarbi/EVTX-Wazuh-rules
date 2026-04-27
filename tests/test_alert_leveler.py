"""Tests for the alert level calculator."""

from generator.alert_leveler import calculate_level


def test_high_confidence_credential_access():
    rule = {
        "metadata": {
            "tactic": "credential_access",
            "confidence": "high",
            "field_matches": {"win.eventdata.image": "mimikatz"},
            "technique_name": "mimikatz execution",
        }
    }
    level = calculate_level(rule)
    assert level >= 12  # High severity for known tool + credential access


def test_low_confidence_discovery():
    rule = {
        "metadata": {
            "tactic": "discovery",
            "confidence": "low",
            "field_matches": {},
            "technique_name": "system info discovery",
        }
    }
    level = calculate_level(rule)
    assert level <= 6  # Low severity for low confidence discovery


def test_level_clamped_to_range():
    rule = {
        "metadata": {
            "tactic": "impact",
            "confidence": "high",
            "field_matches": {"win.eventdata.image": "meterpreter"},
            "technique_name": "meterpreter impact",
        }
    }
    level = calculate_level(rule)
    assert 1 <= level <= 15
