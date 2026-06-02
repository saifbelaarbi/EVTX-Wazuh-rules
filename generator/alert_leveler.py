"""Assign alert severity levels to Wazuh rules based on multiple factors."""

# Tactic base severity scores
TACTIC_BASE_LEVELS = {
    "initial_access": 8,
    "execution": 8,
    "persistence": 9,
    "privilege_escalation": 10,
    "defense_evasion": 9,
    "credential_access": 11,
    "discovery": 6,
    "lateral_movement": 10,
    "collection": 7,
    "command_and_control": 9,
    "exfiltration": 12,
    "impact": 13,
    "composite": 10,
}

# Confidence adjustments
CONFIDENCE_MODIFIER = {
    "high": 1,  # Exact tool name match, etc.
    "medium": 0,  # Pattern match
    "low": -2,  # Heuristic/behavioral
}

# Specific tool/technique overrides (always high severity)
HIGH_SEVERITY_INDICATORS = {
    "mimikatz": 13,
    "cobalt": 13,
    "beacon": 13,
    "meterpreter": 14,
    "empire": 12,
    "bloodhound": 11,
    "lsass": 12,
    "sekurlsa": 13,
    "lsadump": 13,
    "vssadmin delete shadows": 14,
    "bcdedit /set": 12,
}


def calculate_level(rule: dict) -> int:
    """Calculate the alert level for a rule.

    Considers:
    1. MITRE tactic base severity
    2. Detection confidence
    3. Specific indicator overrides
    4. Existing rules in the same tactic (consistency)
    """
    metadata = rule["metadata"]
    tactic = metadata.get("tactic", "composite")
    confidence = metadata.get("confidence", "medium")

    # Start with tactic base level
    level = TACTIC_BASE_LEVELS.get(tactic, 8)

    # Apply confidence modifier
    level += CONFIDENCE_MODIFIER.get(confidence, 0)

    # Check for high-severity indicator overrides
    field_matches = metadata.get("field_matches", {})
    description = metadata.get("technique_name", "").lower()

    for indicator, override_level in HIGH_SEVERITY_INDICATORS.items():
        # Check in field values
        for field_val in field_matches.values():
            if indicator in str(field_val).lower():
                level = max(level, override_level)
                break
        # Check in description/technique name
        if indicator in description:
            level = max(level, override_level)

    # Feedback loop: rules with repeated reported false positives are demoted.
    rule_id = metadata.get("rule_id")
    if rule_id is not None:
        try:
            from . import fp_tracker

            level += fp_tracker.level_penalty(str(rule_id))
        except Exception:
            pass

    # Clamp to valid Wazuh range (0-15)
    level = max(1, min(15, level))

    return level


def apply_levels(rules: list[dict]) -> list[dict]:
    """Apply alert levels to a list of rules."""
    for rule in rules:
        level = calculate_level(rule)
        rule["level"] = level
        rule["xml_element"].set("level", str(level))
        rule["metadata"]["level"] = level

    return rules


def explain_level(rule: dict) -> str:
    """Explain why a rule was assigned its alert level."""
    metadata = rule["metadata"]
    tactic = metadata.get("tactic", "composite")
    confidence = metadata.get("confidence", "medium")
    level = rule.get("level", 0)

    base = TACTIC_BASE_LEVELS.get(tactic, 8)
    mod = CONFIDENCE_MODIFIER.get(confidence, 0)

    parts = [f"Tactic '{tactic}' base: {base}"]
    parts.append(f"Confidence '{confidence}' modifier: {mod:+d}")

    if level > base + mod:
        parts.append(f"High-severity indicator override to {level}")

    parts.append(f"Final level: {level}")
    return " | ".join(parts)
