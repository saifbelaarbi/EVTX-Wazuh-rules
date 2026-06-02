"""Cross-reference new rules with existing rules and Wazuh defaults."""

import json
from pathlib import Path
from xml.etree import ElementTree as ET

from rich.console import Console

console = Console()

PROJECT_ROOT = Path(__file__).resolve().parent.parent
RULE_INDEX_FILE = PROJECT_ROOT / "database" / "metadata" / "rule_index.json"


def load_rule_index() -> dict:
    """Load the master rule index."""
    if RULE_INDEX_FILE.exists():
        with open(RULE_INDEX_FILE) as f:
            return json.load(f)
    return {}


def load_wazuh_default_rules(defaults_dir: Path) -> dict:
    """Parse Wazuh default rules to extract rule IDs and descriptions."""
    default_rules = {}
    if not defaults_dir or not defaults_dir.exists():
        return default_rules

    for xml_file in defaults_dir.glob("*.xml"):
        try:
            tree = ET.parse(str(xml_file))
            root = tree.getroot()
            for rule_elem in root.iter("rule"):
                rule_id = rule_elem.get("id", "")
                level = rule_elem.get("level", "0")
                desc_elem = rule_elem.find("description")
                desc = desc_elem.text if desc_elem is not None else ""

                # Extract field matches for comparison
                fields = {}
                for field_elem in rule_elem.findall("field"):
                    fields[field_elem.get("name", "")] = field_elem.text or ""

                match_elem = rule_elem.find("match")
                if match_elem is not None and match_elem.text:
                    fields["_match"] = match_elem.text

                default_rules[rule_id] = {
                    "level": int(level),
                    "description": desc,
                    "fields": fields,
                    "source_file": xml_file.name,
                }
        except ET.ParseError:
            continue

    return default_rules


def check_duplicate(new_rule: dict, existing_index: dict) -> dict | None:
    """Check if a rule with the same detection logic already exists."""
    new_fields = new_rule["metadata"].get("field_matches", {})
    new_tactic = new_rule["metadata"].get("tactic", "")

    for rule_id, meta in existing_index.items():
        existing_fields = meta.get("field_matches", {})
        if new_fields == existing_fields and new_tactic == meta.get("tactic", ""):
            return {"rule_id": rule_id, "type": "exact_duplicate", "existing": meta}

    return None


def check_overlap(new_rule: dict, existing_index: dict) -> list[dict]:
    """Find rules that partially overlap with the new rule."""
    overlaps = []
    new_fields = set(new_rule["metadata"].get("field_matches", {}).items())

    for rule_id, meta in existing_index.items():
        existing_fields = set(meta.get("field_matches", {}).items())
        common = new_fields & existing_fields
        if common and common != new_fields:
            overlaps.append(
                {
                    "rule_id": rule_id,
                    "type": "partial_overlap",
                    "common_fields": dict(common),
                    "existing": meta,
                }
            )

    return overlaps


def check_default_coverage(new_rule: dict, default_rules: dict) -> dict | None:
    """Check if Wazuh defaults already cover this detection."""
    new_rule["metadata"].get("technique_name", "").lower()
    new_fields = new_rule["metadata"].get("field_matches", {})

    for rule_id, default in default_rules.items():
        # Check field match overlap
        default_fields = default.get("fields", {})
        for field_name, value in new_fields.items():
            for df_name, df_value in default_fields.items():
                if field_name == df_name and value.lower() in df_value.lower():
                    return {
                        "default_rule_id": rule_id,
                        "type": "covered_by_default",
                        "default_description": default["description"],
                        "default_level": default["level"],
                    }

    return None


def find_chain_candidates(new_rule: dict, existing_index: dict) -> list[dict]:
    """Find rules that could form if_sid chains with the new rule."""
    candidates = []
    new_tactic = new_rule["metadata"].get("tactic", "")
    new_rule["pattern"].event_id if hasattr(new_rule.get("pattern", {}), "event_id") else 0

    for rule_id, meta in existing_index.items():
        # Same tactic, could be a refinement
        if meta.get("tactic") == new_tactic and meta.get("tactic"):
            candidates.append(
                {
                    "rule_id": rule_id,
                    "type": "same_tactic",
                    "relationship": "sibling",
                    "existing": meta,
                }
            )

    return candidates


def correlate(new_rule: dict, existing_index: dict = None, default_rules: dict = None) -> dict:
    """Full correlation check for a new rule.

    Returns a correlation report with:
    - duplicate: exact duplicate found (dict or None)
    - overlaps: partially overlapping rules (list)
    - default_coverage: covered by Wazuh defaults (dict or None)
    - chain_candidates: rules that could form chains (list)
    - recommendation: "add", "skip", "review", "enhance"
    """
    if existing_index is None:
        existing_index = load_rule_index()
    if default_rules is None:
        default_rules = {}

    report = {
        "duplicate": check_duplicate(new_rule, existing_index),
        "overlaps": check_overlap(new_rule, existing_index),
        "default_coverage": check_default_coverage(new_rule, default_rules),
        "chain_candidates": find_chain_candidates(new_rule, existing_index),
    }

    # Determine recommendation
    if report["duplicate"]:
        report["recommendation"] = "skip"
        report["reason"] = "Exact duplicate of existing rule"
    elif report["default_coverage"]:
        report["recommendation"] = "review"
        report["reason"] = f"Similar to Wazuh default rule {report['default_coverage']['default_rule_id']}"
    elif report["overlaps"]:
        report["recommendation"] = "review"
        report["reason"] = f"Overlaps with {len(report['overlaps'])} existing rule(s)"
    else:
        report["recommendation"] = "add"
        report["reason"] = "New unique detection"

    return report
