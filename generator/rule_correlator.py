"""Cross-reference new rules with existing rules and Wazuh defaults.

The public check_* functions preserve their original per-rule semantics but
are backed by indexes built once per (existing_index, default_rules) object
and memoized, so correlating N new rules against an M-rule database costs
O(N + M) instead of O(N x M). The caches key on object identity + length;
callers pass the same loaded index for a whole correlation loop (see cli.py),
which is the pattern the memoization is built for.
"""

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


# ── Index caches ─────────────────────────────────────────────────────────────
# One-slot memo per source object. Keyed on (id(obj), len(obj)) — the strong
# reference kept alongside prevents id() reuse, and a length change (rules
# added/removed mid-loop) invalidates the memo.

_index_memo: tuple | None = None  # (source_obj, len, caches)
_defaults_memo: tuple | None = None


def _fields_key(field_matches: dict):
    """Hashable identity of a field-match dict, or None if unhashable."""
    try:
        return frozenset(field_matches.items())
    except TypeError:
        return None


def _index_caches(existing_index: dict) -> dict:
    """Build (or reuse) lookup structures over the existing rule index."""
    global _index_memo
    if _index_memo is not None and _index_memo[0] is existing_index and _index_memo[1] == len(existing_index):
        return _index_memo[2]

    by_signature: dict = {}  # (fields_key, tactic) -> (rule_id, meta), first wins
    entries: list = []  # (position, rule_id, meta, fields_set)
    by_item: dict = {}  # (field, value) -> [entry positions]
    chain_by_tactic: dict = {}  # tactic -> [candidate dicts] (shared, read-only)

    for pos, (rule_id, meta) in enumerate(existing_index.items()):
        fields = meta.get("field_matches", {})
        key = _fields_key(fields)
        if key is not None:
            by_signature.setdefault((key, meta.get("tactic", "")), (rule_id, meta))
            entries.append((pos, rule_id, meta, key))
            for item in key:
                by_item.setdefault(item, []).append(len(entries) - 1)
        tactic = meta.get("tactic")
        if tactic:
            chain_by_tactic.setdefault(tactic, []).append(
                {
                    "rule_id": rule_id,
                    "type": "same_tactic",
                    "relationship": "sibling",
                    "existing": meta,
                }
            )

    caches = {
        "by_signature": by_signature,
        "entries": entries,
        "by_item": by_item,
        "chain_by_tactic": chain_by_tactic,
    }
    _index_memo = (existing_index, len(existing_index), caches)
    return caches


def _defaults_caches(default_rules: dict) -> dict:
    """Build (or reuse) a per-field lookup over Wazuh default rules."""
    global _defaults_memo
    if _defaults_memo is not None and _defaults_memo[0] is default_rules and _defaults_memo[1] == len(default_rules):
        return _defaults_memo[2]

    by_field: dict = {}  # field name -> [(position, rule_id, value_lower, default)]
    for pos, (rule_id, default) in enumerate(default_rules.items()):
        for df_name, df_value in default.get("fields", {}).items():
            by_field.setdefault(df_name, []).append((pos, rule_id, df_value.lower(), default))

    caches = {"by_field": by_field}
    _defaults_memo = (default_rules, len(default_rules), caches)
    return caches


# ── Correlation checks ───────────────────────────────────────────────────────


def check_duplicate(new_rule: dict, existing_index: dict) -> dict | None:
    """Check if a rule with the same detection logic already exists."""
    new_fields = new_rule["metadata"].get("field_matches", {})
    new_tactic = new_rule["metadata"].get("tactic", "")

    key = _fields_key(new_fields)
    if key is None:
        return None
    hit = _index_caches(existing_index)["by_signature"].get((key, new_tactic))
    if hit is None:
        return None
    rule_id, meta = hit
    return {"rule_id": rule_id, "type": "exact_duplicate", "existing": meta}


def check_overlap(new_rule: dict, existing_index: dict) -> list[dict]:
    """Find rules that partially overlap with the new rule."""
    new_fields = set(new_rule["metadata"].get("field_matches", {}).items())
    if not new_fields:
        return []

    caches = _index_caches(existing_index)
    entries = caches["entries"]
    by_item = caches["by_item"]

    candidate_idx: set[int] = set()
    for item in new_fields:
        candidate_idx.update(by_item.get(item, ()))

    overlaps = []
    for idx in sorted(candidate_idx):
        _, rule_id, meta, existing_fields = entries[idx]
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
    new_fields = new_rule["metadata"].get("field_matches", {})
    if not new_fields or not default_rules:
        return None

    by_field = _defaults_caches(default_rules)["by_field"]

    best = None  # (position, rule_id, default) with the lowest position
    for field_name, value in new_fields.items():
        value_lower = value.lower()
        for pos, rule_id, df_value_lower, default in by_field.get(field_name, ()):
            if value_lower in df_value_lower and (best is None or pos < best[0]):
                best = (pos, rule_id, default)

    if best is None:
        return None
    _, rule_id, default = best
    return {
        "default_rule_id": rule_id,
        "type": "covered_by_default",
        "default_description": default["description"],
        "default_level": default["level"],
    }


def find_chain_candidates(new_rule: dict, existing_index: dict) -> list[dict]:
    """Find rules that could form if_sid chains with the new rule.

    The candidate dicts are shared across calls for the same index (they are
    report annotations, treated as read-only by all callers).
    """
    new_tactic = new_rule["metadata"].get("tactic", "")
    if not new_tactic:
        return []

    siblings = _index_caches(existing_index)["chain_by_tactic"].get(new_tactic)
    return list(siblings) if siblings else []


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
