"""Export MITRE ATT&CK Navigator layer from the rule database."""

import json
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
RULE_INDEX_FILE = PROJECT_ROOT / "database" / "metadata" / "rule_index.json"

TACTIC_MAP = {
    "initial_access": ("TA0001", "Initial Access"),
    "execution": ("TA0002", "Execution"),
    "persistence": ("TA0003", "Persistence"),
    "privilege_escalation": ("TA0004", "Privilege Escalation"),
    "defense_evasion": ("TA0005", "Defense Evasion"),
    "credential_access": ("TA0006", "Credential Access"),
    "discovery": ("TA0007", "Discovery"),
    "lateral_movement": ("TA0008", "Lateral Movement"),
    "collection": ("TA0009", "Collection"),
    "exfiltration": ("TA0010", "Exfiltration"),
    "command_and_control": ("TA0011", "Command and Control"),
    "impact": ("TA0040", "Impact"),
}

GRADIENT = [
    "#a1d99b",  # 1 rule  — light green
    "#74c476",  # 2-5
    "#41ab5d",  # 6-10
    "#238b45",  # 11-25
    "#006d2c",  # 26-50
    "#00441b",  # 51+     — dark green
]


def _score_to_color(count: int) -> str:
    if count <= 1:
        return GRADIENT[0]
    if count <= 5:
        return GRADIENT[1]
    if count <= 10:
        return GRADIENT[2]
    if count <= 25:
        return GRADIENT[3]
    if count <= 50:
        return GRADIENT[4]
    return GRADIENT[5]


def export_navigator_layer(
    index_path: Path = RULE_INDEX_FILE,
    output_path: Path | None = None,
) -> dict:
    """Build and optionally write an ATT&CK Navigator v4 layer JSON."""
    if output_path is None:
        output_path = PROJECT_ROOT / "database" / "navigator_layer.json"

    with open(index_path) as f:
        index = json.load(f)

    technique_counts = Counter()
    technique_rules = defaultdict(list)
    technique_tactics = defaultdict(set)

    for rule_id, meta in index.items():
        tactic = meta.get("tactic", "")
        for tid in meta.get("mitre_ids", []):
            technique_counts[tid] += 1
            technique_rules[tid].append(rule_id)
            if tactic in TACTIC_MAP:
                technique_tactics[tid].add(tactic)

    max_count = max(technique_counts.values()) if technique_counts else 1

    techniques = []
    for tid, count in technique_counts.items():
        base = tid.split(".")[0]
        sub = tid if "." in tid else ""

        entry = {
            "techniqueID": base,
            "score": count,
            "color": _score_to_color(count),
            "comment": f"{count} rules: {', '.join(technique_rules[tid][:10])}",
            "enabled": True,
            "showSubtechniques": bool(sub),
        }

        tactic_names = []
        for t in technique_tactics.get(tid, []):
            ta_id, ta_name = TACTIC_MAP[t]
            tactic_names.append(ta_name.lower().replace(" ", "-"))
        if tactic_names:
            entry["tactic"] = tactic_names[0]

        if sub:
            entry["techniqueID"] = tid
            entry["comment"] = f"[{tid}] {entry['comment']}"

        techniques.append(entry)

    layer = {
        "name": "EVTX-Wazuh-Rules Coverage",
        "versions": {
            "attack": "14",
            "navigator": "4.9.1",
            "layer": "4.5",
        },
        "domain": "enterprise-attack",
        "description": (
            f"Auto-generated from {len(index)} Wazuh detection rules. {len(technique_counts)} techniques covered."
        ),
        "filters": {"platforms": ["Windows"]},
        "sorting": 3,
        "layout": {"layout": "side", "aggregateFunction": "average", "showID": True, "showName": True},
        "hideDisabled": False,
        "techniques": techniques,
        "gradient": {
            "colors": [GRADIENT[0], GRADIENT[-1]],
            "minValue": 0,
            "maxValue": max_count,
        },
        "metadata": [
            {"name": "generated", "value": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")},
            {"name": "total_rules", "value": str(len(index))},
            {"name": "techniques_covered", "value": str(len(technique_counts))},
        ],
    }

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w") as f:
        json.dump(layer, f, indent=2)

    return layer
