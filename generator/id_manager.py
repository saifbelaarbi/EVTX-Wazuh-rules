"""Manage Wazuh rule ID allocation (range 100000-130000)."""

import json
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
ALLOCATIONS_FILE = PROJECT_ROOT / "database" / "metadata" / "id_allocations.json"


def _load_allocations() -> dict:
    if ALLOCATIONS_FILE.exists():
        with open(ALLOCATIONS_FILE) as f:
            return json.load(f)
    return {}


def _save_allocations(allocations: dict):
    ALLOCATIONS_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(ALLOCATIONS_FILE, "w") as f:
        json.dump(allocations, f, indent=2)


# Default tactic ranges (loaded from config, but hardcoded fallback)
TACTIC_RANGES = {
    "initial_access":       (100000, 101999),
    "execution":            (102000, 103999),
    "persistence":          (104000, 105999),
    "privilege_escalation": (106000, 107999),
    "defense_evasion":      (108000, 109999),
    "credential_access":    (110000, 111999),
    "discovery":            (112000, 113999),
    "lateral_movement":     (114000, 115999),
    "collection":           (116000, 117999),
    "command_and_control":  (118000, 119999),
    "exfiltration":         (120000, 121999),
    "impact":               (122000, 123999),
    "composite":            (124000, 129999),
}


def load_ranges_from_config(config: dict) -> dict:
    """Load tactic ID ranges from config.yaml."""
    ranges = {}
    for tactic, r in config.get("tactic_id_ranges", {}).items():
        ranges[tactic] = (r["start"], r["end"])
    return ranges or TACTIC_RANGES


def allocate_id(tactic: str) -> int:
    """Allocate the next available rule ID for a given tactic."""
    allocations = _load_allocations()

    if tactic not in TACTIC_RANGES:
        tactic = "composite"

    range_start, range_end = TACTIC_RANGES[tactic]

    # Get the next available ID
    next_id = allocations.get(tactic, {}).get("next_id", range_start)

    if next_id > range_end:
        raise RuntimeError(
            f"ID range exhausted for tactic '{tactic}' "
            f"(range {range_start}-{range_end})"
        )

    # Update allocations
    if tactic not in allocations:
        allocations[tactic] = {"range_start": range_start, "range_end": range_end}
    allocations[tactic]["next_id"] = next_id + 1
    allocations[tactic]["allocated_count"] = allocations[tactic].get("allocated_count", 0) + 1

    _save_allocations(allocations)
    return next_id


def get_allocation_stats() -> dict:
    """Return allocation statistics for all tactics."""
    allocations = _load_allocations()
    stats = {}
    for tactic, (start, end) in TACTIC_RANGES.items():
        alloc = allocations.get(tactic, {})
        used = alloc.get("allocated_count", 0)
        capacity = end - start + 1
        stats[tactic] = {
            "range": f"{start}-{end}",
            "used": used,
            "capacity": capacity,
            "available": capacity - used,
        }
    return stats


def is_id_allocated(rule_id: int) -> bool:
    """Check if a specific rule ID has been allocated."""
    allocations = _load_allocations()
    for tactic, alloc in allocations.items():
        range_start = alloc.get("range_start", TACTIC_RANGES.get(tactic, (0, 0))[0])
        next_id = alloc.get("next_id", range_start)
        if range_start <= rule_id < next_id:
            return True
    return False
