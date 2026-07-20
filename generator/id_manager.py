"""Manage Wazuh rule ID allocation within Wazuh's custom range (100000-119999)."""

import json
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
ALLOCATIONS_FILE = PROJECT_ROOT / "database" / "metadata" / "id_allocations.json"
RULE_INDEX_FILE = PROJECT_ROOT / "database" / "metadata" / "rule_index.json"

# In-memory allocations cache, validated against the file's (mtime_ns, size)
# stat signature. allocate_id() is called once per generated rule — thousands
# of times per pipeline run — so re-parsing the JSON on every call is pure
# waste. External writes (e.g. the CLI's dry-run snapshot/restore) change the
# stat signature and transparently invalidate the cache.
_cache: dict = {"path": None, "stat": None, "data": None}


def _file_stat(path: Path):
    try:
        st = path.stat()
        return (st.st_mtime_ns, st.st_size)
    except OSError:
        return None


def _load_allocations() -> dict:
    stat = _file_stat(ALLOCATIONS_FILE)
    if _cache["path"] == ALLOCATIONS_FILE and _cache["stat"] == stat and _cache["data"] is not None:
        return _cache["data"]

    if stat is not None:
        with open(ALLOCATIONS_FILE) as f:
            data = json.load(f)
    else:
        data = {}
    _cache.update(path=ALLOCATIONS_FILE, stat=stat, data=data)
    return data


def _save_allocations(allocations: dict):
    ALLOCATIONS_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(ALLOCATIONS_FILE, "w") as f:
        json.dump(allocations, f, indent=2)
    _cache.update(path=ALLOCATIONS_FILE, stat=_file_stat(ALLOCATIONS_FILE), data=allocations)


# Tactic ID ranges within Wazuh's custom range (100000-119999).
# Sized proportionally: execution/persistence get more room, smaller tactics get 500.
# 119990-119999 are reserved for deployment infrastructure (e.g. the logtest
# bridge root rule 119999 written by docker-entrypoint.sh) and are never
# allocated to detection rules.
TACTIC_RANGES = {
    "execution": (100000, 103999),
    "persistence": (104000, 106999),
    "privilege_escalation": (107000, 108499),
    "credential_access": (108500, 109999),
    "command_and_control": (110000, 110999),
    "discovery": (111000, 111999),
    "defense_evasion": (112000, 112499),
    "lateral_movement": (112500, 112999),
    "initial_access": (113000, 113499),
    "collection": (113500, 113999),
    "impact": (114000, 114499),
    "exfiltration": (114500, 114999),
    "composite": (115000, 119989),
}


def load_ranges_from_config(config: dict) -> dict:
    """Load tactic ID ranges from config.yaml."""
    ranges = {}
    for tactic, r in config.get("tactic_id_ranges", {}).items():
        ranges[tactic] = (r["start"], r["end"])
    return ranges or TACTIC_RANGES


def _max_id_in_use(tactic: str) -> int | None:
    """Scan rule_index.json for the highest ID actually in use for a tactic."""
    if not RULE_INDEX_FILE.exists():
        return None
    try:
        with open(RULE_INDEX_FILE) as f:
            index = json.load(f)
    except (json.JSONDecodeError, OSError):
        return None

    range_start, range_end = TACTIC_RANGES.get(tactic, (0, 0))
    max_id = None
    for rid_str, meta in index.items():
        rid = int(rid_str)
        if range_start <= rid <= range_end:
            if max_id is None or rid > max_id:
                max_id = rid
    return max_id


def allocate_id(tactic: str) -> int:
    """Allocate the next available rule ID for a given tactic."""
    allocations = _load_allocations()

    if tactic not in TACTIC_RANGES:
        tactic = "composite"

    range_start, range_end = TACTIC_RANGES[tactic]

    # Get the next available ID
    next_id = allocations.get(tactic, {}).get("next_id", range_start)

    # If the pointer is past the range, recalculate from actual usage.
    # This handles re-runs where build_rules allocated IDs that were
    # later discarded by the correlator (dedup), wasting ID slots.
    if next_id > range_end:
        max_used = _max_id_in_use(tactic)
        if max_used is not None:
            next_id = max_used + 1
        else:
            next_id = range_start
        if next_id > range_end:
            raise RuntimeError(f"ID range exhausted for tactic '{tactic}' (range {range_start}-{range_end})")

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
