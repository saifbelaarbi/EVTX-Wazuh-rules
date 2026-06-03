"""False-positive tracking for generated Wazuh rules.

Records analyst-reported false positives in an append-only JSON Lines file and
provides helpers to aggregate them and to suggest severity-level adjustments.

A rule that repeatedly produces false positives is too noisy; the helpers here
let the alert leveler lower such a rule's level. The mapping from FP count to
suggested level delta is intentionally simple and threshold-based:

    count >= threshold      -> -1
    count >= 2 * threshold  -> -2
    count >= 3 * threshold  -> -3  (and so on)

All functions accept an optional ``fp_file`` argument so they can be pointed at
a temporary file in tests. Functions are otherwise pure with respect to that
file: reading never mutates state, and writing only ever appends.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
FP_FILE = PROJECT_ROOT / "database" / "metadata" / "false_positives.jsonl"


@dataclass
class FPRecord:
    """A single reported false-positive occurrence for a rule."""

    rule_id: str
    reason: str
    reporter: str = ""
    event_json: str = ""
    timestamp: str = ""


def _resolve(fp_file: Path | None) -> Path:
    """Return the FP file to use, defaulting to the module-level FP_FILE."""
    return Path(fp_file) if fp_file is not None else FP_FILE


def _now_iso() -> str:
    """Return the current time as an ISO-8601 UTC string."""
    return datetime.now(timezone.utc).isoformat()


def record_fp(
    rule_id: str,
    reason: str,
    reporter: str = "",
    event_json: str = "",
    fp_file: Path | None = None,
) -> FPRecord:
    """Append one false-positive record as a JSON line and return it.

    The parent directory is created if needed. If ``timestamp`` would be empty
    it is auto-filled with the current ISO-8601 UTC time.
    """
    record = FPRecord(
        rule_id=str(rule_id),
        reason=reason,
        reporter=reporter,
        event_json=event_json,
        timestamp=_now_iso(),
    )
    path = _resolve(fp_file)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(asdict(record)) + "\n")
    return record


def load_fp_records(fp_file: Path | None = None) -> list[FPRecord]:
    """Read all FP records, skipping blank or corrupt lines gracefully."""
    path = _resolve(fp_file)
    if not path.exists():
        return []
    records: list[FPRecord] = []
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
            except (ValueError, TypeError):
                continue
            if not isinstance(data, dict) or "rule_id" not in data:
                continue
            records.append(
                FPRecord(
                    rule_id=str(data.get("rule_id", "")),
                    reason=data.get("reason", ""),
                    reporter=data.get("reporter", ""),
                    event_json=data.get("event_json", ""),
                    timestamp=data.get("timestamp", ""),
                )
            )
    return records


def fp_counts(fp_file: Path | None = None) -> dict[str, int]:
    """Return a mapping of rule_id -> number of recorded false positives."""
    counts: dict[str, int] = {}
    for record in load_fp_records(fp_file):
        counts[record.rule_id] = counts.get(record.rule_id, 0) + 1
    return counts


def _delta_for_count(count: int, threshold: int) -> int:
    """Compute the (negative) level delta for a given count and threshold."""
    if threshold <= 0 or count < threshold:
        return 0
    return -(count // threshold)


def suggest_level_adjustments(fp_file: Path | None = None, threshold: int = 3) -> dict[str, int]:
    """Suggest level decrements for rules at or above ``threshold`` FPs.

    Returns a mapping of rule_id -> negative integer delta. Rules below the
    threshold are omitted entirely.
    """
    suggestions: dict[str, int] = {}
    for rule_id, count in fp_counts(fp_file).items():
        delta = _delta_for_count(count, threshold)
        if delta < 0:
            suggestions[rule_id] = delta
    return suggestions


def level_penalty(rule_id: str, fp_file: Path | None = None, threshold: int = 3) -> int:
    """Return the (negative) level delta for a single rule, or 0 if below threshold."""
    count = fp_counts(fp_file).get(str(rule_id), 0)
    return _delta_for_count(count, threshold)
