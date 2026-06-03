"""Back-convert EVTX-generated Wazuh rules to SigmaHQ YAML.

This is the inverse of :mod:`generator.sigma_converter`. It takes Wazuh rules
that were generated from real EVTX attack samples (not rules that were
themselves converted from Sigma) and emits portable Sigma rule YAML files so the
EVTX-derived detections can be shared in the wider Sigma ecosystem.

Sigma-sourced rules (whose ``source_evtx`` ends in ``.yml``/``.yaml``) are
skipped, since round-tripping them back to Sigma would be lossy and redundant.
"""

import json
import uuid
from datetime import date
from pathlib import Path

import yaml

from .sigma_converter import SIGMA_FIELD_TO_WAZUH_EXTENDED

PROJECT_ROOT = Path(__file__).resolve().parent.parent

DEFAULT_INDEX_PATH = PROJECT_ROOT / "database" / "metadata" / "rule_index.json"
DEFAULT_OUT_DIR = PROJECT_ROOT / "database" / "exports" / "sigma"

# Stable namespace so the same Wazuh rule id always yields the same Sigma id.
_SIGMA_NAMESPACE = uuid.UUID("6e9c5f2a-7d1b-4c3e-9a8f-0b1c2d3e4f50")

# Build the inverse of the Sigma->Wazuh field map once. When two Sigma fields map
# to the same Wazuh path (e.g. Hashes/Imphash/md5/sha256 -> win.eventdata.hashes)
# the first one wins, which keeps the mapping deterministic.
_WAZUH_TO_SIGMA: dict[str, str] = {}
for _sigma_field, _wazuh_path in SIGMA_FIELD_TO_WAZUH_EXTENDED.items():
    _WAZUH_TO_SIGMA.setdefault(_wazuh_path, _sigma_field)


def wazuh_field_to_sigma(field_path: str) -> str:
    """Invert a Wazuh decoded field path to a Sigma field name.

    Known paths (``win.eventdata.image`` -> ``Image``,
    ``win.system.eventID`` -> ``EventID``) come from the inverse of
    ``SIGMA_FIELD_TO_WAZUH_EXTENDED``. Unknown paths fall back to the last
    dotted segment with its first letter upper-cased
    (``win.eventdata.fooBar`` -> ``FooBar``).
    """
    if field_path in _WAZUH_TO_SIGMA:
        return _WAZUH_TO_SIGMA[field_path]
    last = field_path.split(".")[-1]
    if not last:
        return field_path
    return last[0].upper() + last[1:]


def _wazuh_level_to_sigma(level: int) -> str:
    """Map a Wazuh numeric level back to a Sigma severity string."""
    if level >= 13:
        return "critical"
    if level >= 11:
        return "high"
    if level >= 8:
        return "medium"
    return "low"


def _logsource_from_category(source_category: str, field_paths: list[str]) -> dict:
    """Derive a Sigma logsource block from the Wazuh source category.

    ``sysmon`` rules are split into the most likely Sigma category based on the
    fields they match (service-creation vs the common process_creation case).
    """
    cat = (source_category or "").lower()
    if cat == "sysmon":
        service_fields = {"win.eventdata.serviceName", "win.eventdata.imagePath"}
        if any(fp in service_fields for fp in field_paths):
            return {"product": "windows", "category": "driver_load"}
        return {"product": "windows", "category": "process_creation"}
    if cat == "security":
        return {"product": "windows", "service": "security"}
    if cat == "powershell":
        return {"product": "windows", "service": "powershell"}
    if cat == "system":
        return {"product": "windows", "service": "system"}
    if cat == "application":
        return {"product": "windows", "service": "application"}
    return {"product": "windows"}


def _clean_value(value: str):
    """Turn a Wazuh OS-regex pattern back into a readable Sigma value.

    Strips leading ``^`` / trailing ``$`` anchors and unescapes ``\\.`` to
    ``.``. A ``|`` (OS-regex alternation) becomes a Sigma value list.
    """
    if "|" in value:
        return [_clean_value(part) for part in value.split("|")]
    cleaned = value
    if cleaned.startswith("^"):
        cleaned = cleaned[1:]
    if cleaned.endswith("$") and not cleaned.endswith("\\$"):
        cleaned = cleaned[:-1]
    cleaned = cleaned.replace("\\.", ".")
    return cleaned


def _mitre_tags(mitre_ids: list[str], tactic: str) -> list[str]:
    """Build Sigma ``attack.*`` tags from MITRE technique ids and the tactic."""
    tags: list[str] = []
    for mid in mitre_ids or []:
        if mid:
            tags.append(f"attack.{mid.lower()}")
    if tactic:
        tags.append(f"attack.{tactic.replace('_', '-')}")
    return tags


def rule_to_sigma(meta: dict, rule_id: str) -> dict:
    """Build a Sigma rule dict from an EVTX-generated rule's metadata."""
    field_matches = meta.get("field_matches", {}) or {}
    field_paths = list(field_matches.keys())

    title = meta.get("technique_name") or meta.get("description") or "EVTX-derived detection"
    sigma_id = str(uuid.uuid5(_SIGMA_NAMESPACE, str(rule_id)))

    selection: dict = {}
    for wazuh_path, pattern in field_matches.items():
        selection[wazuh_field_to_sigma(wazuh_path)] = _clean_value(str(pattern))

    source_evtx = meta.get("source_evtx", "")
    references = [source_evtx] if source_evtx else []

    sigma_rule = {
        "title": title,
        "id": sigma_id,
        "status": "experimental",
        "description": (f"Auto-generated from EVTX attack sample by EVTX-Wazuh-Rules (Wazuh rule {rule_id})."),
        "references": references,
        "author": "EVTX-Wazuh-Rules",
        "date": meta.get("created") or date.today().isoformat(),
        "logsource": _logsource_from_category(meta.get("source_category", ""), field_paths),
        "detection": {
            "selection": selection,
            "condition": "selection",
        },
        "level": _wazuh_level_to_sigma(int(meta.get("level", 0) or 0)),
        "tags": _mitre_tags(meta.get("mitre_ids", []), meta.get("tactic", "")),
    }
    return sigma_rule


def _slug(text: str) -> str:
    """Make a filesystem-safe slug from a rule title."""
    out = []
    for ch in (text or "").lower():
        if ch.isalnum():
            out.append(ch)
        elif ch in (" ", "-", "_", "/", "\\"):
            out.append("_")
    slug = "".join(out).strip("_")
    while "__" in slug:
        slug = slug.replace("__", "_")
    return slug or "rule"


def _is_sigma_sourced(source_evtx: str, meta: dict | None = None) -> bool:
    """True when a rule originated from a Sigma file (skip these).

    YAML extensions are unambiguous; JSON files could be EVTX samples too, so
    we check for a ``sigma_id`` in the metadata as the definitive marker.
    """
    if source_evtx.lower().endswith((".yml", ".yaml")):
        return True
    if meta and meta.get("sigma_id"):
        return True
    return False


def export_evtx_rules_to_sigma(
    index_path: Path | None = None,
    out_dir: Path | None = None,
) -> int:
    """Export EVTX-generated Wazuh rules as Sigma YAML files.

    Reads the rule index, selects rules whose ``source_evtx`` is not a Sigma
    YAML file, and writes one ``<rule_id>_<slug>.yml`` per rule into ``out_dir``.
    Returns the number of Sigma files written.
    """
    index_path = Path(index_path) if index_path else DEFAULT_INDEX_PATH
    out_dir = Path(out_dir) if out_dir else DEFAULT_OUT_DIR

    with open(index_path) as fh:
        index = json.load(fh)

    out_dir.mkdir(parents=True, exist_ok=True)

    count = 0
    for rule_id, meta in index.items():
        meta = dict(meta)
        if "level" not in meta:
            meta["level"] = 0
        if _is_sigma_sourced(meta.get("source_evtx", ""), meta):
            continue

        sigma_rule = rule_to_sigma(meta, rule_id)
        slug = _slug(sigma_rule["title"])
        out_file = out_dir / f"{rule_id}_{slug}.yml"
        with open(out_file, "w") as fh:
            yaml.safe_dump(sigma_rule, fh, sort_keys=False, default_flow_style=False)
        count += 1

    return count
