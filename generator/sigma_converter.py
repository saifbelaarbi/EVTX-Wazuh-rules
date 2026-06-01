"""Convert SigmaHQ Sigma rules to Wazuh XML rule format."""

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml
from lxml import etree
from rich.console import Console

from . import mitre_mapper
from .id_manager import allocate_id
from .sigma_analyzer import (
    SIGMA_FIELD_TO_WAZUH,
    SIGMA_LOGSOURCE_TO_WAZUH,
    parse_sigma_rule,
)

console = Console()


class SigmaConvertError(Exception):
    """Raised when a Sigma rule cannot be converted, carrying a category."""

    def __init__(self, category: str, message: str = ""):
        self.category = category
        super().__init__(f"{category}: {message}" if message else category)


def _source_category_from_mapping(mapping: dict) -> str:
    """Derive a by_source view category from a Sigma logsource mapping."""
    channel = mapping.get("channel", "")
    if channel in ("powershell", "security", "system"):
        return channel
    return "sysmon"

SIGMA_FIELD_TO_WAZUH_EXTENDED = {
    **SIGMA_FIELD_TO_WAZUH,
    "IntegrityLevel": "win.eventdata.integrityLevel",
    "LogonId": "win.eventdata.logonId",
    "Company": "win.eventdata.company",
    "Product": "win.eventdata.product",
    "FileVersion": "win.eventdata.fileVersion",
    "CurrentDirectory": "win.eventdata.currentDirectory",
    "ParentUser": "win.eventdata.parentUser",
    "DestinationIp": "win.eventdata.destinationIp",
    "DestinationPort": "win.eventdata.destinationPort",
    "SourceIp": "win.eventdata.sourceIp",
    "SourcePort": "win.eventdata.sourcePort",
    "Protocol": "win.eventdata.protocol",
    "Initiated": "win.eventdata.initiated",
    "TargetUser": "win.eventdata.targetUser",
    "EventType": "win.eventdata.eventType",
    "Description": "win.eventdata.description",
    "Imphash": "win.eventdata.hashes",
    "md5": "win.eventdata.hashes",
    "sha256": "win.eventdata.hashes",
    "ParentProcessId": "win.eventdata.parentProcessId",
    "ProcessId": "win.eventdata.processId",
    "LogonType": "win.eventdata.logonType",
    "TargetUserName": "win.eventdata.targetUserName",
    "SubjectUserName": "win.eventdata.subjectUserName",
    "SourceHostname": "win.eventdata.sourceHostname",
    "WorkstationName": "win.eventdata.workstationName",
    "EventID": "win.system.eventID",
}

SIGMA_LEVEL_MAP = {
    "critical": 13,
    "high": 11,
    "medium": 8,
    "low": 5,
    "informational": 3,
}

TACTIC_FROM_TAG = {
    "attack.initial_access": "initial_access",
    "attack.execution": "execution",
    "attack.persistence": "persistence",
    "attack.privilege_escalation": "privilege_escalation",
    "attack.defense_evasion": "defense_evasion",
    "attack.credential_access": "credential_access",
    "attack.discovery": "discovery",
    "attack.lateral_movement": "lateral_movement",
    "attack.collection": "collection",
    "attack.command_and_control": "command_and_control",
    "attack.exfiltration": "exfiltration",
    "attack.impact": "impact",
}

OS_REGEX_SPECIAL = r'.+?()[]{}|^$'


def _escape_osregex(value: str) -> str:
    """Escape special chars for Wazuh OS regex."""
    result = []
    for ch in value:
        if ch in OS_REGEX_SPECIAL:
            result.append('\\')
        result.append(ch)
    return ''.join(result)


def _resolve_field(sigma_field: str) -> str | None:
    """Map a Sigma field name to a Wazuh field path."""
    if sigma_field in SIGMA_FIELD_TO_WAZUH_EXTENDED:
        return SIGMA_FIELD_TO_WAZUH_EXTENDED[sigma_field]
    lower = sigma_field[0].lower() + sigma_field[1:] if sigma_field else sigma_field
    return f"win.eventdata.{lower}"


def _escape_osregex_with_globs(value: str) -> str:
    """Escape regex metacharacters but translate Sigma globs to OS-regex.

    Sigma wildcards ``*`` and ``?`` become ``.*`` and ``.``; every other
    special character is escaped so it matches literally in a Wazuh <field>.
    """
    out = []
    for ch in value:
        if ch == "*":
            out.append(".*")
        elif ch == "?":
            out.append(".")
        elif ch in OS_REGEX_SPECIAL:
            out.append("\\" + ch)
        else:
            out.append(ch)
    return "".join(out)


def _apply_modifiers(value: str, modifiers: list[str]) -> str:
    """Convert a Sigma value + modifiers to a Wazuh OS regex pattern."""
    # `re` values are raw regex; pass through untouched.
    if "re" in modifiers:
        return value

    escaped = _escape_osregex_with_globs(value)

    if "windash" in modifiers:
        if escaped.startswith("-") or escaped.startswith("\\-"):
            clean = escaped.lstrip("\\-")
            escaped = "[-/]" + clean

    # endswith/startswith anchor; contains/(none) stay unanchored substrings.
    if "endswith" in modifiers:
        return escaped + "$"
    elif "startswith" in modifiers:
        return "^" + escaped
    return escaped


def _parse_field_key(key: str) -> tuple[str, list[str]]:
    """Parse 'FieldName|modifier1|modifier2' into (field, [modifiers])."""
    parts = key.split("|")
    return parts[0], parts[1:]


def _extract_tags(sigma_rule: dict) -> tuple[str, list[str], list[str]]:
    """Extract MITRE tactic, base techniques and sub-techniques from Sigma tags.

    SigmaHQ tags use hyphens for multi-word tactics (``attack.credential-access``)
    and dotted sub-techniques (``attack.t1003.001``). Both are normalized.
    Returns (tactic, base_technique_ids, full_technique_ids).
    """
    tags = sigma_rule.get("tags", [])
    tactic = ""
    base_ids: list[str] = []
    full_ids: list[str] = []

    for tag in tags:
        tag_lower = tag.lower()
        if tag_lower.startswith("attack.t"):
            tid = tag_lower.replace("attack.", "").upper()
            full_ids.append(tid)
            base_ids.append(tid.split(".")[0])
        elif not tactic:
            normalized = mitre_mapper.normalize_tactic(tag_lower)
            if normalized:
                tactic = normalized

    return (
        tactic or "execution",
        list(dict.fromkeys(base_ids)),
        list(dict.fromkeys(full_ids)),
    )


def _parse_selections(detection: dict) -> tuple[dict, str]:
    """Parse detection block into named selections and condition string."""
    condition = detection.get("condition", "")
    selections = {}

    for key, value in detection.items():
        if key == "condition":
            continue
        selections[key] = value

    return selections, condition


def _selection_to_field_matches(selection, modifiers_override=None) -> list[dict]:
    """Convert a Sigma selection dict/list to a list of field match sets.

    Each returned dict maps wazuh_field -> pattern_string.
    Multiple dicts = OR (any can match). Within one dict = AND (all must match).
    """
    if isinstance(selection, list):
        results = []
        for item in selection:
            if isinstance(item, dict):
                results.extend(_selection_to_field_matches(item, modifiers_override))
            else:
                results.append({"_raw": str(item)})
        return results

    if not isinstance(selection, dict):
        return []

    has_all_modifier = False
    and_groups = [{}]

    for raw_key, raw_values in selection.items():
        field_name, modifiers = _parse_field_key(raw_key)
        if modifiers_override:
            modifiers = modifiers_override + modifiers
        wazuh_field = _resolve_field(field_name)
        if not wazuh_field:
            continue

        if not isinstance(raw_values, list):
            raw_values = [raw_values]

        raw_values = [str(v) for v in raw_values if v is not None]

        is_all = "all" in modifiers
        clean_mods = [m for m in modifiers if m != "all"]

        if is_all:
            has_all_modifier = True
            for val in raw_values:
                pattern = _apply_modifiers(val, clean_mods)
                for group in and_groups:
                    field_key = wazuh_field
                    suffix = 0
                    while field_key in group:
                        suffix += 1
                        field_key = f"{wazuh_field}#{suffix}"
                    group[field_key] = pattern
        else:
            patterns = [_apply_modifiers(v, clean_mods) for v in raw_values]
            combined = "|".join(patterns)

            for group in and_groups:
                group[wazuh_field] = combined

    return and_groups


def _resolve_condition(condition: str, selections: dict) -> list[list[dict]]:
    """Resolve the condition string into a list of rule field-match groups.

    Returns a list of 'rule specs'. Each rule spec is a list of field match dicts
    that should be AND'd together. Multiple rule specs = multiple rules (OR).
    """
    condition = condition.strip()

    filter_names = [k for k in selections if k.startswith("filter")]
    positive_names = [k for k in selections if not k.startswith("filter")]

    if condition == "selection" and "selection" in selections:
        matches = _selection_to_field_matches(selections["selection"])
        if len(matches) == 1:
            return [matches]
        return [[m] for m in matches]

    all_of_match = re.match(r'^all of (selection[_\w]*)\*(.*)$', condition)
    if all_of_match:
        prefix = all_of_match.group(1)
        matching_sels = [k for k in positive_names if k.startswith(prefix)]
        if not matching_sels:
            matching_sels = positive_names

        combined = {}
        for sel_name in sorted(matching_sels):
            field_groups = _selection_to_field_matches(selections[sel_name])
            if field_groups:
                combined.update(field_groups[0])

        return [[combined]] if combined else []

    one_of_match = re.match(r'^1 of (selection[_\w]*)\*(.*)$', condition)
    if one_of_match:
        prefix = one_of_match.group(1)
        matching_sels = [k for k in positive_names if k.startswith(prefix)]
        if not matching_sels:
            matching_sels = positive_names

        rules = []
        for sel_name in sorted(matching_sels):
            field_groups = _selection_to_field_matches(selections[sel_name])
            for fg in field_groups:
                rules.append([fg])
        return rules

    and_parts = re.split(r'\s+and\s+', condition)
    positive_parts = [p.strip() for p in and_parts if not p.strip().startswith("not ")]

    combined = {}
    for part in positive_parts:
        part = part.strip("() ")

        all_match = re.match(r'^all of (\w+)\*$', part)
        one_match = re.match(r'^1 of (\w+)\*$', part)

        if all_match:
            prefix = all_match.group(1)
            matching = [k for k in positive_names if k.startswith(prefix)]
            for sel_name in sorted(matching):
                fgs = _selection_to_field_matches(selections[sel_name])
                if fgs:
                    combined.update(fgs[0])
        elif one_match:
            prefix = one_match.group(1)
            matching = [k for k in positive_names if k.startswith(prefix)]
            or_fields = []
            for sel_name in sorted(matching):
                fgs = _selection_to_field_matches(selections[sel_name])
                or_fields.extend(fgs)
            if or_fields:
                combined.update(or_fields[0])
        elif part in selections:
            fgs = _selection_to_field_matches(selections[part])
            if fgs:
                combined.update(fgs[0])

    if combined:
        return [[combined]]

    if positive_names:
        combined = {}
        for sel_name in positive_names:
            fgs = _selection_to_field_matches(selections[sel_name])
            if fgs:
                combined.update(fgs[0])
        return [[combined]] if combined else []

    return []


_AGG_TOKENS = (" near ", "| count", "|count", "| min", "|min", "| max", "|max",
               "| avg", "|avg", "| sum", "|sum", " | temporal")


def convert_sigma_rule(sigma_rule: dict) -> list[dict]:
    """Convert a parsed Sigma rule to one or more Wazuh rule dicts.

    Raises SigmaConvertError(category) when a rule cannot be converted so the
    batch driver can report *why* each rule was skipped.
    """
    logsource = sigma_rule.get("logsource", {})
    category = logsource.get("category", "")
    service = logsource.get("service", "")
    source_key = category or service

    mapping = SIGMA_LOGSOURCE_TO_WAZUH.get(source_key)
    if not mapping:
        raise SigmaConvertError("unmapped_logsource", source_key or "(none)")

    parent_sid = mapping["parent_sid"]
    source_category = _source_category_from_mapping(mapping)

    detection = sigma_rule.get("detection", {})
    if not detection or "condition" not in detection:
        raise SigmaConvertError("no_detection")

    condition_raw = detection.get("condition", "")
    condition_str = condition_raw if isinstance(condition_raw, str) else " ".join(condition_raw)
    if any(tok in f" {condition_str.lower()} " for tok in _AGG_TOKENS):
        raise SigmaConvertError("unsupported_condition", condition_str)

    tactic, base_ids, full_ids = _extract_tags(sigma_rule)
    mitre_ids = full_ids or base_ids
    sigma_level = sigma_rule.get("level", "medium")
    wazuh_level = SIGMA_LEVEL_MAP.get(sigma_level, 8)
    title = sigma_rule.get("title", "Unknown Sigma rule")
    sigma_id = sigma_rule.get("id", "")

    selections, condition = _parse_selections(detection)
    rule_specs = _resolve_condition(condition, selections)

    if not rule_specs:
        raise SigmaConvertError("empty_rule_spec", condition_str)

    rules = []
    for spec_group in rule_specs:
        combined_fields = {}
        for field_dict in spec_group:
            combined_fields.update(field_dict)

        clean_fields = {}
        for k, v in combined_fields.items():
            real_key = k.split("#")[0]
            if real_key in clean_fields:
                clean_fields[real_key] = clean_fields[real_key] + "|" + v
            else:
                clean_fields[real_key] = v

        clean_fields = {k: v for k, v in clean_fields.items() if k != "_raw"}
        if not clean_fields:
            continue

        rule_id = allocate_id(tactic)

        rule_elem = etree.Element("rule", id=str(rule_id), level=str(wazuh_level))

        if_sid = etree.SubElement(rule_elem, "if_sid")
        if_sid.text = str(parent_sid)

        for field_name, pattern in clean_fields.items():
            field_elem = etree.SubElement(rule_elem, "field", name=field_name)
            field_elem.text = pattern

        desc = etree.SubElement(rule_elem, "description")
        desc.text = f"Sigma: {title}"

        if mitre_ids:
            mitre_elem = etree.SubElement(rule_elem, "mitre")
            for mid in mitre_ids[:3]:
                id_elem = etree.SubElement(mitre_elem, "id")
                id_elem.text = mid

        group = etree.SubElement(rule_elem, "group")
        group.text = f"{tactic},sigma_converted,"

        rules.append({
            "id": rule_id,
            "level": wazuh_level,
            "xml_element": rule_elem,
            "metadata": {
                "rule_id": rule_id,
                "tactic": tactic,
                "technique_name": title,
                "source_evtx": sigma_rule.get("_file_path", ""),
                "source_category": source_category,
                "parent_sid": parent_sid,
                "confidence": "high" if sigma_level in ("critical", "high") else "medium",
                "created": "",
                "field_matches": clean_fields,
                "mitre_ids": mitre_ids[:3],
                "sigma_id": sigma_id,
                "sigma_level": sigma_level,
            },
            "pattern": None,
        })

    if not rules:
        raise SigmaConvertError("empty_rule_spec", "no fields after cleaning")

    return rules


SIGMA_LEVEL_ORDER = ["informational", "low", "medium", "high", "critical"]


CONVERSION_ERRORS_FILE = (
    Path(__file__).resolve().parent.parent / "database" / "metadata" / "sigma_conversion_errors.json"
)


def convert_all(
    rules_dir: Path,
    category: str | None = None,
    min_level: str = "low",
    max_rules: int | None = None,
    write_error_report: bool = True,
) -> list[dict]:
    """Convert all Sigma rules from a directory to Wazuh rules.

    Conversion failures are categorized (unmapped_logsource, no_detection,
    unsupported_condition, empty_rule_spec, parse_error, unexpected) and
    summarized so the skipped rules are explainable rather than opaque.
    """
    yml_files = sorted(rules_dir.rglob("*.yml"))
    console.print(f"[bold]Scanning {len(yml_files)} Sigma rule files...[/]")

    min_idx = SIGMA_LEVEL_ORDER.index(min_level) if min_level in SIGMA_LEVEL_ORDER else 0

    all_rules = []
    converted = 0
    below_level = 0
    error_counts: dict[str, int] = {}
    error_records: list[dict] = []

    for f in yml_files:
        if category:
            if f"/{category}/" not in str(f) and f"\\{category}\\" not in str(f):
                continue

        sigma_rule = parse_sigma_rule(f)
        if not sigma_rule:
            error_counts["parse_error"] = error_counts.get("parse_error", 0) + 1
            error_records.append({"file": str(f), "category": "parse_error", "message": ""})
            continue

        rule_level = sigma_rule.get("level", "medium")
        level_idx = SIGMA_LEVEL_ORDER.index(rule_level) if rule_level in SIGMA_LEVEL_ORDER else 2
        if level_idx < min_idx:
            below_level += 1
            continue

        try:
            wazuh_rules = convert_sigma_rule(sigma_rule)
            all_rules.extend(wazuh_rules)
            converted += 1
        except SigmaConvertError as e:
            error_counts[e.category] = error_counts.get(e.category, 0) + 1
            error_records.append({
                "file": str(f), "sigma_id": sigma_rule.get("id", ""),
                "category": e.category, "message": str(e),
            })
        except Exception as e:  # noqa: BLE001 - categorized as unexpected
            error_counts["unexpected"] = error_counts.get("unexpected", 0) + 1
            error_records.append({
                "file": str(f), "sigma_id": sigma_rule.get("id", ""),
                "category": "unexpected", "message": f"{type(e).__name__}: {e}",
            })

        if max_rules and len(all_rules) >= max_rules:
            break

    console.print(f"[green]Converted {converted} Sigma rules → {len(all_rules)} Wazuh rules[/]")
    if below_level:
        console.print(f"[dim]Below min-level '{min_level}': {below_level}[/]")
    total_errors = sum(error_counts.values())
    if total_errors:
        console.print(f"[yellow]Not converted: {total_errors}[/]")
        for cat in sorted(error_counts, key=lambda c: -error_counts[c]):
            console.print(f"  [dim]{cat}: {error_counts[cat]}[/]")

    if write_error_report and error_records:
        CONVERSION_ERRORS_FILE.parent.mkdir(parents=True, exist_ok=True)
        with open(CONVERSION_ERRORS_FILE, "w") as fh:
            json.dump({"summary": error_counts, "records": error_records}, fh, indent=2)
        console.print(f"[dim]Error report: {CONVERSION_ERRORS_FILE}[/]")

    return all_rules
