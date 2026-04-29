"""Convert SigmaHQ Sigma rules to Wazuh XML rule format."""

import fnmatch
import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml
from lxml import etree
from rich.console import Console

from .id_manager import allocate_id
from .sigma_analyzer import (
    SIGMA_FIELD_TO_WAZUH,
    SIGMA_LOGSOURCE_TO_WAZUH,
    parse_sigma_rule,
)

console = Console()

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


def _apply_modifiers(value: str, modifiers: list[str]) -> str:
    """Convert a Sigma value + modifiers to a Wazuh OS regex pattern."""
    if "re" in modifiers:
        return value

    escaped = _escape_osregex(value)

    if "windash" in modifiers:
        if escaped.startswith("-") or escaped.startswith("\\-"):
            clean = escaped.lstrip("\\-")
            escaped = "[-/]" + clean

    if "endswith" in modifiers:
        return escaped + "$"
    elif "startswith" in modifiers:
        return "^" + escaped
    return escaped


def _parse_field_key(key: str) -> tuple[str, list[str]]:
    """Parse 'FieldName|modifier1|modifier2' into (field, [modifiers])."""
    parts = key.split("|")
    return parts[0], parts[1:]


def _extract_tags(sigma_rule: dict) -> tuple[str, list[str]]:
    """Extract MITRE tactic and technique IDs from Sigma tags."""
    tags = sigma_rule.get("tags", [])
    tactic = ""
    mitre_ids = []

    for tag in tags:
        tag_lower = tag.lower()
        if tag_lower in TACTIC_FROM_TAG and not tactic:
            tactic = TACTIC_FROM_TAG[tag_lower]
        if tag_lower.startswith("attack.t"):
            tid = tag_lower.replace("attack.", "").upper()
            base_tid = tid.split(".")[0]
            mitre_ids.append(base_tid)

    return tactic or "execution", list(dict.fromkeys(mitre_ids))


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


def convert_sigma_rule(sigma_rule: dict) -> list[dict]:
    """Convert a parsed Sigma rule to one or more Wazuh rule dicts."""
    logsource = sigma_rule.get("logsource", {})
    category = logsource.get("category", "")
    service = logsource.get("service", "")
    source_key = category or service

    mapping = SIGMA_LOGSOURCE_TO_WAZUH.get(source_key)
    if not mapping:
        return []

    parent_sid = mapping["parent_sid"]

    detection = sigma_rule.get("detection", {})
    if not detection or "condition" not in detection:
        return []

    tactic, mitre_ids = _extract_tags(sigma_rule)
    sigma_level = sigma_rule.get("level", "medium")
    wazuh_level = SIGMA_LEVEL_MAP.get(sigma_level, 8)
    title = sigma_rule.get("title", "Unknown Sigma rule")
    sigma_id = sigma_rule.get("id", "")

    selections, condition = _parse_selections(detection)
    rule_specs = _resolve_condition(condition, selections)

    if not rule_specs:
        return []

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

        if not clean_fields:
            continue

        rule_id = allocate_id(tactic)

        rule_elem = etree.Element("rule", id=str(rule_id), level=str(wazuh_level))

        if_sid = etree.SubElement(rule_elem, "if_sid")
        if_sid.text = str(parent_sid)

        for field_name, pattern in clean_fields.items():
            if field_name == "_raw":
                continue
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

    return rules


SIGMA_LEVEL_ORDER = ["informational", "low", "medium", "high", "critical"]


def convert_all(
    rules_dir: Path,
    category: str | None = None,
    min_level: str = "low",
    max_rules: int | None = None,
) -> list[dict]:
    """Convert all Sigma rules from a directory to Wazuh rules."""
    yml_files = sorted(rules_dir.rglob("*.yml"))
    console.print(f"[bold]Scanning {len(yml_files)} Sigma rule files...[/]")

    min_idx = SIGMA_LEVEL_ORDER.index(min_level) if min_level in SIGMA_LEVEL_ORDER else 0

    all_rules = []
    converted = 0
    skipped = 0
    errors = 0

    for f in yml_files:
        if category:
            if f"/{category}/" not in str(f) and f"\\{category}\\" not in str(f):
                continue

        sigma_rule = parse_sigma_rule(f)
        if not sigma_rule:
            continue

        rule_level = sigma_rule.get("level", "medium")
        level_idx = SIGMA_LEVEL_ORDER.index(rule_level) if rule_level in SIGMA_LEVEL_ORDER else 2
        if level_idx < min_idx:
            skipped += 1
            continue

        try:
            wazuh_rules = convert_sigma_rule(sigma_rule)
            if wazuh_rules:
                all_rules.extend(wazuh_rules)
                converted += 1
            else:
                skipped += 1
        except Exception:
            errors += 1

        if max_rules and len(all_rules) >= max_rules:
            break

    console.print(f"[green]Converted {converted} Sigma rules → {len(all_rules)} Wazuh rules[/]")
    if skipped:
        console.print(f"[yellow]Skipped: {skipped}[/]")
    if errors:
        console.print(f"[red]Errors: {errors}[/]")

    return all_rules
