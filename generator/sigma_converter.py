"""Convert SigmaHQ Sigma rules to Wazuh XML rule format."""

import json
import re
from pathlib import Path

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
    if channel in ("powershell", "security", "system", "sysmon", "linux", "cloud"):
        return channel
    if channel in ("application", "windefend", "firewall"):
        return "application"
    return "other"


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

# OSRegex chars to backslash-escape for literal matching. Wazuh OSRegex accepts
# only a small set of escapes: the classes (\w \d \s \t \p \b ...), the any-char
# \., the literals \( \) \$, and \\. Escaping anything else (\+ \* \{ \^ \| \? …)
# is an INVALID sequence that Wazuh rejects with error 5107 ("Syntax error on
# tag"), CRITICAL — it aborts loading the whole rule file. Verified against
# Wazuh's default ruleset, which only ever escapes ``. ( ) $``. So escape just
# ``( ) $`` here (backslash is handled separately); ^ | + * etc. stay literal.
OS_REGEX_SPECIAL = r"()$"


def _escape_osregex(value: str) -> str:
    """Escape special chars for Wazuh OS regex.

    In Wazuh OSRegex: ``.`` = literal dot, ``\\.`` = any character.
    Only backslash-expressions carry metacharacter meaning, so a literal
    dot must NOT be escaped. We do need to escape ``\\`` → ``\\\\``.
    """
    result = []
    for ch in value:
        if ch == "\\":
            result.append("\\\\")
        elif ch in OS_REGEX_SPECIAL:
            result.append("\\" + ch)
        else:
            result.append(ch)
    return "".join(result)


# Linux / cloud Sigma field names → Wazuh decoded field paths.
LINUX_CLOUD_FIELD_MAP = {
    # Linux auditd / syslog (Wazuh audit + syslog decoders)
    "exe": "data.audit.exe",
    "comm": "data.audit.command",
    "syscall": "data.audit.syscall",
    "a0": "data.audit.execve.a0",
    "a1": "data.audit.execve.a1",
    "key": "data.audit.key",
    "uid": "data.audit.uid",
    "auid": "data.audit.auid",
    "CommandLine": "data.audit.execve.command",
    "Image": "data.audit.exe",
    "User": "data.audit.uid",
    # Cloud (AWS / Azure / GCP / Okta via Wazuh integrations)
    "eventName": "data.aws.eventName",
    "eventSource": "data.aws.eventSource",
    "sourceIPAddress": "data.aws.sourceIPAddress",
    "userIdentity.type": "data.aws.userIdentity.type",
    "errorCode": "data.aws.errorCode",
    "operationName": "data.azure.operationName",
    "ResultType": "data.azure.resultType",
    "OperationName": "data.azure.OperationName",
    "properties.message": "data.azure.properties.message",
    "methodName": "data.gcp.protoPayload.methodName",
    "displayMessage": "data.okta.displayMessage",
    "eventtype": "data.okta.eventType",
}


# Conversion-time channel context. Set per rule in convert_sigma_rule so the
# field resolver can pick Windows vs Linux/cloud field paths without threading
# the channel through every _resolve_condition / _selection helper. Conversion
# is single-threaded per call, so a module-level value is safe here.
_ACTIVE_CHANNEL = ""


def _resolve_field(sigma_field: str, channel: str | None = None) -> str | None:
    """Map a Sigma field name to a Wazuh field path.

    ``channel`` ("linux"/"cloud") selects non-Windows decoded field paths so
    converted Linux/cloud rules reference real Wazuh fields instead of
    ``win.eventdata.*``. Defaults to the active conversion channel.
    """
    if channel is None:
        channel = _ACTIVE_CHANNEL
    if channel in ("linux", "cloud"):
        if sigma_field in LINUX_CLOUD_FIELD_MAP:
            return LINUX_CLOUD_FIELD_MAP[sigma_field]
        lower = sigma_field[0].lower() + sigma_field[1:] if sigma_field else sigma_field
        return f"data.{lower}"
    if sigma_field in SIGMA_FIELD_TO_WAZUH_EXTENDED:
        return SIGMA_FIELD_TO_WAZUH_EXTENDED[sigma_field]
    lower = sigma_field[0].lower() + sigma_field[1:] if sigma_field else sigma_field
    return f"win.eventdata.{lower}"


def _escape_osregex_with_globs(value: str) -> str:
    """Escape regex metacharacters but translate Sigma globs to OS-regex.

    In Wazuh OSRegex ``\\.`` means *any character* and ``.`` is a literal dot.
    Sigma ``*`` → ``\\.*`` (zero-or-more of any char), ``?`` → ``\\.``
    (single any char). Backslashes are doubled. Other OS_REGEX_SPECIAL chars
    are escaped with a leading backslash.
    """
    out = []
    i = 0
    while i < len(value):
        ch = value[i]
        if ch == "*":
            out.append("\\.*")
        elif ch == "?":
            out.append("\\.")
        elif ch == "\\":
            out.append("\\\\")
        elif ch in OS_REGEX_SPECIAL:
            out.append("\\" + ch)
        else:
            out.append(ch)
        i += 1
    return "".join(out)


def _cidr_to_regex(cidr: str) -> str:
    """Best-effort CIDR -> Wazuh OS-regex prefix match (IPv4).

    Wazuh <field> cannot do true CIDR maths, so we anchor on the network
    portion implied by the prefix length (/8, /16, /24). Other prefixes fall
    back to matching the leading octets present before the mask.
    """
    try:
        net, bits = cidr.split("/")
        bits = int(bits)
        octets = net.split(".")
    except (ValueError, IndexError):
        return _escape_osregex_with_globs(cidr)
    keep = {8: 1, 16: 2, 24: 3, 32: 4}.get(bits, max(1, bits // 8))
    prefix = ".".join(octets[:keep])
    if bits == 32:
        return "^" + net + "$"
    return "^" + prefix + "."


def _base64_variants(value: str, utf16: bool = False) -> list[str]:
    """Return the 3 base64offset encodings of a value (optionally UTF-16LE)."""
    import base64

    raw = value.encode("utf-16-le") if utf16 else value.encode()
    variants = []
    for off in range(3):
        encoded = base64.b64encode(b"\x00" * off + raw).decode()
        # Trim the bytes affected by the offset padding, like Sigma does.
        start = (off * 8 + 5) // 6 if off else 0
        end = len(encoded) - (len(encoded) % 4 if off else 0)
        variants.append(encoded[start:end].rstrip("="))
    return [v for v in dict.fromkeys(variants) if v]


def _apply_modifiers(value: str, modifiers: list[str]) -> str:
    """Convert a Sigma value + modifiers to a Wazuh OS regex pattern.

    Supports the SigmaHQ modifier set: contains/startswith/endswith, re, cidr,
    windash, base64/base64offset (+wide/utf16le), and numeric lt/lte/gt/gte
    (best-effort, since Wazuh <field> regex cannot express true inequalities).
    """
    # `re` values are raw regex; pass through untouched.
    if "re" in modifiers:
        return value

    if "cidr" in modifiers:
        return _cidr_to_regex(value)

    # base64 family: match the encoded form(s) as an unanchored alternation.
    if "base64offset" in modifiers or "base64" in modifiers:
        utf16 = any(m in modifiers for m in ("wide", "utf16", "utf16le"))
        variants = _base64_variants(value, utf16=utf16)
        if variants:
            return "|".join(_escape_osregex_with_globs(v) for v in variants)

    escaped = _escape_osregex_with_globs(value)

    # Numeric comparators: Wazuh can't do inequalities in <field>; match the
    # literal threshold so the rule is at least anchored on the boundary value.
    if any(m in modifiers for m in ("lt", "lte", "gt", "gte")):
        return escaped

    if "windash" in modifiers:
        # Match Windows flag variants: - / and the unicode dashes – —.
        if escaped.startswith("-") or escaped.startswith("\\-"):
            clean = escaped.lstrip("\\-")
            escaped = "[-/–—]" + clean

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
                # Bare 'keywords' string -> match Wazuh's decoded full_log.
                results.append({"full_log": _escape_osregex_with_globs(str(item))})
        return results

    if not isinstance(selection, dict):
        return []

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

    [k for k in selections if k.startswith("filter")]
    positive_names = [k for k in selections if not k.startswith("filter")]

    if condition == "selection" and "selection" in selections:
        matches = _selection_to_field_matches(selections["selection"])
        if len(matches) == 1:
            return [matches]
        return [[m] for m in matches]

    all_of_match = re.match(r"^all of (selection[_\w]*)\*(.*)$", condition)
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

    one_of_match = re.match(r"^1 of (selection[_\w]*)\*(.*)$", condition)
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

    and_parts = re.split(r"\s+and\s+", condition)
    positive_parts = [p.strip() for p in and_parts if not p.strip().startswith("not ")]

    combined = {}
    for part in positive_parts:
        part = part.strip("() ")

        all_match = re.match(r"^all of (\w+)\*$", part)
        one_match = re.match(r"^1 of (\w+)\*$", part)

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


# Aggregations we still cannot model in Wazuh (statistical reducers / temporal).
_AGG_TOKENS = (
    " near ",
    "| min",
    "|min",
    "| max",
    "|max",
    "| avg",
    "|avg",
    "| sum",
    "|sum",
    " | temporal",
)

# `... | count() > 5` or `... | count(field) by user > 5`
_AGG_COUNT_RE = re.compile(
    r"\|\s*count\(\s*([\w.]*)\s*\)\s*(?:by\s+([\w.]+)\s*)?([<>=]+)\s*(\d+)",
    re.IGNORECASE,
)

DEFAULT_FREQ_TIMEFRAME = 300


def _split_aggregation(condition_str: str):
    """Split a Sigma condition into (base_condition, count_spec).

    count_spec is None when there is no supported aggregation, else a dict with
    keys: count_field, group_field, op, threshold. The base_condition is the
    detection logic before the ``|`` pipe.
    """
    m = _AGG_COUNT_RE.search(condition_str)
    if not m:
        return condition_str, None
    base = condition_str[: condition_str.index("|")].strip()
    count_field, group_field, op, threshold = m.groups()
    return base, {
        "count_field": count_field or "",
        "group_field": group_field or "",
        "op": op,
        "threshold": int(threshold),
    }


def _extract_negation(condition: str, selections: dict) -> list[dict]:
    """Collect field matches of each negated (filter) selection separately.

    Handles ``and not <name>``, ``and not 1 of filter*`` and
    ``and not all of filter*``. Returns a list of field match dicts — one per
    negated clause — so each becomes its own Wazuh suppression child rule.
    Empty list when there is no usable negation.
    """
    neg_groups: list[dict] = []
    for m in re.finditer(r"not\s+(1 of\s+[\w*]+|all of\s+[\w*]+|[\w]+)", condition):
        target = m.group(1).strip()
        of_match = re.match(r"(?:1|all) of\s+([\w]+)\*?", target)
        if of_match:
            prefix = of_match.group(1)
            names = [k for k in selections if k.startswith(prefix)]
        elif target in selections:
            names = [target]
        else:
            names = []
        for name in names:
            for fg in _selection_to_field_matches(selections[name]):
                cleaned = {k.split("#")[0]: v for k, v in fg.items() if k != "_raw"}
                if cleaned:
                    neg_groups.append(cleaned)
    return neg_groups


def convert_sigma_rule(sigma_rule: dict, with_negation: bool = False) -> list[dict]:
    """Convert a parsed Sigma rule to one or more Wazuh rule dicts.

    Raises SigmaConvertError(category) when a rule cannot be converted so the
    batch driver can report *why* each rule was skipped.

    When ``with_negation`` is set, ``and not <filter>`` clauses are emitted as
    Wazuh level-0 suppression child rules instead of being dropped.
    """
    logsource = sigma_rule.get("logsource", {})
    category = logsource.get("category", "")
    service = logsource.get("service", "")
    product = logsource.get("product", "")
    source_key = category or service

    # Product-aware lookup: Linux/cloud Sigma rules qualify the category/service
    # with the product so they resolve to the correct (non-Windows) mapping.
    mapping = None
    if product and product != "windows":
        for candidate in (f"{product}_{category}", f"{product}_{service}", source_key):
            if candidate and candidate in SIGMA_LOGSOURCE_TO_WAZUH:
                mapping = SIGMA_LOGSOURCE_TO_WAZUH[candidate]
                break
    else:
        mapping = SIGMA_LOGSOURCE_TO_WAZUH.get(source_key)
    if not mapping:
        raise SigmaConvertError("unmapped_logsource", source_key or "(none)")

    parent_sid = mapping["parent_sid"]
    source_category = _source_category_from_mapping(mapping)

    global _ACTIVE_CHANNEL
    _ACTIVE_CHANNEL = mapping.get("channel", "")

    detection = sigma_rule.get("detection", {})
    if not detection or "condition" not in detection:
        raise SigmaConvertError("no_detection")

    condition_raw = detection.get("condition", "")
    condition_str = condition_raw if isinstance(condition_raw, str) else " ".join(condition_raw)
    # Reject only the aggregations we still cannot model; count() is handled below.
    if any(tok in f" {condition_str.lower()} " for tok in _AGG_TOKENS):
        raise SigmaConvertError("unsupported_condition", condition_str)

    # Split off a supported count() aggregation, if present.
    base_condition_str, count_spec = _split_aggregation(condition_str)

    tactic, base_ids, full_ids = _extract_tags(sigma_rule)
    mitre_ids = full_ids or base_ids
    sigma_level = sigma_rule.get("level", "medium")
    wazuh_level = SIGMA_LEVEL_MAP.get(sigma_level, 8)
    title = sigma_rule.get("title", "Unknown Sigma rule")
    sigma_id = sigma_rule.get("id", "")

    selections, condition = _parse_selections(detection)
    if count_spec:
        # Re-parse only the base (pre-pipe) condition for the detection rule.
        condition = base_condition_str
    rule_specs = _resolve_condition(condition, selections)

    if not rule_specs:
        raise SigmaConvertError("empty_rule_spec", condition_str)

    negation_groups = _extract_negation(condition, selections) if with_negation else []

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
            if not pattern or not pattern.strip():
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

        rules.append(
            {
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
            }
        )

        # Negation -> one Wazuh level-0 suppression child rule per filter.
        for neg_fields in negation_groups:
            sup_id = allocate_id(tactic)
            sup_elem = etree.Element("rule", id=str(sup_id), level="0")
            sup_if = etree.SubElement(sup_elem, "if_sid")
            sup_if.text = str(rule_id)
            for fname, fpat in neg_fields.items():
                fe = etree.SubElement(sup_elem, "field", name=fname)
                fe.text = fpat
            sup_desc = etree.SubElement(sup_elem, "description")
            sup_desc.text = f"Sigma: {title} (excluded by filter)"
            sup_group = etree.SubElement(sup_elem, "group")
            sup_group.text = f"{tactic},sigma_negation,"
            rules.append(
                {
                    "id": sup_id,
                    "level": 0,
                    "xml_element": sup_elem,
                    "metadata": {
                        "rule_id": sup_id,
                        "tactic": tactic,
                        "technique_name": f"{title} (suppression)",
                        "source_evtx": sigma_rule.get("_file_path", ""),
                        "source_category": source_category,
                        "parent_sid": rule_id,
                        "confidence": "medium",
                        "created": "",
                        "field_matches": neg_fields,
                        "mitre_ids": mitre_ids[:3],
                        "sigma_id": sigma_id,
                        "sigma_level": sigma_level,
                    },
                    "pattern": None,
                }
            )

        # count() aggregation -> Wazuh frequency correlation rule.
        if count_spec and count_spec["threshold"] > 0:
            freq_id = allocate_id(tactic)
            # Wazuh <frequency> fires on the Nth event. Adjust for strict >:
            # count() > 5 needs frequency=6; count() >= 5 needs frequency=5.
            freq_threshold = count_spec["threshold"]
            if count_spec["op"] in (">",):
                freq_threshold += 1
            freq_elem = etree.Element(
                "rule",
                id=str(freq_id),
                level=str(min(wazuh_level + 2, 15)),
                frequency=str(freq_threshold),
                timeframe=str(DEFAULT_FREQ_TIMEFRAME),
            )
            freq_if = etree.SubElement(freq_elem, "if_matched_sid")
            freq_if.text = str(rule_id)
            if count_spec["group_field"]:
                gf = _resolve_field(count_spec["group_field"])
                if gf:
                    sf_elem = etree.SubElement(freq_elem, "same_field")
                    sf_elem.text = gf
            freq_desc = etree.SubElement(freq_elem, "description")
            freq_desc.text = f"Sigma: {title} (>= {freq_threshold} in {DEFAULT_FREQ_TIMEFRAME}s)"
            if mitre_ids:
                fm = etree.SubElement(freq_elem, "mitre")
                for mid in mitre_ids[:3]:
                    ie = etree.SubElement(fm, "id")
                    ie.text = mid
            freq_group = etree.SubElement(freq_elem, "group")
            freq_group.text = f"{tactic},sigma_correlation,"
            rules.append(
                {
                    "id": freq_id,
                    "level": min(wazuh_level + 2, 15),
                    "xml_element": freq_elem,
                    "metadata": {
                        "rule_id": freq_id,
                        "tactic": tactic,
                        "technique_name": f"{title} (frequency)",
                        "source_evtx": sigma_rule.get("_file_path", ""),
                        "source_category": source_category,
                        "parent_sid": rule_id,
                        "confidence": "high",
                        "created": "",
                        "field_matches": clean_fields,
                        "mitre_ids": mitre_ids[:3],
                        "sigma_id": sigma_id,
                        "sigma_level": sigma_level,
                    },
                    "pattern": None,
                }
            )

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
    with_negation: bool = False,
) -> list[dict]:
    """Convert all Sigma rules from a directory to Wazuh rules.

    Conversion failures are categorized (unmapped_logsource, no_detection,
    unsupported_condition, empty_rule_spec, parse_error, unexpected) and
    summarized so the skipped rules are explainable rather than opaque.
    """
    yml_files = sorted(rules_dir.rglob("*.yml")) + sorted(rules_dir.rglob("*.yaml"))
    yml_files += sorted(rules_dir.rglob("*.json"))
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
            wazuh_rules = convert_sigma_rule(sigma_rule, with_negation=with_negation)
            all_rules.extend(wazuh_rules)
            converted += 1
        except SigmaConvertError as e:
            error_counts[e.category] = error_counts.get(e.category, 0) + 1
            error_records.append(
                {
                    "file": str(f),
                    "sigma_id": sigma_rule.get("id", ""),
                    "category": e.category,
                    "message": str(e),
                }
            )
        except Exception as e:  # noqa: BLE001 - categorized as unexpected
            error_counts["unexpected"] = error_counts.get("unexpected", 0) + 1
            error_records.append(
                {
                    "file": str(f),
                    "sigma_id": sigma_rule.get("id", ""),
                    "category": "unexpected",
                    "message": f"{type(e).__name__}: {e}",
                }
            )

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
