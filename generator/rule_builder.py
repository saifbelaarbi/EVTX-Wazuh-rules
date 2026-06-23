"""Build Wazuh XML rules from detection patterns."""

import re
from datetime import date

from lxml import etree

from . import mitre_mapper
from .event_analyzer import DetectionPattern
from .id_manager import allocate_id

# OSRegex metacharacters needing escape for literal matching.
# In Wazuh OSRegex ``.`` is literal — do NOT escape it (``\\.`` = any char).
# ``{ } [ ] ?`` are also literal in OSRegex; escaping them yields an invalid
# sequence (e.g. ``\{``) that Wazuh rejects with error 5107 (CRITICAL, aborts
# the whole rule file). Only ``^ $ * + ( ) |`` and ``\`` are real metachars.
_OSREGEX_META = re.compile(r"([\^$*+()|\\])")

# System fields always retained in a minimized sample event.
_SAMPLE_SYSTEM_FIELDS = (
    "event_id",
    "channel",
    "provider_name",
    "computer",
    "timestamp",
)


def _to_osregex(value: str) -> str:
    """Escape an indicator string so it matches literally in a Wazuh <field>."""
    return _OSREGEX_META.sub(r"\\\1", value)


def _minimize_event(event: dict, field_matches: dict) -> dict:
    """Keep system fields + only the eventdata keys referenced by a rule.

    Bounds the size of the persisted sample event while preserving everything
    needed to validate the rule against its own trigger.
    """
    if not isinstance(event, dict):
        return {}
    minimal = {k: event.get(k) for k in _SAMPLE_SYSTEM_FIELDS if event.get(k) is not None}

    referenced = set()
    for key in field_matches:
        if key.startswith("win.eventdata."):
            referenced.add(key[len("win.eventdata.") :].lower())

    src_data = event.get("event_data", {})
    if isinstance(src_data, dict) and referenced:
        kept = {}
        for k, v in src_data.items():
            camel = (k[0].lower() + k[1:]) if k else k
            if camel.lower() in referenced or k.lower() in referenced:
                kept[k] = v
        minimal["event_data"] = kept
    else:
        minimal["event_data"] = {}
    return minimal


# Map Sysmon Event IDs to Wazuh parent SIDs (from 0595-win-sysmon_rules.xml)
PARENT_SID_MAP = {
    (1, "Microsoft-Windows-Sysmon"): 61603,  # Process Create
    (2, "Microsoft-Windows-Sysmon"): 61604,  # File Create Time
    (3, "Microsoft-Windows-Sysmon"): 61605,  # Network Connect
    (4, "Microsoft-Windows-Sysmon"): 61606,  # Sysmon Service State
    (5, "Microsoft-Windows-Sysmon"): 61607,  # Process Terminate
    (6, "Microsoft-Windows-Sysmon"): 61608,  # Driver Load
    (7, "Microsoft-Windows-Sysmon"): 61609,  # Image Load
    (8, "Microsoft-Windows-Sysmon"): 61610,  # CreateRemoteThread
    (9, "Microsoft-Windows-Sysmon"): 61611,  # RawAccessRead
    (10, "Microsoft-Windows-Sysmon"): 61612,  # Process Access
    (11, "Microsoft-Windows-Sysmon"): 61613,  # File Create
    (12, "Microsoft-Windows-Sysmon"): 61614,  # Registry Create/Delete
    (13, "Microsoft-Windows-Sysmon"): 61615,  # Registry Value Set
    (14, "Microsoft-Windows-Sysmon"): 61616,  # Registry Rename
    (15, "Microsoft-Windows-Sysmon"): 61617,  # File Stream Create
    (17, "Microsoft-Windows-Sysmon"): 61619,  # Pipe Created
    (18, "Microsoft-Windows-Sysmon"): 61620,  # Pipe Connected
    (19, "Microsoft-Windows-Sysmon"): 61621,  # WMI Event Filter
    (20, "Microsoft-Windows-Sysmon"): 61622,  # WMI Event Consumer
    (21, "Microsoft-Windows-Sysmon"): 61623,  # WMI Consumer Binding
    (22, "Microsoft-Windows-Sysmon"): 61624,  # DNS Query
    (23, "Microsoft-Windows-Sysmon"): 61625,  # File Delete
    (25, "Microsoft-Windows-Sysmon"): 61627,  # Process Tampering
}

# Generic parent SIDs for non-Sysmon events
CHANNEL_PARENT_SID = {
    "Security": 60100,
    "System": 60106,
    "Microsoft-Windows-PowerShell/Operational": 91801,
    "Windows PowerShell": 91801,
}

# Tactic -> MITRE technique suggestions
TACTIC_TECHNIQUES = {
    "credential_access": ["T1003", "T1110", "T1558"],
    "execution": ["T1059", "T1204", "T1569"],
    "persistence": ["T1547", "T1053", "T1543"],
    "privilege_escalation": ["T1548", "T1134", "T1068"],
    "defense_evasion": ["T1055", "T1027", "T1070"],
    "lateral_movement": ["T1021", "T1570", "T1080"],
    "discovery": ["T1087", "T1082", "T1083"],
    "command_and_control": ["T1071", "T1573", "T1105"],
    "initial_access": ["T1566", "T1190", "T1078"],
    "exfiltration": ["T1041", "T1048", "T1567"],
    "impact": ["T1485", "T1486", "T1489"],
    "collection": ["T1005", "T1039", "T1074"],
}


def _source_category_for(pattern: DetectionPattern) -> str:
    """Classify a pattern into a by_source view category."""
    provider = (pattern.provider_name or "").lower()
    channel = (pattern.channel or "").lower()
    if "sysmon" in provider or "sysmon" in channel:
        return "sysmon"
    if "powershell" in provider or "powershell" in channel:
        return "powershell"
    if "security-auditing" in provider or "security" in channel:
        return "security"
    if "service control manager" in provider or "system" in channel:
        return "system"
    return "other"


def _resolve_parent_sid(pattern: DetectionPattern) -> int:
    """Determine the correct Wazuh parent SID for a detection pattern."""
    # Try Sysmon-specific mapping
    key = (pattern.event_id, pattern.provider_name)
    if key in PARENT_SID_MAP:
        return PARENT_SID_MAP[key]

    # Try partial provider match for Sysmon
    for (eid, prov), sid in PARENT_SID_MAP.items():
        if eid == pattern.event_id and "Sysmon" in pattern.provider_name and "Sysmon" in prov:
            return sid

    # Try channel-based mapping
    for channel_prefix, sid in CHANNEL_PARENT_SID.items():
        if channel_prefix.lower() in pattern.channel.lower():
            return sid

    # Fallback to generic EventChannel
    return 60000


def build_rule(pattern: DetectionPattern) -> dict:
    """Build a Wazuh rule dict from a detection pattern.

    Returns a dict with keys: id, level, xml_element, metadata
    """
    rule_id = allocate_id(pattern.tactic or "composite")
    parent_sid = _resolve_parent_sid(pattern)

    # Build the XML rule element
    rule_elem = etree.Element("rule", id=str(rule_id), level="0")  # level set by alert_leveler

    # Parent rule reference
    if_sid = etree.SubElement(rule_elem, "if_sid")
    if_sid.text = str(parent_sid)

    # Field matches (indicator strings are escaped to literal OS-regex).
    # The escaped form is stored in metadata too so rule_index.json mirrors
    # the deployed XML — the logtest simulator and sigma_exporter both
    # interpret metadata field_matches as OSRegex.
    osregex_fields = {name: _to_osregex(str(value)) for name, value in pattern.field_matches.items()}
    for field_name, value in osregex_fields.items():
        if not value or not value.strip():
            continue
        field_elem = etree.SubElement(rule_elem, "field", name=field_name)
        field_elem.text = value

    # Description
    desc = etree.SubElement(rule_elem, "description")
    desc.text = pattern.description

    # MITRE ATT&CK mapping — semantic, never a tactic default
    mitre_ids = pattern.mitre_ids
    if not mitre_ids:
        mapped = mitre_mapper.classify_for_pattern(pattern)
        mitre_ids = [mapped.technique_id] if mapped.technique_id else []
    if mitre_ids:
        mitre = etree.SubElement(rule_elem, "mitre")
        for mid in mitre_ids:
            id_elem = etree.SubElement(mitre, "id")
            id_elem.text = mid

    # Group tags
    group = etree.SubElement(rule_elem, "group")
    groups = [pattern.tactic] if pattern.tactic else []
    groups.append("evtx_generated")
    group.text = ",".join(groups) + ","

    metadata = {
        "rule_id": rule_id,
        "tactic": pattern.tactic,
        "technique_name": pattern.technique_name,
        "source_evtx": pattern.source_evtx,
        "parent_sid": parent_sid,
        "confidence": pattern.confidence,
        "created": date.today().isoformat(),
        "field_matches": osregex_fields,
        "mitre_ids": mitre_ids,
        "source_category": _source_category_for(pattern),
        "sample_event": _minimize_event(pattern.sample_event, pattern.field_matches),
    }

    return {
        "id": rule_id,
        "level": 0,  # Set by alert_leveler
        "xml_element": rule_elem,
        "metadata": metadata,
        "pattern": pattern,
    }


def build_rules(patterns: list[DetectionPattern]) -> list[dict]:
    """Build Wazuh rules from a list of detection patterns."""
    rules = []
    for pattern in patterns:
        rule = build_rule(pattern)
        rules.append(rule)
    return rules
