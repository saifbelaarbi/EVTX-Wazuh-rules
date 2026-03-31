"""Build Wazuh XML rules from detection patterns."""

from lxml import etree
from datetime import date

from .event_analyzer import DetectionPattern
from .id_manager import allocate_id

# Map Sysmon Event IDs to Wazuh parent SIDs
PARENT_SID_MAP = {
    # Sysmon events
    (1, "Microsoft-Windows-Sysmon"): 61600,   # Process Create
    (2, "Microsoft-Windows-Sysmon"): 61601,   # File Create Time
    (3, "Microsoft-Windows-Sysmon"): 61603,   # Network Connect
    (5, "Microsoft-Windows-Sysmon"): 61604,   # Process Terminate
    (6, "Microsoft-Windows-Sysmon"): 61605,   # Driver Load
    (7, "Microsoft-Windows-Sysmon"): 61606,   # Image Load
    (8, "Microsoft-Windows-Sysmon"): 61607,   # CreateRemoteThread
    (10, "Microsoft-Windows-Sysmon"): 61609,  # Process Access
    (11, "Microsoft-Windows-Sysmon"): 61610,  # File Create
    (12, "Microsoft-Windows-Sysmon"): 61612,  # Registry Create/Delete
    (13, "Microsoft-Windows-Sysmon"): 61613,  # Registry Value Set
    (14, "Microsoft-Windows-Sysmon"): 61614,  # Registry Rename
    (15, "Microsoft-Windows-Sysmon"): 61615,  # File Stream Create
    (17, "Microsoft-Windows-Sysmon"): 61617,  # Pipe Created
    (18, "Microsoft-Windows-Sysmon"): 61618,  # Pipe Connected
    (22, "Microsoft-Windows-Sysmon"): 61625,  # DNS Query
    (23, "Microsoft-Windows-Sysmon"): 61626,  # File Delete
    (25, "Microsoft-Windows-Sysmon"): 61628,  # Process Tampering
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

    # Field matches
    for field_name, value in pattern.field_matches.items():
        field_elem = etree.SubElement(rule_elem, "field", name=field_name)
        # Use regex-safe matching
        field_elem.text = value

    # Description
    desc = etree.SubElement(rule_elem, "description")
    desc.text = pattern.description

    # MITRE ATT&CK mapping
    if pattern.mitre_ids or pattern.tactic:
        mitre = etree.SubElement(rule_elem, "mitre")
        mitre_ids = pattern.mitre_ids or TACTIC_TECHNIQUES.get(pattern.tactic, [])[:1]
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
        "field_matches": pattern.field_matches,
        "mitre_ids": pattern.mitre_ids or TACTIC_TECHNIQUES.get(pattern.tactic, [])[:1],
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
