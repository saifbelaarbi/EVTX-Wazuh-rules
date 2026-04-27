"""Analyze parsed events to extract detection-worthy patterns."""

from dataclasses import dataclass, field
from pathlib import Path

from rich.console import Console

console = Console()

# MITRE ATT&CK tactic normalization
TACTIC_ALIASES = {
    "command and control": "command_and_control",
    "command_and_control": "command_and_control",
    "credential access": "credential_access",
    "credential_access": "credential_access",
    "defense evasion": "defense_evasion",
    "defense_evasion": "defense_evasion",
    "discovery": "discovery",
    "execution": "execution",
    "exfiltration": "exfiltration",
    "impact": "impact",
    "initial access": "initial_access",
    "initial_access": "initial_access",
    "lateral movement": "lateral_movement",
    "lateral_movement": "lateral_movement",
    "persistence": "persistence",
    "privilege escalation": "privilege_escalation",
    "privilege_escalation": "privilege_escalation",
    "collection": "collection",
    "other": "execution",  # Default fallback
}

# Sysmon Event ID meanings
SYSMON_EVENT_IDS = {
    1: "ProcessCreate",
    2: "FileCreateTime",
    3: "NetworkConnect",
    5: "ProcessTerminate",
    6: "DriverLoad",
    7: "ImageLoad",
    8: "CreateRemoteThread",
    10: "ProcessAccess",
    11: "FileCreate",
    12: "RegistryEvent_CreateDelete",
    13: "RegistryEvent_ValueSet",
    14: "RegistryEvent_Rename",
    15: "FileCreateStreamHash",
    17: "PipeEvent_Created",
    18: "PipeEvent_Connected",
    22: "DNSQuery",
    23: "FileDelete",
    25: "ProcessTampering",
    26: "FileDeleteDetected",
}

# Known suspicious indicators for pattern matching
SUSPICIOUS_PROCESSES = {
    "mimikatz", "psexec", "psexesvc", "cobalt", "beacon",
    "meterpreter", "empire", "bloodhound", "sharphound",
    "rubeus", "kekeo", "lazagne", "procdump", "nanodump",
    "secretsdump", "pypykatz", "safetykatz", "sharpkatz",
    "crackmapexec", "impacket", "wmiexec", "smbexec",
    "dcomexec", "atexec", "winpeas", "linpeas", "seatbelt",
    "certutil", "bitsadmin", "mshta", "regsvr32", "rundll32",
    "wmic", "cmstp", "msiexec", "installutil",
}

SUSPICIOUS_CMD_PATTERNS = [
    "invoke-mimikatz", "invoke-expression", "downloadstring",
    "invoke-webrequest", "net user", "net localgroup",
    "whoami /priv", "cmdkey /list", "reg save",
    "sekurlsa::", "lsadump::", "kerberos::",
    "vssadmin delete shadows", "wbadmin delete",
    "bcdedit /set", "powershell -enc", "powershell -e ",
    "iex(", "bypass", "-nop ", "-w hidden",
    "add-mppreference -exclusionpath",
    "set-mppreference -disablerealtimemonitoring",
]


@dataclass
class DetectionPattern:
    """A detection-worthy pattern extracted from EVTX events."""
    event_id: int
    channel: str
    provider_name: str
    field_matches: dict = field(default_factory=dict)
    mitre_ids: list = field(default_factory=list)
    tactic: str = ""
    technique_name: str = ""
    description: str = ""
    source_evtx: str = ""
    confidence: str = "medium"  # low, medium, high
    sample_event: dict = field(default_factory=dict)


def infer_tactic_from_path(file_path: str) -> str:
    """Infer MITRE tactic from the EVTX file's directory path."""
    path_lower = file_path.lower().replace("\\", "/")
    for alias, normalized in TACTIC_ALIASES.items():
        if alias.replace("_", " ") in path_lower or alias in path_lower:
            return normalized
    return ""


def analyze_event(event: dict, source_path: str = "") -> list[DetectionPattern]:
    """Analyze a single event and extract detection patterns."""
    patterns = []
    event_id = event.get("event_id", 0)
    channel = event.get("channel", "")
    provider = event.get("provider_name", "")
    event_data = event.get("event_data", {})

    # Infer tactic from source path
    tactic = infer_tactic_from_path(source_path or event.get("_source_file", ""))

    # === Sysmon Process Create (Event ID 1) ===
    if event_id == 1 and "Microsoft-Windows-Sysmon" in provider:
        image = event_data.get("Image", "").lower()
        cmdline = event_data.get("CommandLine", "").lower()
        parent = event_data.get("ParentImage", "").lower()

        # Check for known suspicious processes
        for proc in SUSPICIOUS_PROCESSES:
            if proc in image or proc in cmdline:
                patterns.append(DetectionPattern(
                    event_id=event_id,
                    channel=channel,
                    provider_name=provider,
                    field_matches={"win.eventdata.image": proc},
                    tactic=tactic or "execution",
                    technique_name=f"Suspicious process: {proc}",
                    description=f"Suspicious process '{proc}' execution detected",
                    source_evtx=source_path,
                    confidence="high",
                    sample_event=event,
                ))

        # Check for suspicious command-line patterns
        for pattern in SUSPICIOUS_CMD_PATTERNS:
            if pattern in cmdline:
                patterns.append(DetectionPattern(
                    event_id=event_id,
                    channel=channel,
                    provider_name=provider,
                    field_matches={"win.eventdata.commandLine": pattern},
                    tactic=tactic or "execution",
                    technique_name=f"Suspicious command: {pattern}",
                    description=f"Suspicious command-line pattern '{pattern}' detected",
                    source_evtx=source_path,
                    confidence="medium",
                    sample_event=event,
                ))

    # === Sysmon Network Connection (Event ID 3) ===
    elif event_id == 3 and "Sysmon" in provider:
        image = event_data.get("Image", "").lower()
        dest_port = event_data.get("DestinationPort", "")
        for proc in SUSPICIOUS_PROCESSES:
            if proc in image:
                patterns.append(DetectionPattern(
                    event_id=event_id,
                    channel=channel,
                    provider_name=provider,
                    field_matches={
                        "win.eventdata.image": proc,
                        "win.eventdata.destinationPort": dest_port,
                    },
                    tactic=tactic or "command_and_control",
                    technique_name=f"Network connection by {proc}",
                    description=f"Suspicious network connection from '{proc}'",
                    source_evtx=source_path,
                    confidence="high",
                    sample_event=event,
                ))

    # === Sysmon CreateRemoteThread (Event ID 8) ===
    elif event_id == 8 and "Sysmon" in provider:
        source_image = event_data.get("SourceImage", "").lower()
        target_image = event_data.get("TargetImage", "").lower()
        if "lsass" in target_image:
            patterns.append(DetectionPattern(
                event_id=event_id,
                channel=channel,
                provider_name=provider,
                field_matches={
                    "win.eventdata.targetImage": "lsass",
                },
                tactic="credential_access",
                technique_name="Remote thread injection into LSASS",
                description="Remote thread created targeting LSASS process - possible credential dumping",
                source_evtx=source_path,
                confidence="high",
                sample_event=event,
            ))

    # === Sysmon Process Access (Event ID 10) ===
    elif event_id == 10 and "Sysmon" in provider:
        target_image = event_data.get("TargetImage", "").lower()
        granted_access = event_data.get("GrantedAccess", "")
        if "lsass" in target_image and granted_access:
            patterns.append(DetectionPattern(
                event_id=event_id,
                channel=channel,
                provider_name=provider,
                field_matches={
                    "win.eventdata.targetImage": "lsass",
                    "win.eventdata.grantedAccess": granted_access,
                },
                tactic="credential_access",
                technique_name="LSASS memory access",
                description=f"Process accessed LSASS with access mask {granted_access}",
                source_evtx=source_path,
                confidence="high",
                sample_event=event,
            ))

    # === Sysmon Registry Events (Event ID 12, 13, 14) ===
    elif event_id in (12, 13, 14) and "Sysmon" in provider:
        target_object = event_data.get("TargetObject", "").lower()
        persistence_keys = [
            "currentversion\\run", "currentversion\\runonce",
            "winlogon\\", "userinit", "shell",
            "currentversion\\explorer\\shell",
        ]
        for key in persistence_keys:
            if key in target_object:
                patterns.append(DetectionPattern(
                    event_id=event_id,
                    channel=channel,
                    provider_name=provider,
                    field_matches={"win.eventdata.targetObject": key},
                    tactic="persistence",
                    technique_name=f"Registry persistence via {key}",
                    description=f"Registry modification in persistence key: {key}",
                    source_evtx=source_path,
                    confidence="medium",
                    sample_event=event,
                ))

    # === Sysmon DNS Query (Event ID 22) ===
    elif event_id == 22 and "Sysmon" in provider:
        query_name = event_data.get("QueryName", "").lower()
        image = event_data.get("Image", "").lower()
        for proc in SUSPICIOUS_PROCESSES:
            if proc in image:
                patterns.append(DetectionPattern(
                    event_id=event_id,
                    channel=channel,
                    provider_name=provider,
                    field_matches={
                        "win.eventdata.image": proc,
                        "win.eventdata.queryName": query_name,
                    },
                    tactic=tactic or "command_and_control",
                    technique_name=f"DNS query by {proc}",
                    description=f"DNS query from suspicious process '{proc}'",
                    source_evtx=source_path,
                    confidence="medium",
                    sample_event=event,
                ))

    # === Windows Security - Logon events (4624, 4625) ===
    elif event_id == 4625 and "Security" in channel:
        logon_type = event_data.get("LogonType", "")
        patterns.append(DetectionPattern(
            event_id=event_id,
            channel=channel,
            provider_name=provider,
            field_matches={"win.system.eventID": "4625"},
            tactic=tactic or "initial_access",
            technique_name="Failed logon attempt",
            description=f"Failed logon attempt (type {logon_type})",
            source_evtx=source_path,
            confidence="low",
            sample_event=event,
        ))

    # === Windows Security - Service installed (7045) ===
    elif event_id == 7045:
        service_name = event_data.get("ServiceName", "")
        image_path = event_data.get("ImagePath", "").lower()
        for proc in SUSPICIOUS_PROCESSES:
            if proc in image_path or proc in service_name.lower():
                patterns.append(DetectionPattern(
                    event_id=event_id,
                    channel=channel,
                    provider_name=provider,
                    field_matches={
                        "win.eventdata.serviceName": service_name,
                        "win.eventdata.imagePath": proc,
                    },
                    tactic=tactic or "persistence",
                    technique_name=f"Suspicious service: {service_name}",
                    description=f"Suspicious service '{service_name}' installed",
                    source_evtx=source_path,
                    confidence="high",
                    sample_event=event,
                ))

    # === PowerShell Script Block Logging (4104) ===
    elif event_id == 4104 and "PowerShell" in channel:
        script_block = event_data.get("ScriptBlockText", "").lower()
        for pattern in SUSPICIOUS_CMD_PATTERNS:
            if pattern in script_block:
                patterns.append(DetectionPattern(
                    event_id=event_id,
                    channel=channel,
                    provider_name=provider,
                    field_matches={"win.eventdata.scriptBlockText": pattern},
                    tactic=tactic or "execution",
                    technique_name=f"Suspicious PowerShell: {pattern}",
                    description=f"Suspicious PowerShell script block containing '{pattern}'",
                    source_evtx=source_path,
                    confidence="medium",
                    sample_event=event,
                ))

    return patterns


def analyze_events(events: list[dict]) -> list[DetectionPattern]:
    """Analyze all events and return deduplicated detection patterns."""
    all_patterns = []
    seen = set()

    for event in events:
        source = event.get("_source_file", "")
        patterns = analyze_event(event, source)

        for p in patterns:
            # Deduplicate by (event_id, tactic, field_matches key)
            key = (p.event_id, p.tactic, tuple(sorted(p.field_matches.items())))
            if key not in seen:
                seen.add(key)
                all_patterns.append(p)

    console.print(f"[green]Found {len(all_patterns)} unique detection patterns[/]")
    return all_patterns
