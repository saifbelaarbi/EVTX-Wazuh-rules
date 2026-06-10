"""Analyze parsed events to extract detection-worthy patterns."""

from dataclasses import dataclass, field

from rich.console import Console

from . import mitre_mapper

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
    "mimikatz",
    "psexec",
    "psexesvc",
    "cobalt",
    "beacon",
    "meterpreter",
    "empire",
    "bloodhound",
    "sharphound",
    "rubeus",
    "kekeo",
    "lazagne",
    "procdump",
    "nanodump",
    "secretsdump",
    "pypykatz",
    "safetykatz",
    "sharpkatz",
    "crackmapexec",
    "impacket",
    "wmiexec",
    "smbexec",
    "dcomexec",
    "atexec",
    "winpeas",
    "linpeas",
    "seatbelt",
    "certutil",
    "bitsadmin",
    "mshta",
    "regsvr32",
    "rundll32",
    "wmic",
    "cmstp",
    "msiexec",
    "installutil",
}

SUSPICIOUS_CMD_PATTERNS = [
    "invoke-mimikatz",
    "invoke-expression",
    "downloadstring",
    "invoke-webrequest",
    "net user",
    "net localgroup",
    "whoami /priv",
    "cmdkey /list",
    "reg save",
    "sekurlsa::",
    "lsadump::",
    "kerberos::",
    "vssadmin delete shadows",
    "wbadmin delete",
    "bcdedit /set",
    "powershell -enc",
    "powershell -e ",
    "iex(",
    "bypass",
    "-nop ",
    "-w hidden",
    "add-mppreference -exclusionpath",
    "set-mppreference -disablerealtimemonitoring",
    "ntdsutil",
    "shadow copy",
    "vssadmin create",
    "comsvcs.dll",
    "minidump",
    "procdump",
    "out-minidump",
    "sharpdump",
    "nanodump",
    "dumpert",
    "invoke-obfuscation",
    "invoke-shellcode",
    "invoke-dcomexec",
    "invoke-wmimethod",
    "new-scheduledtask",
    "register-scheduledjob",
    "wevtutil cl",
    "wevtutil sl",
    "stop-service",
    "sc stop",
    "sc config",
    "disable-windowsoptionalfeature",
    "set-executionpolicy unrestricted",
]

# Suspicious service names/paths for 7045 detection
SUSPICIOUS_SERVICE_PATTERNS = [
    "psexe",
    "meterpreter",
    "cobalt",
    "beacon",
    "cmd.exe /c",
    "powershell",
    "mshta",
    "rundll32",
    "regsvr32",
    "certutil",
    "bitsadmin",
    "\\temp\\",
    "\\tmp\\",
    "appdata\\",
    "programdata\\",
]

# Suspicious DLL/driver paths for image load detection
SUSPICIOUS_IMAGE_LOAD_PATTERNS = [
    "\\temp\\",
    "\\tmp\\",
    "\\appdata\\",
    "\\downloads\\",
    "\\public\\",
    "\\programdata\\",
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
    if not isinstance(event_data, dict):
        event_data = {}

    # Infer tactic from source path
    tactic = infer_tactic_from_path(source_path or event.get("_source_file", ""))

    # === Sysmon Process Create (Event ID 1) ===
    if event_id == 1 and "Microsoft-Windows-Sysmon" in provider:
        image = event_data.get("Image", "").lower()
        cmdline = event_data.get("CommandLine", "").lower()
        event_data.get("ParentImage", "").lower()

        # Check for known suspicious processes — match on the field the
        # indicator actually appeared in, or the rule never fires.
        for proc in SUSPICIOUS_PROCESSES:
            if proc in image:
                proc_field = "win.eventdata.image"
            elif proc in cmdline:
                proc_field = "win.eventdata.commandLine"
            else:
                continue
            patterns.append(
                DetectionPattern(
                    event_id=event_id,
                    channel=channel,
                    provider_name=provider,
                    field_matches={proc_field: proc},
                    tactic=tactic or "execution",
                    technique_name=f"Suspicious process: {proc}",
                    description=f"Suspicious process '{proc}' execution detected",
                    source_evtx=source_path,
                    confidence="high",
                    sample_event=event,
                )
            )

        # Check for suspicious command-line patterns
        for pattern in SUSPICIOUS_CMD_PATTERNS:
            if pattern in cmdline:
                patterns.append(
                    DetectionPattern(
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
                    )
                )

    # === Sysmon Network Connection (Event ID 3) ===
    elif event_id == 3 and "Sysmon" in provider:
        image = event_data.get("Image", "").lower()
        dest_port = event_data.get("DestinationPort", "")
        for proc in SUSPICIOUS_PROCESSES:
            if proc in image:
                patterns.append(
                    DetectionPattern(
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
                    )
                )

    # === Sysmon CreateRemoteThread (Event ID 8) ===
    elif event_id == 8 and "Sysmon" in provider:
        event_data.get("SourceImage", "").lower()
        target_image = event_data.get("TargetImage", "").lower()
        if "lsass" in target_image:
            patterns.append(
                DetectionPattern(
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
                )
            )

    # === Sysmon Process Access (Event ID 10) ===
    elif event_id == 10 and "Sysmon" in provider:
        target_image = event_data.get("TargetImage", "").lower()
        granted_access = event_data.get("GrantedAccess", "")
        if "lsass" in target_image and granted_access:
            patterns.append(
                DetectionPattern(
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
                )
            )

    # === Sysmon Registry Events (Event ID 12, 13, 14) ===
    elif event_id in (12, 13, 14) and "Sysmon" in provider:
        target_object = event_data.get("TargetObject", "").lower()
        persistence_keys = [
            "currentversion\\run",
            "currentversion\\runonce",
            "winlogon\\",
            "userinit",
            "shell",
            "currentversion\\explorer\\shell",
        ]
        for key in persistence_keys:
            if key in target_object:
                patterns.append(
                    DetectionPattern(
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
                    )
                )

    # === Sysmon DNS Query (Event ID 22) ===
    elif event_id == 22 and "Sysmon" in provider:
        query_name = event_data.get("QueryName", "").lower()
        image = event_data.get("Image", "").lower()
        for proc in SUSPICIOUS_PROCESSES:
            if proc in image:
                patterns.append(
                    DetectionPattern(
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
                    )
                )

    # === Sysmon Driver Load (Event ID 6) ===
    elif event_id == 6 and "Sysmon" in provider:
        image_loaded = event_data.get("ImageLoaded", "").lower()
        for susp in SUSPICIOUS_IMAGE_LOAD_PATTERNS:
            if susp in image_loaded:
                patterns.append(
                    DetectionPattern(
                        event_id=event_id,
                        channel=channel,
                        provider_name=provider,
                        field_matches={"win.eventdata.imageLoaded": susp},
                        tactic=tactic or "persistence",
                        technique_name=f"Suspicious driver load from {susp.strip(chr(92))}",
                        description=f"Driver loaded from suspicious path: {susp}",
                        source_evtx=source_path,
                        confidence="medium",
                        sample_event=event,
                    )
                )

    # === Sysmon Image Load (Event ID 7) ===
    elif event_id == 7 and "Sysmon" in provider:
        image_loaded = event_data.get("ImageLoaded", "").lower()
        image = event_data.get("Image", "").lower()
        event_data.get("Signed", "").lower()
        for susp in SUSPICIOUS_IMAGE_LOAD_PATTERNS:
            if susp in image_loaded:
                patterns.append(
                    DetectionPattern(
                        event_id=event_id,
                        channel=channel,
                        provider_name=provider,
                        field_matches={"win.eventdata.imageLoaded": susp},
                        tactic=tactic or "defense_evasion",
                        technique_name="DLL loaded from suspicious path",
                        description=f"DLL loaded from suspicious path: {susp}",
                        source_evtx=source_path,
                        confidence="medium",
                        sample_event=event,
                    )
                )
        for proc in SUSPICIOUS_PROCESSES:
            if proc in image:
                patterns.append(
                    DetectionPattern(
                        event_id=event_id,
                        channel=channel,
                        provider_name=provider,
                        field_matches={"win.eventdata.image": proc},
                        tactic=tactic or "defense_evasion",
                        technique_name=f"DLL sideloading by {proc}",
                        description=f"Image load by suspicious process '{proc}'",
                        source_evtx=source_path,
                        confidence="high",
                        sample_event=event,
                    )
                )

    # === Sysmon File Create (Event ID 11) ===
    elif event_id == 11 and "Sysmon" in provider:
        target_filename = event_data.get("TargetFilename", "").lower()
        image = event_data.get("Image", "").lower()
        for proc in SUSPICIOUS_PROCESSES:
            if proc in image:
                patterns.append(
                    DetectionPattern(
                        event_id=event_id,
                        channel=channel,
                        provider_name=provider,
                        field_matches={"win.eventdata.image": proc},
                        tactic=tactic or "persistence",
                        technique_name=f"File created by {proc}",
                        description=f"File created by suspicious process '{proc}'",
                        source_evtx=source_path,
                        confidence="medium",
                        sample_event=event,
                    )
                )
        # Detect executable drops in suspicious locations
        if any(ext in target_filename for ext in [".exe", ".dll", ".bat", ".ps1", ".vbs", ".hta"]):
            for susp in SUSPICIOUS_IMAGE_LOAD_PATTERNS:
                if susp in target_filename:
                    patterns.append(
                        DetectionPattern(
                            event_id=event_id,
                            channel=channel,
                            provider_name=provider,
                            field_matches={"win.eventdata.targetFilename": susp},
                            tactic=tactic or "execution",
                            technique_name=f"Executable dropped in {susp.strip(chr(92))}",
                            description=f"Executable file created in suspicious path: {susp}",
                            source_evtx=source_path,
                            confidence="medium",
                            sample_event=event,
                        )
                    )

    # === Sysmon Pipe Created/Connected (Event ID 17, 18) ===
    elif event_id in (17, 18) and "Sysmon" in provider:
        pipe_name = event_data.get("PipeName", "").lower()
        image = event_data.get("Image", "").lower()
        suspicious_pipes = [
            "\\msagent_",
            "\\isapi",
            "\\msse-",
            "\\postex_",
            "\\status_",
            "\\mypipe-",
            "\\win_svc",
            "\\ntsvcs",
            "\\scerpc",
            "\\paexec",
            "\\psexe",
        ]
        for sp in suspicious_pipes:
            if sp in pipe_name:
                patterns.append(
                    DetectionPattern(
                        event_id=event_id,
                        channel=channel,
                        provider_name=provider,
                        field_matches={"win.eventdata.pipeName": sp},
                        tactic=tactic or "lateral_movement",
                        technique_name=f"Suspicious named pipe: {sp}",
                        description=f"Known malicious named pipe pattern: {sp}",
                        source_evtx=source_path,
                        confidence="high",
                        sample_event=event,
                    )
                )

    # === Sysmon Process Tampering (Event ID 25) ===
    elif event_id == 25 and "Sysmon" in provider:
        image = event_data.get("Image", "").lower()
        tampering_type = event_data.get("Type", "")
        patterns.append(
            DetectionPattern(
                event_id=event_id,
                channel=channel,
                provider_name=provider,
                field_matches={"win.eventdata.image": image.split("\\")[-1] if image else "unknown"},
                tactic=tactic or "defense_evasion",
                technique_name=f"Process tampering ({tampering_type})",
                description=f"Process tampering detected: {tampering_type}",
                source_evtx=source_path,
                confidence="high",
                sample_event=event,
            )
        )

    # === Sysmon WMI Events (Event ID 19, 20, 21) ===
    elif event_id in (19, 20, 21) and "Sysmon" in provider:
        # Event 21 carries Consumer; events 19/20 only carry Name — match on
        # the field that actually exists in the event.
        if event_data.get("Consumer"):
            wmi_field, wmi_value = "win.eventdata.consumer", event_data["Consumer"]
        elif event_data.get("Name"):
            wmi_field, wmi_value = "win.eventdata.name", event_data["Name"]
        elif event_data.get("Operation"):
            wmi_field, wmi_value = "win.eventdata.operation", event_data["Operation"]
        else:
            wmi_field, wmi_value = "", ""
        if wmi_value:
            patterns.append(
                DetectionPattern(
                    event_id=event_id,
                    channel=channel,
                    provider_name=provider,
                    field_matches={wmi_field: wmi_value[:60]},
                    tactic=tactic or "persistence",
                    technique_name=f"WMI event subscription (EventID {event_id})",
                    description="WMI event subscription activity detected",
                    source_evtx=source_path,
                    confidence="medium",
                    sample_event=event,
                )
            )

    # === Windows Security - Failed Logon (4625) ===
    elif event_id == 4625 and "Security" in channel:
        logon_type = event_data.get("LogonType", "")
        patterns.append(
            DetectionPattern(
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
            )
        )

    # === Windows Security - Successful Logon with suspicious type (4624) ===
    elif event_id == 4624 and "Security" in channel:
        logon_type = event_data.get("LogonType", "")
        # Type 10 = RemoteInteractive (RDP), Type 3 = Network
        if logon_type in ("10", "3"):
            target_user = event_data.get("TargetUserName", "").lower()
            if target_user not in (
                "system",
                "local service",
                "network service",
                "dwm-1",
                "dwm-2",
                "umfd-0",
                "umfd-1",
                "anonymous logon",
                "-",
            ):
                patterns.append(
                    DetectionPattern(
                        event_id=event_id,
                        channel=channel,
                        provider_name=provider,
                        field_matches={
                            "win.system.eventID": "4624",
                            "win.eventdata.logonType": logon_type,
                        },
                        tactic=tactic or "lateral_movement",
                        technique_name=f"Remote logon (type {logon_type})",
                        description=f"Remote logon type {logon_type} detected",
                        source_evtx=source_path,
                        confidence="low",
                        sample_event=event,
                    )
                )

    # === Windows Security - Explicit Credentials (4648) ===
    elif event_id == 4648 and "Security" in channel:
        target_server = event_data.get("TargetServerName", "")
        patterns.append(
            DetectionPattern(
                event_id=event_id,
                channel=channel,
                provider_name=provider,
                field_matches={"win.system.eventID": "4648"},
                tactic=tactic or "lateral_movement",
                technique_name="Explicit credential logon",
                description=f"Logon with explicit credentials targeting {target_server}",
                source_evtx=source_path,
                confidence="low",
                sample_event=event,
            )
        )

    # === Windows Security - Special Privileges (4672) ===
    elif event_id == 4672 and "Security" in channel:
        subject_user = event_data.get("SubjectUserName", "").lower()
        if subject_user not in ("system", "local service", "network service", "-", "dwm-1"):
            patterns.append(
                DetectionPattern(
                    event_id=event_id,
                    channel=channel,
                    provider_name=provider,
                    field_matches={"win.system.eventID": "4672"},
                    tactic=tactic or "privilege_escalation",
                    technique_name="Special privilege assignment",
                    description=f"Special privileges assigned to user: {subject_user}",
                    source_evtx=source_path,
                    confidence="low",
                    sample_event=event,
                )
            )

    # === Windows Security - User Account Created (4720) ===
    elif event_id == 4720 and "Security" in channel:
        target_user = event_data.get("TargetUserName", "")
        patterns.append(
            DetectionPattern(
                event_id=event_id,
                channel=channel,
                provider_name=provider,
                field_matches={"win.system.eventID": "4720"},
                tactic=tactic or "persistence",
                technique_name="User account created",
                description=f"New user account created: {target_user}",
                source_evtx=source_path,
                confidence="medium",
                sample_event=event,
            )
        )

    # === Windows Security - Security Group Changes (4731, 4732, 4735) ===
    elif event_id in (4731, 4732, 4735) and "Security" in channel:
        group_name = event_data.get("TargetUserName", "") or event_data.get("GroupName", "")
        event_names = {4731: "Security group created", 4732: "Member added to group", 4735: "Security group changed"}
        patterns.append(
            DetectionPattern(
                event_id=event_id,
                channel=channel,
                provider_name=provider,
                field_matches={"win.system.eventID": str(event_id)},
                tactic=tactic or "persistence",
                technique_name=event_names[event_id],
                description=f"{event_names[event_id]}: {group_name}",
                source_evtx=source_path,
                confidence="low",
                sample_event=event,
            )
        )

    # === Windows Security - Account Rename (4781) ===
    elif event_id == 4781 and "Security" in channel:
        old_name = event_data.get("OldTargetUserName", "")
        new_name = event_data.get("NewTargetUserName", "")
        patterns.append(
            DetectionPattern(
                event_id=event_id,
                channel=channel,
                provider_name=provider,
                field_matches={"win.system.eventID": "4781"},
                tactic=tactic or "defense_evasion",
                technique_name="Account renamed",
                description=f"Account renamed from '{old_name}' to '{new_name}'",
                source_evtx=source_path,
                confidence="medium",
                sample_event=event,
            )
        )

    # === Windows Security - Service installed (7045) ===
    elif event_id == 7045:
        service_name = event_data.get("ServiceName", "")
        image_path = event_data.get("ImagePath", "").lower()
        matched = False
        for proc in SUSPICIOUS_PROCESSES:
            if proc in image_path:
                svc_field = "win.eventdata.imagePath"
            elif proc in service_name.lower():
                svc_field = "win.eventdata.serviceName"
            else:
                continue
            patterns.append(
                DetectionPattern(
                    event_id=event_id,
                    channel=channel,
                    provider_name=provider,
                    field_matches={
                        "win.eventdata.serviceName": service_name,
                        svc_field: proc,
                    },
                    tactic=tactic or "persistence",
                    technique_name=f"Suspicious service: {service_name}",
                    description=f"Suspicious service '{service_name}' installed",
                    source_evtx=source_path,
                    confidence="high",
                    sample_event=event,
                )
            )
            matched = True
        if not matched:
            for sp in SUSPICIOUS_SERVICE_PATTERNS:
                if sp in image_path:
                    patterns.append(
                        DetectionPattern(
                            event_id=event_id,
                            channel=channel,
                            provider_name=provider,
                            field_matches={
                                "win.eventdata.serviceName": service_name,
                                "win.eventdata.imagePath": sp,
                            },
                            tactic=tactic or "persistence",
                            technique_name=f"Suspicious service path: {sp}",
                            description=f"Service installed with suspicious path pattern: {sp}",
                            source_evtx=source_path,
                            confidence="medium",
                            sample_event=event,
                        )
                    )

    # === Windows Security - Scheduled Task Created (4698) ===
    elif event_id == 4698 and "Security" in channel:
        task_name = event_data.get("TaskName", "")
        event_data.get("TaskContent", "").lower()
        patterns.append(
            DetectionPattern(
                event_id=event_id,
                channel=channel,
                provider_name=provider,
                field_matches={"win.system.eventID": "4698"},
                tactic=tactic or "persistence",
                technique_name="Scheduled task created",
                description=f"Scheduled task created: {task_name}",
                source_evtx=source_path,
                confidence="medium",
                sample_event=event,
            )
        )

    # === Windows Defender/Firewall events ===
    elif event_id == 5001 and "Security" in channel:
        patterns.append(
            DetectionPattern(
                event_id=event_id,
                channel=channel,
                provider_name=provider,
                field_matches={"win.system.eventID": "5001"},
                tactic=tactic or "defense_evasion",
                technique_name="Windows Defender disabled",
                description="Windows Defender real-time protection disabled",
                source_evtx=source_path,
                confidence="high",
                sample_event=event,
            )
        )

    # === PowerShell Script Block Logging (4104) ===
    elif event_id == 4104 and "PowerShell" in channel:
        script_block = event_data.get("ScriptBlockText", "").lower()
        for pattern in SUSPICIOUS_CMD_PATTERNS:
            if pattern in script_block:
                patterns.append(
                    DetectionPattern(
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
                    )
                )

    # === PowerShell Module Logging (4103) ===
    elif event_id == 4103 and "PowerShell" in channel:
        payload = event_data.get("Payload", "").lower()
        for pattern in SUSPICIOUS_CMD_PATTERNS:
            if pattern in payload:
                patterns.append(
                    DetectionPattern(
                        event_id=event_id,
                        channel=channel,
                        provider_name=provider,
                        field_matches={"win.eventdata.payload": pattern},
                        tactic=tactic or "execution",
                        technique_name=f"PowerShell module: {pattern}",
                        description=f"PowerShell module logging captured: '{pattern}'",
                        source_evtx=source_path,
                        confidence="medium",
                        sample_event=event,
                    )
                )

    return patterns


def enrich_pattern(pattern: DetectionPattern) -> DetectionPattern:
    """Reclassify a pattern's tactic + MITRE technique from event semantics.

    Uses mitre_mapper to replace folder-path tactic guesses and tactic-default
    technique assignments with a defensible mapping derived from the indicator
    that fired. The original path-inferred tactic is passed only as a last-resort
    hint inside classify_for_pattern.
    """
    mapping = mitre_mapper.classify_for_pattern(pattern)
    pattern.tactic = mapping.tactic or pattern.tactic or "execution"
    if mapping.technique_id:
        pattern.mitre_ids = [mapping.technique_id]
    return pattern


def analyze_events(events: list[dict]) -> list[DetectionPattern]:
    """Analyze all events and return deduplicated detection patterns.

    Patterns are semantically reclassified (tactic + technique) before
    deduplication, so cross-tactic clones of the same detection logic collapse
    into a single rule instead of proliferating across tactics.
    """
    all_patterns = []
    seen = set()

    for event in events:
        source = event.get("_source_file", "")
        patterns = analyze_event(event, source)

        for p in patterns:
            enrich_pattern(p)
            # Deduplicate by detection logic (event_id + fields), tactic-independent
            key = (p.event_id, tuple(sorted(p.field_matches.items())))
            if key not in seen:
                seen.add(key)
                all_patterns.append(p)

    console.print(f"[green]Found {len(all_patterns)} unique detection patterns[/]")
    return all_patterns
