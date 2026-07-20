"""Semantic MITRE ATT&CK technique + tactic inference.

Replaces folder-path-based tactic guessing and tactic-default technique
assignment with a data-driven lookup keyed on event semantics and the
indicator string that actually fired. The goal is defensible ATT&CK mappings:
a failed logon maps to brute force (T1110), not phishing; an LSASS access maps
to OS credential dumping (T1003.001), not a tactic default.
"""

from dataclasses import dataclass

# Canonical snake_case tactic names (the 12 ATT&CK enterprise tactics).
CANONICAL_TACTICS = {
    "initial_access",
    "execution",
    "persistence",
    "privilege_escalation",
    "defense_evasion",
    "credential_access",
    "discovery",
    "lateral_movement",
    "collection",
    "command_and_control",
    "exfiltration",
    "impact",
}


def normalize_tactic(raw: str) -> str:
    """Normalize a tactic label to canonical snake_case.

    Handles Sigma's hyphenated tags (``credential-access``), spaced labels
    (``credential access``) and an ``attack.`` prefix. Returns "" if unknown.
    """
    if not raw:
        return ""
    t = raw.strip().lower()
    if t.startswith("attack."):
        t = t[len("attack.") :]
    t = t.replace("-", "_").replace(" ", "_")
    return t if t in CANONICAL_TACTICS else ""


@dataclass(frozen=True)
class MitreMapping:
    """A resolved ATT&CK mapping for a detection signal."""

    technique_id: str  # full id, e.g. "T1003.001"
    technique_name: str
    tactic: str  # canonical snake_case

    @property
    def base_technique(self) -> str:
        """The parent technique id without sub-technique, e.g. "T1003"."""
        return self.technique_id.split(".")[0] if self.technique_id else ""


# ── Indicator → mapping table ────────────────────────────────────────────────
# Keyed on a lowercase substring that may appear in a matched field value or
# command line. Longer (more specific) keys win over shorter ones.
INDICATOR_TO_MAPPING: dict[str, MitreMapping] = {
    # Credential access — OS credential dumping
    "lsass": MitreMapping("T1003.001", "LSASS Memory", "credential_access"),
    "sekurlsa::": MitreMapping("T1003.001", "LSASS Memory", "credential_access"),
    "comsvcs.dll": MitreMapping("T1003.001", "LSASS Memory", "credential_access"),
    "minidump": MitreMapping("T1003.001", "LSASS Memory", "credential_access"),
    "out-minidump": MitreMapping("T1003.001", "LSASS Memory", "credential_access"),
    "procdump": MitreMapping("T1003.001", "LSASS Memory", "credential_access"),
    "nanodump": MitreMapping("T1003.001", "LSASS Memory", "credential_access"),
    "sharpdump": MitreMapping("T1003.001", "LSASS Memory", "credential_access"),
    "dumpert": MitreMapping("T1003.001", "LSASS Memory", "credential_access"),
    "mimikatz": MitreMapping("T1003", "OS Credential Dumping", "credential_access"),
    "invoke-mimikatz": MitreMapping("T1003", "OS Credential Dumping", "credential_access"),
    "pypykatz": MitreMapping("T1003", "OS Credential Dumping", "credential_access"),
    "safetykatz": MitreMapping("T1003", "OS Credential Dumping", "credential_access"),
    "sharpkatz": MitreMapping("T1003", "OS Credential Dumping", "credential_access"),
    "secretsdump": MitreMapping("T1003", "OS Credential Dumping", "credential_access"),
    "lsadump::": MitreMapping("T1003.002", "Security Account Manager", "credential_access"),
    "reg save": MitreMapping("T1003.002", "Security Account Manager", "credential_access"),
    "ntdsutil": MitreMapping("T1003.003", "NTDS", "credential_access"),
    "lazagne": MitreMapping("T1555", "Credentials from Password Stores", "credential_access"),
    "cmdkey /list": MitreMapping("T1555", "Credentials from Password Stores", "credential_access"),
    "rubeus": MitreMapping("T1558", "Steal or Forge Kerberos Tickets", "credential_access"),
    "kekeo": MitreMapping("T1558", "Steal or Forge Kerberos Tickets", "credential_access"),
    "kerberos::": MitreMapping("T1558", "Steal or Forge Kerberos Tickets", "credential_access"),
    "gsecdump": MitreMapping("T1003", "OS Credential Dumping", "credential_access"),
    "certify.exe": MitreMapping("T1649", "Steal or Forge Authentication Certificates", "credential_access"),
    "certipy": MitreMapping("T1649", "Steal or Forge Authentication Certificates", "credential_access"),
    # Discovery
    "bloodhound": MitreMapping("T1087", "Account Discovery", "discovery"),
    "sharphound": MitreMapping("T1087", "Account Discovery", "discovery"),
    "adfind": MitreMapping("T1087.002", "Domain Account Discovery", "discovery"),
    "powerview": MitreMapping("T1087.002", "Domain Account Discovery", "discovery"),
    "net user": MitreMapping("T1087.001", "Local Account Discovery", "discovery"),
    "net localgroup": MitreMapping("T1069.001", "Local Groups", "discovery"),
    "nltest /domain_trusts": MitreMapping("T1482", "Domain Trust Discovery", "discovery"),
    "nltest /dclist": MitreMapping("T1018", "Remote System Discovery", "discovery"),
    "whoami /priv": MitreMapping("T1033", "System Owner/User Discovery", "discovery"),
    "seatbelt": MitreMapping("T1082", "System Information Discovery", "discovery"),
    "winpeas": MitreMapping("T1082", "System Information Discovery", "discovery"),
    "linpeas": MitreMapping("T1082", "System Information Discovery", "discovery"),
    # Lateral movement — remote service execution
    "psexec": MitreMapping("T1021.002", "SMB/Windows Admin Shares", "lateral_movement"),
    "psexesvc": MitreMapping("T1021.002", "SMB/Windows Admin Shares", "lateral_movement"),
    "paexec": MitreMapping("T1021.002", "SMB/Windows Admin Shares", "lateral_movement"),
    "smbexec": MitreMapping("T1021.002", "SMB/Windows Admin Shares", "lateral_movement"),
    "wmiexec": MitreMapping("T1021", "Remote Services", "lateral_movement"),
    "dcomexec": MitreMapping("T1021.003", "Distributed Component Object Model", "lateral_movement"),
    "invoke-dcomexec": MitreMapping("T1021.003", "Distributed Component Object Model", "lateral_movement"),
    "atexec": MitreMapping("T1021", "Remote Services", "lateral_movement"),
    "crackmapexec": MitreMapping("T1021", "Remote Services", "lateral_movement"),
    "impacket": MitreMapping("T1021", "Remote Services", "lateral_movement"),
    # Execution
    "invoke-wmimethod": MitreMapping("T1047", "Windows Management Instrumentation", "execution"),
    "wmic": MitreMapping("T1047", "Windows Management Instrumentation", "execution"),
    "powershell -enc": MitreMapping("T1059.001", "PowerShell", "execution"),
    "powershell -e ": MitreMapping("T1059.001", "PowerShell", "execution"),
    "invoke-expression": MitreMapping("T1059.001", "PowerShell", "execution"),
    "iex(": MitreMapping("T1059.001", "PowerShell", "execution"),
    "downloadstring": MitreMapping("T1059.001", "PowerShell", "execution"),
    "invoke-webrequest": MitreMapping("T1059.001", "PowerShell", "execution"),
    "invoke-shellcode": MitreMapping("T1059.001", "PowerShell", "execution"),
    "-nop ": MitreMapping("T1059.001", "PowerShell", "execution"),
    "-w hidden": MitreMapping("T1059.001", "PowerShell", "execution"),
    "bypass": MitreMapping("T1059.001", "PowerShell", "execution"),
    "set-executionpolicy unrestricted": MitreMapping("T1059.001", "PowerShell", "execution"),
    # Defense evasion — signed binary proxy execution & friends
    "rundll32": MitreMapping("T1218.011", "Rundll32", "defense_evasion"),
    "regsvr32": MitreMapping("T1218.010", "Regsvr32", "defense_evasion"),
    "mshta": MitreMapping("T1218.005", "Mshta", "defense_evasion"),
    "cmstp": MitreMapping("T1218.003", "CMSTP", "defense_evasion"),
    "installutil": MitreMapping("T1218.004", "InstallUtil", "defense_evasion"),
    "msiexec": MitreMapping("T1218.007", "Msiexec", "defense_evasion"),
    "certutil": MitreMapping("T1140", "Deobfuscate/Decode Files or Information", "defense_evasion"),
    "bitsadmin": MitreMapping("T1197", "BITS Jobs", "defense_evasion"),
    "invoke-obfuscation": MitreMapping("T1027", "Obfuscated Files or Information", "defense_evasion"),
    "add-mppreference -exclusionpath": MitreMapping("T1562.001", "Disable or Modify Tools", "defense_evasion"),
    "set-mppreference -disablerealtimemonitoring": MitreMapping(
        "T1562.001", "Disable or Modify Tools", "defense_evasion"
    ),
    "disable-windowsoptionalfeature": MitreMapping("T1562.001", "Disable or Modify Tools", "defense_evasion"),
    "wevtutil cl": MitreMapping("T1070.001", "Clear Windows Event Logs", "defense_evasion"),
    "wevtutil sl": MitreMapping("T1070.001", "Clear Windows Event Logs", "defense_evasion"),
    "fsutil usn deletejournal": MitreMapping("T1070", "Indicator Removal", "defense_evasion"),
    "netsh advfirewall set": MitreMapping("T1562.004", "Disable or Modify System Firewall", "defense_evasion"),
    "netsh firewall set": MitreMapping("T1562.004", "Disable or Modify System Firewall", "defense_evasion"),
    # Impact
    "vssadmin delete shadows": MitreMapping("T1490", "Inhibit System Recovery", "impact"),
    "wmic shadowcopy delete": MitreMapping("T1490", "Inhibit System Recovery", "impact"),
    "wbadmin delete": MitreMapping("T1490", "Inhibit System Recovery", "impact"),
    "bcdedit /set": MitreMapping("T1490", "Inhibit System Recovery", "impact"),
    "vssadmin create": MitreMapping("T1490", "Inhibit System Recovery", "impact"),
    "shadow copy": MitreMapping("T1490", "Inhibit System Recovery", "impact"),
    "stop-service": MitreMapping("T1489", "Service Stop", "impact"),
    "sc stop": MitreMapping("T1489", "Service Stop", "impact"),
    "sc config": MitreMapping("T1489", "Service Stop", "impact"),
    # Persistence
    "new-scheduledtask": MitreMapping("T1053.005", "Scheduled Task", "persistence"),
    "register-scheduledjob": MitreMapping("T1053.005", "Scheduled Task", "persistence"),
    "schtasks /create": MitreMapping("T1053.005", "Scheduled Task", "persistence"),
    "currentversion\\run": MitreMapping("T1547.001", "Registry Run Keys / Startup Folder", "persistence"),
    "runonce": MitreMapping("T1547.001", "Registry Run Keys / Startup Folder", "persistence"),
    "winlogon\\": MitreMapping("T1547.004", "Winlogon Helper DLL", "persistence"),
    "userinit": MitreMapping("T1547.004", "Winlogon Helper DLL", "persistence"),
    # Command & control — post-exploitation frameworks
    "cobalt": MitreMapping("T1071", "Application Layer Protocol", "command_and_control"),
    "beacon": MitreMapping("T1071", "Application Layer Protocol", "command_and_control"),
    "meterpreter": MitreMapping("T1071", "Application Layer Protocol", "command_and_control"),
    "empire": MitreMapping("T1059.001", "PowerShell", "execution"),
}

# Ordered most-specific-first so substring resolution prefers precise indicators.
_INDICATOR_KEYS = sorted(INDICATOR_TO_MAPPING, key=len, reverse=True)


# ── Event-id default table ───────────────────────────────────────────────────
# Used when no string indicator matched. Keyed by (event_id, family) where
# family is "sysmon", "security", "powershell" or "" (any).
_EVENTID_DEFAULTS: dict[tuple[int, str], MitreMapping] = {
    (6, "sysmon"): MitreMapping("T1014", "Rootkit", "defense_evasion"),
    (7, "sysmon"): MitreMapping("T1574.002", "DLL Side-Loading", "defense_evasion"),
    (8, "sysmon"): MitreMapping("T1055", "Process Injection", "defense_evasion"),
    (10, "sysmon"): MitreMapping("T1003.001", "LSASS Memory", "credential_access"),
    (11, "sysmon"): MitreMapping("T1105", "Ingress Tool Transfer", "command_and_control"),
    (12, "sysmon"): MitreMapping("T1112", "Modify Registry", "defense_evasion"),
    (13, "sysmon"): MitreMapping("T1112", "Modify Registry", "defense_evasion"),
    (14, "sysmon"): MitreMapping("T1112", "Modify Registry", "defense_evasion"),
    (17, "sysmon"): MitreMapping("T1021.002", "SMB/Windows Admin Shares", "lateral_movement"),
    (18, "sysmon"): MitreMapping("T1021.002", "SMB/Windows Admin Shares", "lateral_movement"),
    (19, "sysmon"): MitreMapping("T1546.003", "Windows Management Instrumentation Event Subscription", "persistence"),
    (20, "sysmon"): MitreMapping("T1546.003", "Windows Management Instrumentation Event Subscription", "persistence"),
    (21, "sysmon"): MitreMapping("T1546.003", "Windows Management Instrumentation Event Subscription", "persistence"),
    (22, "sysmon"): MitreMapping("T1071.004", "DNS", "command_and_control"),
    (25, "sysmon"): MitreMapping("T1055", "Process Injection", "defense_evasion"),
    (4625, "security"): MitreMapping("T1110", "Brute Force", "credential_access"),
    (4624, "security"): MitreMapping("T1021.001", "Remote Desktop Protocol", "lateral_movement"),
    (4648, "security"): MitreMapping("T1078", "Valid Accounts", "lateral_movement"),
    (4672, "security"): MitreMapping("T1078", "Valid Accounts", "privilege_escalation"),
    (4720, "security"): MitreMapping("T1136.001", "Local Account", "persistence"),
    (4731, "security"): MitreMapping("T1098", "Account Manipulation", "persistence"),
    (4732, "security"): MitreMapping("T1098", "Account Manipulation", "persistence"),
    (4735, "security"): MitreMapping("T1098", "Account Manipulation", "persistence"),
    (4781, "security"): MitreMapping("T1036", "Masquerading", "defense_evasion"),
    (4698, "security"): MitreMapping("T1053.005", "Scheduled Task", "persistence"),
    (5001, "security"): MitreMapping("T1562.001", "Disable or Modify Tools", "defense_evasion"),
    (7045, ""): MitreMapping("T1543.003", "Windows Service", "persistence"),
    (4104, "powershell"): MitreMapping("T1059.001", "PowerShell", "execution"),
    (4103, "powershell"): MitreMapping("T1059.001", "PowerShell", "execution"),
}

# Generic technique used as a last resort when only a tactic hint is available.
_TACTIC_GENERIC_TECHNIQUE: dict[str, MitreMapping] = {
    "initial_access": MitreMapping("T1078", "Valid Accounts", "initial_access"),
    "execution": MitreMapping("T1059", "Command and Scripting Interpreter", "execution"),
    "persistence": MitreMapping("T1547", "Boot or Logon Autostart Execution", "persistence"),
    "privilege_escalation": MitreMapping("T1068", "Exploitation for Privilege Escalation", "privilege_escalation"),
    "defense_evasion": MitreMapping("T1070", "Indicator Removal", "defense_evasion"),
    "credential_access": MitreMapping("T1003", "OS Credential Dumping", "credential_access"),
    "discovery": MitreMapping("T1082", "System Information Discovery", "discovery"),
    "lateral_movement": MitreMapping("T1021", "Remote Services", "lateral_movement"),
    "collection": MitreMapping("T1005", "Data from Local System", "collection"),
    "command_and_control": MitreMapping("T1071", "Application Layer Protocol", "command_and_control"),
    "exfiltration": MitreMapping("T1041", "Exfiltration Over C2 Channel", "exfiltration"),
    "impact": MitreMapping("T1489", "Service Stop", "impact"),
}

_HARD_FALLBACK = MitreMapping("", "", "execution")

# Reverse index: technique id → tactic. Built from the indicator and event-id
# tables so external callers (e.g. atomic_collector) can resolve tactic from
# a known technique id without duplicating data.
TECHNIQUE_TO_TACTIC: dict[str, str] = {}
for _m in INDICATOR_TO_MAPPING.values():
    if _m.technique_id and _m.tactic:
        TECHNIQUE_TO_TACTIC.setdefault(_m.technique_id, _m.tactic)
        TECHNIQUE_TO_TACTIC.setdefault(_m.technique_id.split(".")[0], _m.tactic)
for _m in _EVENTID_DEFAULTS.values():
    if _m.technique_id and _m.tactic:
        TECHNIQUE_TO_TACTIC.setdefault(_m.technique_id, _m.tactic)
        TECHNIQUE_TO_TACTIC.setdefault(_m.technique_id.split(".")[0], _m.tactic)
for _tac, _m in _TACTIC_GENERIC_TECHNIQUE.items():
    if _m.technique_id:
        TECHNIQUE_TO_TACTIC.setdefault(_m.technique_id, _tac)


def _family(channel: str, provider: str) -> str:
    """Classify an event into a coarse log family for the default table."""
    blob = f"{channel} {provider}".lower()
    if "sysmon" in blob:
        return "sysmon"
    if "powershell" in blob:
        return "powershell"
    if "security" in blob:
        return "security"
    return ""


def _match_indicator(indicators: list[str]) -> MitreMapping | None:
    """Return the most-specific indicator mapping found in any indicator string."""
    for ind in indicators:
        if not ind:
            continue
        low = ind.lower()
        for key in _INDICATOR_KEYS:
            if key in low:
                return INDICATOR_TO_MAPPING[key]
    return None


def classify(
    *,
    event_id: int,
    channel: str = "",
    provider: str = "",
    indicators: list[str] | None = None,
    path_hint_tactic: str = "",
) -> MitreMapping:
    """Resolve the best ATT&CK mapping for a detection signal.

    Resolution order:
      1. Indicator table (specific tool/command strings).
      2. Event-id default table (event semantics).
      3. ``path_hint_tactic`` -> a generic technique for that tactic.
      4. Hard fallback ("", "", "execution").
    """
    indicators = indicators or []

    hit = _match_indicator(indicators)
    if hit is not None:
        return hit

    fam = _family(channel, provider)
    for key in ((event_id, fam), (event_id, "")):
        if key in _EVENTID_DEFAULTS:
            return _EVENTID_DEFAULTS[key]

    hint = normalize_tactic(path_hint_tactic)
    if hint:
        return _TACTIC_GENERIC_TECHNIQUE.get(hint, MitreMapping("", "", hint))

    return _HARD_FALLBACK


def classify_for_pattern(pattern) -> MitreMapping:
    """Convenience wrapper that pulls signal fields off a DetectionPattern."""
    indicators = [str(v) for v in pattern.field_matches.values()]
    return classify(
        event_id=pattern.event_id,
        channel=pattern.channel,
        provider=pattern.provider_name,
        indicators=indicators,
        path_hint_tactic=pattern.tactic,
    )
