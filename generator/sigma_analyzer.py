"""Analyze SigmaHQ Sigma rules and assess conversion potential to Wazuh format."""

from collections import defaultdict
from pathlib import Path

import yaml
from rich.console import Console
from rich.table import Table

console = Console()


SIGMA_STATUS_PRIORITY = {"stable": 3, "test": 2, "experimental": 1, "deprecated": 0}

SIGMA_LOGSOURCE_TO_WAZUH = {
    # Sysmon categories (channel: Microsoft-Windows-Sysmon/Operational)
    "process_creation": {"sysmon_eid": 1, "parent_sid": 61603, "channel": "sysmon"},
    "network_connection": {"sysmon_eid": 3, "parent_sid": 61605, "channel": "sysmon"},
    "driver_load": {"sysmon_eid": 6, "parent_sid": 61608, "channel": "sysmon"},
    "image_load": {"sysmon_eid": 7, "parent_sid": 61609, "channel": "sysmon"},
    "create_remote_thread": {"sysmon_eid": 8, "parent_sid": 61610, "channel": "sysmon"},
    "process_access": {"sysmon_eid": 10, "parent_sid": 61612, "channel": "sysmon"},
    "file_event": {"sysmon_eid": 11, "parent_sid": 61613, "channel": "sysmon"},
    "registry_event": {"sysmon_eid": 13, "parent_sid": 61615, "channel": "sysmon"},
    "registry_set": {"sysmon_eid": 13, "parent_sid": 61615, "channel": "sysmon"},
    "registry_add": {"sysmon_eid": 12, "parent_sid": 61614, "channel": "sysmon"},
    "registry_delete": {"sysmon_eid": 12, "parent_sid": 61614, "channel": "sysmon"},
    "registry_rename": {"sysmon_eid": 14, "parent_sid": 61616, "channel": "sysmon"},
    "file_access": {"sysmon_eid": 11, "parent_sid": 61613, "channel": "sysmon"},
    "file_delete": {"sysmon_eid": 23, "parent_sid": 61625, "channel": "sysmon"},
    "file_change": {"sysmon_eid": 2, "parent_sid": 61604, "channel": "sysmon"},
    "file_rename": {"sysmon_eid": 11, "parent_sid": 61613, "channel": "sysmon"},
    "file_executable_detected": {"sysmon_eid": 29, "parent_sid": 61613, "channel": "sysmon"},
    "dns_query": {"sysmon_eid": 22, "parent_sid": 61624, "channel": "sysmon"},
    "pipe_created": {"sysmon_eid": 17, "parent_sid": 61619, "channel": "sysmon"},
    "create_stream_hash": {"sysmon_eid": 15, "parent_sid": 61617, "channel": "sysmon"},
    "wmi_event": {"sysmon_eid": 19, "parent_sid": 61621, "channel": "sysmon"},
    "wmi": {"sysmon_eid": 19, "parent_sid": 61621, "channel": "sysmon"},
    "process_tampering": {"sysmon_eid": 25, "parent_sid": 61627, "channel": "sysmon"},
    "sysmon_status": {"parent_sid": 60004, "channel": "sysmon"},
    "sysmon_error": {"parent_sid": 60004, "channel": "sysmon"},
    "sysmon": {"parent_sid": 60004, "channel": "sysmon"},
    # PowerShell
    "ps_script": {"channel": "powershell", "parent_sid": 91801},
    "ps_module": {"channel": "powershell", "parent_sid": 91801},
    "ps_classic_start": {"channel": "powershell", "parent_sid": 91801},
    "ps_classic_provider_start": {"channel": "powershell", "parent_sid": 91801},
    "powershell-classic": {"channel": "powershell", "parent_sid": 91801},
    # Core Windows channels
    "security": {"channel": "security", "parent_sid": 60100},
    "system": {"channel": "system", "parent_sid": 60106},
    "application": {"channel": "application", "parent_sid": 60003},
    # Windows Defender (parent 60005 in Wazuh defaults)
    "windefend": {"channel": "windefend", "parent_sid": 60005},
    # Windows Firewall (parent 60016 in Wazuh defaults)
    "firewall-as": {"channel": "firewall", "parent_sid": 60016},
    # Other Windows services → generic eventchannel parent (60000)
    "appxdeployment-server": {"channel": "application", "parent_sid": 60000},
    "appxpackaging-om": {"channel": "application", "parent_sid": 60000},
    "codeintegrity-operational": {"channel": "system", "parent_sid": 60000},
    "bits-client": {"channel": "system", "parent_sid": 60000},
    "dns-client": {"channel": "system", "parent_sid": 60000},
    "dns-server": {"channel": "system", "parent_sid": 60000},
    "taskscheduler": {"channel": "system", "parent_sid": 60000},
    "iis-configuration": {"channel": "application", "parent_sid": 60000},
    "ntlm": {"channel": "security", "parent_sid": 60000},
    "security-mitigations": {"channel": "security", "parent_sid": 60000},
    "applocker": {"channel": "security", "parent_sid": 60000},
    "ldap": {"channel": "system", "parent_sid": 60000},
    "lsa-server": {"channel": "security", "parent_sid": 60000},
    "openssh": {"channel": "system", "parent_sid": 60000},
    "microsoft-servicebus-client": {"channel": "application", "parent_sid": 60000},
    "shell-core": {"channel": "system", "parent_sid": 60000},
    "smbclient-security": {"channel": "security", "parent_sid": 60000},
    "smbserver-connectivity": {"channel": "system", "parent_sid": 60000},
    "terminalservices-localsessionmanager": {"channel": "system", "parent_sid": 60000},
    "capi2": {"channel": "application", "parent_sid": 60000},
    "certificateservicesclient-lifecycle-system": {"channel": "system", "parent_sid": 60000},
    "diagnosis-scripted": {"channel": "system", "parent_sid": 60000},
    "msexchange-management": {"channel": "application", "parent_sid": 60000},
    "raw_access_thread": {"sysmon_eid": 9, "parent_sid": 61611, "channel": "sysmon"},
    # ── Linux (Wazuh syslog/auditd decoders) ──
    # Sigma linux logsource uses `product: linux` with these categories/services.
    "auditd": {"channel": "linux", "parent_sid": 80700},
    "syslog": {"channel": "linux", "parent_sid": 5100},
    "sshd": {"channel": "linux", "parent_sid": 5700},
    "sudo": {"channel": "linux", "parent_sid": 5300},
    "cron": {"channel": "linux", "parent_sid": 2800},
    "clamav": {"channel": "linux", "parent_sid": 52500},
    "modsecurity": {"channel": "linux", "parent_sid": 30300},
    "linux_process_creation": {"channel": "linux", "parent_sid": 80700},
    "linux_network_connection": {"channel": "linux", "parent_sid": 80700},
    "linux_file_event": {"channel": "linux", "parent_sid": 80700},
    # ── Cloud (Wazuh cloud integration decoders) ──
    "aws_cloudtrail": {"channel": "cloud", "parent_sid": 80200},
    "azure_activitylogs": {"channel": "cloud", "parent_sid": 87800},
    "azure_signinlogs": {"channel": "cloud", "parent_sid": 87800},
    "azure_auditlogs": {"channel": "cloud", "parent_sid": 87800},
    "azure": {"channel": "cloud", "parent_sid": 87800},
    "gcp_audit": {"channel": "cloud", "parent_sid": 65000},
    "gcp.audit": {"channel": "cloud", "parent_sid": 65000},
    "okta": {"channel": "cloud", "parent_sid": 87200},
    "m365": {"channel": "cloud", "parent_sid": 87800},
    "microsoft365": {"channel": "cloud", "parent_sid": 87800},
}

SIGMA_FIELD_TO_WAZUH = {
    "Image": "win.eventdata.image",
    "OriginalFileName": "win.eventdata.originalFileName",
    "CommandLine": "win.eventdata.commandLine",
    "ParentImage": "win.eventdata.parentImage",
    "ParentCommandLine": "win.eventdata.parentCommandLine",
    "User": "win.eventdata.user",
    "TargetFilename": "win.eventdata.targetFilename",
    "TargetObject": "win.eventdata.targetObject",
    "SourceImage": "win.eventdata.sourceImage",
    "TargetImage": "win.eventdata.targetImage",
    "DestinationHostname": "win.eventdata.destinationHostname",
    "DestinationPort": "win.eventdata.destinationPort",
    "QueryName": "win.eventdata.queryName",
    "PipeName": "win.eventdata.pipeName",
    "ScriptBlockText": "win.eventdata.scriptBlockText",
    "ServiceName": "win.eventdata.serviceName",
    "ImagePath": "win.eventdata.imagePath",
    "Details": "win.eventdata.details",
    "CallTrace": "win.eventdata.callTrace",
    "GrantedAccess": "win.eventdata.grantedAccess",
    "Hashes": "win.eventdata.hashes",
    "ImageLoaded": "win.eventdata.imageLoaded",
    "SignatureStatus": "win.eventdata.signatureStatus",
    "Signed": "win.eventdata.signed",
}


def parse_sigma_rule(file_path: Path) -> dict | None:
    """Parse a single Sigma rule file (YAML or JSON; they map 1:1)."""
    try:
        with open(file_path) as f:
            content = f.read()
        if str(file_path).endswith(".json"):
            import json

            rule = json.loads(content)
        else:
            docs = list(yaml.safe_load_all(content))
            if not docs:
                return None
            rule = docs[0]
        if not isinstance(rule, dict) or "title" not in rule:
            return None
        rule["_file_path"] = str(file_path)
        return rule
    except Exception:
        return None


def assess_convertibility(rule: dict) -> dict:
    """Assess whether a Sigma rule can be converted to Wazuh format."""
    result = {
        "title": rule.get("title", ""),
        "status": rule.get("status", "unknown"),
        "level": rule.get("level", "medium"),
        "convertible": False,
        "reason": "",
        "complexity": "simple",
        "logsource_category": "",
        "mitre_tags": [],
    }

    logsource = rule.get("logsource", {})
    category = logsource.get("category", "")
    product = logsource.get("product", "")
    service = logsource.get("service", "")

    result["logsource_category"] = category or service

    if product and product != "windows":
        result["reason"] = f"Non-Windows product: {product}"
        return result

    source_key = category or service
    if source_key not in SIGMA_LOGSOURCE_TO_WAZUH:
        result["reason"] = f"Unmapped logsource: {source_key}"
        return result

    detection = rule.get("detection", {})
    if not detection:
        result["reason"] = "No detection block"
        return result

    condition = detection.get("condition", "")
    if any(op in condition for op in ["near", "temporal", "|count", "|min", "|max", "|avg", "|sum"]):
        result["reason"] = f"Aggregation/temporal condition: {condition}"
        result["complexity"] = "aggregation"
        return result

    tags = rule.get("tags", [])
    for tag in tags:
        if tag.startswith("attack.t"):
            tid = tag.replace("attack.", "").upper()
            result["mitre_tags"].append(tid)

    if " or " in condition and " and " in condition:
        result["complexity"] = "complex"
    elif " or " in condition or "1 of" in condition or "all of" in condition:
        result["complexity"] = "moderate"

    result["convertible"] = True
    return result


def analyze_sigma_directory(rules_dir: Path) -> dict:
    """Analyze all Sigma rules in a directory and produce a report."""
    all_rules = []
    category_stats = defaultdict(lambda: {"total": 0, "convertible": 0, "rules": []})
    level_stats = defaultdict(int)
    status_stats = defaultdict(int)
    complexity_stats = defaultdict(int)
    mitre_techniques = defaultdict(int)

    yml_files = sorted(rules_dir.rglob("*.yml"))
    console.print(f"[bold]Analyzing {len(yml_files)} Sigma rules...[/]")

    for f in yml_files:
        rule = parse_sigma_rule(f)
        if not rule:
            continue

        assessment = assess_convertibility(rule)
        all_rules.append(assessment)

        cat = assessment["logsource_category"] or "unknown"
        category_stats[cat]["total"] += 1
        if assessment["convertible"]:
            category_stats[cat]["convertible"] += 1
            category_stats[cat]["rules"].append(assessment)

        level_stats[assessment["level"]] += 1
        status_stats[assessment["status"]] += 1
        complexity_stats[assessment["complexity"]] += 1

        for t in assessment["mitre_tags"]:
            mitre_techniques[t] += 1

    convertible = [r for r in all_rules if r["convertible"]]
    high_value = [r for r in convertible if r["level"] in ("high", "critical")]

    report = {
        "total_rules": len(all_rules),
        "convertible": len(convertible),
        "high_value": len(high_value),
        "category_stats": dict(category_stats),
        "level_stats": dict(level_stats),
        "status_stats": dict(status_stats),
        "complexity_stats": dict(complexity_stats),
        "mitre_techniques": dict(mitre_techniques),
        "convertible_rules": convertible,
    }

    _print_report(report)
    return report


def _print_report(report: dict):
    """Print a summary of the Sigma analysis."""
    console.print("\n[bold green]Sigma Analysis Complete[/]")
    console.print(f"  Total rules analyzed: {report['total_rules']}")
    console.print(f"  Convertible to Wazuh: {report['convertible']}")
    console.print(f"  High/Critical value: {report['high_value']}")

    table = Table(title="Sigma Rules by Category")
    table.add_column("Category", style="bold")
    table.add_column("Total", justify="right")
    table.add_column("Convertible", justify="right")
    table.add_column("Rate", justify="right")

    for cat, stats in sorted(report["category_stats"].items(), key=lambda x: -x[1]["total"]):
        rate = f"{stats['convertible'] / stats['total'] * 100:.0f}%" if stats["total"] > 0 else "0%"
        table.add_row(cat, str(stats["total"]), str(stats["convertible"]), rate)
    console.print(table)

    table2 = Table(title="Sigma Rules by Severity Level")
    table2.add_column("Level", style="bold")
    table2.add_column("Count", justify="right")
    for lvl in ["critical", "high", "medium", "low", "informational"]:
        if lvl in report["level_stats"]:
            table2.add_row(lvl, str(report["level_stats"][lvl]))
    console.print(table2)

    table3 = Table(title="Conversion Complexity")
    table3.add_column("Complexity", style="bold")
    table3.add_column("Count", justify="right")
    for cx in ["simple", "moderate", "complex", "aggregation"]:
        if cx in report["complexity_stats"]:
            table3.add_row(cx, str(report["complexity_stats"][cx]))
    console.print(table3)

    console.print("\n[bold]Top MITRE techniques in Sigma rules:[/]")
    for tech, count in sorted(report["mitre_techniques"].items(), key=lambda x: -x[1])[:15]:
        console.print(f"  {tech}: {count} rules")
