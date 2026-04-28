"""Analyze SigmaHQ Sigma rules and assess conversion potential to Wazuh format."""

from pathlib import Path
from collections import defaultdict

import yaml
from rich.console import Console
from rich.table import Table

console = Console()


SIGMA_STATUS_PRIORITY = {"stable": 3, "test": 2, "experimental": 1, "deprecated": 0}

SIGMA_LOGSOURCE_TO_WAZUH = {
    "process_creation": {"sysmon_eid": 1, "parent_sid": 61603},
    "network_connection": {"sysmon_eid": 3, "parent_sid": 61605},
    "driver_load": {"sysmon_eid": 6, "parent_sid": 61608},
    "image_load": {"sysmon_eid": 7, "parent_sid": 61609},
    "create_remote_thread": {"sysmon_eid": 8, "parent_sid": 61610},
    "process_access": {"sysmon_eid": 10, "parent_sid": 61612},
    "file_event": {"sysmon_eid": 11, "parent_sid": 61613},
    "registry_event": {"sysmon_eid": 13, "parent_sid": 61615},
    "registry_set": {"sysmon_eid": 13, "parent_sid": 61615},
    "registry_add": {"sysmon_eid": 12, "parent_sid": 61614},
    "registry_delete": {"sysmon_eid": 12, "parent_sid": 61614},
    "registry_rename": {"sysmon_eid": 14, "parent_sid": 61616},
    "file_access": {"sysmon_eid": 11, "parent_sid": 61613},
    "file_delete": {"sysmon_eid": 23, "parent_sid": 61625},
    "file_change": {"sysmon_eid": 2, "parent_sid": 61604},
    "file_rename": {"sysmon_eid": 11, "parent_sid": 61613},
    "dns_query": {"sysmon_eid": 22, "parent_sid": 61624},
    "pipe_created": {"sysmon_eid": 17, "parent_sid": 61619},
    "create_stream_hash": {"sysmon_eid": 15, "parent_sid": 61617},
    "wmi_event": {"sysmon_eid": 19, "parent_sid": 61621},
    "process_tampering": {"sysmon_eid": 25, "parent_sid": 61627},
    "ps_script": {"channel": "powershell", "parent_sid": 91801},
    "ps_module": {"channel": "powershell", "parent_sid": 91801},
    "ps_classic_start": {"channel": "powershell", "parent_sid": 91801},
    "security": {"channel": "security", "parent_sid": 60100},
    "system": {"channel": "system", "parent_sid": 60106},
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
    """Parse a single Sigma YAML rule file."""
    try:
        with open(file_path) as f:
            content = f.read()
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
    console.print(f"\n[bold green]Sigma Analysis Complete[/]")
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

    console.print(f"\n[bold]Top MITRE techniques in Sigma rules:[/]")
    for tech, count in sorted(report["mitre_techniques"].items(), key=lambda x: -x[1])[:15]:
        console.print(f"  {tech}: {count} rules")
