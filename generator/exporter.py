"""Export generated rules to organized XML files and update metadata."""

import json
import shutil
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

from lxml import etree
from rich.console import Console

console = Console()

PROJECT_ROOT = Path(__file__).resolve().parent.parent
RULES_DIR = PROJECT_ROOT / "database" / "rules"
DRAFTS_DIR = PROJECT_ROOT / "database" / "drafts"
METADATA_DIR = PROJECT_ROOT / "database" / "metadata"
RULE_INDEX_FILE = METADATA_DIR / "rule_index.json"
PROVENANCE_FILE = METADATA_DIR / "provenance.json"

# MITRE technique ID -> human-readable name mapping (common ones)
TECHNIQUE_NAMES = {
    "T1003": "credential_dumping",
    "T1059": "command_scripting",
    "T1547": "boot_autostart",
    "T1053": "scheduled_task",
    "T1543": "create_modify_service",
    "T1548": "abuse_elevation",
    "T1134": "access_token_manipulation",
    "T1055": "process_injection",
    "T1027": "obfuscated_files",
    "T1070": "indicator_removal",
    "T1021": "remote_services",
    "T1087": "account_discovery",
    "T1082": "system_info_discovery",
    "T1071": "application_layer_protocol",
    "T1573": "encrypted_channel",
    "T1105": "ingress_tool_transfer",
    "T1566": "phishing",
    "T1190": "exploit_public_app",
    "T1078": "valid_accounts",
    "T1041": "exfil_over_c2",
    "T1485": "data_destruction",
    "T1486": "data_encrypted_for_impact",
    "T1489": "service_stop",
    "T1110": "brute_force",
    "T1558": "steal_kerberos_ticket",
    "T1569": "system_services",
    "T1204": "user_execution",
    "T1068": "exploitation_for_privesc",
    "T1083": "file_directory_discovery",
    "T1570": "lateral_tool_transfer",
    "T1080": "taint_shared_content",
    "T1005": "data_from_local_system",
    "T1039": "data_from_network_shared",
    "T1074": "data_staged",
    "T1048": "exfil_over_alt_protocol",
    "T1567": "exfil_over_web_service",
}

# Map Sysmon provider to source category
SOURCE_CATEGORIES = {
    "Microsoft-Windows-Sysmon": "sysmon",
    "Microsoft-Windows-Security-Auditing": "security",
    "Microsoft-Windows-PowerShell": "powershell",
    "PowerShell": "powershell",
    "Service Control Manager": "system",
}


def _get_source_category(rule: dict) -> str:
    """Determine the event source category for a rule."""
    pattern = rule.get("pattern")
    if pattern:
        provider = pattern.provider_name
        for key, cat in SOURCE_CATEGORIES.items():
            if key in provider:
                return cat
        channel = pattern.channel.lower()
        if "security" in channel:
            return "security"
        if "system" in channel:
            return "system"
        if "powershell" in channel:
            return "powershell"
        if "sysmon" in channel:
            return "sysmon"
    return "other"


def _get_technique_slug(rule: dict) -> str:
    """Get a filename-safe technique identifier."""
    mitre_ids = rule["metadata"].get("mitre_ids", [])
    if mitre_ids:
        tid = mitre_ids[0]
        name = TECHNIQUE_NAMES.get(tid, "unknown")
        return f"{tid}_{name}"
    return f"unknown_{rule['metadata'].get('tactic', 'misc')}"


def _build_xml_group(rules: list[dict], group_name: str) -> str:
    """Build a complete Wazuh XML rule group."""
    root = etree.Element("group", name=f"{group_name},")

    # Add comment header
    root.addprevious(etree.Comment(
        f" EVTX-Wazuh-Rules | Auto-generated | {group_name} "
    ))

    for rule in rules:
        root.append(rule["xml_element"])

    # Pretty print
    etree.indent(root, space="  ")
    xml_decl = '<?xml version="1.0" encoding="UTF-8"?>\n'
    xml_str = etree.tostring(root, pretty_print=True, encoding="unicode")
    return xml_decl + xml_str


def export_drafts(rules: list[dict]) -> Path:
    """Export rules as drafts for review."""
    DRAFTS_DIR.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    draft_file = DRAFTS_DIR / f"draft_{timestamp}.xml"

    xml_content = _build_xml_group(rules, "evtx_generated,draft")

    with open(draft_file, "w") as f:
        f.write(xml_content)

    # Also write a review manifest
    manifest_file = DRAFTS_DIR / f"draft_{timestamp}_manifest.json"
    manifest = []
    for rule in rules:
        manifest.append({
            "rule_id": rule["id"],
            "level": rule["level"],
            "tactic": rule["metadata"]["tactic"],
            "technique": rule["metadata"]["technique_name"],
            "confidence": rule["metadata"]["confidence"],
            "description": rule["metadata"].get("technique_name", ""),
            "source_evtx": rule["metadata"]["source_evtx"],
            "field_matches": rule["metadata"]["field_matches"],
        })

    with open(manifest_file, "w") as f:
        json.dump(manifest, f, indent=2)

    console.print(f"[bold yellow]Drafts exported:[/] {draft_file}")
    console.print(f"[bold yellow]Review manifest:[/] {manifest_file}")
    console.print(f"  {len(rules)} rules awaiting review")

    return draft_file


def export_by_tactic(rules: list[dict]):
    """Export rules grouped by MITRE tactic."""
    out_dir = RULES_DIR / "by_tactic"
    out_dir.mkdir(parents=True, exist_ok=True)

    by_tactic = defaultdict(list)
    for rule in rules:
        tactic = rule["metadata"].get("tactic", "other")
        by_tactic[tactic].append(rule)

    for tactic, tactic_rules in by_tactic.items():
        xml_content = _build_xml_group(tactic_rules, f"windows,{tactic}")
        out_file = out_dir / f"{tactic}.xml"
        with open(out_file, "w") as f:
            f.write(xml_content)
        console.print(f"  [green]{tactic}.xml[/]: {len(tactic_rules)} rules")


def export_by_technique(rules: list[dict]):
    """Export rules grouped by MITRE technique."""
    out_dir = RULES_DIR / "by_technique"
    out_dir.mkdir(parents=True, exist_ok=True)

    by_technique = defaultdict(list)
    for rule in rules:
        slug = _get_technique_slug(rule)
        by_technique[slug].append(rule)

    for slug, tech_rules in by_technique.items():
        xml_content = _build_xml_group(tech_rules, f"windows,{slug}")
        out_file = out_dir / f"{slug}.xml"
        with open(out_file, "w") as f:
            f.write(xml_content)
        console.print(f"  [green]{slug}.xml[/]: {len(tech_rules)} rules")


def export_by_source(rules: list[dict]):
    """Export rules grouped by Windows event source."""
    out_dir = RULES_DIR / "by_source"
    out_dir.mkdir(parents=True, exist_ok=True)

    by_source = defaultdict(list)
    for rule in rules:
        source = _get_source_category(rule)
        by_source[source].append(rule)

    for source, source_rules in by_source.items():
        xml_content = _build_xml_group(source_rules, f"windows,{source}")
        out_file = out_dir / f"{source}.xml"
        with open(out_file, "w") as f:
            f.write(xml_content)
        console.print(f"  [green]{source}.xml[/]: {len(source_rules)} rules")


def export_all_views(rules: list[dict]):
    """Export rules in all three organizational views."""
    console.print("\n[bold]Exporting by tactic...[/]")
    export_by_tactic(rules)

    console.print("\n[bold]Exporting by technique...[/]")
    export_by_technique(rules)

    console.print("\n[bold]Exporting by source...[/]")
    export_by_source(rules)


def update_rule_index(rules: list[dict]):
    """Update the master rule index with new rules."""
    METADATA_DIR.mkdir(parents=True, exist_ok=True)

    index = {}
    if RULE_INDEX_FILE.exists():
        with open(RULE_INDEX_FILE) as f:
            index = json.load(f)

    for rule in rules:
        meta = rule["metadata"]
        index[str(rule["id"])] = {
            "description": meta.get("technique_name", ""),
            "level": rule["level"],
            "tactic": meta.get("tactic", ""),
            "technique_id": meta.get("mitre_ids", [""])[0] if meta.get("mitre_ids") else "",
            "technique_name": meta.get("technique_name", ""),
            "source_evtx": meta.get("source_evtx", ""),
            "parent_sid": meta.get("parent_sid", 0),
            "confidence": meta.get("confidence", "medium"),
            "created": meta.get("created", ""),
            "field_matches": meta.get("field_matches", {}),
        }

    with open(RULE_INDEX_FILE, "w") as f:
        json.dump(index, f, indent=2)

    console.print(f"\n[bold green]Rule index updated:[/] {len(index)} total rules")


def update_provenance(rules: list[dict]):
    """Update the provenance tracking file."""
    METADATA_DIR.mkdir(parents=True, exist_ok=True)

    provenance = {}
    if PROVENANCE_FILE.exists():
        with open(PROVENANCE_FILE) as f:
            provenance = json.load(f)

    for rule in rules:
        source = rule["metadata"].get("source_evtx", "unknown")
        if source not in provenance:
            provenance[source] = {
                "rules_generated": [],
                "last_processed": datetime.now(timezone.utc).isoformat(),
            }
        if rule["id"] not in provenance[source]["rules_generated"]:
            provenance[source]["rules_generated"].append(rule["id"])
        provenance[source]["last_processed"] = datetime.now(timezone.utc).isoformat()

    with open(PROVENANCE_FILE, "w") as f:
        json.dump(provenance, f, indent=2)


def export_for_deployment(dest: Path, view: str = "by_tactic"):
    """Copy rules to a deployment target directory."""
    source_dir = RULES_DIR / view
    if not source_dir.exists():
        console.print(f"[red]No rules found in {source_dir}[/]")
        return

    dest.mkdir(parents=True, exist_ok=True)
    copied = 0
    for xml_file in source_dir.glob("*.xml"):
        shutil.copy2(xml_file, dest / xml_file.name)
        copied += 1

    console.print(f"[bold green]Deployed {copied} rule files to {dest}[/]")
