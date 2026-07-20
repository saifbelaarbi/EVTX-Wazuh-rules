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
SAMPLE_EVENTS_FILE = METADATA_DIR / "sample_events.json"

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

# Composite/correlation rules (ids in this range) reference parents across
# tactics via if_sid/if_matched_sid. Wazuh loads etc/rules alphabetically and
# a reference to a not-yet-loaded rule is dropped (warning 7620), so these
# rules must live in a file that sorts AFTER every tactic/technique/source
# file in the same view.
COMPOSITE_ID_RANGE = (115000, 119989)
COMPOSITE_FILE = "zz_composites"


def _is_composite(rule: dict) -> bool:
    return COMPOSITE_ID_RANGE[0] <= rule["id"] <= COMPOSITE_ID_RANGE[1]


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
    # Prefer an explicit category from metadata (set by rule_builder and
    # sigma_converter); converted Sigma rules have no `pattern` object.
    meta_cat = rule.get("metadata", {}).get("source_category")
    if meta_cat:
        return meta_cat

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
    root.addprevious(etree.Comment(f" EVTX-Wazuh-Rules | Auto-generated | {group_name} "))

    for rule in rules:
        root.append(rule["xml_element"])

    # Pretty print
    etree.indent(root, space="  ")
    xml_str = etree.tostring(root, pretty_print=True, encoding="unicode")
    return xml_str


def _load_existing_rule_elements(out_file: Path) -> dict[str, etree._Element]:
    """Read existing <rule> elements from an XML group file, keyed by rule id.

    Lets the by_tactic / by_technique / by_source exports MERGE with rules
    already on disk instead of overwriting them. Without this, running
    ``generate`` (EVTX) then ``convert-sigma`` (Sigma) would clobber the shared
    per-tactic files and leave the rule index pointing at rules that no longer
    exist in any XML (phantom entries).
    """
    existing: dict[str, etree._Element] = {}
    if not out_file.exists():
        return existing
    try:
        tree = etree.parse(str(out_file))
    except etree.XMLSyntaxError:
        return existing
    for rule_elem in tree.getroot().iter("rule"):
        rid = rule_elem.get("id")
        if rid:
            existing[rid] = rule_elem
    return existing


def _write_group_merged(out_file: Path, new_rules: list[dict], group_name: str):
    """Merge ``new_rules`` into any rules already in ``out_file`` and write.

    New rules win on id collision. Output is sorted by rule id for stable diffs.
    """
    merged = _load_existing_rule_elements(out_file)
    for rule in new_rules:
        merged[str(rule["id"])] = rule["xml_element"]

    root = etree.Element("group", name=f"{group_name},")
    root.addprevious(etree.Comment(f" EVTX-Wazuh-Rules | Auto-generated | {group_name} "))
    for rid in sorted(merged, key=int):
        root.append(merged[rid])

    etree.indent(root, space="  ")
    xml_str = etree.tostring(root, pretty_print=True, encoding="unicode")
    with open(out_file, "w") as f:
        f.write(xml_str)
    return len(merged)


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
        manifest.append(
            {
                "rule_id": rule["id"],
                "level": rule["level"],
                "tactic": rule["metadata"]["tactic"],
                "technique": rule["metadata"]["technique_name"],
                "confidence": rule["metadata"]["confidence"],
                "description": rule["metadata"].get("technique_name", ""),
                "source_evtx": rule["metadata"]["source_evtx"],
                "field_matches": rule["metadata"]["field_matches"],
            }
        )

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
        key = COMPOSITE_FILE if _is_composite(rule) else rule["metadata"].get("tactic", "other")
        by_tactic[key].append(rule)

    for tactic, tactic_rules in by_tactic.items():
        out_file = out_dir / f"{tactic}.xml"
        total = _write_group_merged(out_file, tactic_rules, f"windows,{tactic}")
        console.print(f"  [green]{tactic}.xml[/]: +{len(tactic_rules)} ({total} total)")


def export_by_technique(rules: list[dict]):
    """Export rules grouped by MITRE technique."""
    out_dir = RULES_DIR / "by_technique"
    out_dir.mkdir(parents=True, exist_ok=True)

    by_technique = defaultdict(list)
    for rule in rules:
        slug = COMPOSITE_FILE if _is_composite(rule) else _get_technique_slug(rule)
        by_technique[slug].append(rule)

    for slug, tech_rules in by_technique.items():
        out_file = out_dir / f"{slug}.xml"
        total = _write_group_merged(out_file, tech_rules, f"windows,{slug}")
        console.print(f"  [green]{slug}.xml[/]: +{len(tech_rules)} ({total} total)")


def export_by_source(rules: list[dict]):
    """Export rules grouped by Windows event source."""
    out_dir = RULES_DIR / "by_source"
    out_dir.mkdir(parents=True, exist_ok=True)

    by_source = defaultdict(list)
    for rule in rules:
        source = COMPOSITE_FILE if _is_composite(rule) else _get_source_category(rule)
        by_source[source].append(rule)

    for source, source_rules in by_source.items():
        out_file = out_dir / f"{source}.xml"
        total = _write_group_merged(out_file, source_rules, f"windows,{source}")
        console.print(f"  [green]{source}.xml[/]: +{len(source_rules)} ({total} total)")


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

    changelog_entries = []
    now = datetime.now(timezone.utc).isoformat()

    for rule in rules:
        meta = rule["metadata"]
        mitre_ids = meta.get("mitre_ids", []) or []
        rid = str(rule["id"])
        prev = index.get(rid)

        entry = {
            "description": meta.get("technique_name", ""),
            "level": rule["level"],
            "tactic": meta.get("tactic", ""),
            "technique_id": mitre_ids[0] if mitre_ids else "",
            "mitre_ids": mitre_ids,
            "technique_name": meta.get("technique_name", ""),
            "source_evtx": meta.get("source_evtx", ""),
            "source_category": meta.get("source_category", ""),
            "parent_sid": meta.get("parent_sid", 0),
            "confidence": meta.get("confidence", "medium"),
            "created": meta.get("created", ""),
            "field_matches": meta.get("field_matches", {}),
            "sigma_id": meta.get("sigma_id", ""),
        }

        # Versioning: bump when the detection logic or level changes.
        if prev is None:
            entry["version"] = 1
            entry["last_modified"] = now
            changelog_entries.append({"timestamp": now, "rule_id": rid, "action": "add", "version": 1})
        else:
            changed = prev.get("field_matches") != entry["field_matches"] or prev.get("level") != entry["level"]
            if changed:
                entry["version"] = prev.get("version", 1) + 1
                entry["last_modified"] = now
                changelog_entries.append(
                    {
                        "timestamp": now,
                        "rule_id": rid,
                        "action": "modify",
                        "old_version": prev.get("version", 1),
                        "version": entry["version"],
                    }
                )
            else:
                entry["version"] = prev.get("version", 1)
                entry["last_modified"] = prev.get("last_modified", now)

        index[rid] = entry

    with open(RULE_INDEX_FILE, "w") as f:
        json.dump(index, f, indent=2)

    if changelog_entries:
        _append_changelog(changelog_entries)

    console.print(f"\n[bold green]Rule index updated:[/] {len(index)} total rules")
    _update_sample_events(rules)


CHANGELOG_FILE = METADATA_DIR / "changelog.json"


def _append_changelog(entries: list[dict]):
    """Append rule add/modify records to the changelog history."""
    history = []
    if CHANGELOG_FILE.exists():
        try:
            with open(CHANGELOG_FILE) as f:
                history = json.load(f)
        except (json.JSONDecodeError, OSError):
            history = []
    history.extend(entries)
    with open(CHANGELOG_FILE, "w") as f:
        json.dump(history, f, indent=2)


def _update_sample_events(rules: list[dict]):
    """Persist each rule's minimized trigger event to a sidecar file.

    Kept out of rule_index.json so the index stays lean; keyed by rule id.
    """
    samples = {}
    if SAMPLE_EVENTS_FILE.exists():
        with open(SAMPLE_EVENTS_FILE) as f:
            samples = json.load(f)

    for rule in rules:
        sample = rule["metadata"].get("sample_event")
        if sample:
            samples[str(rule["id"])] = sample

    with open(SAMPLE_EVENTS_FILE, "w") as f:
        json.dump(samples, f, indent=2)


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
