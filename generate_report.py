#!/usr/bin/env python3
"""Generate a comprehensive report of all extracted Wazuh rules.

Outputs:
  - docs/RULES_REPORT.md   : Full human-readable rule report
  - docs/COVERAGE_MATRIX.md: MITRE ATT&CK coverage matrix
  - docs/SOURCES.md        : EVTX source documentation
"""

import json
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent
RULE_INDEX = PROJECT_ROOT / "database" / "metadata" / "rule_index.json"
PROVENANCE = PROJECT_ROOT / "database" / "metadata" / "provenance.json"
ID_ALLOC = PROJECT_ROOT / "database" / "metadata" / "id_allocations.json"
RULES_DIR = PROJECT_ROOT / "database" / "rules"
DOCS_DIR = PROJECT_ROOT / "docs"

# MITRE ATT&CK tactic display names and order
TACTIC_ORDER = [
    ("initial_access", "Initial Access", "TA0001"),
    ("execution", "Execution", "TA0002"),
    ("persistence", "Persistence", "TA0003"),
    ("privilege_escalation", "Privilege Escalation", "TA0004"),
    ("defense_evasion", "Defense Evasion", "TA0005"),
    ("credential_access", "Credential Access", "TA0006"),
    ("discovery", "Discovery", "TA0007"),
    ("lateral_movement", "Lateral Movement", "TA0008"),
    ("collection", "Collection", "TA0009"),
    ("command_and_control", "Command and Control", "TA0011"),
    ("exfiltration", "Exfiltration", "TA0010"),
    ("impact", "Impact", "TA0040"),
]

TECHNIQUE_NAMES = {
    "T1003": "OS Credential Dumping",
    "T1021": "Remote Services",
    "T1027": "Obfuscated Files or Information",
    "T1053": "Scheduled Task/Job",
    "T1055": "Process Injection",
    "T1059": "Command and Scripting Interpreter",
    "T1068": "Exploitation for Privilege Escalation",
    "T1070": "Indicator Removal",
    "T1071": "Application Layer Protocol",
    "T1078": "Valid Accounts",
    "T1082": "System Information Discovery",
    "T1083": "File and Directory Discovery",
    "T1087": "Account Discovery",
    "T1105": "Ingress Tool Transfer",
    "T1110": "Brute Force",
    "T1134": "Access Token Manipulation",
    "T1190": "Exploit Public-Facing Application",
    "T1204": "User Execution",
    "T1485": "Data Destruction",
    "T1486": "Data Encrypted for Impact",
    "T1489": "Service Stop",
    "T1543": "Create or Modify System Process",
    "T1547": "Boot or Logon Autostart Execution",
    "T1548": "Abuse Elevation Control Mechanism",
    "T1558": "Steal or Forge Kerberos Tickets",
    "T1566": "Phishing",
    "T1569": "System Services",
    "T1570": "Lateral Tool Transfer",
    "T1573": "Encrypted Channel",
}

LEVEL_NAMES = {
    0: "Ignored", 1: "None", 2: "System low", 3: "System low",
    4: "System low", 5: "User-generated", 6: "Low relevance",
    7: "Bad word matching", 8: "First time seen", 9: "Error from invalid source",
    10: "Multiple user-generated errors", 11: "Integrity checking warning",
    12: "High importance event", 13: "Unusual error (high importance)",
    14: "High importance security event", 15: "Severe attack",
}


def load_json(path):
    if path.exists():
        with open(path) as f:
            return json.load(f)
    return {}


def generate_rules_report():
    """Generate the main RULES_REPORT.md."""
    index = load_json(RULE_INDEX)
    provenance = load_json(PROVENANCE)
    allocations = load_json(ID_ALLOC)

    if not index:
        print("No rules found in index.")
        return

    # Group rules by tactic
    by_tactic = defaultdict(list)
    for rid, meta in index.items():
        tactic = meta.get("tactic", "unknown")
        by_tactic[tactic].append((rid, meta))

    # Sort each tactic's rules by ID
    for tactic in by_tactic:
        by_tactic[tactic].sort(key=lambda x: int(x[0]))

    # Compute stats
    total_rules = len(index)
    levels = Counter(m["level"] for m in index.values())
    tactics = Counter(m["tactic"] for m in index.values())
    confidences = Counter(m["confidence"] for m in index.values())
    techniques = Counter(m.get("technique_id", "") for m in index.values())
    sources_used = set()
    for p_key in provenance:
        parts = p_key.split("/")
        if parts:
            sources_used.add(parts[0])

    total_evtx_processed = len(provenance)

    lines = []
    lines.append("# Wazuh Rule Database Report")
    lines.append("")
    lines.append(f"> Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}")
    lines.append(f"> Pipeline version: 1.0.0")
    lines.append("")

    # ── Overview ──
    lines.append("## Overview")
    lines.append("")
    lines.append("| Metric | Value |")
    lines.append("|--------|-------|")
    lines.append(f"| Total rules generated | **{total_rules}** |")
    lines.append(f"| EVTX files processed | {total_evtx_processed} |")
    lines.append(f"| EVTX sources used | {len(sources_used)} |")
    lines.append(f"| MITRE tactics covered | {len(tactics)} / 12 |")
    lines.append(f"| MITRE techniques covered | {len([t for t in techniques if t])} |")
    lines.append(f"| Rule ID range | 100000 - 120000 |")
    lines.append("")

    # ── Alert Level Distribution ──
    lines.append("## Alert Level Distribution")
    lines.append("")
    lines.append("| Level | Wazuh Severity | Count | Percentage |")
    lines.append("|-------|----------------|-------|------------|")
    for lvl in sorted(levels.keys()):
        count = levels[lvl]
        pct = count / total_rules * 100
        name = LEVEL_NAMES.get(lvl, "")
        bar = "█" * int(pct / 2)
        lines.append(f"| {lvl} | {name} | {count} | {pct:.1f}% {bar} |")
    lines.append("")

    # ── Confidence Distribution ──
    lines.append("## Detection Confidence Distribution")
    lines.append("")
    lines.append("| Confidence | Count | Description |")
    lines.append("|------------|-------|-------------|")
    conf_desc = {
        "high": "Exact tool/process name match",
        "medium": "Command-line pattern or behavioral indicator",
        "low": "Heuristic / generic event",
    }
    for conf in ["high", "medium", "low"]:
        count = confidences.get(conf, 0)
        lines.append(f"| {conf} | {count} | {conf_desc.get(conf, '')} |")
    lines.append("")

    # ── Rules by MITRE Tactic ──
    lines.append("## Rules by MITRE ATT&CK Tactic")
    lines.append("")

    for tactic_key, tactic_name, tactic_id in TACTIC_ORDER:
        rules = by_tactic.get(tactic_key, [])
        if not rules:
            continue

        lines.append(f"### {tactic_name} ({tactic_id}) — {len(rules)} rules")
        lines.append("")
        lines.append("| Rule ID | Level | Technique | Description | Confidence | Parent SID |")
        lines.append("|---------|-------|-----------|-------------|------------|------------|")

        for rid, meta in rules:
            tech_id = meta.get("technique_id", "")
            tech_name = TECHNIQUE_NAMES.get(tech_id, tech_id)
            tech_display = f"`{tech_id}` {tech_name}" if tech_id else "-"
            desc = meta.get("description", meta.get("technique_name", ""))
            # Truncate long descriptions
            if len(desc) > 70:
                desc = desc[:67] + "..."
            lines.append(
                f"| `{rid}` | {meta['level']} | {tech_display} "
                f"| {desc} | {meta.get('confidence', '-')} | {meta.get('parent_sid', '-')} |"
            )

        lines.append("")

    # ── File Organization ──
    lines.append("## Exported Rule Files")
    lines.append("")
    lines.append("Rules are exported in three parallel views. Each view contains the same rules, organized differently:")
    lines.append("")

    for view_name, description in [
        ("by_tactic", "One XML file per MITRE ATT&CK tactic. Best for broad deployment."),
        ("by_technique", "One XML file per MITRE technique. Best for selective/granular deployment."),
        ("by_source", "Grouped by Windows event source (Sysmon, Security, PowerShell, System). Aligns with Wazuh decoder structure."),
    ]:
        view_dir = RULES_DIR / view_name
        if not view_dir.exists():
            continue
        files = sorted(view_dir.glob("*.xml"))
        lines.append(f"### `database/rules/{view_name}/`")
        lines.append(f"_{description}_")
        lines.append("")
        lines.append("| File | Rules |")
        lines.append("|------|-------|")
        for f in files:
            # Count rules in file
            content = f.read_text()
            rule_count = content.count('<rule id="')
            lines.append(f"| `{f.name}` | {rule_count} |")
        lines.append("")

    # ── Deployment ──
    lines.append("## Deployment to Wazuh")
    lines.append("")
    lines.append("Copy the desired view's XML files to your Wazuh manager:")
    lines.append("")
    lines.append("```bash")
    lines.append("# Option A: Deploy by tactic (recommended)")
    lines.append("sudo cp database/rules/by_tactic/*.xml /var/ossec/etc/rules/")
    lines.append("")
    lines.append("# Option B: Deploy by source (matches Wazuh decoder structure)")
    lines.append("sudo cp database/rules/by_source/*.xml /var/ossec/etc/rules/")
    lines.append("")
    lines.append("# Restart Wazuh manager to load new rules")
    lines.append("sudo systemctl restart wazuh-manager")
    lines.append("")
    lines.append("# Verify rules loaded")
    lines.append("sudo /var/ossec/bin/wazuh-logtest")
    lines.append("```")
    lines.append("")

    DOCS_DIR.mkdir(parents=True, exist_ok=True)
    report_path = DOCS_DIR / "RULES_REPORT.md"
    report_path.write_text("\n".join(lines))
    print(f"Generated: {report_path} ({len(lines)} lines)")
    return lines


def generate_coverage_matrix():
    """Generate COVERAGE_MATRIX.md — MITRE ATT&CK coverage overview."""
    index = load_json(RULE_INDEX)

    by_tactic = defaultdict(lambda: defaultdict(list))
    for rid, meta in index.items():
        tactic = meta.get("tactic", "unknown")
        tech = meta.get("technique_id", "unknown")
        by_tactic[tactic][tech].append(rid)

    lines = []
    lines.append("# MITRE ATT&CK Coverage Matrix")
    lines.append("")
    lines.append(f"> {len(index)} rules across {len(by_tactic)} tactics")
    lines.append("")
    lines.append("## Coverage Heatmap")
    lines.append("")
    lines.append("| Tactic | ID | Rules | Techniques | Coverage |")
    lines.append("|--------|----|-------|------------|----------|")

    for tactic_key, tactic_name, tactic_id in TACTIC_ORDER:
        techniques = by_tactic.get(tactic_key, {})
        if not techniques:
            rule_count = 0
            tech_count = 0
            bar = ""
        else:
            rule_count = sum(len(rids) for rids in techniques.values())
            tech_count = len([t for t in techniques if t])
            bar = "🟩" * min(rule_count, 20)
        lines.append(
            f"| {tactic_name} | `{tactic_id}` | {rule_count} | {tech_count} | {bar} |"
        )

    lines.append("")

    # Detailed technique breakdown
    lines.append("## Technique Detail")
    lines.append("")
    for tactic_key, tactic_name, tactic_id in TACTIC_ORDER:
        techniques = by_tactic.get(tactic_key, {})
        if not techniques:
            continue
        lines.append(f"### {tactic_name}")
        lines.append("")
        lines.append("| Technique | Name | Rules | Rule IDs |")
        lines.append("|-----------|------|-------|----------|")
        for tech_id, rule_ids in sorted(techniques.items()):
            tech_name = TECHNIQUE_NAMES.get(tech_id, "")
            ids_str = ", ".join(f"`{r}`" for r in sorted(rule_ids, key=int))
            lines.append(f"| `{tech_id}` | {tech_name} | {len(rule_ids)} | {ids_str} |")
        lines.append("")

    # Gaps
    lines.append("## Coverage Gaps")
    lines.append("")
    lines.append("Tactics with **no rules yet** (opportunities for expansion):")
    lines.append("")
    covered = set(by_tactic.keys())
    for tactic_key, tactic_name, tactic_id in TACTIC_ORDER:
        if tactic_key not in covered:
            lines.append(f"- **{tactic_name}** (`{tactic_id}`)")
    lines.append("")

    DOCS_DIR.mkdir(parents=True, exist_ok=True)
    path = DOCS_DIR / "COVERAGE_MATRIX.md"
    path.write_text("\n".join(lines))
    print(f"Generated: {path} ({len(lines)} lines)")


def generate_sources_doc():
    """Generate SOURCES.md — documentation of EVTX sources used."""
    provenance = load_json(PROVENANCE)

    # Group provenance by source (extract source name from full path)
    by_source = defaultdict(list)
    for evtx_path, info in provenance.items():
        # Path like: /home/.../data/evtx_samples/EVTX-ATTACK-SAMPLES/Credential Access/foo.evtx
        source_name = "unknown"
        for known in ["EVTX-ATTACK-SAMPLES", "EVTX-to-MITRE-Attack", "hayabusa-sample-evtx"]:
            if known in evtx_path:
                source_name = known
                break
        # Get the relative path within the source
        if source_name != "unknown" and source_name in evtx_path:
            rel_path = evtx_path.split(source_name + "/", 1)[-1]
        else:
            rel_path = evtx_path.split("/")[-1]
        by_source[source_name].append((rel_path, info))

    lines = []
    lines.append("# EVTX Sources Documentation")
    lines.append("")
    lines.append("This document describes the EVTX sample sources used to generate the Wazuh rule database.")
    lines.append("")

    lines.append("## Source Repositories")
    lines.append("")
    lines.append("| # | Source | Repository | EVTX Files Used | Rules Generated |")
    lines.append("|---|--------|------------|-----------------|-----------------|")

    source_repos = {
        "EVTX-ATTACK-SAMPLES": "https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES",
        "EVTX-to-MITRE-Attack": "https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack",
        "hayabusa-sample-evtx": "https://github.com/Yamato-Security/hayabusa-sample-evtx",
    }

    total_all_rules = 0
    total_all_files = 0
    for i, (source_name, entries) in enumerate(sorted(by_source.items()), 1):
        total_rules = sum(len(e[1].get("rules_generated", [])) for e in entries)
        total_all_rules += total_rules
        total_all_files += len(entries)
        repo_url = source_repos.get(source_name, "")
        repo_link = f"[{source_name}]({repo_url})" if repo_url else source_name
        lines.append(f"| {i} | {repo_link} | `{source_name}` | {len(entries)} | {total_rules} |")
    lines.append(f"| | **Total** | | **{total_all_files}** | **{total_all_rules}** |")

    lines.append("")

    # Per-source detail
    for source_name, entries in sorted(by_source.items()):
        repo_url = source_repos.get(source_name, "")
        lines.append(f"## {source_name}")
        if repo_url:
            lines.append(f"**Repository:** {repo_url}")
        lines.append("")

        # Group by subdirectory (tactic)
        by_subdir = defaultdict(list)
        for evtx_path, info in entries:
            parts = evtx_path.split("/")
            subdir = parts[0] if len(parts) > 1 else "(root)"
            by_subdir[subdir].append((evtx_path, info))

        lines.append("| Directory | EVTX Files | Rules Generated | Sample Files |")
        lines.append("|-----------|------------|-----------------|--------------|")

        for subdir, sub_entries in sorted(by_subdir.items()):
            total_rules = sum(len(e[1].get("rules_generated", [])) for e in sub_entries)
            sample_files = ", ".join(
                f"`{e[0].split('/')[-1]}`" for e in sub_entries[:3]
            )
            if len(sub_entries) > 3:
                sample_files += f" +{len(sub_entries) - 3} more"
            lines.append(f"| {subdir} | {len(sub_entries)} | {total_rules} | {sample_files} |")

        lines.append("")

    # Credit
    lines.append("## Credits")
    lines.append("")
    lines.append("This project relies on the security research community for EVTX samples:")
    lines.append("")
    lines.append("- **SBousseaden** — [EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES) — Windows EVTX samples mapped to MITRE ATT&CK")
    lines.append("- **mdecrevoisier** — [EVTX-to-MITRE-Attack](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack) — 270+ EVTX samples with ATT&CK mapping")
    lines.append("- **Yamato Security** — [hayabusa-sample-evtx](https://github.com/Yamato-Security/hayabusa-sample-evtx) — Aggregated EVTX sample collection")
    lines.append("- **Wazuh Inc.** — [wazuh-ruleset](https://github.com/wazuh/wazuh-ruleset) — Official default Wazuh rules and decoders")
    lines.append("")

    DOCS_DIR.mkdir(parents=True, exist_ok=True)
    path = DOCS_DIR / "SOURCES.md"
    path.write_text("\n".join(lines))
    print(f"Generated: {path} ({len(lines)} lines)")


if __name__ == "__main__":
    print("Generating rule database documentation...\n")
    generate_rules_report()
    generate_coverage_matrix()
    generate_sources_doc()
    print("\nDone. See docs/ directory.")
