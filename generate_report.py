#!/usr/bin/env python3
"""Generate documentation for the Wazuh rule database."""

import json
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent
RULE_INDEX = PROJECT_ROOT / "database" / "metadata" / "rule_index.json"
PROVENANCE = PROJECT_ROOT / "database" / "metadata" / "provenance.json"
VALIDATION = PROJECT_ROOT / "database" / "metadata" / "validation_results.json"
RULES_DIR = PROJECT_ROOT / "database" / "rules"
DOCS_DIR = PROJECT_ROOT / "docs"

KNOWN_EVTX_SOURCES = [
    "EVTX-ATTACK-SAMPLES",
    "EVTX-to-MITRE-Attack",
    "hayabusa-sample-evtx",
    "Security-Datasets",
    "danderspritz-evtx",
    "evtx-hunter",
    "ThreatSeeker",
]

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
    0: "Ignored",
    1: "None",
    2: "System low",
    3: "System low",
    4: "System low",
    5: "User-generated",
    6: "Low relevance",
    7: "Bad word matching",
    8: "First time seen",
    9: "Error from invalid source",
    10: "Multiple user-generated errors",
    11: "Integrity checking warning",
    12: "High importance event",
    13: "Unusual error (high importance)",
    14: "High importance security event",
    15: "Severe attack",
}

ORIGIN_LABELS = {
    "evtx": "EVTX-derived",
    "sigma": "Sigma-converted",
    "other": "Other",
}


def load_json(path):
    if path.exists():
        with open(path, encoding="utf-8") as handle:
            return json.load(handle)
    return {}


def write_doc(name, lines):
    DOCS_DIR.mkdir(parents=True, exist_ok=True)
    path = DOCS_DIR / name
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"Generated: {path} ({len(lines)} lines)")


def normalize_path(path):
    return (path or "").replace("\\", "/")


def classify_source_path(path):
    normalized = normalize_path(path)
    if "/data/evtx_samples/" in normalized:
        return "evtx"
    if "/data/sigma_rules/" in normalized:
        return "sigma"
    return "other"


def classify_rule_origin(meta):
    return classify_source_path(meta.get("source_evtx", ""))


def get_known_evtx_source(path):
    normalized = normalize_path(path)
    for source_name in KNOWN_EVTX_SOURCES:
        if f"/{source_name}/" in normalized:
            return source_name
    return "unknown"


def get_sigma_category(path):
    parts = normalize_path(path).split("/")
    if "windows" in parts:
        idx = parts.index("windows")
        if idx + 1 < len(parts):
            return parts[idx + 1]
    return "unknown"


def build_origin_buckets(index):
    buckets = defaultdict(dict)
    for rid, meta in index.items():
        buckets[classify_rule_origin(meta)][str(rid)] = meta
    return buckets


def compute_validation_summary(rule_ids, validation_results):
    tested = 0
    passed = 0
    for rid in rule_ids:
        result = validation_results.get(str(rid))
        if not result:
            continue
        tested += 1
        if result.get("passed"):
            passed += 1
    failed = tested - passed
    pass_rate = (passed / tested * 100) if tested else 0.0
    return {
        "tested": tested,
        "passed": passed,
        "failed": failed,
        "pass_rate": pass_rate,
    }


def summarize_origin(records, validation_results):
    tactics = {meta.get("tactic") for meta in records.values() if meta.get("tactic")}
    techniques = {meta.get("technique_id") for meta in records.values() if meta.get("technique_id")}
    validation = compute_validation_summary(records.keys(), validation_results)
    return {
        "rules": len(records),
        "tactics": len(tactics),
        "techniques": len(techniques),
        "validation": validation,
    }


def generate_rules_report():
    index = load_json(RULE_INDEX)
    provenance = load_json(PROVENANCE)
    validation_results = load_json(VALIDATION)

    if not index:
        print("No rules found in index.")
        return

    origin_buckets = build_origin_buckets(index)
    levels = Counter(meta["level"] for meta in index.values())
    confidences = Counter(meta["confidence"] for meta in index.values())
    tactics = {meta.get("tactic") for meta in index.values() if meta.get("tactic")}
    techniques = {meta.get("technique_id") for meta in index.values() if meta.get("technique_id")}

    by_tactic = defaultdict(list)
    for rid, meta in index.items():
        by_tactic[meta.get("tactic", "unknown")].append((str(rid), meta))
    for tactic in by_tactic:
        by_tactic[tactic].sort(key=lambda item: int(item[0]))

    evtx_provenance = {path: info for path, info in provenance.items() if classify_source_path(path) == "evtx"}
    sigma_provenance = {path: info for path, info in provenance.items() if classify_source_path(path) == "sigma"}
    evtx_sources_used = sorted(
        source for source in {get_known_evtx_source(path) for path in evtx_provenance} if source != "unknown"
    )

    lines = [
        "# Wazuh Rule Database Report",
        "",
        f"> Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
        "> Pipeline version: 1.0.0",
        "",
        "## Overview",
        "",
        "| Metric | Value |",
        "|--------|-------|",
        f"| Total rules generated | **{len(index)}** |",
        f"| EVTX-derived rules | {len(origin_buckets.get('evtx', {}))} |",
        f"| Sigma-converted rules | {len(origin_buckets.get('sigma', {}))} |",
        f"| EVTX sample files processed | {len(evtx_provenance)} |",
        f"| Sigma rule files processed | {len(sigma_provenance)} |",
        f"| EVTX source repositories used | {len(evtx_sources_used)} |",
        f"| MITRE tactics covered | {len(tactics)} / 12 |",
        f"| MITRE techniques covered | {len(techniques)} |",
        "| Rule ID range | 100000 - 120000 |",
        "",
        "## Origin Breakdown",
        "",
        "| Origin | Rules | Tactics | Techniques | Validation |",
        "|--------|-------|---------|------------|------------|",
    ]

    for origin in ["evtx", "sigma", "other"]:
        records = origin_buckets.get(origin, {})
        if not records:
            continue
        summary = summarize_origin(records, validation_results)
        validation = summary["validation"]
        validation_text = (
            f"{validation['passed']}/{validation['tested']} passed ({validation['pass_rate']:.1f}%)"
            if validation["tested"]
            else "not run"
        )
        lines.append(
            f"| {ORIGIN_LABELS.get(origin, origin)} | {summary['rules']} | {summary['tactics']} | "
            f"{summary['techniques']} | {validation_text} |"
        )

    combined_validation = compute_validation_summary(index.keys(), validation_results)
    lines.extend(
        [
            "",
            "## Validation Summary",
            "",
            "| Scope | Tested | Passed | Failed | Pass Rate |",
            "|-------|--------|--------|--------|-----------|",
            f"| Combined | {combined_validation['tested']} | {combined_validation['passed']} | "
            f"{combined_validation['failed']} | {combined_validation['pass_rate']:.1f}% |",
        ]
    )
    for origin in ["evtx", "sigma", "other"]:
        records = origin_buckets.get(origin, {})
        if not records:
            continue
        validation = compute_validation_summary(records.keys(), validation_results)
        lines.append(
            f"| {ORIGIN_LABELS.get(origin, origin)} | {validation['tested']} | {validation['passed']} | "
            f"{validation['failed']} | {validation['pass_rate']:.1f}% |"
        )

    lines.extend(
        [
            "",
            "## Alert Level Distribution",
            "",
            "| Level | Wazuh Severity | Count | Percentage |",
            "|-------|----------------|-------|------------|",
        ]
    )
    for level in sorted(levels):
        count = levels[level]
        pct = count / len(index) * 100
        bar = "#" * int(pct / 2)
        lines.append(f"| {level} | {LEVEL_NAMES.get(level, '')} | {count} | {pct:.1f}% {bar} |")

    lines.extend(
        [
            "",
            "## Detection Confidence Distribution",
            "",
            "| Confidence | Count | Description |",
            "|------------|-------|-------------|",
        ]
    )
    confidence_descriptions = {
        "high": "Exact tool or process indicator",
        "medium": "Command-line pattern or behavioral indicator",
        "low": "Heuristic or generic event",
    }
    for confidence in ["high", "medium", "low"]:
        lines.append(
            f"| {confidence} | {confidences.get(confidence, 0)} | "
            f"{confidence_descriptions.get(confidence, '')} |"
        )

    lines.extend(["", "## Rules by MITRE ATT&CK Tactic", ""])
    for tactic_key, tactic_name, tactic_id in TACTIC_ORDER:
        rules = by_tactic.get(tactic_key, [])
        if not rules:
            continue
        lines.extend(
            [
                f"### {tactic_name} ({tactic_id}) - {len(rules)} rules",
                "",
                "| Rule ID | Level | Technique | Description | Confidence | Parent SID |",
                "|---------|-------|-----------|-------------|------------|------------|",
            ]
        )
        for rid, meta in rules:
            technique_id = meta.get("technique_id", "")
            technique_name = TECHNIQUE_NAMES.get(technique_id, technique_id)
            technique_display = f"`{technique_id}` {technique_name}" if technique_id else "-"
            description = meta.get("description", meta.get("technique_name", ""))
            if len(description) > 70:
                description = description[:67] + "..."
            lines.append(
                f"| `{rid}` | {meta['level']} | {technique_display} | {description} | "
                f"{meta.get('confidence', '-')} | {meta.get('parent_sid', '-')} |"
            )
        lines.append("")

    lines.extend(
        [
            "## Exported Rule Files",
            "",
            "Rules are exported in three parallel views. Each view contains the same rules, organized differently.",
            "",
        ]
    )
    for view_name, description in [
        ("by_tactic", "One XML file per MITRE ATT&CK tactic. Best for broad deployment."),
        ("by_technique", "One XML file per MITRE technique. Best for selective deployment."),
        ("by_source", "Grouped by Windows event source to align with Wazuh decoders."),
    ]:
        view_dir = RULES_DIR / view_name
        if not view_dir.exists():
            continue
        lines.extend(
            [
                f"### `database/rules/{view_name}/`",
                f"_{description}_",
                "",
                "| File | Rules |",
                "|------|-------|",
            ]
        )
        for xml_file in sorted(view_dir.glob("*.xml")):
            content = xml_file.read_text(encoding="utf-8")
            rule_count = content.count('<rule id="')
            lines.append(f"| `{xml_file.name}` | {rule_count} |")
        lines.append("")

    lines.extend(
        [
            "## Deployment to Wazuh",
            "",
            "Copy the desired view's XML files to your Wazuh manager:",
            "",
            "```bash",
            "# Option A: Deploy by tactic",
            "sudo cp database/rules/by_tactic/*.xml /var/ossec/etc/rules/",
            "",
            "# Option B: Deploy by source",
            "sudo cp database/rules/by_source/*.xml /var/ossec/etc/rules/",
            "",
            "# Restart Wazuh manager to load new rules",
            "sudo systemctl restart wazuh-manager",
            "",
            "# Verify rules loaded",
            "sudo /var/ossec/bin/wazuh-logtest",
            "```",
        ]
    )

    write_doc("RULES_REPORT.md", lines)


def build_tactic_matrix(records):
    matrix = defaultdict(lambda: defaultdict(list))
    for rid, meta in records.items():
        tactic = meta.get("tactic", "unknown")
        technique = meta.get("technique_id", "unknown")
        matrix[tactic][technique].append(str(rid))
    return matrix


def generate_coverage_matrix():
    index = load_json(RULE_INDEX)
    origin_buckets = build_origin_buckets(index)
    by_tactic = build_tactic_matrix(index)

    lines = [
        "# MITRE ATT&CK Coverage Matrix",
        "",
        f"> {len(index)} rules across {len(by_tactic)} tactics",
        "",
        "## Origin Coverage Summary",
        "",
        "| Origin | Rules | Tactics Covered | Techniques Covered |",
        "|--------|-------|-----------------|--------------------|",
    ]
    for origin in ["evtx", "sigma", "other"]:
        records = origin_buckets.get(origin, {})
        if not records:
            continue
        tactics = {meta.get("tactic") for meta in records.values() if meta.get("tactic")}
        techniques = {meta.get("technique_id") for meta in records.values() if meta.get("technique_id")}
        lines.append(
            f"| {ORIGIN_LABELS.get(origin, origin)} | {len(records)} | {len(tactics)} | {len(techniques)} |"
        )

    lines.extend(
        [
            "",
            "## Coverage Heatmap",
            "",
            "| Tactic | ID | Rules | Techniques | Coverage |",
            "|--------|----|-------|------------|----------|",
        ]
    )
    for tactic_key, tactic_name, tactic_id in TACTIC_ORDER:
        techniques = by_tactic.get(tactic_key, {})
        if not techniques:
            rule_count = 0
            technique_count = 0
            bar = ""
        else:
            rule_count = sum(len(rule_ids) for rule_ids in techniques.values())
            technique_count = len([technique for technique in techniques if technique])
            bar = "#" * min(rule_count, 20)
        lines.append(f"| {tactic_name} | `{tactic_id}` | {rule_count} | {technique_count} | {bar} |")

    lines.extend(["", "## Technique Detail", ""])
    for tactic_key, tactic_name, _ in TACTIC_ORDER:
        techniques = by_tactic.get(tactic_key, {})
        if not techniques:
            continue
        lines.extend(
            [
                f"### {tactic_name}",
                "",
                "| Technique | Name | Rules | Rule IDs |",
                "|-----------|------|-------|----------|",
            ]
        )
        for technique_id, rule_ids in sorted(techniques.items()):
            technique_name = TECHNIQUE_NAMES.get(technique_id, "")
            ids_display = ", ".join(f"`{rule_id}`" for rule_id in sorted(rule_ids, key=int))
            lines.append(f"| `{technique_id}` | {technique_name} | {len(rule_ids)} | {ids_display} |")
        lines.append("")

    covered_tactics = set(by_tactic.keys())
    lines.extend(["## Coverage Gaps", "", "Tactics with **no rules yet**:", ""])
    missing = False
    for tactic_key, tactic_name, tactic_id in TACTIC_ORDER:
        if tactic_key not in covered_tactics:
            missing = True
            lines.append(f"- **{tactic_name}** (`{tactic_id}`)")
    if not missing:
        lines.append("- None")

    write_doc("COVERAGE_MATRIX.md", lines)


def generate_sources_doc():
    provenance = load_json(PROVENANCE)

    by_evtx_source = defaultdict(list)
    by_sigma_category = defaultdict(list)
    for source_path, info in provenance.items():
        origin = classify_source_path(source_path)
        normalized = normalize_path(source_path)
        if origin == "evtx":
            source_name = get_known_evtx_source(normalized)
            rel_path = normalized.split(f"{source_name}/", 1)[-1] if source_name != "unknown" and f"{source_name}/" in normalized else Path(normalized).name
            by_evtx_source[source_name].append((rel_path, info))
        elif origin == "sigma":
            by_sigma_category[get_sigma_category(normalized)].append((normalized, info))

    evtx_input_count = sum(len(entries) for entries in by_evtx_source.values())
    evtx_rule_count = sum(len(entry[1].get("rules_generated", [])) for entries in by_evtx_source.values() for entry in entries)
    sigma_input_count = sum(len(entries) for entries in by_sigma_category.values())
    sigma_rule_count = sum(len(entry[1].get("rules_generated", [])) for entries in by_sigma_category.values() for entry in entries)

    lines = [
        "# Rule Source Attribution",
        "",
        "This document separates EVTX sample provenance from Sigma rule provenance.",
        "",
        "## Overview",
        "",
        "| Origin | Input Files | Rules Generated |",
        "|--------|-------------|-----------------|",
        f"| EVTX samples | {evtx_input_count} | {evtx_rule_count} |",
        f"| Sigma rules | {sigma_input_count} | {sigma_rule_count} |",
        "",
        "## EVTX Source Repositories",
        "",
        "| # | Source | Repository | Sample Files Used | Rules Generated |",
        "|---|--------|------------|-------------------|-----------------|",
    ]

    source_repos = {
        "EVTX-ATTACK-SAMPLES": "https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES",
        "EVTX-to-MITRE-Attack": "https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack",
        "hayabusa-sample-evtx": "https://github.com/Yamato-Security/hayabusa-sample-evtx",
        "Security-Datasets": "https://github.com/OTRF/Security-Datasets",
        "danderspritz-evtx": "https://github.com/fox-it/danderspritz-evtx",
        "evtx-hunter": "https://github.com/NVISOsecurity/evtx-hunter",
        "ThreatSeeker": "https://github.com/ine-labs/ThreatSeeker",
    }

    total_evtx_rules = 0
    total_evtx_files = 0
    for idx, (source_name, entries) in enumerate(sorted(by_evtx_source.items()), 1):
        rules_generated = sum(len(entry[1].get("rules_generated", [])) for entry in entries)
        total_evtx_rules += rules_generated
        total_evtx_files += len(entries)
        repo_url = source_repos.get(source_name, "")
        repo_link = f"[{source_name}]({repo_url})" if repo_url else source_name
        lines.append(f"| {idx} | {repo_link} | `{source_name}` | {len(entries)} | {rules_generated} |")
    lines.append(f"| | **Total** | | **{total_evtx_files}** | **{total_evtx_rules}** |")

    for source_name, entries in sorted(by_evtx_source.items()):
        lines.extend(["", f"## {source_name}"])
        repo_url = source_repos.get(source_name, "")
        if repo_url:
            lines.append(f"**Repository:** {repo_url}")
        lines.extend(["", "| Directory | Sample Files | Rules Generated | Sample Inputs |", "|-----------|--------------|-----------------|---------------|"])

        by_directory = defaultdict(list)
        for rel_path, info in entries:
            parts = rel_path.split("/")
            directory = parts[0] if len(parts) > 1 else "(root)"
            by_directory[directory].append((rel_path, info))

        for directory, directory_entries in sorted(by_directory.items()):
            rules_generated = sum(len(entry[1].get("rules_generated", [])) for entry in directory_entries)
            sample_names = ", ".join(f"`{Path(entry[0]).name}`" for entry in directory_entries[:3])
            if len(directory_entries) > 3:
                sample_names += f" +{len(directory_entries) - 3} more"
            lines.append(f"| {directory} | {len(directory_entries)} | {rules_generated} | {sample_names} |")

    lines.extend(
        [
            "",
            "## SigmaHQ Input Breakdown",
            "",
            "All Sigma-derived rules in this repository come from [SigmaHQ/sigma](https://github.com/SigmaHQ/sigma).",
            "",
            "| Category | Sigma Rule Files | Rules Generated |",
            "|----------|------------------|-----------------|",
        ]
    )
    for category, entries in sorted(by_sigma_category.items()):
        rules_generated = sum(len(entry[1].get("rules_generated", [])) for entry in entries)
        lines.append(f"| {category} | {len(entries)} | {rules_generated} |")

    lines.extend(["", "## Sample Sigma Inputs", "", "| Category | Sample Files |", "|----------|--------------|"])
    for category, entries in sorted(by_sigma_category.items()):
        sample_names = ", ".join(f"`{Path(path).name}`" for path, _ in entries[:3])
        if len(entries) > 3:
            sample_names += f" +{len(entries) - 3} more"
        lines.append(f"| {category} | {sample_names} |")

    lines.extend(
        [
            "",
            "## Credits",
            "",
            "This project relies on the security research community for EVTX samples and Sigma rules:",
            "",
            "- **SBousseaden** - [EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES) - Windows EVTX samples mapped to MITRE ATT&CK",
            "- **mdecrevoisier** - [EVTX-to-MITRE-Attack](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack) - EVTX samples with ATT&CK mapping",
            "- **Yamato Security** - [hayabusa-sample-evtx](https://github.com/Yamato-Security/hayabusa-sample-evtx) - Aggregated EVTX sample collection",
            "- **OTRF** - [Security-Datasets](https://github.com/OTRF/Security-Datasets) - Pre-recorded adversary simulation data",
            "- **Fox-IT** - [danderspritz-evtx](https://github.com/fox-it/danderspritz-evtx) - DanderSpritz detection events",
            "- **SigmaHQ** - [sigma](https://github.com/SigmaHQ/sigma) - Community detection rules in Sigma format",
            "- **Wazuh Inc.** - [wazuh/wazuh-ruleset](https://github.com/wazuh/wazuh-ruleset) - Official default Wazuh rules and decoders",
        ]
    )

    write_doc("SOURCES.md", lines)


if __name__ == "__main__":
    print("Generating rule database documentation...\n")
    generate_rules_report()
    generate_coverage_matrix()
    generate_sources_doc()
    print("\nDone. See docs/ directory.")
