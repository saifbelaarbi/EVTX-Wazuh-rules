#!/usr/bin/env python3
"""Phase-two reconciliation using per-run CSV intake files.

This script is intentionally schema-tolerant because upstream CSV exports may
change between runs. It uses header/content heuristics to find rule IDs and
status fields, then produces both JSON and Markdown summaries.
"""

from __future__ import annotations

import csv
import json
import re
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
CSV_DIR = PROJECT_ROOT / "phase2" / "csv_inputs"
OUTPUT_DIR = PROJECT_ROOT / "phase2" / "output"
RULE_INDEX_PATH = PROJECT_ROOT / "database" / "metadata" / "rule_index.json"
VALIDATION_PATH = PROJECT_ROOT / "database" / "metadata" / "validation_results.json"
SOURCE_EXPORTS_DIR = PROJECT_ROOT / "phase2" / "source_exports"

EXPECTED_INPUTS = {
    "agent_inventory": CSV_DIR / "agent_inventory.csv",
    "deployed_rules": CSV_DIR / "deployed_rules.csv",
    "candidate_rules": CSV_DIR / "candidate_rules.csv",
    "rule_test_results": CSV_DIR / "rule_test_results.csv",
    "deployment_status": CSV_DIR / "deployment_status.csv",
}

RULE_ID_HEADER_HINTS = ("rule", "id", "sid", "rule_id", "ruleid")
STATUS_HEADER_HINTS = ("status", "result", "state", "outcome")
AGENT_HEADER_HINTS = ("agent", "hostname", "host", "name")
PASS_VALUES = {"pass", "passed", "ok", "success", "succeeded", "true", "1"}
FAIL_VALUES = {"fail", "failed", "error", "false", "0"}
DEPLOYED_VALUES = {"deployed", "active", "enabled", "loaded", "present"}


@dataclass
class CsvDataset:
    name: str
    path: Path
    row_count: int
    columns: list[str]
    rule_ids: set[str]
    statuses: Counter
    agents: set[str]


def load_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def normalize(value: Any) -> str:
    return str(value).strip().lower()


def parse_rule_ids_from_text(text: str) -> set[str]:
    # Match ids like 100000, "rule 100000", "id=100000".
    matches = re.findall(r"\b(1\d{5})\b", text)
    return set(matches)


def find_rule_ids(row: dict[str, str]) -> set[str]:
    ids: set[str] = set()

    # Header-based extraction first.
    for key, value in row.items():
        key_norm = normalize(key)
        if any(hint in key_norm for hint in RULE_ID_HEADER_HINTS):
            ids.update(parse_rule_ids_from_text(str(value)))

    if ids:
        return ids

    # Fallback: scan the whole row text.
    joined = " ".join(str(v) for v in row.values())
    ids.update(parse_rule_ids_from_text(joined))
    return ids


def extract_status_values(row: dict[str, str]) -> list[str]:
    values: list[str] = []
    for key, value in row.items():
        if any(hint in normalize(key) for hint in STATUS_HEADER_HINTS):
            values.append(normalize(value))
    return values


def extract_agent_values(row: dict[str, str]) -> list[str]:
    values: list[str] = []
    for key, value in row.items():
        if any(hint in normalize(key) for hint in AGENT_HEADER_HINTS):
            cleaned = str(value).strip()
            if cleaned:
                values.append(cleaned)
    return values


def load_csv_dataset(name: str, path: Path) -> CsvDataset:
    if not path.exists():
        return CsvDataset(name=name, path=path, row_count=0, columns=[], rule_ids=set(), statuses=Counter(), agents=set())

    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        columns = list(reader.fieldnames or [])
        rule_ids: set[str] = set()
        statuses: Counter = Counter()
        agents: set[str] = set()
        row_count = 0

        for row in reader:
            row_count += 1
            row_ids = find_rule_ids(row)
            rule_ids.update(row_ids)

            for status in extract_status_values(row):
                statuses[status] += 1

            for agent in extract_agent_values(row):
                agents.add(agent)

    return CsvDataset(
        name=name,
        path=path,
        row_count=row_count,
        columns=columns,
        rule_ids=rule_ids,
        statuses=statuses,
        agents=agents,
    )


def summarize_pass_fail(statuses: Counter) -> dict[str, int]:
    passed = 0
    failed = 0
    deployed = 0
    for status, count in statuses.items():
        if status in PASS_VALUES:
            passed += count
        if status in FAIL_VALUES:
            failed += count
        if status in DEPLOYED_VALUES:
            deployed += count
    return {"passed": passed, "failed": failed, "deployed_like": deployed}


def build_summary() -> dict[str, Any]:
    rule_index = load_json(RULE_INDEX_PATH)
    validation_results = load_json(VALIDATION_PATH)
    local_rule_ids = set(rule_index.keys())

    datasets = {name: load_csv_dataset(name, path) for name, path in EXPECTED_INPUTS.items()}
    missing_inputs = [name for name, path in EXPECTED_INPUTS.items() if not path.exists()]
    source_export_files = sorted(f.name for f in SOURCE_EXPORTS_DIR.glob("*") if f.is_file() and f.name.lower() != "readme.md")

    deployed_ids = datasets["deployed_rules"].rule_ids
    candidate_ids = datasets["candidate_rules"].rule_ids
    tested_ids = datasets["rule_test_results"].rule_ids
    deployment_ids = datasets["deployment_status"].rule_ids

    known_deployed_ids = deployed_ids & local_rule_ids
    unknown_deployed_ids = deployed_ids - local_rule_ids
    candidate_existing_ids = candidate_ids & local_rule_ids
    candidate_new_ids = candidate_ids - local_rule_ids
    tested_known_ids = tested_ids & local_rule_ids
    deployment_known_ids = deployment_ids & local_rule_ids

    evtx_rule_ids = {rid for rid, meta in rule_index.items() if "/data/evtx_samples/" in str(meta.get("source_evtx", ""))}
    sigma_rule_ids = {rid for rid, meta in rule_index.items() if "/data/sigma_rules/" in str(meta.get("source_evtx", ""))}

    validated_local_ids = {rid for rid, result in validation_results.items() if result.get("passed") is True}

    per_dataset = {}
    for name, dataset in datasets.items():
        per_dataset[name] = {
            "present": dataset.path.exists(),
            "path": str(dataset.path.relative_to(PROJECT_ROOT)),
            "rows": dataset.row_count,
            "columns": dataset.columns,
            "rule_ids_detected": len(dataset.rule_ids),
            "agents_detected": len(dataset.agents),
            "status_counts": dict(dataset.statuses),
            "status_summary": summarize_pass_fail(dataset.statuses),
        }

    return {
        "generated_at_utc": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "input_gate_open": len(missing_inputs) == 0,
        "missing_inputs": missing_inputs,
        "source_export_files": source_export_files,
        "local_rules": {
            "total": len(local_rule_ids),
            "evtx": len(evtx_rule_ids),
            "sigma": len(sigma_rule_ids),
            "validated_passed": len(validated_local_ids),
        },
        "reconciliation": {
            "deployed": {
                "csv_rule_ids": len(deployed_ids),
                "known_in_repo": len(known_deployed_ids),
                "unknown_to_repo": len(unknown_deployed_ids),
            },
            "candidate": {
                "csv_rule_ids": len(candidate_ids),
                "already_in_repo": len(candidate_existing_ids),
                "new_not_in_repo": len(candidate_new_ids),
            },
            "testing": {
                "csv_rule_ids": len(tested_ids),
                "known_in_repo": len(tested_known_ids),
            },
            "deployment_status": {
                "csv_rule_ids": len(deployment_ids),
                "known_in_repo": len(deployment_known_ids),
            },
        },
        "datasets": per_dataset,
    }


def render_markdown(summary: dict[str, Any]) -> str:
    lines: list[str] = []
    lines.append("# Phase 2 Reconciliation Report")
    lines.append("")
    lines.append(f"> Generated: {summary['generated_at_utc']}")
    lines.append("")

    gate_text = "open" if summary["input_gate_open"] else "blocked"
    lines.append("## Intake Gate")
    lines.append("")
    lines.append(f"- Gate status: **{gate_text}**")
    if summary["missing_inputs"]:
        lines.append("- Missing CSV inputs:")
        for name in summary["missing_inputs"]:
            lines.append(f"  - `{name}.csv`")
    else:
        lines.append("- All required CSV inputs are present.")
    lines.append("")

    lines.append("## Raw Source Exports")
    lines.append("")
    if summary["source_export_files"]:
        for name in summary["source_export_files"]:
            lines.append(f"- `{name}`")
    else:
        lines.append("- none")
    lines.append("")

    local = summary["local_rules"]
    lines.append("## Local Rule Snapshot")
    lines.append("")
    lines.append("| Metric | Value |")
    lines.append("|--------|-------|")
    lines.append(f"| Total local rules | {local['total']} |")
    lines.append(f"| EVTX-derived rules | {local['evtx']} |")
    lines.append(f"| Sigma-converted rules | {local['sigma']} |")
    lines.append(f"| Validation passed (local metadata) | {local['validated_passed']} |")
    lines.append("")

    rec = summary["reconciliation"]
    lines.append("## Reconciliation")
    lines.append("")
    lines.append("| Area | CSV Rule IDs | Known In Repo | Unknown/New |")
    lines.append("|------|--------------|---------------|-------------|")
    lines.append(f"| deployed_rules | {rec['deployed']['csv_rule_ids']} | {rec['deployed']['known_in_repo']} | {rec['deployed']['unknown_to_repo']} |")
    lines.append(f"| candidate_rules | {rec['candidate']['csv_rule_ids']} | {rec['candidate']['already_in_repo']} | {rec['candidate']['new_not_in_repo']} |")
    lines.append(f"| rule_test_results | {rec['testing']['csv_rule_ids']} | {rec['testing']['known_in_repo']} | - |")
    lines.append(f"| deployment_status | {rec['deployment_status']['csv_rule_ids']} | {rec['deployment_status']['known_in_repo']} | - |")
    lines.append("")

    lines.append("## Dataset Diagnostics")
    lines.append("")
    lines.append("| Dataset | Present | Rows | Columns | Rule IDs | Agents |")
    lines.append("|---------|---------|------|---------|----------|--------|")
    for name, data in summary["datasets"].items():
        lines.append(
            f"| {name} | {str(data['present']).lower()} | {data['rows']} | {len(data['columns'])} | "
            f"{data['rule_ids_detected']} | {data['agents_detected']} |"
        )
    lines.append("")

    lines.append("## Next Actions")
    lines.append("")
    if summary["input_gate_open"]:
        lines.append("1. Review unknown deployed IDs and map false positives from CSV parsing if needed.")
        lines.append("2. Prioritize `candidate_rules` rows where rule IDs are not in local repo.")
        lines.append("3. Update `docs/PHASE_TWO_MASTER.md` bucket tables with this run's reconciled counts.")
    else:
        lines.append("1. Convert or export normalized CSVs into `phase2/csv_inputs/`.")
        lines.append("2. Re-run `python phase2/reconcile_phase2.py` after the CSV refresh.")
    lines.append("")

    return "\n".join(lines)


def write_outputs(summary: dict[str, Any]) -> None:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    json_path = OUTPUT_DIR / "reconciliation_summary.json"
    md_path = OUTPUT_DIR / "reconciliation_report.md"
    json_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    md_path.write_text(render_markdown(summary), encoding="utf-8")
    print(f"Generated: {json_path}")
    print(f"Generated: {md_path}")


def main() -> None:
    summary = build_summary()
    write_outputs(summary)


if __name__ == "__main__":
    main()
