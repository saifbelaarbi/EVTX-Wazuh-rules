"""CLI entry point for the Wazuh Rule Database Generator."""

from contextlib import contextmanager
from pathlib import Path

import click
import yaml
from rich.console import Console
from rich.table import Table

from . import (
    alert_leveler,
    event_analyzer,
    evtx_parser,
    exporter,
    id_manager,
    logtest_validator,
    rule_builder,
    rule_correlator,
    sigma_converter,
    validator,
)

console = Console()
PROJECT_ROOT = Path(__file__).resolve().parent.parent
CONFIG_FILE = PROJECT_ROOT / "config.yaml"


@contextmanager
def _snapshot_allocations():
    """Save and restore id_allocations.json so dry runs don't consume IDs."""
    alloc_file = PROJECT_ROOT / "database" / "metadata" / "id_allocations.json"
    backup = alloc_file.read_text() if alloc_file.exists() else None
    try:
        yield
    finally:
        if backup is not None:
            alloc_file.write_text(backup)
        elif alloc_file.exists():
            alloc_file.unlink()


def load_config():
    with open(CONFIG_FILE) as f:
        return yaml.safe_load(f)


@click.group()
def cli():
    """Wazuh Rule Database Generator - Generate and manage Wazuh rules from EVTX samples."""
    pass


@cli.command("analyze")
@click.option("--source", default=None, help="Analyze specific EVTX source only")
def analyze(source):
    """Parse all EVTX samples and show detection patterns found."""
    config = load_config()
    data_dir = PROJECT_ROOT / config["paths"]["evtx_data"]

    if not data_dir.exists():
        console.print("[red]No EVTX data found. Run 'python -m collector download-all' first.[/]")
        return

    if source:
        data_dir = data_dir / source
        if not data_dir.exists():
            console.print(f"[red]Source '{source}' not found in {data_dir.parent}[/]")
            return

    console.print(f"[bold]Parsing EVTX files from {data_dir}...[/]\n")
    events = evtx_parser.parse_directory(data_dir)

    if not events:
        console.print("[yellow]No events parsed. Check that EVTX files exist.[/]")
        return

    console.print(f"\n[bold]Analyzing {len(events)} events...[/]")
    patterns = event_analyzer.analyze_events(events)

    # Display results
    table = Table(title=f"Detection Patterns ({len(patterns)} found)")
    table.add_column("Event ID", justify="right")
    table.add_column("Tactic")
    table.add_column("Confidence")
    table.add_column("Description")

    for p in patterns[:50]:  # Show first 50
        table.add_row(
            str(p.event_id),
            p.tactic,
            p.confidence,
            p.description[:80],
        )

    console.print(table)
    if len(patterns) > 50:
        console.print(f"  ... and {len(patterns) - 50} more patterns")


@cli.command("generate")
@click.option("--source", default=None, help="Generate from specific EVTX source")
@click.option("--auto-approve", is_flag=True, help="Skip review for high-confidence rules")
@click.option("--diff-only", is_flag=True, help="Report what would change without writing")
def generate(source, auto_approve, diff_only):
    """Generate Wazuh rules from EVTX samples (creates drafts by default)."""
    config = load_config()
    data_dir = PROJECT_ROOT / config["paths"]["evtx_data"]

    if not data_dir.exists():
        console.print("[red]No EVTX data found. Run 'python -m collector download-all' first.[/]")
        return

    if source:
        data_dir = data_dir / source
        if not data_dir.exists():
            console.print(f"[red]Source '{source}' not found.[/]")
            return

    # Step 1: Parse
    console.print("[bold]Step 1/6: Parsing EVTX files...[/]")
    events = evtx_parser.parse_directory(data_dir)
    if not events:
        console.print("[yellow]No events parsed.[/]")
        return

    # Step 2: Analyze
    console.print(f"\n[bold]Step 2/6: Analyzing {len(events)} events...[/]")
    patterns = event_analyzer.analyze_events(events)
    if not patterns:
        console.print("[yellow]No detection patterns found.[/]")
        return

    # Wrap rule building in an allocation snapshot when dry-running so IDs
    # are not permanently consumed.
    ctx = _snapshot_allocations() if diff_only else contextmanager(lambda: (yield))()
    with ctx:
        # Step 3: Build rules
        console.print(f"\n[bold]Step 3/6: Building {len(patterns)} rules...[/]")
        rules = rule_builder.build_rules(patterns)

        # Step 4: Correlate
        console.print("\n[bold]Step 4/6: Correlating with existing rules...[/]")
        existing_index = rule_correlator.load_rule_index()
        defaults_dir = PROJECT_ROOT / config["paths"]["wazuh_defaults"] / "wazuh-ruleset" / "ruleset" / "rules"
        default_rules = rule_correlator.load_wazuh_default_rules(defaults_dir)

        kept_rules = []
        skipped = 0
        for rule in rules:
            report = rule_correlator.correlate(rule, existing_index, default_rules)
            if report["recommendation"] == "skip":
                skipped += 1
                continue
            rule["correlation_report"] = report
            kept_rules.append(rule)

        console.print(f"  Kept: {len(kept_rules)}, Skipped (duplicates): {skipped}")

        # Step 5: Apply alert levels
        console.print("\n[bold]Step 5/6: Assigning alert levels...[/]")
        kept_rules = alert_leveler.apply_levels(kept_rules)

        # Step 6: Validate
        console.print("\n[bold]Step 6/6: Validating rules...[/]")
        errors = validator.validate_rules(kept_rules)
        if errors:
            console.print(f"[yellow]Validation warnings ({len(errors)}):[/]")
            for err in errors[:10]:
                console.print(f"  - {err}")

        if diff_only:
            console.print(f"\n[cyan]--diff-only:[/] would add/update {len(kept_rules)} rules. No files written.")
            return

    if auto_approve:
        # Export directly to rule database
        console.print("\n[bold green]Auto-approving and exporting...[/]")
        exporter.export_all_views(kept_rules)
        exporter.update_rule_index(kept_rules)
        exporter.update_provenance(kept_rules)
    else:
        # Export as drafts for review
        console.print("\n[bold yellow]Exporting as drafts for review...[/]")
        exporter.export_drafts(kept_rules)
        console.print("\nRun 'python -m generator review' to review and approve drafts.")

    # Summary
    table = Table(title="Generation Summary")
    table.add_column("Metric", style="bold")
    table.add_column("Value", justify="right")
    table.add_row("Events parsed", str(len(events)))
    table.add_row("Patterns found", str(len(patterns)))
    table.add_row("Rules generated", str(len(kept_rules)))
    table.add_row("Duplicates skipped", str(skipped))
    table.add_row("Validation errors", str(len(errors)))
    console.print(table)


@cli.command("review")
def review():
    """Interactively review draft rules."""
    drafts_dir = PROJECT_ROOT / "database" / "drafts"
    if not drafts_dir.exists():
        console.print("[yellow]No drafts to review.[/]")
        return

    manifests = sorted(drafts_dir.glob("*_manifest.json"))
    if not manifests:
        console.print("[yellow]No draft manifests found.[/]")
        return

    for manifest_file in manifests:
        console.print(f"\n[bold]Reviewing:[/] {manifest_file.name}")
        import json

        with open(manifest_file) as f:
            manifest = json.load(f)

        table = Table()
        table.add_column("ID", justify="right")
        table.add_column("Level", justify="right")
        table.add_column("Tactic")
        table.add_column("Confidence")
        table.add_column("Description")

        for entry in manifest:
            table.add_row(
                str(entry["rule_id"]),
                str(entry["level"]),
                entry["tactic"],
                entry["confidence"],
                entry["description"][:60],
            )
        console.print(table)

        console.print(f"\n  Draft XML: {manifest_file.name.replace('_manifest.json', '.xml')}")
        console.print("  To approve: python -m generator approve <draft_file>")


@cli.command("approve")
@click.argument("draft_file")
def approve(draft_file):
    """Approve a draft file and add rules to the database."""
    from lxml import etree

    draft_path = PROJECT_ROOT / "database" / "drafts" / draft_file
    if not draft_path.exists():
        # Try with full path
        draft_path = Path(draft_file)
    if not draft_path.exists():
        console.print(f"[red]Draft not found:[/] {draft_file}")
        return

    # Parse the draft XML and rebuild rule dicts for export
    tree = etree.parse(str(draft_path))
    root = tree.getroot()

    rules = []
    for rule_elem in root.iter("rule"):
        rule_id = int(rule_elem.get("id", "0"))
        level = int(rule_elem.get("level", "0"))

        desc_elem = rule_elem.find("description")
        desc = desc_elem.text if desc_elem is not None else ""

        # Extract tactic from group
        group_elem = rule_elem.find("group")
        tactic = ""
        if group_elem is not None and group_elem.text:
            parts = [p.strip() for p in group_elem.text.split(",") if p.strip()]
            for p in parts:
                if p in event_analyzer.TACTIC_ALIASES.values():
                    tactic = p
                    break

        # Extract MITRE IDs
        mitre_ids = []
        mitre_elem = rule_elem.find("mitre")
        if mitre_elem is not None:
            for id_elem in mitre_elem.findall("id"):
                if id_elem.text:
                    mitre_ids.append(id_elem.text)

        rules.append(
            {
                "id": rule_id,
                "level": level,
                "xml_element": rule_elem,
                "metadata": {
                    "rule_id": rule_id,
                    "level": level,
                    "tactic": tactic,
                    "technique_name": desc,
                    "source_evtx": "",
                    "confidence": "reviewed",
                    "mitre_ids": mitre_ids,
                    "field_matches": {},
                    "created": "",
                },
                "pattern": type("P", (), {"provider_name": "", "channel": "", "event_id": 0})(),
            }
        )

    if not rules:
        console.print("[yellow]No rules found in draft.[/]")
        return

    console.print(f"[bold green]Approving {len(rules)} rules...[/]")
    exporter.export_all_views(rules)
    exporter.update_rule_index(rules)
    exporter.update_provenance(rules)

    # Clean up draft
    draft_path.unlink(missing_ok=True)
    manifest = draft_path.with_name(draft_path.stem.replace(".xml", "") + "_manifest.json")
    manifest.unlink(missing_ok=True)

    console.print("[bold green]Rules approved and exported to database.[/]")


@cli.command("validate")
def validate_cmd():
    """Validate the entire rule database."""
    rules_dir = PROJECT_ROOT / "database" / "rules"
    if not rules_dir.exists():
        console.print("[yellow]No rules database found.[/]")
        return

    errors = validator.validate_database(rules_dir)
    if errors:
        console.print(f"\n[red]Found {len(errors)} validation errors:[/]")
        for err in errors:
            console.print(f"  - {err}")
        raise SystemExit(1)
    else:
        xml_count = sum(1 for _ in rules_dir.rglob("*.xml"))
        console.print(f"[bold green]All rules valid![/] ({xml_count} XML files checked)")


@cli.command("stats")
def stats():
    """Show rule database statistics."""
    # ID allocation stats
    alloc_stats = id_manager.get_allocation_stats()

    table = Table(title="Rule ID Allocation")
    table.add_column("Tactic", style="bold")
    table.add_column("Range")
    table.add_column("Used", justify="right")
    table.add_column("Available", justify="right")

    total_used = 0
    for tactic, s in alloc_stats.items():
        table.add_row(tactic, s["range"], str(s["used"]), str(s["available"]))
        total_used += s["used"]
    console.print(table)
    console.print(f"\n[bold]Total rules: {total_used}[/]")

    # Rule file stats
    rules_dir = PROJECT_ROOT / "database" / "rules"
    if rules_dir.exists():
        for view in ["by_tactic", "by_technique", "by_source"]:
            view_dir = rules_dir / view
            if view_dir.exists():
                files = list(view_dir.glob("*.xml"))
                console.print(f"  {view}: {len(files)} files")

    # Drafts
    drafts_dir = PROJECT_ROOT / "database" / "drafts"
    if drafts_dir.exists():
        drafts = list(drafts_dir.glob("*.xml"))
        console.print(f"\n[yellow]Pending drafts: {len(drafts)}[/]")


@cli.command("export")
@click.option("--dest", required=True, type=click.Path(), help="Deployment destination path")
@click.option("--view", default="by_tactic", type=click.Choice(["by_tactic", "by_technique", "by_source"]))
def export_cmd(dest, view):
    """Export rules for Wazuh deployment."""
    exporter.export_for_deployment(Path(dest), view)


@cli.command("convert-sigma")
@click.option("--auto-approve", is_flag=True, help="Export directly to rule database")
@click.option("--category", default=None, help="Only convert rules from this category (e.g., process_creation)")
@click.option(
    "--min-level",
    default="low",
    type=click.Choice(["informational", "low", "medium", "high", "critical"]),
    help="Minimum Sigma severity level to convert",
)
@click.option("--max-rules", default=None, type=int, help="Maximum number of rules to generate")
@click.option("--with-negation", is_flag=True, help="Emit Wazuh level-0 suppression rules for 'not' filters")
@click.option(
    "--platform",
    default="windows",
    type=click.Choice(["windows", "linux", "cloud", "all"]),
    help="Which Sigma rule platform(s) to convert",
)
@click.option("--diff-only", is_flag=True, help="Report what would change without writing")
def convert_sigma_cmd(auto_approve, category, min_level, max_rules, with_negation, platform, diff_only):
    """Convert SigmaHQ detection rules to Wazuh XML rules."""
    config = load_config()
    sigma_dir = PROJECT_ROOT / config["paths"]["sigma_data"]

    if not sigma_dir.exists():
        console.print("[red]No Sigma rules found. Run 'python -m collector download-sigma' first.[/]")
        return

    # Locate the SigmaHQ rules root (handles a few clone layouts).
    rules_root = sigma_dir
    for candidate in [
        sigma_dir / "SigmaHQ" / "rules",
        sigma_dir / "sigma" / "rules",
        sigma_dir / "rules",
        sigma_dir,
    ]:
        if candidate.exists():
            rules_root = candidate
            break

    platforms = ["windows", "linux", "cloud"] if platform == "all" else [platform]

    # Wrap conversion in an allocation snapshot when dry-running so IDs
    # are not permanently consumed.
    ctx = _snapshot_allocations() if diff_only else contextmanager(lambda: (yield))()
    with ctx:
        rules = []
        for plat in platforms:
            plat_path = rules_root / plat
            if not plat_path.exists():
                console.print(f"[yellow]No '{plat}' Sigma rules at {plat_path}, skipping.[/]")
                continue
            console.print(f"[bold]Converting {plat} Sigma rules from {plat_path}...[/]")
            rules.extend(
                sigma_converter.convert_all(
                    rules_dir=plat_path,
                    category=category,
                    min_level=min_level,
                    max_rules=max_rules,
                    with_negation=with_negation,
                    write_error_report=(plat == platforms[-1]),
                )
            )

        if not rules:
            console.print("[yellow]No rules converted.[/]")
            return

        if diff_only:
            console.print(f"[cyan]--diff-only:[/] would add/update {len(rules)} rules. No files written.")
            return

    # Step 2: Correlate against existing database
    console.print(f"\n[bold]Correlating {len(rules)} rules against existing database...[/]")
    existing_index = rule_correlator.load_rule_index()
    defaults_dir = PROJECT_ROOT / config["paths"]["wazuh_defaults"] / "wazuh-ruleset" / "ruleset" / "rules"
    default_rules = rule_correlator.load_wazuh_default_rules(defaults_dir)

    kept_rules = []
    skipped = 0
    for rule in rules:
        report = rule_correlator.correlate(rule, existing_index, default_rules)
        if report["recommendation"] == "skip":
            skipped += 1
            continue
        rule["correlation_report"] = report
        kept_rules.append(rule)

    console.print(f"  Kept: {len(kept_rules)}, Skipped (duplicates): {skipped}")

    if not kept_rules:
        console.print("[yellow]All converted rules already exist in the database.[/]")
        return

    # Step 3: Apply alert levels
    console.print("\n[bold]Assigning alert levels...[/]")
    kept_rules = alert_leveler.apply_levels(kept_rules)

    # Step 4: Validate
    console.print("\n[bold]Validating rules...[/]")
    errors = validator.validate_rules(kept_rules)
    if errors:
        console.print(f"[yellow]Validation warnings ({len(errors)}):[/]")
        for err in errors[:10]:
            console.print(f"  - {err}")

    if auto_approve:
        console.print("\n[bold green]Auto-approving and exporting...[/]")
        exporter.export_all_views(kept_rules)
        exporter.update_rule_index(kept_rules)
        exporter.update_provenance(kept_rules)
    else:
        console.print("\n[bold yellow]Exporting as drafts for review...[/]")
        exporter.export_drafts(kept_rules)
        console.print("\nRun 'python -m generator review' to review and approve drafts.")

    # Summary
    table = Table(title="Sigma Conversion Summary")
    table.add_column("Metric", style="bold")
    table.add_column("Value", justify="right")
    table.add_row("Sigma rules scanned", "all")
    table.add_row("Wazuh rules generated", str(len(kept_rules)))
    table.add_row("Duplicates skipped", str(skipped))
    table.add_row("Validation errors", str(len(errors)))
    table.add_row("Mode", "auto-approved" if auto_approve else "drafts")
    console.print(table)


@cli.command("logtest")
@click.option(
    "--mode",
    type=click.Choice(["simulate", "live"]),
    default="simulate",
    help="Validation mode: simulate (offline) or live (API/SSH)",
)
@click.option("--rule-id", default=None, type=int, help="Validate a specific rule by ID")
@click.option("--source", default=None, help="Validate rules from a specific EVTX source")
@click.option("--verbose", is_flag=True, help="Show detailed field match results")
@click.option("--save", is_flag=True, help="Save results to validation_results.json")
def logtest_cmd(mode, rule_id, source, verbose, save):
    """Validate rules against source events via simulation or live wazuh-logtest."""
    if rule_id:
        console.print(f"[bold]Validating rule {rule_id} (mode={mode})...[/]\n")
        result = logtest_validator.validate_single_rule(rule_id, mode=mode)
        logtest_validator.print_result(result, verbose=verbose)

        if save:
            logtest_validator.save_results([result], mode=mode)
    else:
        results = logtest_validator.validate_all_rules(mode=mode, source_filter=source)

        if verbose:
            for r in results:
                logtest_validator.print_result(r, verbose=True)

        if save and results:
            logtest_validator.save_results(results, mode=mode)


@cli.command("navigator")
@click.option("--output", default=None, type=click.Path(), help="Output path for Navigator JSON layer")
def navigator_cmd(output):
    """Export a MITRE ATT&CK Navigator layer from the rule database."""
    from .navigator_export import export_navigator_layer

    output_path = Path(output) if output else None
    layer = export_navigator_layer(output_path=output_path)

    tech_count = len(layer["techniques"])
    total = layer["metadata"][0]["value"] if layer["metadata"] else "?"
    dest = output or "database/navigator_layer.json"
    console.print(f"[bold green]Navigator layer exported:[/] {dest}")
    console.print(f"  {total} rules → {tech_count} technique entries")
    console.print("  Open at https://mitre-attack.github.io/attack-navigator/ → Open Existing Layer")


@cli.command("export-sigma")
@click.option("--output", default=None, type=click.Path(), help="Output directory for Sigma YAML")
def export_sigma_cmd(output):
    """Back-convert EVTX-generated rules to Sigma YAML for sharing."""
    from .sigma_exporter import export_evtx_rules_to_sigma

    out_dir = Path(output) if output else None
    count = export_evtx_rules_to_sigma(out_dir=out_dir)
    dest = output or "database/exports/sigma"
    console.print(f"[bold green]Exported {count} EVTX-derived rules to Sigma YAML:[/] {dest}")


@cli.command("build-composites")
@click.option("--auto-approve", is_flag=True, help="Export directly to rule database")
def build_composites_cmd(auto_approve):
    """Build composite/chained correlation rules from templates."""
    from . import composite_builder

    templates = composite_builder.load_templates()
    if not templates:
        console.print("[yellow]No composite templates found.[/]")
        return

    if auto_approve:
        valid = [t for t in templates if not composite_builder.has_placeholder_sids(t)]
        skipped = len(templates) - len(valid)
        if skipped:
            console.print(
                f"[yellow]Skipped {skipped} template(s) with placeholder SIDs "
                f"(wire real rule IDs before auto-approving).[/]"
            )
        templates = valid
        if not templates:
            console.print("[yellow]No templates with real SIDs to build.[/]")
            return

    rules = composite_builder.build_from_templates(templates)
    console.print(f"[bold]Built {len(rules)} composite rules.[/]")
    if auto_approve:
        exporter.export_all_views(rules)
        exporter.update_rule_index(rules)
        console.print("[bold green]Composite rules exported.[/]")
    else:
        exporter.export_drafts(rules)
        console.print("[dim]Composite rules written to drafts (use --auto-approve to publish).[/]")


@cli.command("generate-atomic")
@click.option("--auto-approve", is_flag=True, help="Export directly to rule database")
def generate_atomic_cmd(auto_approve):
    """Generate rules from a cloned Atomic Red Team repo (data/atomic-red-team)."""
    from collector.atomic_collector import parse_atomic_repo

    config = load_config()
    atomic_dir = PROJECT_ROOT / config["paths"].get("evtx_data", "data/evtx_samples")
    repo = PROJECT_ROOT / "data" / "atomic-red-team"
    if not repo.exists():
        console.print(f"[red]Atomic Red Team repo not found at {repo}.[/]")
        console.print("[dim]Clone redcanaryco/atomic-red-team into data/atomic-red-team first.[/]")
        return

    patterns = parse_atomic_repo(repo)
    console.print(f"[bold]Parsed {len(patterns)} Atomic test patterns.[/]")
    rules = [rule_builder.build_rule(p) for p in patterns]
    rules = alert_leveler.apply_levels(rules)
    rules = [r for r in rules if r]
    if auto_approve:
        exporter.export_all_views(rules)
        exporter.update_rule_index(rules)
        exporter.update_provenance(rules)
        console.print(f"[bold green]Exported {len(rules)} Atomic-derived rules.[/]")
    else:
        exporter.export_drafts(rules)
        console.print(f"[dim]{len(rules)} rules written to drafts (use --auto-approve).[/]")
    _ = atomic_dir  # reserved for future per-source layout


@cli.command("report-fp")
@click.option("--rule-id", required=True, help="Rule ID that produced a false positive")
@click.option("--reason", required=True, help="Why this is a false positive")
@click.option("--reporter", default="", help="Who reported it")
def report_fp_cmd(rule_id, reason, reporter):
    """Record a false positive for a rule."""
    from . import fp_tracker

    rec = fp_tracker.record_fp(rule_id, reason, reporter=reporter)
    console.print(f"[bold green]Recorded FP for rule {rec.rule_id}[/] at {rec.timestamp}")


@cli.command("fp-summary")
@click.option("--threshold", default=3, help="FP count at which to suggest a level drop")
def fp_summary_cmd(threshold):
    """Summarize reported false positives and suggested level adjustments."""
    from . import fp_tracker

    counts = fp_tracker.fp_counts()
    if not counts:
        console.print("[dim]No false positives recorded.[/]")
        return
    suggestions = fp_tracker.suggest_level_adjustments(threshold=threshold)
    table = Table(title="False Positive Summary")
    table.add_column("Rule ID")
    table.add_column("FP Count", justify="right")
    table.add_column("Suggested Δlevel", justify="right")
    for rid in sorted(counts, key=lambda r: -counts[r]):
        table.add_row(rid, str(counts[rid]), str(suggestions.get(rid, 0)))
    console.print(table)


@cli.command("changelog")
@click.option("--limit", default=20, help="Number of recent entries to show")
def changelog_cmd(limit):
    """Show recent rule database changes (adds/modifications)."""
    changelog_file = PROJECT_ROOT / "database" / "metadata" / "changelog.json"
    if not changelog_file.exists():
        console.print("[dim]No changelog yet.[/]")
        return
    import json as _json

    history = _json.loads(changelog_file.read_text())
    table = Table(title=f"Rule Changelog (last {limit})")
    table.add_column("Timestamp")
    table.add_column("Rule ID")
    table.add_column("Action")
    table.add_column("Version", justify="right")
    for entry in history[-limit:]:
        table.add_row(
            entry.get("timestamp", "")[:19],
            entry.get("rule_id", ""),
            entry.get("action", ""),
            str(entry.get("version", "")),
        )
    console.print(table)


@cli.command("serve")
@click.option("--host", default="127.0.0.1", help="Bind host")
@click.option("--port", default=8000, type=int, help="Bind port")
def serve_cmd(host, port):
    """Launch the read-only web dashboard (requires the [web] extra)."""
    try:
        import uvicorn

        from web.app import create_app
    except ImportError:
        console.print("[red]Web extra not installed.[/] Run: pip install -e '.[web]'")
        return
    uvicorn.run(create_app(), host=host, port=port)


if __name__ == "__main__":
    cli()
