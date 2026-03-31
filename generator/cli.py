"""CLI entry point for the Wazuh Rule Database Generator."""

from pathlib import Path

import click
import yaml
from rich.console import Console
from rich.table import Table

from . import (
    evtx_parser,
    event_analyzer,
    rule_builder,
    rule_correlator,
    alert_leveler,
    validator,
    exporter,
    id_manager,
)

console = Console()
PROJECT_ROOT = Path(__file__).resolve().parent.parent
CONFIG_FILE = PROJECT_ROOT / "config.yaml"


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
def generate(source, auto_approve):
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

        rules.append({
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
        })

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


if __name__ == "__main__":
    cli()
