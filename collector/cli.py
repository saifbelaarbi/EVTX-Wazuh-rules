"""CLI entry point for the EVTX Collection Engine."""

import click
from rich.console import Console
from rich.table import Table

from . import downloader, registry, sigma_downloader, wazuh_defaults

console = Console()


@click.group()
def cli():
    """EVTX Collection Engine - Download EVTX samples and Wazuh default rules."""
    pass


@cli.command("download-all")
def download_all():
    """Download all registered EVTX sources."""
    results = downloader.download_all_sources()
    for info in results:
        registry.record_download(info)
    console.print(f"\n[bold]Registry updated with {len(results)} sources.[/]")


@cli.command("download")
@click.argument("name")
def download_single(name):
    """Download a specific EVTX source by name."""
    info = downloader.download_single_source(name)
    if info:
        registry.record_download(info)
        console.print("[bold]Registry updated.[/]")


@cli.command("download-defaults")
def download_defaults():
    """Download Wazuh default rules and decoders."""
    info = wazuh_defaults.download_wazuh_defaults()
    if info:
        console.print(f"\n[bold green]Wazuh defaults ready at:[/] {info['path']}")


@cli.command("status")
def status():
    """Show download status of all sources."""
    reg = registry.get_status()
    sources_config = downloader.load_sources()

    table = Table(title="EVTX Collection Status")
    table.add_column("Source", style="bold")
    table.add_column("Status")
    table.add_column("EVTX Files", justify="right")
    table.add_column("Downloaded At")

    for source in sources_config:
        name = source["name"]
        info = reg["sources"].get(name)
        if info:
            table.add_row(
                name,
                "[green]Downloaded[/]",
                str(info["evtx_count"]),
                info["downloaded_at"][:19],
            )
        else:
            table.add_row(name, "[red]Not downloaded[/]", "-", "-")

    console.print(table)

    # Wazuh defaults status
    rules_dir = wazuh_defaults.get_default_rules_dir()
    if rules_dir:
        console.print(f"\n[green]Wazuh defaults:[/] Available at {rules_dir}")
    else:
        console.print("\n[yellow]Wazuh defaults:[/] Not downloaded yet")


@cli.command("download-sigma")
def download_sigma():
    """Download SigmaHQ Sigma detection rules (Windows)."""
    info = sigma_downloader.download_sigma_rules()
    if info:
        console.print(f"\n[bold green]Sigma rules ready at:[/] {info['rules_path']}")


@cli.command("download-atomic")
def download_atomic():
    """Clone the Atomic Red Team repo for the atomic ingestion path."""
    from pathlib import Path

    from . import downloader

    project_root = Path(__file__).resolve().parent.parent
    dest = project_root / "data" / "atomic-red-team"
    ok = downloader._git_clone_shallow("https://github.com/redcanaryco/atomic-red-team", dest)
    if ok:
        console.print(f"[bold green]Atomic Red Team ready at:[/] {dest}")
        console.print("[dim]Run: python -m generator generate-atomic --auto-approve[/]")
    else:
        console.print("[red]Failed to clone Atomic Red Team.[/]")


@cli.command("list-sources")
def list_sources():
    """List all registered EVTX sources."""
    sources = downloader.load_sources()
    table = Table(title="Registered EVTX Sources")
    table.add_column("Name", style="bold")
    table.add_column("Repository")
    table.add_column("Description")
    table.add_column("MITRE Mapped")

    for s in sources:
        table.add_row(
            s["name"],
            s["repo"],
            s["description"],
            "[green]Yes[/]" if s.get("mitre_mapped") else "[yellow]No[/]",
        )
    console.print(table)

    # Also show sigma sources
    try:
        sigma_sources = sigma_downloader.load_sigma_sources()
        console.print()
        table2 = Table(title="Registered Sigma Sources")
        table2.add_column("Name", style="bold")
        table2.add_column("Repository")
        table2.add_column("Description")
        for s in sigma_sources:
            table2.add_row(s["name"], s["repo"], s["description"])
        console.print(table2)
    except FileNotFoundError:
        pass


if __name__ == "__main__":
    cli()
