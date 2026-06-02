"""Click CLI for deploying generated rules to a Wazuh manager."""

from pathlib import Path

import click
from rich.console import Console

from .wazuh_deployer import PROJECT_ROOT, deploy_with_rollback

console = Console()

DEFAULT_SRC = PROJECT_ROOT / "database" / "rules"
DEFAULT_DEST = Path("/var/ossec/etc/rules")


@click.group()
def cli():
    """Deploy EVTX-Wazuh-Rules to a Wazuh manager."""


@cli.command()
@click.option(
    "--src",
    type=click.Path(path_type=Path),
    default=DEFAULT_SRC,
    show_default=True,
    help="Source rules directory (database/rules).",
)
@click.option(
    "--dest",
    type=click.Path(path_type=Path),
    default=DEFAULT_DEST,
    show_default=True,
    help="Wazuh manager rules directory (deploy_path).",
)
@click.option(
    "--view",
    type=click.Choice(["by_tactic", "by_technique", "by_source"]),
    default="by_tactic",
    show_default=True,
    help="Which organizational view to deploy.",
)
def deploy(src: Path, dest: Path, view: str):
    """Back up, deploy, health-check, and roll back on failure."""
    summary = deploy_with_rollback(src, dest, view=view)

    console.print("\n[bold]Deployment summary[/]")
    console.print(f"  deployed    : {summary['deployed']} files")
    console.print(f"  backed_up   : {summary['backed_up']}")
    console.print(f"  healthy     : {summary['healthy']}")
    console.print(f"  rolled_back : {summary['rolled_back']}")
    console.print(f"  backup_path : {summary['backup_path']}")

    if summary["rolled_back"]:
        console.print("[bold red]Deployment failed health check; rolled back.[/]")
    else:
        console.print("[bold green]Deployment healthy.[/]")
