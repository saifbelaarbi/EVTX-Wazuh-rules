"""Download Wazuh default rules and decoders for reference."""

import subprocess
from pathlib import Path

import yaml
from rich.console import Console

console = Console()

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SOURCES_FILE = PROJECT_ROOT / "sources" / "wazuh_default_sources.yaml"
CONFIG_FILE = PROJECT_ROOT / "config.yaml"


def load_config():
    with open(CONFIG_FILE) as f:
        return yaml.safe_load(f)


def load_wazuh_sources():
    with open(SOURCES_FILE) as f:
        return yaml.safe_load(f)["wazuh_defaults"]


def download_wazuh_defaults() -> dict | None:
    """Download Wazuh default rules via sparse checkout."""
    config = load_config()
    data_dir = PROJECT_ROOT / config["paths"]["wazuh_defaults"]

    sources = load_wazuh_sources()
    source = sources[0]  # Primary wazuh source

    dest = data_dir / source["name"]

    console.print(f"\n[bold blue]Downloading Wazuh defaults:[/] {source['name']}")
    console.print(f"  URL: {source['url']}")

    if dest.exists():
        console.print(f"  [yellow]Already exists,[/] pulling updates...")
        result = subprocess.run(
            ["git", "-C", str(dest), "pull", "--ff-only"],
            capture_output=True, text=True,
        )
        if result.returncode != 0:
            console.print(f"  [red]Pull failed:[/] {result.stderr.strip()}")
            return None
    else:
        dest.parent.mkdir(parents=True, exist_ok=True)

        # Initialize sparse checkout for just the ruleset directory
        commands = [
            ["git", "clone", "--depth", "1", "--filter=blob:none",
             "--sparse", source["url"], str(dest)],
        ]
        # Add sparse-checkout paths
        for sparse_path in source.get("sparse_paths", []):
            commands.append(
                ["git", "-C", str(dest), "sparse-checkout", "add", sparse_path]
            )

        for cmd in commands:
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode != 0:
                console.print(f"  [red]Failed:[/] {' '.join(cmd)}")
                console.print(f"  {result.stderr.strip()}")
                return None

    # Count rule files
    rules_dir = dest / "ruleset" / "rules"
    rule_count = sum(1 for _ in rules_dir.glob("*.xml")) if rules_dir.exists() else 0

    decoders_dir = dest / "ruleset" / "decoders"
    decoder_count = sum(1 for _ in decoders_dir.glob("*.xml")) if decoders_dir.exists() else 0

    console.print(f"  [green]Success:[/] {rule_count} rule files, {decoder_count} decoder files")

    return {
        "name": source["name"],
        "path": str(dest),
        "rule_count": rule_count,
        "decoder_count": decoder_count,
        "rules_dir": str(rules_dir),
        "decoders_dir": str(decoders_dir),
    }


def get_default_rules_dir() -> Path | None:
    """Get the path to downloaded Wazuh default rules."""
    config = load_config()
    rules_dir = PROJECT_ROOT / config["paths"]["wazuh_defaults"] / "wazuh-ruleset" / "ruleset" / "rules"
    return rules_dir if rules_dir.exists() else None


def get_default_decoders_dir() -> Path | None:
    """Get the path to downloaded Wazuh default decoders."""
    config = load_config()
    decoders_dir = PROJECT_ROOT / config["paths"]["wazuh_defaults"] / "wazuh-ruleset" / "ruleset" / "decoders"
    return decoders_dir if decoders_dir.exists() else None
