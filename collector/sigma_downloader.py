"""Download Sigma detection rules from SigmaHQ."""

import subprocess
from pathlib import Path

import yaml
from rich.console import Console

console = Console()

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SIGMA_SOURCES_FILE = PROJECT_ROOT / "sources" / "sigma_sources.yaml"
CONFIG_FILE = PROJECT_ROOT / "config.yaml"


def load_config():
    with open(CONFIG_FILE) as f:
        return yaml.safe_load(f)


def load_sigma_sources():
    with open(SIGMA_SOURCES_FILE) as f:
        return yaml.safe_load(f)["sigma_sources"]


def download_sigma_rules() -> dict | None:
    """Download Sigma rules (Windows only) via shallow clone."""
    config = load_config()
    data_dir = PROJECT_ROOT / config["paths"]["sigma_data"]
    data_dir.mkdir(parents=True, exist_ok=True)

    sources = load_sigma_sources()

    results = []
    for source in sources:
        name = source["name"]
        url = source["url"]
        dest = data_dir / name

        console.print(f"\n[bold blue]Downloading Sigma rules:[/] {name}")
        console.print(f"  URL: {url}")

        if dest.exists():
            console.print(f"  [yellow]Already exists:[/] {dest.name}, pulling updates...")
            result = subprocess.run(
                ["git", "-C", str(dest), "pull", "--ff-only"],
                capture_output=True, text=True,
            )
            if result.returncode != 0:
                console.print(f"  [red]Pull failed:[/] {result.stderr.strip()}")
                continue
        else:
            result = subprocess.run(
                ["git", "clone", "--depth", "1", url, str(dest)],
                capture_output=True, text=True,
            )
            if result.returncode != 0:
                console.print(f"  [red]Clone failed:[/] {result.stderr.strip()}")
                continue

        rules_subdir = source.get("rules_subdir", "rules/windows")
        rules_path = dest / rules_subdir

        if not rules_path.exists():
            console.print(f"  [red]Rules directory not found:[/] {rules_subdir}")
            continue

        yaml_count = sum(1 for _ in rules_path.rglob("*.yml"))
        console.print(f"  [green]Success:[/] {yaml_count} Sigma YAML rules found in {rules_subdir}")

        category_counts = {}
        for category in source.get("categories", []):
            cat_path = rules_path / category
            if cat_path.exists():
                count = sum(1 for _ in cat_path.rglob("*.yml"))
                category_counts[category] = count

        if category_counts:
            console.print("  [bold]Categories:[/]")
            for cat, count in sorted(category_counts.items(), key=lambda x: -x[1]):
                console.print(f"    {cat}: {count} rules")

        results.append({
            "name": name,
            "path": str(dest),
            "rules_path": str(rules_path),
            "yaml_count": yaml_count,
            "categories": category_counts,
        })

    if results:
        total = sum(r["yaml_count"] for r in results)
        console.print(f"\n[bold green]Sigma download complete:[/] {total} total rules")
        return results[0]
    return None


def get_sigma_rules_dir() -> Path | None:
    """Get the path to downloaded Sigma Windows rules."""
    config = load_config()
    data_dir = PROJECT_ROOT / config["paths"]["sigma_data"]

    sources = load_sigma_sources()
    for source in sources:
        rules_path = data_dir / source["name"] / source.get("rules_subdir", "rules/windows")
        if rules_path.exists():
            return rules_path
    return None
