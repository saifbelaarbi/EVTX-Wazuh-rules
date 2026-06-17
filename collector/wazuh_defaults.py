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
    """Download Wazuh default rules via shallow clone."""
    config = load_config()
    data_dir = PROJECT_ROOT / config["paths"]["wazuh_defaults"]

    sources = load_wazuh_sources()
    source = sources[0]

    dest = data_dir / source["name"]

    console.print(f"\n[bold blue]Downloading Wazuh defaults:[/] {source['name']}")
    console.print(f"  URL: {source['url']}")

    sparse_subdir = source.get("sparse_subdir")

    if dest.exists():
        console.print("  [yellow]Already exists,[/] pulling updates...")
        result = subprocess.run(
            ["git", "-C", str(dest), "pull", "--ff-only"],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            console.print(f"  [red]Pull failed:[/] {result.stderr.strip()}")
            return None
    elif sparse_subdir:
        # wazuh/wazuh is a large monorepo — blobless + sparse checkout pulls
        # only the requested subtree (e.g. ruleset/) instead of the whole repo.
        dest.parent.mkdir(parents=True, exist_ok=True)
        clone = subprocess.run(
            [
                "git",
                "clone",
                "--depth",
                "1",
                "--filter=blob:none",
                "--sparse",
                source["url"],
                str(dest),
            ],
            capture_output=True,
            text=True,
        )
        if clone.returncode != 0:
            console.print(f"  [red]Clone failed:[/] {clone.stderr.strip()}")
            return None
        sparse = subprocess.run(
            ["git", "-C", str(dest), "sparse-checkout", "set", sparse_subdir],
            capture_output=True,
            text=True,
        )
        if sparse.returncode != 0:
            console.print(f"  [red]Sparse checkout failed:[/] {sparse.stderr.strip()}")
            return None
    else:
        dest.parent.mkdir(parents=True, exist_ok=True)
        result = subprocess.run(
            ["git", "clone", "--depth", "1", source["url"], str(dest)],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            console.print(f"  [red]Clone failed:[/] {result.stderr.strip()}")
            return None

    # Locate rules and decoders using configured subdirs
    rules_subdir = source.get("rules_subdir", "rules")
    decoders_subdir = source.get("decoders_subdir", "decoders")

    rules_dir = dest / rules_subdir
    decoders_dir = dest / decoders_subdir

    # Fallback: search for the directories if not at expected location
    if not rules_dir.exists():
        for candidate in dest.rglob("rules"):
            if candidate.is_dir() and any(candidate.glob("*.xml")):
                rules_dir = candidate
                break

    if not decoders_dir.exists():
        for candidate in dest.rglob("decoders"):
            if candidate.is_dir() and any(candidate.glob("*.xml")):
                decoders_dir = candidate
                break

    rule_count = sum(1 for _ in rules_dir.glob("*.xml")) if rules_dir.exists() else 0
    decoder_count = sum(1 for _ in decoders_dir.glob("*.xml")) if decoders_dir.exists() else 0

    console.print(f"  [green]Success:[/] {rule_count} rule files, {decoder_count} decoder files")
    if rules_dir.exists():
        console.print(f"  Rules at: {rules_dir.relative_to(dest)}")

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
    base = PROJECT_ROOT / config["paths"]["wazuh_defaults"] / "wazuh-ruleset"
    # Check common locations
    for candidate in [base / "rules", base / "ruleset" / "rules"]:
        if candidate.exists() and any(candidate.glob("*.xml")):
            return candidate
    # Fallback search
    if base.exists():
        for d in base.rglob("rules"):
            if d.is_dir() and any(d.glob("*.xml")):
                return d
    return None


def get_default_decoders_dir() -> Path | None:
    """Get the path to downloaded Wazuh default decoders."""
    config = load_config()
    base = PROJECT_ROOT / config["paths"]["wazuh_defaults"] / "wazuh-ruleset"
    for candidate in [base / "decoders", base / "ruleset" / "decoders"]:
        if candidate.exists() and any(candidate.glob("*.xml")):
            return candidate
    if base.exists():
        for d in base.rglob("decoders"):
            if d.is_dir() and any(d.glob("*.xml")):
                return d
    return None
