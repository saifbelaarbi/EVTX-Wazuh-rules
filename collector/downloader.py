"""Download EVTX samples from registered GitHub sources."""

import subprocess
from pathlib import Path

import yaml
from rich.console import Console

console = Console()

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SOURCES_FILE = PROJECT_ROOT / "sources" / "evtx_sources.yaml"
CONFIG_FILE = PROJECT_ROOT / "config.yaml"


def load_config():
    with open(CONFIG_FILE) as f:
        return yaml.safe_load(f)


def load_sources():
    with open(SOURCES_FILE) as f:
        return yaml.safe_load(f)["sources"]


def _git_clone_shallow(url: str, dest: Path) -> bool:
    """Shallow clone a git repo. Returns True on success."""
    if dest.exists():
        console.print(f"  [yellow]Already exists:[/] {dest.name}, pulling updates...")
        result = subprocess.run(
            ["git", "-C", str(dest), "pull", "--ff-only"],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            console.print(f"  [red]Pull failed:[/] {result.stderr.strip()}")
            return False
        return True

    dest.parent.mkdir(parents=True, exist_ok=True)
    result = subprocess.run(
        ["git", "clone", "--depth", "1", url, str(dest)],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        console.print(f"  [red]Clone failed:[/] {result.stderr.strip()}")
        return False
    return True


def _count_evtx_files(directory: Path) -> int:
    """Count .evtx files recursively."""
    return sum(1 for _ in directory.rglob("*.evtx"))


def download_source(source: dict, data_dir: Path) -> dict | None:
    """Download a single EVTX source. Returns download info or None on failure."""
    name = source["name"]
    url = source["url"]
    dest = data_dir / name

    console.print(f"\n[bold blue]Downloading:[/] {name}")
    console.print(f"  URL: {url}")

    if source["type"] == "github_clone":
        success = _git_clone_shallow(url, dest)
    else:
        console.print(f"  [red]Unknown source type:[/] {source['type']}")
        return None

    if not success:
        return None

    evtx_count = _count_evtx_files(dest)
    console.print(f"  [green]Success:[/] {evtx_count} .evtx files found")

    return {
        "name": name,
        "path": str(dest),
        "evtx_count": evtx_count,
        "type": source["type"],
    }


def download_all_sources() -> list[dict]:
    """Download all registered EVTX sources."""
    config = load_config()
    data_dir = PROJECT_ROOT / config["paths"]["evtx_data"]
    data_dir.mkdir(parents=True, exist_ok=True)

    sources = load_sources()
    results = []

    console.print(f"[bold]Downloading {len(sources)} EVTX sources...[/]")

    for source in sources:
        info = download_source(source, data_dir)
        if info:
            results.append(info)

    total_evtx = sum(r["evtx_count"] for r in results)
    console.print(f"\n[bold green]Done:[/] {len(results)}/{len(sources)} sources, {total_evtx} total .evtx files")
    return results


def download_single_source(name: str) -> dict | None:
    """Download a specific source by name."""
    config = load_config()
    data_dir = PROJECT_ROOT / config["paths"]["evtx_data"]
    data_dir.mkdir(parents=True, exist_ok=True)

    sources = load_sources()
    for source in sources:
        if source["name"] == name:
            return download_source(source, data_dir)

    console.print(f"[red]Source not found:[/] {name}")
    console.print(f"Available: {', '.join(s['name'] for s in sources)}")
    return None
