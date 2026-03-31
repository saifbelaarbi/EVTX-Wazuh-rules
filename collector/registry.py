"""Track downloaded EVTX sources - checksums, timestamps, file counts."""

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
REGISTRY_FILE = PROJECT_ROOT / "data" / ".registry.json"


def _load_registry() -> dict:
    if REGISTRY_FILE.exists():
        with open(REGISTRY_FILE) as f:
            return json.load(f)
    return {"sources": {}, "last_updated": None}


def _save_registry(registry: dict):
    REGISTRY_FILE.parent.mkdir(parents=True, exist_ok=True)
    registry["last_updated"] = datetime.now(timezone.utc).isoformat()
    with open(REGISTRY_FILE, "w") as f:
        json.dump(registry, f, indent=2)


def _hash_directory(directory: Path) -> str:
    """SHA256 of all .evtx filenames + sizes (fast fingerprint, not content hash)."""
    entries = []
    for f in sorted(directory.rglob("*.evtx")):
        entries.append(f"{f.relative_to(directory)}:{f.stat().st_size}")
    return hashlib.sha256("\n".join(entries).encode()).hexdigest()[:16]


def record_download(info: dict):
    """Record a successful download in the registry."""
    registry = _load_registry()
    path = Path(info["path"])

    registry["sources"][info["name"]] = {
        "path": info["path"],
        "evtx_count": info["evtx_count"],
        "fingerprint": _hash_directory(path) if path.exists() else None,
        "downloaded_at": datetime.now(timezone.utc).isoformat(),
        "type": info["type"],
    }
    _save_registry(registry)


def is_current(name: str, data_dir: Path) -> bool:
    """Check if a source is already downloaded and unchanged."""
    registry = _load_registry()
    if name not in registry["sources"]:
        return False

    entry = registry["sources"][name]
    source_path = Path(entry["path"])
    if not source_path.exists():
        return False

    current_fingerprint = _hash_directory(source_path)
    return current_fingerprint == entry.get("fingerprint")


def get_status() -> dict:
    """Return current registry status."""
    return _load_registry()


def get_source_info(name: str) -> dict | None:
    """Get registry info for a specific source."""
    registry = _load_registry()
    return registry["sources"].get(name)
