"""Parse EVTX binary files and JSON/XML exports into normalized event dicts."""

import json
import hashlib
from pathlib import Path
from xml.etree import ElementTree as ET

from rich.console import Console

console = Console()

# Namespace used in EVTX XML
NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}


def detect_format(file_path: Path) -> str:
    """Auto-detect input format from extension and content."""
    suffix = file_path.suffix.lower()
    if suffix == ".evtx":
        return "evtx"
    elif suffix == ".json" or suffix == ".jsonl":
        return "json"
    elif suffix == ".xml":
        return "xml"
    raise ValueError(f"Unsupported file format: {suffix}")


def parse_evtx_binary(file_path: Path) -> list[dict]:
    """Parse a .evtx binary file. Supports both 'evtx' (Rust) and 'python-evtx' packages."""
    events = []

    # Try the Rust-based 'evtx' package first (faster, easier to install)
    try:
        import evtx as evtx_rs

        parser = evtx_rs.PyEvtxParser(str(file_path))
        for record in parser.records_json():
            try:
                import json as _json
                raw = _json.loads(record["data"])
                event = _normalize_evtx_rs_record(raw)
                if event:
                    event["_source_file"] = str(file_path)
                    event["_record_id"] = record.get("event_record_id", 0)
                    events.append(event)
            except Exception:
                continue
        return events
    except ImportError:
        pass

    # Fallback to python-evtx
    try:
        import Evtx.Evtx as evtx_py

        with evtx_py.Evtx(str(file_path)) as log:
            for record in log.records():
                try:
                    event = _parse_evtx_xml_record(record.xml())
                    if event:
                        event["_source_file"] = str(file_path)
                        event["_record_id"] = record.record_num()
                        events.append(event)
                except Exception:
                    continue
        return events
    except ImportError:
        console.print("[red]No EVTX parser installed. Run: pip install evtx[/]")
        return []
    except Exception as e:
        console.print(f"[red]Failed to parse {file_path.name}:[/] {e}")
        return events


def _normalize_evtx_rs_record(raw: dict) -> dict | None:
    """Normalize a record from the Rust evtx parser's JSON output."""
    event = {}
    system = raw.get("Event", {}).get("System", {})
    event_data_raw = raw.get("Event", {}).get("EventData", {})

    if not system:
        return None

    # Provider
    provider = system.get("Provider", {})
    if isinstance(provider, dict):
        event["provider_name"] = provider.get("#attributes", {}).get("Name", "")
        event["provider_guid"] = provider.get("#attributes", {}).get("Guid", "")
    else:
        event["provider_name"] = str(provider)

    # EventID - may be int or dict
    eid = system.get("EventID", 0)
    if isinstance(eid, dict):
        eid = eid.get("#text", 0)
    event["event_id"] = int(eid) if str(eid).isdigit() else 0

    event["channel"] = system.get("Channel", "")
    event["computer"] = system.get("Computer", "")

    time_created = system.get("TimeCreated", {})
    if isinstance(time_created, dict):
        event["timestamp"] = time_created.get("#attributes", {}).get("SystemTime", "")
    else:
        event["timestamp"] = str(time_created)

    # EventData
    event["event_data"] = {}
    if isinstance(event_data_raw, dict):
        for k, v in event_data_raw.items():
            if k.startswith("#"):
                continue
            if isinstance(v, dict):
                v = v.get("#text", str(v))
            event["event_data"][k] = str(v) if v is not None else ""

    return event


def _parse_evtx_xml_record(xml_str: str) -> dict | None:
    """Parse a single EVTX XML record into a normalized dict."""
    try:
        root = ET.fromstring(xml_str)
    except ET.ParseError:
        return None

    event = {}

    # System fields
    system = root.find("e:System", NS)
    if system is not None:
        provider = system.find("e:Provider", NS)
        if provider is not None:
            event["provider_name"] = provider.get("Name", "")
            event["provider_guid"] = provider.get("Guid", "")

        event_id_elem = system.find("e:EventID", NS)
        if event_id_elem is not None:
            event["event_id"] = int(event_id_elem.text or 0)

        event["channel"] = _get_text(system, "e:Channel", NS)
        event["computer"] = _get_text(system, "e:Computer", NS)
        event["level"] = _get_text(system, "e:Level", NS)
        event["task"] = _get_text(system, "e:Task", NS)
        event["opcode"] = _get_text(system, "e:Opcode", NS)
        event["keywords"] = _get_text(system, "e:Keywords", NS)

        time_created = system.find("e:TimeCreated", NS)
        if time_created is not None:
            event["timestamp"] = time_created.get("SystemTime", "")

    # EventData fields
    event_data = root.find("e:EventData", NS)
    if event_data is not None:
        event["event_data"] = {}
        for data in event_data:
            name = data.get("Name", "")
            value = data.text or ""
            if name:
                event["event_data"][name] = value

    # UserData fields (some events use this instead of EventData)
    user_data = root.find("e:UserData", NS)
    if user_data is not None and "event_data" not in event:
        event["event_data"] = {}
        for child in user_data:
            for elem in child:
                tag = elem.tag.split("}")[-1] if "}" in elem.tag else elem.tag
                event["event_data"][tag] = elem.text or ""

    return event


def _get_text(parent, tag: str, ns: dict) -> str:
    elem = parent.find(tag, ns)
    return elem.text if elem is not None and elem.text else ""


def parse_json_export(file_path: Path) -> list[dict]:
    """Parse JSON/JSONL exports (e.g., from EvtxECmd, chainsaw, hayabusa)."""
    events = []
    try:
        with open(file_path) as f:
            content = f.read().strip()
            if content.startswith("["):
                raw_events = json.loads(content)
            else:
                # JSONL format
                raw_events = [json.loads(line) for line in content.splitlines() if line.strip()]

        for raw in raw_events:
            event = _normalize_json_event(raw)
            event["_source_file"] = str(file_path)
            events.append(event)
    except Exception as e:
        console.print(f"[red]Failed to parse JSON {file_path.name}:[/] {e}")

    return events


def _normalize_json_event(raw: dict) -> dict:
    """Normalize a JSON event to our common schema."""
    event = {}

    event["event_id"] = raw.get("EventID") or raw.get("event_id") or raw.get("Event.System.EventID") or 0
    if isinstance(event["event_id"], str):
        event["event_id"] = int(event["event_id"]) if event["event_id"].isdigit() else 0
    elif isinstance(event["event_id"], dict):
        event["event_id"] = int(event["event_id"].get("#text", 0))

    event["channel"] = raw.get("Channel") or raw.get("channel") or raw.get("Event.System.Channel") or ""
    event["provider_name"] = (raw.get("Provider") or raw.get("SourceName")
                               or raw.get("provider_name") or "")
    event["computer"] = raw.get("Computer") or raw.get("Hostname") or raw.get("computer") or ""
    event["timestamp"] = (raw.get("Timestamp") or raw.get("TimeCreated")
                           or raw.get("EventTime") or raw.get("@timestamp")
                           or raw.get("timestamp") or "")

    event_data = raw.get("EventData") or raw.get("event_data") or {}
    if not event_data:
        _SYSTEM_FIELDS = {
            "EventID", "Channel", "Provider", "Computer", "Timestamp",
            "TimeCreated", "event_id", "channel", "provider_name",
            "computer", "timestamp", "Level", "Task", "SourceName",
            "Hostname", "EventTime", "@timestamp", "@version", "tags",
            "EventType", "Version", "ThreadID", "OpcodeValue",
            "RecordNumber", "EventReceivedTime", "SourceModuleName",
            "SourceModuleType", "Severity", "SeverityValue", "UserID",
            "ProviderGuid", "AccountType", "Domain", "AccountName",
            "ExecutionProcessID", "host", "port", "Message",
        }
        event_data = {k: str(v) for k, v in raw.items()
                      if k not in _SYSTEM_FIELDS and v is not None}

    event["event_data"] = event_data
    return event


def parse_xml_export(file_path: Path) -> list[dict]:
    """Parse XML exports of Windows Event Logs."""
    events = []
    try:
        tree = ET.parse(str(file_path))
        root = tree.getroot()

        # Handle both single events and collections
        for event_elem in root.iter():
            if event_elem.tag.endswith("Event") or event_elem.tag == "Event":
                event = _parse_evtx_xml_record(ET.tostring(event_elem, encoding="unicode"))
                if event:
                    event["_source_file"] = str(file_path)
                    events.append(event)
    except Exception as e:
        console.print(f"[red]Failed to parse XML {file_path.name}:[/] {e}")

    return events


def parse_file(file_path: Path, max_events: int | None = None) -> list[dict]:
    """Parse any supported file format, auto-detecting type."""
    fmt = detect_format(file_path)
    if fmt == "evtx":
        events = parse_evtx_binary(file_path)
    elif fmt == "json":
        events = parse_json_export(file_path)
    elif fmt == "xml":
        events = parse_xml_export(file_path)
    else:
        events = []
    if max_events and len(events) > max_events:
        return events[:max_events]
    return events


def parse_directory(directory: Path, extensions: tuple = (".evtx", ".json", ".jsonl", ".xml")) -> list[dict]:
    """Parse all supported files in a directory recursively."""
    all_events = []
    files = [f for f in directory.rglob("*") if f.suffix.lower() in extensions]
    console.print(f"[bold]Found {len(files)} parseable files in {directory.name}[/]")

    for f in sorted(files):
        events = parse_file(f)
        all_events.extend(events)

    console.print(f"[green]Parsed {len(all_events)} events total[/]")
    return all_events


def cache_events(events: list[dict], cache_key: str, cache_dir: Path):
    """Cache parsed events as JSON for faster re-runs."""
    cache_dir.mkdir(parents=True, exist_ok=True)
    safe_key = hashlib.md5(cache_key.encode()).hexdigest()
    cache_file = cache_dir / f"{safe_key}.json"
    with open(cache_file, "w") as f:
        json.dump(events, f)


def load_cached_events(cache_key: str, cache_dir: Path) -> list[dict] | None:
    """Load cached events if available."""
    safe_key = hashlib.md5(cache_key.encode()).hexdigest()
    cache_file = cache_dir / f"{safe_key}.json"
    if cache_file.exists():
        with open(cache_file) as f:
            return json.load(f)
    return None
