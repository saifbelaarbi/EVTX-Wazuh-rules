"""Validate Wazuh rules against source events via simulation or live wazuh-logtest."""

import json
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

import yaml
from lxml import etree
from rich.console import Console
from rich.table import Table

console = Console()

PROJECT_ROOT = Path(__file__).resolve().parent.parent
CONFIG_FILE = PROJECT_ROOT / "config.yaml"
RULE_INDEX_FILE = PROJECT_ROOT / "database" / "metadata" / "rule_index.json"
PROVENANCE_FILE = PROJECT_ROOT / "database" / "metadata" / "provenance.json"
RULES_DIR = PROJECT_ROOT / "database" / "rules"
RESULTS_FILE = PROJECT_ROOT / "database" / "metadata" / "validation_results.json"


@dataclass
class ValidationResult:
    rule_id: int
    passed: bool
    mode: str
    details: list[str] = field(default_factory=list)
    error: str = ""


def load_config():
    with open(CONFIG_FILE) as f:
        return yaml.safe_load(f)


# ── Event Formatting ──


def format_event_for_wazuh(event: dict) -> str:
    """Format a parsed event dict into Wazuh eventchannel JSON."""
    wazuh_event = {
        "win": {
            "system": {
                "providerName": event.get("provider_name", ""),
                "eventID": str(event.get("event_id", "")),
                "channel": event.get("channel", ""),
                "computer": event.get("computer", ""),
                "severityValue": "INFORMATION",
                "systemTime": event.get("timestamp", ""),
            },
            "eventdata": {},
        }
    }

    for key, value in event.get("event_data", {}).items():
        if not isinstance(value, str):
            value = str(value)
        camel_key = key[0].lower() + key[1:] if key else key
        wazuh_event["win"]["eventdata"][camel_key] = value

    return json.dumps(wazuh_event)


def _flatten_event_fields(event: dict) -> dict:
    """Flatten event into Wazuh-style dotted field paths."""
    flat = {}

    flat["win.system.eventID"] = str(event.get("event_id", ""))
    flat["win.system.providerName"] = event.get("provider_name", "")
    flat["win.system.channel"] = event.get("channel", "")
    flat["win.system.computer"] = event.get("computer", "")

    for key, value in event.get("event_data", {}).items():
        if not isinstance(value, str):
            value = str(value)
        camel_key = key[0].lower() + key[1:] if key else key
        flat[f"win.eventdata.{camel_key}"] = value

    return flat


# ── Mode A: Offline Simulator ──


def _osregex_to_python(pattern: str) -> str:
    """Convert Wazuh OS regex to Python regex.

    OS regex differences from standard:
    - Without ^ or $, it's a substring match
    - Case insensitive by default
    - | is alternation
    - \d, \w, \s work as expected
    - . matches any char
    """
    has_start = pattern.startswith("^")
    has_end = pattern.endswith("$")

    if not has_start:
        pattern = ".*" + pattern
    if not has_end:
        pattern = pattern + ".*"

    return pattern


def _match_field(pattern: str, value: str) -> bool:
    """Simulate Wazuh field matching.

    Wazuh <field> matching:
    - Case insensitive
    - Pipe | is OR (alternation)
    - Without anchors, substring match
    """
    if not pattern or not value:
        return False

    alternatives = pattern.split("|")

    for alt in alternatives:
        alt = alt.strip()
        if not alt:
            continue
        try:
            py_pattern = _osregex_to_python(alt)
            if re.search(py_pattern, value, re.IGNORECASE | re.DOTALL):
                return True
        except re.error:
            if alt.lower() in value.lower():
                return True

    return False


def simulate_rule_match(rule_fields: dict, event_fields: dict) -> tuple[bool, list[str]]:
    """Simulate matching a rule's field conditions against an event.

    All field conditions must match (AND logic).
    Returns (matched, detail_messages).
    """
    details = []
    all_matched = True

    for field_name, pattern in rule_fields.items():
        event_value = event_fields.get(field_name, "")

        if not event_value:
            alt_key = field_name
            for ek, ev in event_fields.items():
                if ek.lower() == field_name.lower():
                    event_value = ev
                    break

        matched = _match_field(pattern, event_value)
        status = "PASS" if matched else "FAIL"
        details.append(f"  {status}: {field_name} = '{pattern}' vs '{event_value[:80]}'")

        if not matched:
            all_matched = False

    return all_matched, details


def validate_simulate(rule_id: int, rule_meta: dict, event: dict) -> ValidationResult:
    """Validate a single rule in simulation mode."""
    field_matches = rule_meta.get("field_matches", {})
    if not field_matches:
        return ValidationResult(
            rule_id=rule_id, passed=False, mode="simulate",
            error="No field_matches in metadata",
        )

    event_fields = _flatten_event_fields(event)
    passed, details = simulate_rule_match(field_matches, event_fields)

    return ValidationResult(
        rule_id=rule_id, passed=passed, mode="simulate", details=details,
    )


# ── Mode B: Wazuh REST API ──


def _run_via_api(event_json: str, config: dict) -> dict:
    """Run logtest via Wazuh REST API."""
    try:
        import requests
        from urllib3.exceptions import InsecureRequestWarning
        requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
    except ImportError:
        return {"error": "requests package not installed: pip install requests"}

    wazuh_cfg = config.get("wazuh", {})
    api_url = wazuh_cfg.get("api_url", "")
    user = wazuh_cfg.get("api_user", "wazuh-wui")
    password = ""

    pw_file = wazuh_cfg.get("api_password_file", "")
    if pw_file:
        pw_path = Path(pw_file).expanduser()
        if pw_path.exists():
            password = pw_path.read_text().strip()

    if not password:
        password = wazuh_cfg.get("api_password", "")

    if not api_url:
        return {"error": "wazuh.api_url not configured"}

    verify_ssl = wazuh_cfg.get("api_verify_ssl", False)

    try:
        auth_resp = requests.post(
            f"{api_url}/security/user/authenticate",
            auth=(user, password),
            verify=verify_ssl,
            timeout=10,
        )
        auth_resp.raise_for_status()
        token = auth_resp.json()["data"]["token"]
    except Exception as e:
        return {"error": f"API auth failed: {e}"}

    headers = {"Authorization": f"Bearer {token}"}

    try:
        logtest_resp = requests.put(
            f"{api_url}/logtest",
            headers=headers,
            json={
                "event": event_json,
                "log_format": "eventchannel",
                "location": "EventChannel",
            },
            verify=verify_ssl,
            timeout=30,
        )
        logtest_resp.raise_for_status()
        return logtest_resp.json()
    except Exception as e:
        return {"error": f"API logtest failed: {e}"}


# ── Mode C: SSH ──


def _run_via_ssh(event_json: str, config: dict) -> dict:
    """Run logtest via SSH to remote Wazuh manager."""
    wazuh_cfg = config.get("wazuh", {})
    ssh_host = wazuh_cfg.get("ssh_host", "")
    ssh_user = wazuh_cfg.get("ssh_user", "root")
    ssh_key = wazuh_cfg.get("ssh_key", "")
    logtest_path = wazuh_cfg.get("logtest_path", "/var/ossec/bin/wazuh-logtest")
    use_sudo = wazuh_cfg.get("sudo", True)

    if not ssh_host:
        return {"error": "wazuh.ssh_host not configured"}

    cmd = ["ssh"]
    if ssh_key:
        cmd.extend(["-i", str(Path(ssh_key).expanduser())])
    cmd.extend(["-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=10"])
    cmd.append(f"{ssh_user}@{ssh_host}")

    remote_cmd = logtest_path
    if use_sudo:
        remote_cmd = f"sudo {remote_cmd}"

    cmd.append(remote_cmd)

    try:
        result = subprocess.run(
            cmd,
            input=event_json + "\n",
            capture_output=True,
            text=True,
            timeout=30,
        )
        return {"output": result.stdout, "stderr": result.stderr, "returncode": result.returncode}
    except subprocess.TimeoutExpired:
        return {"error": "SSH logtest timed out"}
    except Exception as e:
        return {"error": f"SSH logtest failed: {e}"}


def validate_live(rule_id: int, event: dict, config: dict) -> ValidationResult:
    """Validate a rule via live wazuh-logtest (API first, SSH fallback)."""
    event_json = format_event_for_wazuh(event)

    wazuh_cfg = config.get("wazuh", {})
    if wazuh_cfg.get("api_url"):
        result = _run_via_api(event_json, config)
        if "error" not in result:
            data = result.get("data", {}).get("output", {})
            matched_rule = data.get("rule", {}).get("id", "")
            passed = str(matched_rule) == str(rule_id)
            details = [
                f"API matched rule: {matched_rule}",
                f"Expected: {rule_id}",
                f"Level: {data.get('rule', {}).get('level', 'N/A')}",
            ]
            return ValidationResult(
                rule_id=rule_id, passed=passed, mode="live_api", details=details,
            )
        api_error = result["error"]
    else:
        api_error = "API not configured"

    if wazuh_cfg.get("ssh_host"):
        result = _run_via_ssh(event_json, config)
        if "error" not in result:
            output = result.get("output", "")
            passed = str(rule_id) in output
            details = [f"SSH output: {output[:200]}"]
            return ValidationResult(
                rule_id=rule_id, passed=passed, mode="live_ssh", details=details,
            )
        ssh_error = result["error"]
    else:
        ssh_error = "SSH not configured"

    return ValidationResult(
        rule_id=rule_id, passed=False, mode="live",
        error=f"No live method available. API: {api_error}; SSH: {ssh_error}",
    )


# ── Batch Validation ──


def _load_rule_index() -> dict:
    if RULE_INDEX_FILE.exists():
        with open(RULE_INDEX_FILE) as f:
            return json.load(f)
    return {}


def _load_provenance() -> dict:
    if PROVENANCE_FILE.exists():
        with open(PROVENANCE_FILE) as f:
            return json.load(f)
    return {}


def _find_sample_event(source_evtx: str, rule_meta: dict) -> dict | None:
    """Try to find a sample event for a rule from its source file."""
    from . import evtx_parser

    source_path = Path(source_evtx)
    if not source_path.exists():
        return None

    suffix = source_path.suffix.lower()
    if suffix in (".yml", ".yaml", ".md", ".txt", ".py"):
        return None

    try:
        events = evtx_parser.parse_file(source_path, max_events=100)
    except Exception:
        return None

    if not events:
        return None

    field_matches = rule_meta.get("field_matches", {})
    for event in events:
        flat = _flatten_event_fields(event)
        match_count = 0
        for field_name, pattern in field_matches.items():
            ev = flat.get(field_name, "")
            if ev and pattern.lower() in ev.lower():
                match_count += 1
        if match_count > 0:
            return event

    return events[0]


def validate_all_rules(mode: str = "simulate", source_filter: str = None) -> list[ValidationResult]:
    """Validate all rules that have source events."""
    index = _load_rule_index()
    config = load_config()

    results = []
    tested = 0
    passed = 0
    skipped = 0

    console.print(f"[bold]Validating {len(index)} rules (mode={mode})...[/]\n")

    event_cache: dict[str, dict | None] = {}

    for rule_id_str, meta in sorted(index.items(), key=lambda x: int(x[0])):
        source = meta.get("source_evtx", "")
        if not source:
            skipped += 1
            continue

        if source_filter and source_filter not in source:
            continue

        cache_key = f"{source}::{rule_id_str}"
        if source in event_cache:
            event = event_cache[source]
        else:
            event = _find_sample_event(source, meta)
            if len(event_cache) < 500:
                event_cache[source] = event

        if not event:
            skipped += 1
            continue

        rule_id = int(rule_id_str)
        if mode == "simulate":
            result = validate_simulate(rule_id, meta, event)
        else:
            result = validate_live(rule_id, event, config)

        results.append(result)
        tested += 1
        if result.passed:
            passed += 1

    console.print(f"\n[bold]Validation Complete[/]")
    console.print(f"  Tested: {tested}")
    console.print(f"  Passed: [green]{passed}[/]")
    console.print(f"  Failed: [red]{tested - passed}[/]")
    console.print(f"  Skipped (no source): {skipped}")

    return results


def validate_single_rule(rule_id: int, mode: str = "simulate") -> ValidationResult:
    """Validate a specific rule by ID."""
    index = _load_rule_index()
    config = load_config()

    rule_id_str = str(rule_id)
    if rule_id_str not in index:
        return ValidationResult(
            rule_id=rule_id, passed=False, mode=mode, error="Rule not found in index",
        )

    meta = index[rule_id_str]
    source = meta.get("source_evtx", "")

    if not source:
        return ValidationResult(
            rule_id=rule_id, passed=False, mode=mode,
            error="No source event file for this rule",
        )

    event = _find_sample_event(source, meta)
    if not event:
        return ValidationResult(
            rule_id=rule_id, passed=False, mode=mode,
            error=f"Could not parse source: {source}",
        )

    if mode == "simulate":
        return validate_simulate(rule_id, meta, event)
    else:
        return validate_live(rule_id, event, config)


def save_results(results: list[ValidationResult]):
    """Save validation results to JSON."""
    RESULTS_FILE.parent.mkdir(parents=True, exist_ok=True)

    data = {}
    for r in results:
        data[str(r.rule_id)] = {
            "passed": r.passed,
            "mode": r.mode,
            "details": r.details,
            "error": r.error,
        }

    with open(RESULTS_FILE, "w") as f:
        json.dump(data, f, indent=2)

    console.print(f"\n[bold green]Results saved to:[/] {RESULTS_FILE}")


def print_result(result: ValidationResult, verbose: bool = False):
    """Print a single validation result."""
    icon = "[green]PASS[/]" if result.passed else "[red]FAIL[/]"
    console.print(f"  {icon} Rule {result.rule_id} ({result.mode})")

    if result.error:
        console.print(f"    [red]Error: {result.error}[/]")

    if verbose and result.details:
        for detail in result.details:
            console.print(f"    {detail}")
