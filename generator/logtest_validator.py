"""Validate Wazuh rules against source events via simulation or live wazuh-logtest."""

import json
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

import yaml
from rich.console import Console

console = Console()

PROJECT_ROOT = Path(__file__).resolve().parent.parent
CONFIG_FILE = PROJECT_ROOT / "config.yaml"
RULE_INDEX_FILE = PROJECT_ROOT / "database" / "metadata" / "rule_index.json"
PROVENANCE_FILE = PROJECT_ROOT / "database" / "metadata" / "provenance.json"
SAMPLE_EVENTS_FILE = PROJECT_ROOT / "database" / "metadata" / "sample_events.json"
RULES_DIR = PROJECT_ROOT / "database" / "rules"
RESULTS_FILE = PROJECT_ROOT / "database" / "metadata" / "validation_results.json"


@dataclass
class ValidationResult:
    rule_id: int
    passed: bool
    mode: str
    details: list[str] = field(default_factory=list)
    error: str = ""
    inconclusive: bool = False


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
    r"""Convert Wazuh OSRegex to Python regex.

    Key semantic inversion vs PCRE:
    - OSRegex ``.``  = literal dot    → Python ``\.``
    - OSRegex ``\.`` = any character  → Python ``.``
    - OSRegex ``\.*`` = zero-or-more any → Python ``.*``
    - ``\\`` = literal backslash → Python ``\\``
    - Without ``^``/``$``, substring match (wrap with ``.*``).
    """
    has_start = pattern.startswith("^")
    has_end = pattern.endswith("$") and not pattern.endswith("\\$")

    out: list[str] = []
    if not has_start:
        out.append(".*")

    i = 0
    while i < len(pattern):
        ch = pattern[i]
        if ch == "\\" and i + 1 < len(pattern):
            nxt = pattern[i + 1]
            if nxt == ".":
                if i + 2 < len(pattern) and pattern[i + 2] == "*":
                    out.append(".*")
                    i += 3
                elif i + 2 < len(pattern) and pattern[i + 2] == "+":
                    out.append(".+")
                    i += 3
                else:
                    out.append(".")
                    i += 2
            elif nxt == "\\":
                out.append("\\\\")
                i += 2
            elif nxt in "dwsWDS":
                out.append("\\" + nxt)
                i += 2
            else:
                out.append(re.escape(nxt))
                i += 2
        elif ch == ".":
            out.append("\\.")
            i += 1
        else:
            out.append(ch)
            i += 1

    if not has_end:
        out.append(".*")

    return "".join(out)


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
            rule_id=rule_id,
            passed=False,
            mode="simulate",
            error="No field_matches in metadata",
        )

    event_fields = _flatten_event_fields(event)
    passed, details = simulate_rule_match(field_matches, event_fields)

    return ValidationResult(
        rule_id=rule_id,
        passed=passed,
        mode="simulate",
        details=details,
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
                rule_id=rule_id,
                passed=passed,
                mode="live_api",
                details=details,
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
                rule_id=rule_id,
                passed=passed,
                mode="live_ssh",
                details=details,
            )
        ssh_error = result["error"]
    else:
        ssh_error = "SSH not configured"

    return ValidationResult(
        rule_id=rule_id,
        passed=False,
        mode="live",
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


_SAMPLE_EVENTS_CACHE: dict | None = None


def _load_sample_events() -> dict:
    """Load (and cache) the persisted per-rule sample events sidecar."""
    global _SAMPLE_EVENTS_CACHE
    if _SAMPLE_EVENTS_CACHE is None:
        if SAMPLE_EVENTS_FILE.exists():
            with open(SAMPLE_EVENTS_FILE) as f:
                _SAMPLE_EVENTS_CACHE = json.load(f)
        else:
            _SAMPLE_EVENTS_CACHE = {}
    return _SAMPLE_EVENTS_CACHE


def _literal_from_pattern(pattern: str) -> str:
    """Derive a concrete literal that satisfies an OSRegex field pattern.

    OSRegex semantics: ``.`` = literal dot, ``\\.`` = any char, ``\\.*`` = any*.
    """
    p = pattern.split("|")[0]
    p = p.lstrip("^").rstrip("$")
    p = p.replace("[-/]", "-")
    out: list[str] = []
    i = 0
    while i < len(p):
        if p[i] == "\\" and i + 1 < len(p):
            nxt = p[i + 1]
            if nxt == "." and i + 2 < len(p) and p[i + 2] == "*":
                out.append("x")
                i += 3
            elif nxt == ".":
                out.append("x")
                i += 2
            elif nxt == "\\":
                out.append("\\")
                i += 2
            else:
                out.append(nxt)
                i += 2
        elif p[i] == ".":
            out.append(".")
            i += 1
        else:
            out.append(p[i])
            i += 1
    return "".join(out) or "x"


def synthesize_event(field_matches: dict, event_id, channel: str, provider: str) -> dict:
    """Build a minimal event whose flattened fields satisfy every pattern.

    Used to round-trip-validate source-less (Sigma-converted) rules: the event
    is constructed to match the rule, proving the rule is well-formed and
    matchable rather than that it fires on real attack telemetry.
    """
    event_data = {}
    derived_eid = event_id
    for field_path, pattern in field_matches.items():
        literal = _literal_from_pattern(str(pattern))
        if field_path == "win.system.eventID":
            derived_eid = literal
            continue
        if field_path.startswith("win.eventdata."):
            camel = field_path[len("win.eventdata.") :]
            key = camel[0].upper() + camel[1:] if camel else camel
            event_data[key] = literal

    return {
        "event_id": derived_eid or event_id or "",
        "channel": channel,
        "provider_name": provider,
        "computer": "synthetic",
        "timestamp": "",
        "event_data": event_data,
        "_synthetic": True,
    }


def _provider_for_parent(parent_sid) -> tuple[str, str]:
    """Best-effort (channel, provider) for a parent SID, for synthetic events."""
    sid = int(parent_sid) if str(parent_sid).isdigit() else 0
    if 61600 <= sid <= 61699:
        return ("Microsoft-Windows-Sysmon/Operational", "Microsoft-Windows-Sysmon")
    if sid == 91801:
        return ("Microsoft-Windows-PowerShell/Operational", "Microsoft-Windows-PowerShell")
    if sid == 60100:
        return ("Security", "Microsoft-Windows-Security-Auditing")
    if sid == 60106:
        return ("System", "Service Control Manager")
    return ("", "")


def _resolve_sample_event(rule_id, rule_meta: dict) -> tuple[dict | None, str]:
    """Resolve the event a rule should be validated against.

    Order: (1) stored trigger event, (2) re-parse source & search for a match,
    (3) synthesize from field_matches (source-less rules). Never falls back to
    an arbitrary event. Returns (event, provenance_mode) or (None, "").
    """
    from . import evtx_parser

    # (1) stored trigger event
    stored = _load_sample_events().get(str(rule_id))
    if stored:
        return stored, "stored"

    field_matches = rule_meta.get("field_matches", {})
    source = rule_meta.get("source_evtx", "")
    source_path = Path(source) if source else None

    # (2) re-parse the source and search for a genuinely matching event
    if (
        source_path
        and source_path.exists()
        and source_path.suffix.lower()
        not in (
            ".yml",
            ".yaml",
            ".md",
            ".txt",
            ".py",
        )
    ):
        try:
            events = evtx_parser.parse_file(source_path, max_events=100)
        except Exception:
            events = []
        for event in events:
            flat = _flatten_event_fields(event)
            if all(_match_field(pat, flat.get(fn, "")) for fn, pat in field_matches.items()) and field_matches:
                return event, "reparsed"

    # (3) synthesize an event from the rule's own field_matches
    if field_matches:
        channel, provider = _provider_for_parent(rule_meta.get("parent_sid", 0))
        synthetic = synthesize_event(field_matches, "", channel, provider)
        return synthetic, "synthetic"

    return None, ""


def validate_all_rules(mode: str = "simulate", source_filter: str = None) -> list[ValidationResult]:
    """Validate all rules using stored/reparsed/synthetic sample events."""
    index = _load_rule_index()
    config = load_config()

    results = []
    tested = 0
    passed = 0
    inconclusive = 0
    provenance_counts: dict[str, int] = {}

    console.print(f"[bold]Validating {len(index)} rules (mode={mode})...[/]\n")

    for rule_id_str, meta in sorted(index.items(), key=lambda x: int(x[0])):
        if source_filter and source_filter not in meta.get("source_evtx", ""):
            continue

        event, provenance = _resolve_sample_event(rule_id_str, meta)

        if not event:
            inconclusive += 1
            results.append(
                ValidationResult(
                    rule_id=int(rule_id_str),
                    passed=False,
                    mode=mode,
                    error="No sample event could be resolved",
                    inconclusive=True,
                )
            )
            continue

        provenance_counts[provenance] = provenance_counts.get(provenance, 0) + 1
        rule_id = int(rule_id_str)
        sim_mode = f"simulate_{provenance}" if mode == "simulate" else mode

        if mode == "simulate":
            result = validate_simulate(rule_id, meta, event)
            result.mode = sim_mode
        else:
            result = validate_live(rule_id, event, config)

        results.append(result)
        tested += 1
        if result.passed:
            passed += 1

    console.print("\n[bold]Validation Complete[/]")
    console.print(f"  Tested: {tested}")
    console.print(f"  Passed: [green]{passed}[/]")
    console.print(f"  Failed: [red]{tested - passed}[/]")
    console.print(f"  Inconclusive: [yellow]{inconclusive}[/]")
    for prov, cnt in sorted(provenance_counts.items()):
        console.print(f"  Event source ({prov}): {cnt}")

    return results


def validate_single_rule(rule_id: int, mode: str = "simulate") -> ValidationResult:
    """Validate a specific rule by ID."""
    index = _load_rule_index()
    config = load_config()

    rule_id_str = str(rule_id)
    if rule_id_str not in index:
        return ValidationResult(
            rule_id=rule_id,
            passed=False,
            mode=mode,
            error="Rule not found in index",
        )

    meta = index[rule_id_str]
    event, provenance = _resolve_sample_event(rule_id_str, meta)

    if not event:
        return ValidationResult(
            rule_id=rule_id,
            passed=False,
            mode=mode,
            error="No sample event could be resolved",
            inconclusive=True,
        )

    if mode == "simulate":
        result = validate_simulate(rule_id, meta, event)
        result.mode = f"simulate_{provenance}"
        return result
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
            "inconclusive": r.inconclusive,
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
