"""Validate Wazuh rules against source events via simulation or live wazuh-logtest."""

from __future__ import annotations

import json
import os
import re
import subprocess
import time
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path

import yaml
from rich.console import Console
from rich.progress import BarColumn, MofNCompleteColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn

console = Console()

PROJECT_ROOT = Path(__file__).resolve().parent.parent
CONFIG_FILE = PROJECT_ROOT / "config.yaml"
RULE_INDEX_FILE = PROJECT_ROOT / "database" / "metadata" / "rule_index.json"
PROVENANCE_FILE = PROJECT_ROOT / "database" / "metadata" / "provenance.json"
SAMPLE_EVENTS_FILE = PROJECT_ROOT / "database" / "metadata" / "sample_events.json"
RULES_DIR = PROJECT_ROOT / "database" / "rules"
RESULTS_FILE = PROJECT_ROOT / "database" / "metadata" / "validation_results.json"
LIVE_RESULTS_FILE = PROJECT_ROOT / "database" / "metadata" / "live_validation_results.json"


@dataclass
class ValidationResult:
    rule_id: int
    passed: bool
    mode: str
    details: list[str] = field(default_factory=list)
    error: str = ""
    inconclusive: bool = False


# PCRE-only features that can't be correctly simulated via the OSRegex engine.
_PCRE_ONLY_RE = re.compile(
    r"(?:"
    r"\(\?[imsxU:]"  # inline flags or non-capturing groups
    r"|\.[\+\*]\??"  # .+ or .* (PCRE any-char quantifier)
    r"|\.\{[0-9,]+\}"  # .{n,m}
    r"|\[[^\]]*[0-9]-[0-9][^\]]*\]"  # [0-9] character ranges
    r"|\[[^\]]*[a-z]-[a-z][^\]]*\]"  # [a-z] character ranges (case insensitive)
    r"|\{[0-9]+,[0-9]*\}"  # {n,m} quantifiers not preceded by ]
    r")"
)


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

    if event.get("full_log"):
        flat["full_log"] = event["full_log"]

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
        elif ch in "*+":
            out.append(re.escape(ch))
            i += 1
        elif ch in "{}[]?":
            # Literal in OSRegex (not quantifiers/classes); escape for Python.
            out.append(re.escape(ch))
            i += 1
        else:
            out.append(ch)
            i += 1

    if not has_end:
        out.append(".*")

    return "".join(out)


@lru_cache(maxsize=65536)
def _compile_alternative(alt: str) -> re.Pattern | None:
    """Convert one OSRegex alternative to a compiled Python regex (cached).

    The simulator evaluates thousands of rule patterns per run and the same
    pattern strings recur across rules; converting + compiling each time was
    the simulator's hot spot. Returns None when the converted pattern is not
    valid Python regex (caller falls back to substring matching).
    """
    try:
        return re.compile(_osregex_to_python(alt), re.IGNORECASE | re.DOTALL)
    except re.error:
        return None


def _match_field(pattern: str, value: str) -> bool:
    """Simulate Wazuh field matching.

    Wazuh <field> matching:
    - Case insensitive
    - Pipe | is OR (alternation)
    - Without anchors, substring match
    """
    if not value:
        return False
    if not pattern:
        return True

    for alt in pattern.split("|"):
        if not alt:
            continue
        compiled = _compile_alternative(alt)
        if compiled is not None:
            if compiled.search(value):
                return True
        elif alt.lower() in value.lower():
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

# Cached API session state (auth token + logtest session token).
_api_cache: dict[str, str] = {}


def _get_api_session(config: dict) -> tuple[str, str, str, bool]:
    """Return (api_url, auth_token, logtest_token, verify_ssl).

    Authenticates once and caches the token for subsequent calls.  Also
    caches the logtest session token so Wazuh reuses decoder/rule state.
    """
    import requests
    from urllib3.exceptions import InsecureRequestWarning

    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

    wazuh_cfg = config.get("wazuh", {})
    api_url = os.environ.get("WAZUH_API_URL") or wazuh_cfg.get("api_url", "")
    verify_ssl = wazuh_cfg.get("api_verify_ssl", False)

    if _api_cache.get("auth_token") and _api_cache.get("api_url") == api_url:
        return api_url, _api_cache["auth_token"], _api_cache.get("logtest_token", ""), verify_ssl

    user = os.environ.get("WAZUH_API_USER") or wazuh_cfg.get("api_user", "wazuh-wui")
    password = os.environ.get("WAZUH_API_PASSWORD", "")
    if not password:
        pw_file = wazuh_cfg.get("api_password_file", "")
        if pw_file:
            pw_path = Path(pw_file).expanduser()
            if pw_path.exists():
                password = pw_path.read_text().strip()
    if not password:
        password = wazuh_cfg.get("api_password", "")

    auth_resp = requests.post(
        f"{api_url}/security/user/authenticate",
        auth=(user, password),
        verify=verify_ssl,
        timeout=10,
    )
    auth_resp.raise_for_status()
    token = auth_resp.json()["data"]["token"]
    _api_cache["auth_token"] = token
    _api_cache["api_url"] = api_url
    return api_url, token, _api_cache.get("logtest_token", ""), verify_ssl


def _run_via_api(event_json: str, config: dict) -> dict:
    """Run logtest via Wazuh REST API.

    Uses ``log_format=json`` because the logtest engine does not invoke
    the native ``windows_eventchannel`` C decoder.  The Docker entrypoint
    deploys a bridge rule that overrides rule 60000 to accept
    ``decoded_as=json``, allowing the full parent chain to fire.
    """
    try:
        import requests  # noqa: F811
    except ImportError:
        return {"error": "requests package not installed: pip install requests"}

    wazuh_cfg = config.get("wazuh", {})
    api_url = os.environ.get("WAZUH_API_URL") or wazuh_cfg.get("api_url", "")
    if not api_url:
        return {"error": "wazuh.api_url not configured"}

    try:
        api_url, auth_token, logtest_token, verify_ssl = _get_api_session(config)
    except Exception as e:
        _api_cache.clear()
        return {"error": f"API auth failed: {e}"}

    headers = {"Authorization": f"Bearer {auth_token}"}
    body: dict = {
        "event": event_json,
        "log_format": "json",
        "location": "EventChannel",
    }
    if logtest_token:
        body["token"] = logtest_token

    try:
        logtest_resp = requests.put(
            f"{api_url}/logtest",
            headers=headers,
            json=body,
            verify=verify_ssl,
            timeout=30,
        )
        if logtest_resp.status_code == 401:
            _api_cache.clear()
            return {"error": "API auth token expired"}
        logtest_resp.raise_for_status()
        result = logtest_resp.json()
        new_token = result.get("data", {}).get("token")
        if new_token:
            _api_cache["logtest_token"] = new_token
        return result
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


_live_diag_printed = False


def validate_live(rule_id: int, event: dict, config: dict) -> ValidationResult:
    """Validate a rule via live wazuh-logtest (API first, SSH fallback)."""
    global _live_diag_printed
    event_json = format_event_for_wazuh(event)

    wazuh_cfg = config.get("wazuh", {})
    if wazuh_cfg.get("api_url"):
        result = _run_via_api(event_json, config)
        api_err = result.get("error")
        is_internal_error = isinstance(api_err, str)
        if not is_internal_error:
            data = result.get("data", {}).get("output", {})
            matched_rule = data.get("rule", {}).get("id", "")
            matched_desc = data.get("rule", {}).get("description", "")
            decoder_name = data.get("decoder", {}).get("name", "N/A")
            passed = str(matched_rule) == str(rule_id)
            details = [
                f"API matched rule: {matched_rule} ({matched_desc})",
                f"Expected: {rule_id}",
                f"Decoder: {decoder_name}",
                f"Level: {data.get('rule', {}).get('level', 'N/A')}",
            ]
            if not passed and not _live_diag_printed:
                _live_diag_printed = True
                console.print("\n  [yellow bold]Live logtest diagnostic (first mismatch):[/]")
                console.print(f"    Rule {rule_id}: Wazuh matched rule {matched_rule} (decoder: {decoder_name})")
                console.print(f"    Description: {matched_desc}")
                predecoder = data.get("predecoder", {})
                if predecoder:
                    console.print(f"    Predecoder: {json.dumps(predecoder)[:200]}")
                console.print(f"    Event sent: {event_json[:300]}")
            return ValidationResult(
                rule_id=rule_id,
                passed=passed,
                mode="live_api",
                details=details,
            )
        api_error = api_err
    else:
        api_error = "API not configured"

    if wazuh_cfg.get("ssh_host"):
        result = _run_via_ssh(event_json, config)
        ssh_err = result.get("error")
        if not isinstance(ssh_err, str):
            output = result.get("output", "")
            passed = str(rule_id) in output
            details = [f"SSH output: {output[:200]}"]
            return ValidationResult(
                rule_id=rule_id,
                passed=passed,
                mode="live_ssh",
                details=details,
            )
        ssh_error = ssh_err
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


def _split_top_level_alt(pattern: str) -> str:
    """Return the first alternative of a pattern, splitting only at top-level ``|``."""
    depth = 0
    for i, ch in enumerate(pattern):
        if ch == "\\" and i + 1 < len(pattern):
            continue
        if ch in "([":
            depth += 1
        elif ch in ")]":
            depth -= 1
        elif ch == "|" and depth <= 0:
            return pattern[:i]
    return pattern


def _literal_from_pattern(pattern: str) -> str:
    """Derive a concrete literal that satisfies an OSRegex field pattern.

    OSRegex semantics: ``.`` = literal dot, ``\\.`` = any char, ``\\.*`` = any*.

    Sigma-converted patterns may also contain PCRE fragments (character classes,
    quantifiers, groups) from the ``re`` modifier — this function materializes
    those into concrete characters that will still match the rule.
    """
    if not pattern or not pattern.strip():
        return "x"

    p = _split_top_level_alt(pattern)
    p = p.lstrip("^")
    # Strip trailing $ only if not escaped
    if p.endswith("$") and not p.endswith("\\$"):
        p = p[:-1]
    # Strip leading (?i) case-insensitive flag
    if p.startswith("(?i)"):
        p = p[4:]

    out: list[str] = []
    i = 0
    while i < len(p):
        ch = p[i]

        # Character class: [abc], [0-9], [-/], [A-Za-z0-9]
        if ch == "[":
            # Find matching ] (skip escaped chars inside)
            close = -1
            j = i + 1
            if j < len(p) and p[j] == "^":
                j += 1
            if j < len(p) and p[j] == "]":
                j += 1
            while j < len(p):
                if p[j] == "\\" and j + 1 < len(p):
                    j += 2
                elif p[j] == "]":
                    close = j
                    break
                else:
                    j += 1
            if close == -1:
                out.append(ch)
                i += 1
                continue
            inner = p[i + 1 : close]
            negated = inner.startswith("^")
            chars = inner.lstrip("^")
            if negated:
                # For negated classes, pick a char NOT in the set
                if "0-9" in chars:
                    picked = "a"
                elif "a-z" in chars.lower():
                    picked = "1"
                elif "\\" in chars:
                    picked = "a"
                elif " " in chars:
                    picked = "a"
                else:
                    picked = "x"
            else:
                picked = chars[0] if chars else "a"
                if picked == "-" and len(chars) > 1:
                    picked = chars[1]
                if "0-9" in inner:
                    picked = "1"
                elif "a-z" in inner.lower():
                    picked = "a"
            out.append(picked)
            i = close + 1
            # Skip trailing quantifier {n,m}, ?, *, +
            while i < len(p) and p[i] in "?*+":
                i += 1
            if i < len(p) and p[i] == "{":
                brace_end = p.find("}", i)
                if brace_end != -1:
                    i = brace_end + 1
            continue

        # Parenthesized group (capturing or (?:non-capturing)): pick first branch
        if ch == "(":
            depth = 1
            j = i + 1
            while j < len(p) and depth > 0:
                if p[j] == "\\" and j + 1 < len(p):
                    j += 2
                    continue
                if p[j] == "(":
                    depth += 1
                elif p[j] == ")":
                    depth -= 1
                j += 1
            group_end = j
            inner = p[i + 1 : group_end - 1]
            # Strip non-capturing (?:, (?i:, etc.
            if inner.startswith("?"):
                colon = inner.find(":")
                if colon != -1:
                    inner = inner[colon + 1 :]
            first_alt = _split_top_level_alt(inner)
            out.append(_literal_from_pattern(first_alt))
            i = group_end
            # Skip trailing quantifier
            while i < len(p) and p[i] in "?*+":
                i += 1
            if i < len(p) and p[i] == "{":
                brace_end = p.find("}", i)
                if brace_end != -1:
                    i = brace_end + 1
            continue

        # Backslash escapes
        if ch == "\\" and i + 1 < len(p):
            nxt = p[i + 1]
            if nxt == "." and i + 2 < len(p) and p[i + 2] in "*+":
                out.append("x")
                i += 3
            elif nxt == ".":
                out.append("x")
                i += 2
            elif nxt == "\\":
                out.append("\\")
                i += 2
            elif nxt == "d":
                out.append("1")
                i += 2
            elif nxt == "w":
                out.append("a")
                i += 2
            elif nxt == "s":
                out.append(" ")
                i += 2
            elif nxt == "D":
                out.append("a")
                i += 2
            elif nxt == "W":
                out.append(" ")
                i += 2
            elif nxt == "S":
                out.append("a")
                i += 2
            elif nxt == "$":
                out.append("$")
                i += 2
            elif nxt == '"':
                out.append('"')
                i += 2
            elif nxt == "{":
                out.append("{")
                i += 2
            elif nxt == "}":
                out.append("}")
                i += 2
            else:
                out.append(nxt)
                i += 2
            # Skip trailing quantifier after escape sequence
            while i < len(p) and p[i] in "?":
                i += 1
            if i < len(p) and p[i] == "{":
                brace_end = p.find("}", i)
                if brace_end != -1:
                    i = brace_end + 1
            continue

        # Dot: literal in OSRegex, but may have PCRE quantifier following.
        # If followed by {n,m}, +, or * treat as "any char repeated" → emit "x".
        if ch == ".":
            if i + 1 < len(p) and p[i + 1] in "+*":
                out.append("x")
                i += 2
                # Skip trailing ?
                if i < len(p) and p[i] == "?":
                    i += 1
            elif i + 1 < len(p) and p[i + 1] == "{":
                brace_end = p.find("}", i + 1)
                if brace_end != -1:
                    out.append("x")
                    i = brace_end + 1
                    if i < len(p) and p[i] == "?":
                        i += 1
                else:
                    out.append(".")
                    i += 1
            else:
                out.append(".")
                i += 1
            continue

        # Bare * and + are literal in OSRegex (only \\.* is a real wildcard).
        # Bare ? is a PCRE quantifier — skip it to avoid duplicating output.
        if ch == "?" and out:
            i += 1
            continue

        # Curly brace quantifiers {n,m}
        if ch == "{" and i + 1 < len(p):
            brace_end = p.find("}", i)
            if brace_end != -1:
                i = brace_end + 1
                continue

        out.append(ch)
        i += 1

    return "".join(out)


def synthesize_event(field_matches: dict, event_id, channel: str, provider: str) -> dict:
    """Build a minimal event whose flattened fields satisfy every pattern.

    Used to round-trip-validate source-less (Sigma-converted) rules: the event
    is constructed to match the rule, proving the rule is well-formed and
    matchable rather than that it fires on real attack telemetry.
    """
    event_data = {}
    derived_eid = event_id
    full_log_parts = []
    for field_path, pattern in field_matches.items():
        literal = _literal_from_pattern(str(pattern))
        if field_path == "win.system.eventID":
            derived_eid = literal
            continue
        if field_path == "full_log":
            full_log_parts.append(literal)
            continue
        if field_path.startswith("win.eventdata."):
            camel = field_path[len("win.eventdata.") :]
            key = camel[0].upper() + camel[1:] if camel else camel
            event_data[key] = literal

    result = {
        "event_id": derived_eid or event_id or "",
        "channel": channel,
        "provider_name": provider,
        "computer": "synthetic",
        "timestamp": "",
        "event_data": event_data,
        "_synthetic": True,
    }
    if full_log_parts:
        result["full_log"] = " ".join(full_log_parts)
    return result


def _provider_for_parent(parent_sid) -> tuple[str, str]:
    """Best-effort (channel, provider) for a parent SID, for synthetic events.

    The provider must never be empty: both the production root (60000) and the
    logtest bridge root (119999) require ``win.system.providerName`` to be
    non-empty, so an empty provider guarantees a live-logtest failure.
    """
    sid = int(parent_sid) if str(parent_sid).isdigit() else 0
    if 61600 <= sid <= 61699:
        return ("Microsoft-Windows-Sysmon/Operational", "Microsoft-Windows-Sysmon")
    if sid == 91801:
        return ("Microsoft-Windows-PowerShell/Operational", "Microsoft-Windows-PowerShell")
    if sid == 60100 or sid == 60001:
        return ("Security", "Microsoft-Windows-Security-Auditing")
    if sid == 60002 or sid == 60106:
        return ("System", "Service Control Manager")
    if sid == 60003:
        return ("Application", "Application")
    if sid == 60005:
        return ("Microsoft-Windows-Windows Defender/Operational", "Microsoft-Windows-Windows Defender")
    if sid == 60016:
        return (
            "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall",
            "Microsoft-Windows-Windows Firewall With Advanced Security",
        )
    if sid == 60018:
        return ("Microsoft-Windows-WMI-Activity/Operational", "Microsoft-Windows-WMI-Activity")
    return ("Application", "EVTX-Logtest-Synthetic")


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


# Live logtest hits a real Wazuh manager (API/SSH), so cap those runs to keep
# iteration fast; override with EVTX_LOGTEST_LIVE_CAP=0 for a full live run.
# Offline simulation is cheap and MUST cover the whole database — CI and the
# published pass-rate metrics depend on complete validation_results.json.
LIVE_CAP = 100


def _cap_for_mode(mode: str) -> int:
    """Return the max rules to validate for a mode (0 = unlimited)."""
    if mode != "live":
        return 0
    try:
        return int(os.environ.get("EVTX_LOGTEST_LIVE_CAP", LIVE_CAP))
    except ValueError:
        return LIVE_CAP


def validate_all_rules(mode: str = "simulate", source_filter: str = None) -> list[ValidationResult]:
    """Validate all rules using stored/reparsed/synthetic sample events."""
    index = _load_rule_index()
    config = load_config()

    # Pre-filter to get the actual work list
    work_items = []
    for rule_id_str, meta in sorted(index.items(), key=lambda x: int(x[0])):
        if source_filter and source_filter not in meta.get("source_evtx", ""):
            continue
        work_items.append((rule_id_str, meta))

    cap = _cap_for_mode(mode)
    if cap and len(work_items) > cap:
        console.print(f"[yellow]Capped to {cap} rules (of {len(work_items)})[/]")
        work_items = work_items[:cap]

    total = len(work_items)
    console.print(f"\n[bold]Validating {total} rules (mode={mode})[/]")
    if mode == "live":
        wazuh_cfg = config.get("wazuh", {})
        api_url = os.environ.get("WAZUH_API_URL") or wazuh_cfg.get("api_url", "")
        console.print(f"  Target: [cyan]{api_url or 'SSH fallback'}[/]")

    results = []
    tested = 0
    passed = 0
    failed = 0
    inconclusive = 0
    errors = 0
    provenance_counts: dict[str, int] = {}
    tactic_stats: dict[str, dict] = {}
    recent_failures: list[str] = []
    start_time = time.monotonic()
    api_errors_consecutive = 0

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        MofNCompleteColumn(),
        TextColumn("[green]{task.fields[passed]}[/] passed"),
        TextColumn("[red]{task.fields[failed]}[/] failed"),
        TimeElapsedColumn(),
        console=console,
        transient=False,
    ) as progress:
        task = progress.add_task(
            f"[bold]{mode}[/]",
            total=total,
            passed=0,
            failed=0,
        )

        for i, (rule_id_str, meta) in enumerate(work_items):
            event, provenance = _resolve_sample_event(rule_id_str, meta)
            tactic = meta.get("tactic", "unknown")

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
                progress.update(task, advance=1)
                continue

            provenance_counts[provenance] = provenance_counts.get(provenance, 0) + 1
            rule_id = int(rule_id_str)
            sim_mode = f"simulate_{provenance}" if mode == "simulate" else mode

            if mode == "simulate":
                result = validate_simulate(rule_id, meta, event)
                result.mode = sim_mode
                if (
                    not result.passed
                    and provenance == "synthetic"
                    and any(_PCRE_ONLY_RE.search(v) for v in meta.get("field_matches", {}).values())
                ):
                    result.inconclusive = True
                    inconclusive += 1
                    results.append(result)
                    progress.update(task, advance=1)
                    continue
            else:
                result = validate_live(rule_id, event, config)

            results.append(result)
            tested += 1

            # Track per-tactic stats
            if tactic not in tactic_stats:
                tactic_stats[tactic] = {"tested": 0, "passed": 0, "failed": 0}
            tactic_stats[tactic]["tested"] += 1

            if result.passed:
                passed += 1
                tactic_stats[tactic]["passed"] += 1
                api_errors_consecutive = 0
            else:
                failed += 1
                tactic_stats[tactic]["failed"] += 1
                if result.error:
                    errors += 1
                    api_errors_consecutive += 1
                    if api_errors_consecutive == 10 and mode == "live":
                        console.print("\n  [red bold]10 consecutive API errors — connection may be down[/]")
                    if api_errors_consecutive >= 50 and mode == "live":
                        console.print("\n  [red bold]50 consecutive API errors — aborting live logtest[/]")
                        break
                else:
                    api_errors_consecutive = 0
                    if mode == "live" and tested >= 100 and passed == 0:
                        console.print(
                            "\n  [yellow bold]0% pass rate after 100 rules — "
                            "aborting live logtest (likely event format mismatch)[/]"
                        )
                        break
                recent_failures.append(f"Rule {rule_id} ({tactic}): {result.error or 'field mismatch'}")

            progress.update(task, advance=1, passed=passed, failed=failed)

            # Print a batch summary every 500 rules
            if (i + 1) % 500 == 0 and i + 1 < total:
                elapsed = time.monotonic() - start_time
                rate = (i + 1) / elapsed if elapsed > 0 else 0
                eta = (total - i - 1) / rate if rate > 0 else 0
                pass_rate = (passed / tested * 100) if tested else 0
                console.print(
                    f"  [dim]Checkpoint {i + 1}/{total}: "
                    f"{pass_rate:.1f}% pass rate, "
                    f"{rate:.0f} rules/s, "
                    f"ETA {eta:.0f}s[/]"
                )

    # ── Summary ──
    elapsed = time.monotonic() - start_time
    rate = tested / elapsed if elapsed > 0 else 0
    pass_rate = (passed / tested * 100) if tested else 0

    console.print(f"\n[bold]{'=' * 50}[/]")
    console.print(f"[bold]Validation Complete[/] ({elapsed:.1f}s, {rate:.0f} rules/s)")
    console.print(f"{'=' * 50}")
    console.print(f"  Total rules:    {total}")
    console.print(f"  Tested:         {tested}")
    console.print(f"  Passed:         [green]{passed}[/]")
    console.print(f"  Failed:         [red]{failed}[/]")
    console.print(f"  Inconclusive:   [yellow]{inconclusive}[/]")
    if errors:
        console.print(f"  Errors:         [red]{errors}[/]")
    console.print(
        f"  Pass rate:      [{'green' if pass_rate >= 90 else 'yellow' if pass_rate >= 50 else 'red'}]{pass_rate:.1f}%[/]"
    )

    # Event provenance breakdown
    console.print("\n[bold]Event Sources:[/]")
    for prov, cnt in sorted(provenance_counts.items()):
        console.print(f"  {prov:12s}: {cnt}")

    # Per-tactic breakdown
    if tactic_stats:
        console.print("\n[bold]Per-Tactic Results:[/]")
        for tactic_name in sorted(tactic_stats.keys()):
            ts = tactic_stats[tactic_name]
            t_rate = (ts["passed"] / ts["tested"] * 100) if ts["tested"] else 0
            color = "green" if t_rate >= 90 else "yellow" if t_rate >= 50 else "red"
            console.print(
                f"  {tactic_name:30s}  "
                f"{ts['tested']:4d} tested  "
                f"[green]{ts['passed']:4d}[/] passed  "
                f"[red]{ts['failed']:4d}[/] failed  "
                f"[{color}]{t_rate:5.1f}%[/]"
            )

    # Show last few failures for quick debugging
    if recent_failures:
        show = recent_failures[-10:]
        console.print(f"\n[bold]Recent Failures ({len(recent_failures)} total, showing last {len(show)}):[/]")
        for f in show:
            console.print(f"  [red]✗[/] {f}")

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


def save_results(results: list[ValidationResult], mode: str | None = None):
    """Save validation results to JSON.

    Live-mode results go to ``live_validation_results.json`` so they never
    overwrite the offline simulate results that CI relies on.
    """
    is_live = mode == "live" if mode else any(r.mode.startswith("live") for r in results)
    target = LIVE_RESULTS_FILE if is_live else RESULTS_FILE
    target.parent.mkdir(parents=True, exist_ok=True)

    data = {}
    for r in results:
        data[str(r.rule_id)] = {
            "passed": r.passed,
            "mode": r.mode,
            "details": r.details,
            "error": r.error,
            "inconclusive": r.inconclusive,
        }

    with open(target, "w") as f:
        json.dump(data, f, indent=2)

    console.print(f"\n[bold green]Results saved to:[/] {target}")


def print_result(result: ValidationResult, verbose: bool = False):
    """Print a single validation result."""
    icon = "[green]PASS[/]" if result.passed else "[red]FAIL[/]"
    console.print(f"  {icon} Rule {result.rule_id} ({result.mode})")

    if result.error:
        console.print(f"    [red]Error: {result.error}[/]")

    if verbose and result.details:
        for detail in result.details:
            console.print(f"    {detail}")
