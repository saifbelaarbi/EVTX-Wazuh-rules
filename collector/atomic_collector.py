"""Atomic Red Team ingestion path.

This is a *second* ingestion path that feeds the existing generator pipeline.
Instead of parsing recorded EVTX logs, it reads Atomic Red Team test
definitions (YAML) from a cloned ``redcanaryco/atomic-red-team`` repository and
emits :class:`generator.event_analyzer.DetectionPattern` objects directly,
bypassing EVTX parsing and event analysis.

Each Atomic test contains an ``attack_technique`` id and one or more
``atomic_tests`` with an executor command. For Windows-supported tests we
synthesize a Sysmon ProcessCreate (Event ID 1) pattern keyed on a command-line
indicator derived from the executor command. The resulting patterns are
consumed by the same downstream stages (rule_builder, alert_leveler, exporter)
as EVTX-derived patterns.

Atomic YAML layout::

    atomics/<Txxxx>/<Txxxx>.yaml
      attack_technique: T1003
      display_name: OS Credential Dumping
      atomic_tests:
        - name: Dump LSASS.exe Memory using ProcDump
          supported_platforms: [windows]
          executor:
            name: command_prompt
            command: "procdump.exe -accepteula -ma lsass.exe"
"""

from pathlib import Path

import yaml

from generator.event_analyzer import DetectionPattern
from generator.mitre_mapper import normalize_tactic

PROJECT_ROOT = Path(__file__).resolve().parent.parent

# Synthetic Sysmon ProcessCreate identity used for all atomic-derived patterns.
_SYSMON_EVENT_ID = 1
_SYSMON_CHANNEL = "Microsoft-Windows-Sysmon/Operational"
_SYSMON_PROVIDER = "Microsoft-Windows-Sysmon"
_COMMANDLINE_FIELD = "win.eventdata.commandLine"


def _is_windows_test(test: dict) -> bool:
    """True if the atomic test lists ``windows`` among supported platforms."""
    platforms = test.get("supported_platforms") or []
    if not isinstance(platforms, list):
        return False
    return any(str(p).strip().lower() == "windows" for p in platforms)


def _extract_command(test: dict) -> str:
    """Return the executor command string for a test, or "" if absent."""
    executor = test.get("executor") or {}
    if not isinstance(executor, dict):
        return ""
    command = executor.get("command")
    if not command:
        return ""
    return str(command).strip()


def _command_indicator(command: str) -> str:
    """Derive a concise command-line indicator from an executor command.

    Takes the first non-empty line and its first whitespace-delimited token
    (typically the executable). Falls back to the whole first line if no token
    can be isolated. Surrounding quotes are stripped.
    """
    if not command:
        return ""
    # Use the first meaningful line of (possibly multi-line) commands.
    first_line = ""
    for line in command.splitlines():
        if line.strip():
            first_line = line.strip()
            break
    if not first_line:
        return ""
    token = first_line.split()[0] if first_line.split() else first_line
    return token.strip("\"'")


def _kill_chain_tactic(technique: dict) -> str:
    """Best-effort tactic from a technique's kill-chain phase, else "".

    Atomic YAML does not always carry kill-chain data; when present it may be a
    string or a list. Each candidate is run through ``normalize_tactic``.
    """
    raw = technique.get("kill_chain_phase") or technique.get("kill_chain_phases")
    candidates: list = []
    if isinstance(raw, str):
        candidates = [raw]
    elif isinstance(raw, list):
        candidates = raw
    for candidate in candidates:
        if isinstance(candidate, dict):
            candidate = candidate.get("phase_name") or candidate.get("tactic") or ""
        tactic = normalize_tactic(str(candidate))
        if tactic:
            return tactic
    return ""


def _build_pattern(
    test: dict,
    attack_technique: str,
    display_name: str,
    tactic: str,
    source_path: Path,
) -> DetectionPattern | None:
    """Build a DetectionPattern from a single windows atomic test."""
    command = _extract_command(test)
    if not command:
        return None

    indicator = _command_indicator(command)
    if not indicator:
        return None

    test_name = str(test.get("name") or "").strip()
    technique_name = display_name or test_name or attack_technique

    return DetectionPattern(
        event_id=_SYSMON_EVENT_ID,
        channel=_SYSMON_CHANNEL,
        provider_name=_SYSMON_PROVIDER,
        field_matches={_COMMANDLINE_FIELD: indicator},
        mitre_ids=[attack_technique] if attack_technique else [],
        tactic=tactic,
        technique_name=technique_name,
        description=test_name or technique_name,
        source_evtx=str(source_path),
        confidence="medium",
        sample_event={
            "atomic_test_name": test_name,
            "executor_command": command,
            "attack_technique": attack_technique,
        },
    )


def parse_atomic_file(path: Path) -> list[DetectionPattern]:
    """Parse one Atomic Red Team YAML file into DetectionPattern objects.

    For each atomic test that supports the ``windows`` platform and carries an
    executor command, a synthetic Sysmon ProcessCreate pattern is emitted.
    Tests without a command, or supporting only non-windows platforms, are
    skipped. Missing/None fields are handled defensively.
    """
    path = Path(path)
    try:
        with open(path) as f:
            data = yaml.safe_load(f)
    except (OSError, yaml.YAMLError):
        return []

    if not isinstance(data, dict):
        return []

    attack_technique = str(data.get("attack_technique") or "").strip()
    display_name = str(data.get("display_name") or "").strip()
    tactic = _kill_chain_tactic(data) or "execution"

    tests = data.get("atomic_tests") or []
    if not isinstance(tests, list):
        return []

    patterns: list[DetectionPattern] = []
    for test in tests:
        if not isinstance(test, dict):
            continue
        if not _is_windows_test(test):
            continue
        pattern = _build_pattern(test, attack_technique, display_name, tactic, path)
        if pattern is not None:
            patterns.append(pattern)
    return patterns


def parse_atomic_repo(repo_path: Path) -> list[DetectionPattern]:
    """Walk a cloned atomic-red-team repo and aggregate DetectionPatterns.

    Globs ``atomics/T*/T*.yaml`` and ``atomics/T*/T*.yml`` under ``repo_path``.
    The repo is expected to already be cloned locally (e.g. via the
    downloader); this function does not perform any network access.
    """
    repo_path = Path(repo_path)
    atomics_dir = repo_path / "atomics"
    if not atomics_dir.is_dir():
        return []

    patterns: list[DetectionPattern] = []
    files = sorted(atomics_dir.glob("T*/T*.yaml")) + sorted(atomics_dir.glob("T*/T*.yml"))
    for yaml_file in files:
        patterns.extend(parse_atomic_file(yaml_file))
    return patterns
