"""Tests for the Atomic Red Team ingestion path."""

import textwrap
from pathlib import Path

from collector.atomic_collector import parse_atomic_file, parse_atomic_repo
from generator.event_analyzer import DetectionPattern


def _write(path: Path, content: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(textwrap.dedent(content))
    return path


def test_parse_atomic_file_basic(tmp_path):
    yaml_file = _write(
        tmp_path / "T1003.yaml",
        """
        attack_technique: T1003
        display_name: OS Credential Dumping
        atomic_tests:
          - name: Dump LSASS.exe Memory using ProcDump
            supported_platforms: [windows]
            executor:
              name: command_prompt
              command: "procdump.exe -accepteula -ma lsass.exe"
        """,
    )

    patterns = parse_atomic_file(yaml_file)
    assert len(patterns) == 1
    p = patterns[0]
    assert isinstance(p, DetectionPattern)
    assert p.mitre_ids == ["T1003"]
    assert p.event_id == 1
    assert p.channel == "Microsoft-Windows-Sysmon/Operational"
    assert p.provider_name == "Microsoft-Windows-Sysmon"
    assert p.field_matches == {"win.eventdata.commandLine": "procdump.exe"}
    assert p.technique_name == "OS Credential Dumping"
    assert p.description == "Dump LSASS.exe Memory using ProcDump"
    assert p.confidence == "medium"
    assert p.tactic == "credential_access"  # T1003 resolves via TECHNIQUE_TO_TACTIC
    assert p.source_evtx == str(yaml_file)


def test_multi_test_atomic_yields_multiple_patterns(tmp_path):
    yaml_file = _write(
        tmp_path / "T1059.yaml",
        """
        attack_technique: T1059
        display_name: Command and Scripting Interpreter
        atomic_tests:
          - name: PowerShell download
            supported_platforms: [windows]
            executor:
              command: powershell.exe -enc ABC123
          - name: cmd echo
            supported_platforms: [windows]
            executor:
              command: cmd.exe /c echo hello
        """,
    )

    patterns = parse_atomic_file(yaml_file)
    assert len(patterns) == 2
    indicators = {p.field_matches["win.eventdata.commandLine"] for p in patterns}
    assert indicators == {"powershell.exe", "cmd.exe"}


def test_non_windows_only_tests_skipped(tmp_path):
    yaml_file = _write(
        tmp_path / "T1110.yaml",
        """
        attack_technique: T1110
        display_name: Brute Force
        atomic_tests:
          - name: linux only test
            supported_platforms: [linux, macos]
            executor:
              command: hydra -l root target
          - name: windows test
            supported_platforms: [windows]
            executor:
              command: net user administrator
        """,
    )

    patterns = parse_atomic_file(yaml_file)
    assert len(patterns) == 1
    assert patterns[0].description == "windows test"


def test_tests_without_command_skipped(tmp_path):
    yaml_file = _write(
        tmp_path / "T1000.yaml",
        """
        attack_technique: T1000
        display_name: No Command
        atomic_tests:
          - name: manual test
            supported_platforms: [windows]
            executor:
              name: manual
        """,
    )

    assert parse_atomic_file(yaml_file) == []


def test_kill_chain_phase_maps_tactic(tmp_path):
    yaml_file = _write(
        tmp_path / "T1003-kc.yaml",
        """
        attack_technique: T1003
        display_name: OS Credential Dumping
        kill_chain_phase: credential-access
        atomic_tests:
          - name: dump
            supported_platforms: [windows]
            executor:
              command: mimikatz.exe
        """,
    )

    patterns = parse_atomic_file(yaml_file)
    assert len(patterns) == 1
    assert patterns[0].tactic == "credential_access"


def test_malformed_file_returns_empty(tmp_path):
    yaml_file = _write(tmp_path / "bad.yaml", "just a string, not a mapping")
    assert parse_atomic_file(yaml_file) == []


def test_parse_atomic_repo_walks_layout(tmp_path):
    _write(
        tmp_path / "atomics" / "T1003" / "T1003.yaml",
        """
        attack_technique: T1003
        display_name: OS Credential Dumping
        atomic_tests:
          - name: dump lsass
            supported_platforms: [windows]
            executor:
              command: procdump.exe -ma lsass.exe
        """,
    )
    _write(
        tmp_path / "atomics" / "T1059" / "T1059.yml",
        """
        attack_technique: T1059
        display_name: Scripting
        atomic_tests:
          - name: ps test
            supported_platforms: [windows]
            executor:
              command: powershell.exe whoami
        """,
    )
    # A non-atomic stray file that should be ignored.
    _write(tmp_path / "atomics" / "T1059" / "notes.txt", "ignore me")

    patterns = parse_atomic_repo(tmp_path)
    assert len(patterns) == 2
    techniques = {p.mitre_ids[0] for p in patterns}
    assert techniques == {"T1003", "T1059"}


def test_parse_atomic_repo_missing_dir_returns_empty(tmp_path):
    assert parse_atomic_repo(tmp_path / "nonexistent") == []
