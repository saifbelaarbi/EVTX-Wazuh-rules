"""Tests for the ID manager."""

import json
import tempfile
from pathlib import Path
from unittest import mock

from generator import id_manager


def test_allocate_id_sequential():
    """Test that IDs are allocated sequentially within a tactic range."""
    with tempfile.NamedTemporaryFile(suffix=".json", mode="w", delete=False) as f:
        json.dump({}, f)
        tmp_path = Path(f.name)

    with mock.patch.object(id_manager, "ALLOCATIONS_FILE", tmp_path):
        id1 = id_manager.allocate_id("credential_access")
        id2 = id_manager.allocate_id("credential_access")

        assert id1 == 108500  # Start of credential_access range
        assert id2 == 108501
        assert id2 == id1 + 1

    tmp_path.unlink()


def test_allocate_different_tactics():
    """Test that different tactics get IDs from different ranges."""
    with tempfile.NamedTemporaryFile(suffix=".json", mode="w", delete=False) as f:
        json.dump({}, f)
        tmp_path = Path(f.name)

    with mock.patch.object(id_manager, "ALLOCATIONS_FILE", tmp_path):
        cred_id = id_manager.allocate_id("credential_access")
        exec_id = id_manager.allocate_id("execution")
        disc_id = id_manager.allocate_id("discovery")

        assert 108500 <= cred_id <= 109999
        assert 100000 <= exec_id <= 103999
        assert 111000 <= disc_id <= 111999

    tmp_path.unlink()


def test_unknown_tactic_uses_composite():
    """Test that unknown tactics fall back to composite range."""
    with tempfile.NamedTemporaryFile(suffix=".json", mode="w", delete=False) as f:
        json.dump({}, f)
        tmp_path = Path(f.name)

    with mock.patch.object(id_manager, "ALLOCATIONS_FILE", tmp_path):
        rule_id = id_manager.allocate_id("totally_unknown_tactic")
        assert 115000 <= rule_id <= 119999

    tmp_path.unlink()


def test_external_write_invalidates_cache():
    """The CLI dry-run snapshot restores id_allocations.json externally; the
    in-memory cache must notice and re-read instead of serving stale state."""
    with tempfile.NamedTemporaryFile(suffix=".json", mode="w", delete=False) as f:
        json.dump({}, f)
        tmp_path = Path(f.name)

    with mock.patch.object(id_manager, "ALLOCATIONS_FILE", tmp_path):
        first = id_manager.allocate_id("impact")
        assert first == 114000
        snapshot = tmp_path.read_text()

        id_manager.allocate_id("impact")
        id_manager.allocate_id("impact")

        # Simulate the CLI restoring the snapshot (external write).
        tmp_path.write_text(snapshot)
        rewound = id_manager.allocate_id("impact")
        assert rewound == 114001  # continues from restored state, not cache

    tmp_path.unlink()
