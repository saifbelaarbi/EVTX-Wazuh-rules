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

        assert id1 == 110000  # Start of credential_access range
        assert id2 == 110001
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

        assert 110000 <= cred_id <= 111999
        assert 102000 <= exec_id <= 103999
        assert 112000 <= disc_id <= 113999

    tmp_path.unlink()


def test_unknown_tactic_uses_composite():
    """Test that unknown tactics fall back to composite range."""
    with tempfile.NamedTemporaryFile(suffix=".json", mode="w", delete=False) as f:
        json.dump({}, f)
        tmp_path = Path(f.name)

    with mock.patch.object(id_manager, "ALLOCATIONS_FILE", tmp_path):
        rule_id = id_manager.allocate_id("totally_unknown_tactic")
        assert 124000 <= rule_id <= 129999

    tmp_path.unlink()
