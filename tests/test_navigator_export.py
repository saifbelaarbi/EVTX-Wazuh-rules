"""Tests for the MITRE ATT&CK Navigator layer export."""

import json
import tempfile
from pathlib import Path

from generator.navigator_export import _score_to_color, export_navigator_layer


def test_score_to_color_gradient():
    assert _score_to_color(1) != _score_to_color(100)
    assert _score_to_color(0) == _score_to_color(1)


def test_export_from_real_index():
    """Export from the committed rule_index.json and verify structure."""
    index_path = Path(__file__).resolve().parent.parent / "database" / "metadata" / "rule_index.json"
    if not index_path.exists():
        return

    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
        out = Path(f.name)

    try:
        layer = export_navigator_layer(index_path=index_path, output_path=out)

        assert layer["domain"] == "enterprise-attack"
        assert layer["versions"]["layer"] == "4.5"
        assert len(layer["techniques"]) > 0
        assert layer["gradient"]["minValue"] == 0

        with open(out) as f:
            written = json.load(f)
        assert written["name"] == "EVTX-Wazuh-Rules Coverage"
    finally:
        out.unlink(missing_ok=True)


def test_export_minimal_index():
    """Export from a minimal synthetic index."""
    with tempfile.NamedTemporaryFile(suffix=".json", mode="w", delete=False) as f:
        json.dump(
            {
                "100000": {"tactic": "execution", "mitre_ids": ["T1059.001"]},
                "100001": {"tactic": "execution", "mitre_ids": ["T1059.001"]},
                "100002": {"tactic": "credential_access", "mitre_ids": ["T1003"]},
            },
            f,
        )
        idx_path = Path(f.name)

    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
        out_path = Path(f.name)

    try:
        layer = export_navigator_layer(index_path=idx_path, output_path=out_path)

        assert len(layer["techniques"]) == 2
        scores = {t["techniqueID"]: t["score"] for t in layer["techniques"]}
        assert scores.get("T1059") == 2 or any(t["score"] == 2 for t in layer["techniques"])
    finally:
        idx_path.unlink(missing_ok=True)
        out_path.unlink(missing_ok=True)
