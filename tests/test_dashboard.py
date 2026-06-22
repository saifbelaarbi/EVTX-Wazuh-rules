"""Tests for the static GitHub Pages dashboard generator."""

import json

import generate_dashboard as gd


def test_val_stats_empty():
    s = gd._val_stats({})
    assert s["total"] == 0
    assert s["pass_rate"] == 0.0


def test_val_stats_excludes_inconclusive():
    data = {
        "1": {"passed": True, "inconclusive": False},
        "2": {"passed": False, "inconclusive": False},
        "3": {"passed": False, "inconclusive": True},  # excluded from rate
    }
    s = gd._val_stats(data)
    assert s["total"] == 3
    assert s["passed"] == 1
    assert s["failed"] == 1
    assert s["inconclusive"] == 1
    # 1 passed of 2 considered = 50%
    assert s["pass_rate"] == 50.0


def test_collect_stats_keys(monkeypatch, tmp_path):
    # Point the module at a temp metadata dir with a minimal index.
    meta = tmp_path / "metadata"
    meta.mkdir()
    index = {
        "100000": {
            "tactic": "execution",
            "source_category": "sysmon",
            "level": 9,
            "technique_id": "T1059",
            "mitre_ids": ["T1059"],
        },
        "100001": {
            "tactic": "persistence",
            "source_category": "security",
            "level": 12,
            "technique_id": "T1547",
            "mitre_ids": ["T1547.001"],
            "sigma_id": "abc",
        },
    }
    (meta / "rule_index.json").write_text(json.dumps(index))
    (meta / "validation_results.json").write_text(json.dumps({"100000": {"passed": True}}))
    monkeypatch.setattr(gd, "META", meta)

    stats = gd.collect_stats()
    assert stats["total"] == 2
    assert stats["techniques"] == 2
    assert stats["provenance"] == {"evtx": 1, "sigma": 1}
    assert stats["by_tactic"]["execution"] == 1
    assert stats["simulate"]["pass_rate"] == 100.0
    # No live results -> zeroed
    assert stats["live"]["total"] == 0


def test_render_html_is_valid_and_embeds_data(monkeypatch, tmp_path):
    meta = tmp_path / "metadata"
    meta.mkdir()
    (meta / "rule_index.json").write_text(json.dumps({"100000": {"tactic": "execution", "level": 9}}))
    monkeypatch.setattr(gd, "META", meta)

    stats = gd.collect_stats()
    html = gd.render_html(stats)
    assert '<canvas id="tacticChart">' in html
    assert "const DATA = {" in html
    # The embedded JSON must round-trip.
    start = html.index("const DATA = ") + len("const DATA = ")
    end = html.index(";", start)
    json.loads(html[start:end])
