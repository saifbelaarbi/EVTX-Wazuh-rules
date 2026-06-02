"""Tests for the read-only web dashboard pure functions and optional API."""

from __future__ import annotations

import json

import pytest

from web.app import (
    create_app,
    filter_rules,
    load_index,
    load_validation,
    summary_stats,
)


@pytest.fixture
def fake_index() -> dict:
    return {
        "100000": {
            "tactic": "execution",
            "technique_name": "WMIC process call create",
            "level": 9,
            "source_category": "sysmon",
        },
        "100001": {
            "tactic": "execution",
            "technique_name": "PowerShell download cradle",
            "level": 12,
            "source_category": "powershell",
        },
        "104000": {
            "tactic": "persistence",
            "technique_name": "Registry Run key",
            "level": 9,
            "source_category": "security",
        },
    }


@pytest.fixture
def fake_validation() -> dict:
    return {
        "100000": {"passed": False, "inconclusive": False, "mode": "simulate_stored"},
        "100001": {"passed": True, "inconclusive": False, "mode": "simulate_stored"},
        "104000": {"passed": True, "inconclusive": True, "mode": "simulate_stored"},
    }


def _write_json(path, data) -> None:
    path.write_text(json.dumps(data), encoding="utf-8")


# --------------------------------------------------------------------------- #
# Loader functions
# --------------------------------------------------------------------------- #
def test_load_index_reads_file(tmp_path, fake_index):
    p = tmp_path / "rule_index.json"
    _write_json(p, fake_index)
    assert load_index(p) == fake_index


def test_load_validation_reads_file(tmp_path, fake_validation):
    p = tmp_path / "validation_results.json"
    _write_json(p, fake_validation)
    assert load_validation(p) == fake_validation


def test_load_index_missing_returns_empty(tmp_path):
    assert load_index(tmp_path / "nope.json") == {}


def test_load_validation_missing_returns_empty(tmp_path):
    assert load_validation(tmp_path / "nope.json") == {}


def test_load_index_invalid_json_returns_empty(tmp_path):
    p = tmp_path / "bad.json"
    p.write_text("{not json", encoding="utf-8")
    assert load_index(p) == {}


# --------------------------------------------------------------------------- #
# summary_stats
# --------------------------------------------------------------------------- #
def test_summary_stats_totals_and_groups(fake_index, fake_validation):
    stats = summary_stats(fake_index, fake_validation)
    assert stats["total"] == 3
    assert stats["by_tactic"] == {"execution": 2, "persistence": 1}
    assert stats["by_source"] == {"powershell": 1, "security": 1, "sysmon": 1}


def test_summary_stats_pass_rate_excludes_inconclusive(fake_index, fake_validation):
    stats = summary_stats(fake_index, fake_validation)
    # 100000 fail, 100001 pass, 104000 inconclusive -> 1/2 considered
    assert stats["passed"] == 1
    assert stats["pass_rate"] == pytest.approx(0.5)


def test_summary_stats_no_validation(fake_index):
    stats = summary_stats(fake_index)
    assert stats["passed"] == 0
    assert stats["pass_rate"] == 0.0
    assert stats["total"] == 3


def test_summary_stats_empty_index():
    stats = summary_stats({}, {})
    assert stats["total"] == 0
    assert stats["by_tactic"] == {}
    assert stats["pass_rate"] == 0.0


# --------------------------------------------------------------------------- #
# filter_rules
# --------------------------------------------------------------------------- #
def test_filter_rules_by_tactic(fake_index):
    rules = filter_rules(fake_index, tactic="execution")
    assert {r["id"] for r in rules} == {"100000", "100001"}
    assert all(r["tactic"] == "execution" for r in rules)


def test_filter_rules_by_source(fake_index):
    rules = filter_rules(fake_index, source="security")
    assert [r["id"] for r in rules] == ["104000"]


def test_filter_rules_by_q_technique_name(fake_index):
    rules = filter_rules(fake_index, q="powershell")
    assert [r["id"] for r in rules] == ["100001"]


def test_filter_rules_by_q_rule_id(fake_index):
    rules = filter_rules(fake_index, q="104000")
    assert [r["id"] for r in rules] == ["104000"]


def test_filter_rules_no_filters_returns_all(fake_index):
    rules = filter_rules(fake_index)
    assert len(rules) == 3
    assert all("id" in r for r in rules)


def test_filter_rules_combined(fake_index):
    rules = filter_rules(fake_index, tactic="execution", q="wmic")
    assert [r["id"] for r in rules] == ["100000"]


# --------------------------------------------------------------------------- #
# Optional FastAPI app (skipped if FastAPI not installed)
# --------------------------------------------------------------------------- #
def test_fastapi_api_stats(tmp_path, fake_index, fake_validation):
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient

    idx = tmp_path / "rule_index.json"
    val = tmp_path / "validation_results.json"
    _write_json(idx, fake_index)
    _write_json(val, fake_validation)

    app = create_app(index_path=idx, validation_path=val)
    client = TestClient(app)

    resp = client.get("/api/stats")
    assert resp.status_code == 200
    data = resp.json()
    assert "total" in data
    assert data["total"] == 3


def test_fastapi_api_rules_filter(tmp_path, fake_index):
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient

    idx = tmp_path / "rule_index.json"
    _write_json(idx, fake_index)

    client = TestClient(create_app(index_path=idx))
    resp = client.get("/api/rules", params={"tactic": "persistence"})
    assert resp.status_code == 200
    data = resp.json()
    assert [r["id"] for r in data] == ["104000"]


def test_fastapi_index_html(tmp_path, fake_index, fake_validation):
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient

    idx = tmp_path / "rule_index.json"
    val = tmp_path / "validation_results.json"
    _write_json(idx, fake_index)
    _write_json(val, fake_validation)

    client = TestClient(create_app(index_path=idx, validation_path=val))
    resp = client.get("/")
    assert resp.status_code == 200
    assert "Total rules" in resp.text
