"""Tests for the false-positive tracking module."""

from generator import fp_tracker
from generator.fp_tracker import (
    FPRecord,
    fp_counts,
    level_penalty,
    load_fp_records,
    record_fp,
    suggest_level_adjustments,
)


def test_record_fp_appends_and_autotimestamps(tmp_path):
    fp_file = tmp_path / "fp.jsonl"
    rec = record_fp("100100", "noisy on admin login", reporter="alice", fp_file=fp_file)

    assert isinstance(rec, FPRecord)
    assert rec.rule_id == "100100"
    assert rec.reason == "noisy on admin login"
    assert rec.reporter == "alice"
    assert rec.timestamp  # auto-filled
    # ISO-8601 round trip
    from datetime import datetime

    datetime.fromisoformat(rec.timestamp)

    records = load_fp_records(fp_file)
    assert len(records) == 1
    assert records[0].rule_id == "100100"


def test_multiple_records_accumulate(tmp_path):
    fp_file = tmp_path / "fp.jsonl"
    record_fp("100100", "a", fp_file=fp_file)
    record_fp("100100", "b", fp_file=fp_file)
    record_fp("100200", "c", fp_file=fp_file)

    records = load_fp_records(fp_file)
    assert len(records) == 3


def test_load_fp_records_roundtrip(tmp_path):
    fp_file = tmp_path / "fp.jsonl"
    record_fp(
        "100300",
        "reason text",
        reporter="bob",
        event_json='{"k": "v"}',
        fp_file=fp_file,
    )
    [rec] = load_fp_records(fp_file)
    assert rec.rule_id == "100300"
    assert rec.reason == "reason text"
    assert rec.reporter == "bob"
    assert rec.event_json == '{"k": "v"}'


def test_load_missing_file_returns_empty(tmp_path):
    assert load_fp_records(tmp_path / "nope.jsonl") == []


def test_corrupt_line_is_skipped(tmp_path):
    fp_file = tmp_path / "fp.jsonl"
    record_fp("100100", "good", fp_file=fp_file)
    with fp_file.open("a", encoding="utf-8") as handle:
        handle.write("not json at all\n")
        handle.write("\n")  # blank line
        handle.write('{"no_rule_id": true}\n')  # missing key
    record_fp("100100", "good2", fp_file=fp_file)

    records = load_fp_records(fp_file)
    assert len(records) == 2
    assert all(r.rule_id == "100100" for r in records)


def test_fp_counts_aggregates(tmp_path):
    fp_file = tmp_path / "fp.jsonl"
    for _ in range(3):
        record_fp("100100", "x", fp_file=fp_file)
    record_fp("100200", "y", fp_file=fp_file)

    counts = fp_counts(fp_file)
    assert counts == {"100100": 3, "100200": 1}


def test_suggest_level_adjustments_thresholds(tmp_path):
    fp_file = tmp_path / "fp.jsonl"
    # below threshold (2 < 3) -> excluded
    record_fp("100001", "a", fp_file=fp_file)
    record_fp("100001", "b", fp_file=fp_file)
    # at threshold (3) -> -1
    for _ in range(3):
        record_fp("100002", "a", fp_file=fp_file)
    # at 2x threshold (6) -> -2
    for _ in range(6):
        record_fp("100003", "a", fp_file=fp_file)

    suggestions = suggest_level_adjustments(fp_file, threshold=3)
    assert "100001" not in suggestions
    assert suggestions["100002"] == -1
    assert suggestions["100003"] == -2


def test_level_penalty_below_and_above(tmp_path):
    fp_file = tmp_path / "fp.jsonl"
    record_fp("100002", "a", fp_file=fp_file)
    record_fp("100002", "b", fp_file=fp_file)
    assert level_penalty("100002", fp_file=fp_file, threshold=3) == 0

    record_fp("100002", "c", fp_file=fp_file)
    assert level_penalty("100002", fp_file=fp_file, threshold=3) == -1

    for _ in range(3):
        record_fp("100002", "d", fp_file=fp_file)
    # now 6 total -> -2
    assert level_penalty("100002", fp_file=fp_file, threshold=3) == -2

    # unknown rule -> 0
    assert level_penalty("999999", fp_file=fp_file, threshold=3) == 0


def test_default_fp_file_constant():
    assert fp_tracker.FP_FILE.name == "false_positives.jsonl"
    assert fp_tracker.FP_FILE.parent.name == "metadata"
