# Playbook

Operational guide for building, validating, and maintaining the EVTX-Wazuh detection rule database.

---

## 1. End-to-End Workflow

### Setup

```bash
pip install -r requirements.txt
```

If `python-evtx` fails to build, use the Rust-based parser instead:

```bash
pip install evtx
```

### Collector: download source data

```bash
python -m collector download-all       # EVTX attack samples from 7 GitHub repos
python -m collector download-sigma     # SigmaHQ rule repository
python -m collector download-defaults  # Wazuh default rulesets (for parent SID resolution)
```

All downloads land in `data/` (gitignored). Sources are defined in `sources/*.yaml`.

### Generator: build and convert rules

```bash
# Generate rules from EVTX samples
python -m generator generate --auto-approve

# Convert Sigma rules to Wazuh format
python -m generator convert-sigma --auto-approve --min-level medium

# Validate the database (structural XML checks)
python -m generator validate

# Validate rules against source events
python -m generator logtest --mode simulate --save

# Generate documentation
python generate_report.py
```

Without `--auto-approve`, new rules go to `database/drafts/` for human review.

### Tests

```bash
python -m pytest tests/                # full suite (93+ tests)
python -m pytest tests/ -k test_name   # single test
```

---

## 2. Quality Gates

Run these checks after every rebuild. A passing pipeline means all five are green.

### All tests pass

```bash
python -m pytest tests/
```

Expect 93+ tests passing, zero failures.

### Zero structural validation errors

```bash
python -m generator validate
```

Every rule must have a valid `<rule>` element with `id`, `level`, `if_sid`, and `<description>`.

### Tactic distribution is balanced

Check that all 12 tactic ID ranges are populated:

```
initial_access        100000-100999
execution             101000-101999
persistence           102000-102999
privilege_escalation  103000-103999
defense_evasion       104000-104999
credential_access     105000-105999
discovery             106000-106999
lateral_movement      107000-107999
collection            108000-108999
command_and_control   109000-109999
exfiltration          110000-110999
impact                111000-111999
```

If one tactic (typically execution) is capped at 1000 while others are empty, there is a tactic normalization bug. See troubleshooting below.

### by_source view is populated correctly

```bash
ls database/rules/by_source/
```

Expect at minimum: `sysmon.xml`, `security.xml`, `powershell.xml`. If everything is in `other.xml`, the source-category routing is broken.

### Sigma conversion errors are categorized

Check `database/metadata/sigma_conversion_errors.json`. Every skipped Sigma rule should have a category from: `unmapped_logsource`, `no_detection`, `unsupported_condition`, `empty_rule_spec`, `parse_error`, `unexpected`.

### Logtest pass rate above baseline

The pre-fix baseline was 12.4% (98/793). After the sample-event-backed validation work, the pass rate should be materially higher. Check `database/metadata/validation_results.json` for the current numbers.

---

## 3. Troubleshooting

### Tactic skew: all rules end up in execution

**Symptom:** `id_allocations.json` shows execution range nearly full, other tactics empty.

**Cause:** Tactic normalization failure. SigmaHQ uses hyphens in tags (`attack.credential-access`), not underscores. If `_extract_tags` in `sigma_converter.py` does not convert hyphens to underscores, every unrecognized tactic falls through to the default (execution).

**Fix:** Verify `mitre_mapper.normalize_tactic()` is called on all Sigma tag values. It handles `attack.` prefix stripping and hyphen-to-underscore conversion.

### ID range exhaustion

**Symptom:** `allocate_id` raises an error or silently fails for a tactic.

**Cause:** Tactic mismatch funneling all rules to one range. Check `database/metadata/id_allocations.json` to see which range is full.

**Fix:** Trace the tactic assignment for the overloaded range back through `mitre_mapper.py` and `event_analyzer.py`. The mismatch is usually in tactic normalization, not in the range definitions.

### Low logtest pass rate

**Symptom:** `validation_results.json` shows pass rate near the 12.4% baseline.

**Cause:** The validator is not finding stored sample events. The old code path used `_find_sample_event` which fell back to `events[0]` from provenance (often a non-matching event). The current path should use `_resolve_sample_event` which reads from `database/metadata/sample_events.json`.

**Fix:** Verify `sample_events.json` exists and is populated. Re-run `python -m generator generate --auto-approve` to regenerate it, then re-run logtest.

### All Sigma rules land in other.xml

**Symptom:** `database/rules/by_source/other.xml` contains everything; sysmon/security/powershell XMLs are empty or missing.

**Cause:** `_get_source_category` in `exporter.py` needs to handle Sigma-converted rules that have no `pattern` object. These rules should use the `metadata.source_category` field set during Sigma conversion.

**Fix:** Check that `sigma_converter.py` populates `source_category` in the rule metadata dict, and that `exporter.py` falls back to it when `pattern` is `None`.

### Sigma conversion errors

Check `database/metadata/sigma_conversion_errors.json` for categorized failures:

| Category | Meaning |
|---|---|
| `unmapped_logsource` | Sigma logsource has no Wazuh parent SID mapping |
| `no_detection` | Rule YAML has no `detection` block |
| `unsupported_condition` | Condition uses operators we do not translate (e.g., `near`, `temporal`) |
| `empty_rule_spec` | Detection translated to zero field conditions |
| `parse_error` | YAML parsing failure |
| `unexpected` | Unhandled exception |

### python-evtx build failures

The `python-evtx` C-extension package has build issues on some platforms. Use the Rust-based drop-in replacement:

```bash
pip uninstall python-evtx
pip install evtx
```

---

## 4. Architecture Quick-Reference

### Pipeline stages

```
EVTX/JSON/XML files
    |
    v
evtx_parser.py          Parse into normalized event dicts
    |
    v
event_analyzer.py        Extract DetectionPattern objects (tactic, technique,
    |                    confidence, field_matches) using mitre_mapper for
    v                    enrichment
rule_builder.py          Convert patterns to Wazuh XML <rule> elements
    |                    (OS-regex escaping, minimal sample events)
    v
rule_correlator.py       Deduplicate against existing DB + Wazuh defaults
    |
    v
alert_leveler.py         Assign severity 3-15 (tactic + confidence + tool overrides)
    |
    v
validator.py -> exporter.py    Validate XML, export three views + metadata
```

### Key modules

**`mitre_mapper.py`** -- Semantic MITRE ATT&CK mapping. Resolution order: indicator table (longest substring match) then event-ID defaults then path hints then fallback. Replaces the old folder-path-derived tactic guessing. Exports `normalize_tactic()` used by both EVTX and Sigma pipelines.

**`event_analyzer.py`** -- Converts a parsed EVTX event into one or more `DetectionPattern` dataclass instances. Each pattern carries tactic, technique_id, confidence, and a dict of field_matches. Uses `mitre_mapper.infer_mapping()` for ATT&CK assignment.

**`rule_builder.py`** -- Converts a `DetectionPattern` into an lxml `etree.Element` representing a `<rule>`. Handles OS-regex escaping of field values (backslash doubling, special-char escaping) and minimizes which sample events are stored.

**`sigma_converter.py`** -- Converts Sigma YAML rules to Wazuh XML. Key behaviors: glob-to-OS-regex translation (`*` to `\.+`, `?` to `.`), categorized conversion errors via `SigmaConvertError`, tactic normalization through `mitre_mapper.normalize_tactic()`, and source-category tagging for the by_source view.

**`logtest_validator.py`** -- Validates rules against stored sample events (`sample_events.json`), reparsed EVTX events, or synthetic events. Supports offline simulation mode and live Wazuh API/SSH modes.

**`exporter.py`** -- Writes three parallel views of the rule database (`by_tactic/`, `by_technique/`, `by_source/`) and updates metadata files: `rule_index.json`, `sample_events.json`, `provenance.json`.

**`id_manager.py`** -- Allocates rule IDs from the 100000-120000 range, partitioned by MITRE tactic (1000 IDs each). Reads/writes `database/metadata/id_allocations.json`.

### Data structures

- **`DetectionPattern`** (dataclass in `event_analyzer.py`): central data structure passed between pipeline stages
- **Rule dict**: `{"xml_element": etree.Element, "metadata": dict, "pattern": DetectionPattern}`
- **`MitreMapping`** (dataclass in `mitre_mapper.py`): resolved ATT&CK mapping with `technique_id`, `technique_name`, `tactic`

### Configuration

`config.yaml` defines:
- ID ranges per tactic (`tactic_id_ranges`)
- File paths (`paths`)
- Parent SIDs for Wazuh rule chaining (`wazuh.parent_sids`)
- Optional Wazuh API/SSH connection settings for live logtest

---

## 5. Future Roadmap

### Phase 1: Negation handling

Convert Sigma `not` / `filter` blocks into Wazuh child suppression rules. Gate behind a `--with-negation` flag to avoid breaking existing output. This closes the largest category of Sigma rules we currently skip.

### Phase 2: Composite and chained rules

Support multi-stage detections using Wazuh `if_sid` chains and `<frequency>` rules. Allocate from the composite ID range (112000-119999). Enables detection of attack sequences like "recon then lateral movement then exfiltration."

### Phase 3: CI auto-generation

GitHub Actions workflow: download sources, generate rules, validate, open a PR with the diff. Makes the rule database automatically track upstream SigmaHQ and EVTX sample updates.

### Phase 4: ATT&CK Navigator export

Generate a Navigator JSON layer from `rule_index.json` for coverage visualization. Color-code techniques by rule count and confidence. Useful for identifying detection gaps.
