# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## First-Run Workflow

On the first pass in a new session, read and update this file before doing substantial work if you learn project-specific workflow, review, or cleanup context that will help the next agent. Keep the update short and focused on durable repo guidance rather than temporary scratch notes.

Before starting deeper rule work, also check:
- `docs/HANDOFF.md`
- `docs/CURATED_RULE_REVIEW.md`
- `docs/RULE_CLEANUP_PLAN.md`

## Project Overview

EVTX-Wazuh-Rules is a pipeline that builds a Wazuh detection rule database from real-world Windows EVTX attack samples and SigmaHQ rules. It parses EVTX logs, extracts malicious patterns, and generates MITRE ATT&CK-mapped Wazuh XML rules.

## Commands

### Setup
```bash
pip install -e ".[dev]"
```

### Full pipeline
```bash
# 1. Download EVTX samples, Sigma rules, and Wazuh defaults
python -m collector download-all
python -m collector download-sigma
python -m collector download-defaults

# 2. Generate rules from EVTX samples
python -m generator generate --auto-approve

# 3. Convert Sigma rules to Wazuh format
python -m generator convert-sigma --auto-approve --min-level high

# 4. Validate the database
python -m generator validate

# 5. Validate rules against source events
python -m generator logtest --mode simulate --save

# 6. Generate documentation
python generate_report.py
```

### Running tests
```bash
python -m pytest tests/
python -m pytest tests/test_rule_builder.py       # single file
python -m pytest tests/test_rule_builder.py -k test_build_rule_structure  # single test
```

## Architecture

Two-part pipeline: **Collector** (downloads data) → **Generator** (builds rules).

### Collector (`collector/`)
Downloads EVTX samples from 7 GitHub repos, SigmaHQ Sigma rules, and Wazuh default rulesets. All downloaded data goes to `data/` (gitignored). Sources are defined in `sources/*.yaml`. Entry point: `collector/cli.py` using Click.

### Generator (`generator/`)
Six-stage pipeline orchestrated by `generator/cli.py`:
1. **evtx_parser.py** — Parses EVTX/JSON/XML files into normalized event dicts
2. **event_analyzer.py** — Extracts `DetectionPattern` objects from events (tactic, technique, confidence, field matches)
3. **rule_builder.py** — Converts patterns into Wazuh XML `<rule>` elements using lxml
4. **rule_correlator.py** — Deduplicates against existing database and Wazuh default rules
5. **alert_leveler.py** — Assigns severity levels (3-15) based on tactic, confidence, and tool-specific overrides
6. **validator.py** → **exporter.py** — Validates XML and exports in three parallel views

Additional modules:
- **mitre_mapper.py** — Semantic MITRE ATT&CK mapping (indicator table → event-id defaults → path hint → fallback). Replaces path-based tactic guessing.
- **sigma_converter.py** — Converts Sigma YAML/JSON to Wazuh XML (glob→OS-regex, full modifier set, `keywords`, `count()` frequency rules, `--with-negation` suppression rules, Windows/Linux/cloud platforms)
- **sigma_analyzer.py** — Assesses Sigma rule convertibility; holds Win/Linux/cloud logsource mappings
- **sigma_exporter.py** — Back-converts EVTX-derived Wazuh rules to Sigma YAML
- **composite_builder.py** — Builds chained correlation rules (`if_matched_sid`/frequency/same_field) from `sources/composite_templates.yaml`
- **logtest_validator.py** — Validates rules via stored/reparsed/synthetic sample events or live Wazuh API/SSH
- **fp_tracker.py** — Append-only false-positive log; feeds a level penalty back into `alert_leveler`
- **navigator_export.py** — Exports MITRE ATT&CK Navigator layer JSON (sub-techniques preserved)
- **id_manager.py** — Allocates rule IDs within Wazuh's custom range (100000-119999) partitioned by MITRE tactic
- **collector/atomic_collector.py** — Second ingestion path: Atomic Red Team test YAML → `DetectionPattern`
- **deployer/** — Deploy to a Wazuh manager with backup → health check → rollback
- **web/** — Optional read-only FastAPI dashboard (`pip install -e '.[web]'`; `python -m generator serve`)

`exporter.update_rule_index` maintains rule `version`/`last_modified` and writes `database/metadata/changelog.json` on add/modify. The by_tactic/technique/source XML writers MERGE with existing files (so a second export pass — e.g. convert-sigma after generate — does not clobber earlier rules).

### Key data flow
- `DetectionPattern` (dataclass in `event_analyzer.py`) is the central data structure passed between pipeline stages
- Rules are built as lxml `etree.Element` objects, stored in rule dicts with `xml_element`, `metadata`, and `pattern` keys
- The `config.yaml` defines ID ranges, paths, parent SIDs, and Wazuh connection settings

## Rule Database (`database/`)

Committed to git. Three parallel views of the same rules:
- `rules/by_tactic/` — One XML per MITRE ATT&CK tactic
- `rules/by_technique/` — One XML per technique ID
- `rules/by_source/` — By Windows log source (sysmon, security, powershell, etc.)

Metadata in `database/metadata/`: `rule_index.json`, `id_allocations.json`, `provenance.json`, `validation_results.json`, `sample_events.json`, `sigma_conversion_errors.json`.

Draft rules go to `database/drafts/` for human review (default behavior without `--auto-approve`).

## Important Conventions

- Rule IDs use Wazuh's custom range 100000-119999, partitioned per tactic in `config.yaml` under `tactic_id_ranges`
- Parent SIDs (e.g., `60009` for Sysmon, `60100` for Security) must match Wazuh's built-in rule IDs — defined in `config.yaml` under `wazuh.parent_sids`
- Generated rules must reference a valid `if_sid` parent that exists in Wazuh defaults
- All CLI commands use Click groups: `python -m collector <cmd>` and `python -m generator <cmd>`
- The `data/` directory is gitignored — never commit downloaded EVTX files
- **Wazuh OSRegex inverts PCRE dot semantics**: `.` is a literal dot, `\.` is any character, and quantifiers (`*`/`+`) only apply to backslash-expressions. All escaping lives in `rule_builder._to_osregex`, `sigma_converter._escape_osregex*`, and `logtest_validator._osregex_to_python` — keep them in sync.
- `rule_index.json` `field_matches` stores the **escaped OSRegex**, identical to the deployed XML (the logtest simulator and `sigma_exporter` interpret it as OSRegex, not raw literals)
- `sources/composite_templates.yaml` references concrete rule SIDs. `if_matched_sid` = the earlier repeated stage, `if_sid` = the triggering event. **After any clean regeneration, re-verify those SIDs against the new `rule_index.json`** — IDs shift when analyzer changes alter the pattern count.

## Clean Regeneration

The correlator dedupes on exact `field_matches` equality, so regenerating on top of an
existing database after a pattern-format change ADDS near-duplicates instead of fixing
rules. To regenerate cleanly, wipe first (everything is committed, so this is recoverable):
```bash
rm -rf database/rules database/drafts database/exports database/navigator_layer.json \
  database/metadata/{rule_index,id_allocations,provenance,sample_events,validation_results,sigma_conversion_errors,changelog}.json
```
then run generate → convert-sigma → build-composites (verify template SIDs!) → validate → logtest.

## Quality Gates

After any rebuild, verify:
```bash
python -m pytest tests/                              # 175+ tests pass
python -m generator validate                          # 0 structural errors
python -m generator logtest --mode simulate --save    # pass-rate ≥96% (baseline 96.5%)
```
Check `database/metadata/id_allocations.json` — all 12 tactic ranges should be populated, execution should not be capped. Check `database/rules/by_source/` — sysmon/security/powershell should have rules, not just other.xml.

See `docs/PLAYBOOK.md` for the full end-to-end workflow, troubleshooting, and roadmap.
