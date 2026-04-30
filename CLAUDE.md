# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## First-Run Workflow

On the first pass in a new session, read and update this file before doing substantial work if you learn project-specific workflow, review, or cleanup context that will help the next agent. Keep the update short and focused on durable repo guidance rather than temporary scratch notes.

Before starting deeper rule work, also check:
- `docs/HANDOFF.md`
- `docs/CURATED_RULE_REVIEW.md`
- `docs/RULE_CLEANUP_PLAN.md`

Durable repo guidance:
- `database/metadata/provenance.json` contains both EVTX sample provenance and Sigma rule provenance. Do not treat every provenance entry as an EVTX file.
- `generate_report.py` is responsible for keeping `docs/RULES_REPORT.md`, `docs/COVERAGE_MATRIX.md`, and `docs/SOURCES.md` split by origin (`evtx` vs `sigma`).

## Project Overview

EVTX-Wazuh-Rules is a pipeline that builds a Wazuh detection rule database from real-world Windows EVTX attack samples and SigmaHQ rules. It parses EVTX logs, extracts malicious patterns, and generates MITRE ATT&CK-mapped Wazuh XML rules.

## Commands

### Setup
```bash
pip install -r requirements.txt
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
- **sigma_converter.py** — Converts Sigma YAML directly to Wazuh XML rules
- **sigma_analyzer.py** — Assesses Sigma rule convertibility
- **logtest_validator.py** — Validates rules via offline simulation or live Wazuh API/SSH
- **id_manager.py** — Allocates rule IDs (100000-120000) partitioned by MITRE tactic

### Key data flow
- `DetectionPattern` (dataclass in `event_analyzer.py`) is the central data structure passed between pipeline stages
- Rules are built as lxml `etree.Element` objects, stored in rule dicts with `xml_element`, `metadata`, and `pattern` keys
- The `config.yaml` defines ID ranges, paths, parent SIDs, and Wazuh connection settings

## Rule Database (`database/`)

Committed to git. Three parallel views of the same rules:
- `rules/by_tactic/` — One XML per MITRE ATT&CK tactic
- `rules/by_technique/` — One XML per technique ID
- `rules/by_source/` — By Windows log source (sysmon, security, powershell, etc.)

Metadata in `database/metadata/`: `rule_index.json`, `id_allocations.json`, `provenance.json`, `validation_results.json`.

Draft rules go to `database/drafts/` for human review (default behavior without `--auto-approve`).

## Important Conventions

- Rule IDs use range 100000-120000, partitioned per tactic in `config.yaml` under `tactic_id_ranges`
- Parent SIDs (e.g., `60009` for Sysmon, `60100` for Security) must match Wazuh's built-in rule IDs — defined in `config.yaml` under `wazuh.parent_sids`
- Generated rules must reference a valid `if_sid` parent that exists in Wazuh defaults
- All CLI commands use Click groups: `python -m collector <cmd>` and `python -m generator <cmd>`
- The `data/` directory is gitignored — never commit downloaded EVTX files
