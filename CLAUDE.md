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
- **logtest_validator.py** — Validates rules via stored/reparsed/synthetic sample events or live Wazuh API/SSH. Simulate results save to `validation_results.json`; live results save to `live_validation_results.json` (separate files to prevent overwrites).
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

## Asset Onboarding Agents (Part Two)

Beyond the EVTX/Sigma pipeline, `agents/` holds two **Claude Code subagents** that onboard an
arbitrary new asset (a firewall, appliance, or app Wazuh doesn't decode by default):

- **decoder-agent** (`agents/decoder-agent/AGENT.md`) — input: a folder of raw logs for **one**
  asset + a slug. Output: `database/decoders/<asset>_decoder.xml` (Wazuh decoder) +
  `database/decoders/<asset>_schema.json` (field-schema contract).
- **rule-agent** (`agents/rule-agent/AGENT.md`) — input: the `<asset>_schema.json`. Output:
  `database/rules/by_source/<asset>.xml` (MITRE-mapped Wazuh rules referencing the decoder's fields).

The schema (`agents/schemas/field_schema.schema.json`) is the contract between them, so the
rule-agent never references a field the decoder didn't parse. Both are registered for Claude Code
via symlinks in `.claude/agents/` (single source of truth stays in `agents/`). A complete Cisco
ASA worked example lives in the agents' `examples/` folders. See `agents/README.md`.

## Important Conventions

- Rule IDs use Wazuh's custom range 100000-119999, partitioned per tactic in `config.yaml` under `tactic_id_ranges`
- Parent SIDs (e.g., `60009` for Sysmon, `60100` for Security, `60002` for System) must match Wazuh's built-in rule IDs — defined in `config.yaml` under `wazuh.parent_sids`
- Generated rules must reference a valid `if_sid` parent that exists in Wazuh defaults. **A dangling `if_sid` (parent rule absent from the deployed ruleset) makes the entire child rule silently fail to load — it never fires in live logtest or in production, even though the offline simulator still passes it (the simulator checks only the rule's own `field_matches`, never the parent chain).** Audit parents against the downloaded ruleset + `rule_index.json` after analyzer changes. Two parents are NOT in the stock Wazuh v4.12 ruleset and need care:
  - **System channel** = `60002` (60000 → channel `^System$`). Do NOT use `60106` — that is "Windows Logon Success" (Security channel, requires eventID 4624/4769 + AUDIT_SUCCESS), a different chain entirely.
  - **PowerShell channel** has NO built-in classifier (the base chain stops at Sysmon/Defender/Firewall). The project ships its own parent rule `91801` in `database/rules/parent_rules.xml` (chains off 60000 + channel match). It is deployed by `docker-entrypoint.sh` and `deployer.deploy_rules`; it is NOT a detection rule and is absent from `rule_index.json`.
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

## Wazuh Logtest Limitation

The Wazuh logtest API (and `wazuh-logtest` CLI) does **not** invoke the native `windows_eventchannel` C decoder. Events sent with `log_format=eventchannel` are silently decoded via the JSON decoder, so `decoded_as=windows_eventchannel` never matches and the parent rule chain (60000→60004→61600→61603) never fires. This is a known Wazuh limitation (issues #13715, #5599).

**Docker workaround**: `docker-entrypoint.sh` deploys `0000-logtest-bridge.xml` which overrides rule 60000 with `decoded_as=json` + `overwrite="yes"`. The logtest API call uses `log_format=json`. This makes the full parent chain fire for JSON-decoded events in the test environment.

**Production deployments** are unaffected — real Windows agents use the native eventchannel path and rule 60000 works as-is. The bridge rule is only deployed in Docker Compose.
