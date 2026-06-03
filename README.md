# EVTX-Wazuh-Rules

A production-ready system for building and expanding a **Wazuh detection rule database** from real-world Windows EVTX attack samples and SigmaHQ detection rules. Parses EVTX logs from security research repositories, converts Sigma YAML rules, extracts malicious patterns, and generates categorized, MITRE ATT&CK-mapped Wazuh rules with semantic technique classification.

## Current Database

| Metric | Value |
|--------|-------|
| Total rules | **3,289** |
| EVTX-generated rules | 619 from 7 EVTX sources |
| Sigma-converted rules | 2,670 from SigmaHQ |
| EVTX files processed | 2,292 |
| MITRE tactics covered | 12 / 12 |
| MITRE techniques | 270+ |
| Alert level range | 6 - 14 |
| Sigma rules converted | 2,670 (from 2,230 convertible Windows rules) |
| Sigma conversion errors | 2 |
| Validation errors | 0 |
| Test suite | 93 tests |
| Logtest pass rate | 55.2% (93.1% EVTX stored, 46.5% Sigma synthetic) |

### Tactic Distribution

| Tactic | Rules | Tactic | Rules |
|--------|------:|--------|------:|
| Execution | 1,163 | Discovery | 137 |
| Persistence | 843 | Lateral Movement | 77 |
| Privilege Escalation | 383 | Collection | 51 |
| Credential Access | 295 | Impact | 44 |
| Command & Control | 193 | Exfiltration | 36 |
| Defense Evasion | 35 | Initial Access | 32 |

### Source Distribution

| Source | Rules |
|--------|------:|
| Sysmon | 2,258 |
| System | 591 |
| PowerShell | 226 |
| Security | 156 |
| Application | 58 |

See [docs/RULES_REPORT.md](docs/RULES_REPORT.md) for the full rule listing, [docs/COVERAGE_MATRIX.md](docs/COVERAGE_MATRIX.md) for MITRE ATT&CK coverage, [docs/SOURCES.md](docs/SOURCES.md) for source attribution, and [docs/PLAYBOOK.md](docs/PLAYBOOK.md) for the end-to-end workflow.

## Architecture

```
┌──────────────────────────────────────────────────────────────────────────┐
│                         EVTX-Wazuh-Rules Pipeline                        │
│                                                                          │
│  ┌─────────────┐    ┌──────────────────────────────────────────────────┐ │
│  │   Part 1     │    │                  Part 2                          │ │
│  │  Collector   │    │              Generator                           │ │
│  │             │    │                                                   │ │
│  │ EVTX Sources├───>│ Parser ─> Analyzer ─> Builder ─> Correlator      │ │
│  │ Wazuh Defs  │    │                                   │              │ │
│  │ Registry    │    │              Alert Leveler <───────┘              │ │
│  │             │    │                   │                               │ │
│  └─────────────┘    │              Validator                            │ │
│                     │                   │                               │ │
│    data/ (git-      │              Exporter ──> database/rules/         │ │
│    ignored)         │              (3 views)    (committed)             │ │
│                     └──────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────────────────┘
```

**Part 1 — Collector** downloads EVTX samples, SigmaHQ rules, and Wazuh default rules from GitHub. Downloaded data stays in `data/` (gitignored).

**Part 2 — Generator** parses events, extracts detection patterns, classifies MITRE ATT&CK techniques via semantic indicator mapping, builds Wazuh XML rules, converts Sigma YAML rules, cross-references against existing rules and Wazuh defaults, assigns severity levels, validates, and exports in three views.

## EVTX Sources

| Source | Repository | Description |
|--------|------------|-------------|
| EVTX-ATTACK-SAMPLES | [sbousseaden/EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES) | ~200 EVTX samples organized by MITRE ATT&CK tactic |
| EVTX-to-MITRE-Attack | [mdecrevoisier/EVTX-to-MITRE-Attack](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack) | 270+ EVTX samples mapped to ATT&CK techniques |
| hayabusa-sample-evtx | [Yamato-Security/hayabusa-sample-evtx](https://github.com/Yamato-Security/hayabusa-sample-evtx) | Aggregated samples from multiple security research sources |
| Security-Datasets | [OTRF/Security-Datasets](https://github.com/OTRF/Security-Datasets) | Pre-recorded adversary simulation data (Mordor) |
| danderspritz-evtx | [fox-it/danderspritz-evtx](https://github.com/fox-it/danderspritz-evtx) | DanderSpritz (NSA EternalBlue) EVTX detection events |
| evtx-hunter | [NVISOsecurity/evtx-hunter](https://github.com/NVISOsecurity/evtx-hunter) | Security-related EVTX activity identification |
| ThreatSeeker | [ine-labs/ThreatSeeker](https://github.com/ine-labs/ThreatSeeker) | Threat hunting via Windows Event Logs |

## Sigma Rule Integration

| Metric | Value |
|--------|-------|
| Source | [SigmaHQ/sigma](https://github.com/SigmaHQ/sigma) |
| Total Windows rules | 2,396 |
| Converted to Wazuh | 2,670 rules from 2,230 files |
| Conversion errors | 2 (down from 214 after logsource expansion) |
| Logsource mappings | 61+ (sysmon, security, powershell, system, application, windefend, etc.) |
| Top category | process_creation |

The Sigma analyzer (`generator/sigma_analyzer.py`) assesses convertibility with 61+ logsource-to-Wazuh mappings. The converter (`generator/sigma_converter.py`) generates Wazuh XML rules directly from Sigma YAML with:
- Glob-to-OS-regex translation (`*`→`.*`, `?`→`.`)
- Full modifier support (endswith, startswith, contains, re, windash)
- Tactic normalization (hyphenated ATT&CK tags → snake_case)
- Categorized error reporting (`database/metadata/sigma_conversion_errors.json`)

Wazuh default rules are downloaded from [wazuh/wazuh-ruleset](https://github.com/wazuh/wazuh-ruleset) for cross-referencing (133 rule files, 104 decoder files).

## Quick Start

```bash
# Install dependencies
pip install -e .

# Step 1: Download EVTX samples, Sigma rules, and Wazuh defaults
python -m collector download-all
python -m collector download-sigma
python -m collector download-defaults

# Step 2: Generate rules from EVTX samples
python -m generator generate --auto-approve

# Step 3: Convert Sigma rules to Wazuh format
python -m generator convert-sigma --auto-approve --min-level medium

# Step 4: Validate the database
python -m generator validate

# Step 5: Validate rules against source events
python -m generator logtest --mode simulate --save

# Step 6: Deploy to Wazuh
python -m generator export --dest /var/ossec/etc/rules/ --view by_tactic
sudo systemctl restart wazuh-manager
```

### Docker

```bash
docker build -t evtx-wazuh-rules .
docker run -v $(pwd)/database:/app/database evtx-wazuh-rules
```

## CLI Reference

### Collector (`python -m collector`)

| Command | Description |
|---------|-------------|
| `download-all` | Download all registered EVTX sources |
| `download <name>` | Download a specific EVTX source |
| `download-sigma` | Download SigmaHQ Sigma detection rules (Windows) |
| `download-defaults` | Download Wazuh default rules and decoders |
| `download-atomic` | Clone Atomic Red Team for the atomic ingestion path |
| `status` | Show download status table |
| `list-sources` | List all registered sources (EVTX + Sigma) |

### Generator (`python -m generator`)

| Command | Description |
|---------|-------------|
| `analyze [--source NAME]` | Parse EVTX files and show detection patterns |
| `generate [--source NAME] [--auto-approve] [--diff-only]` | Generate Wazuh rules from EVTX samples |
| `convert-sigma [--auto-approve] [--category CAT] [--min-level LVL] [--platform windows\|linux\|cloud\|all] [--with-negation] [--diff-only]` | Convert SigmaHQ rules to Wazuh format |
| `generate-atomic [--auto-approve]` | Generate rules from a cloned Atomic Red Team repo |
| `build-composites [--auto-approve]` | Build composite/chained correlation rules from templates |
| `logtest [--mode simulate\|live] [--rule-id ID] [--verbose] [--save]` | Validate rules against source events |
| `report-fp --rule-id ID --reason TEXT` | Record a false positive for a rule |
| `fp-summary [--threshold N]` | Summarize false positives and suggested level drops |
| `changelog [--limit N]` | Show recent rule add/modify history |
| `review` | Show pending draft rules |
| `approve <draft_file>` | Promote a draft into the rule database |
| `validate` | Validate the entire rule database (exits non-zero on errors) |
| `stats` | Show ID allocation and rule statistics |
| `navigator [--output PATH]` | Export MITRE ATT&CK Navigator layer JSON |
| `export-sigma [--output DIR]` | Back-convert EVTX-derived rules to Sigma YAML |
| `serve [--host H] [--port P]` | Launch the read-only web dashboard (needs `[web]` extra) |
| `export --dest PATH [--view VIEW]` | Export rules for Wazuh deployment |

### Deployer (`python -m deployer`)

| Command | Description |
|---------|-------------|
| `deploy --src DIR --dest PATH [--view VIEW]` | Deploy rules to a Wazuh manager with backup, health check, and automatic rollback |

### Report Generator

```bash
python generate_report.py           # Markdown reports
python generate_excel_report.py     # Excel tracker (requires openpyxl)
```

Markdown reports in `docs/`:
- **RULES_REPORT.md** — Full rule listing with alert levels, MITRE mapping, confidence scores
- **COVERAGE_MATRIX.md** — MITRE ATT&CK coverage heatmap and gap analysis
- **SOURCES.md** — EVTX source attribution and per-source breakdown

Excel tracker (`EVTX_Wazuh_Rules_Tracker.xlsx`):
- Dashboard with charts and summary stats
- Per-tactic sheets with all rule details
- Validation results, Sigma conversion errors, deployment tracking

## Rule Organization

Generated rules are exported in **three parallel views** — same rules, different organization:

```
database/rules/
├── by_tactic/              # One XML per MITRE tactic (e.g., credential_access.xml)
├── by_technique/           # One XML per technique (e.g., T1003_credential_dumping.xml)
└── by_source/              # By Windows log source (sysmon.xml, security.xml, powershell.xml)
```

**Recommended for production:** Use `by_tactic/` for broad deployment, or `by_source/` for Wazuh-native organization.

## Rule Quality Controls

### ID Management
- Custom rule IDs in Wazuh's standard range **100000 - 119999**
- Partitioned by MITRE tactic, sized by usage (execution: 4000, persistence: 3000, smaller tactics: 500-1500)
- Atomic allocation prevents conflicts across runs

### Correlation
Every new rule is checked against:
- Existing rules in the database (exact duplicate and partial overlap detection)
- Wazuh default rules (avoids duplicating built-in detections)
- Rules in the same tactic (maintains consistent severity scoring)

### Alert Levels
Severity is computed from three factors:
1. **Tactic base score** — Discovery (6) < Execution (8) < Credential Access (11) < Exfiltration (12)
2. **Detection confidence** — High (+1), Medium (0), Low (-2)
3. **Tool-specific overrides** — mimikatz (13), meterpreter (14), LSASS access (12)

### Semi-Automated Workflow
Rules are generated as **drafts** for human review by default. Use `--auto-approve` only when confident in the source data. Each draft includes a manifest with confidence scores and review notes.

### MITRE ATT&CK Mapping
Semantic indicator-driven classification via `generator/mitre_mapper.py`:
- Indicator table (lsass→T1003.001, mimikatz→T1003, rundll32→T1218.011, vssadmin→T1490, etc.)
- Event-ID defaults (4625→T1110 Brute Force, 4624→T1021 lateral movement, 4720→T1136.001)
- Path hint fallback (last resort only — no more tactic-from-folder-name)

### Validation
- XML well-formedness
- Required elements (id, level, description, if_sid)
- ID uniqueness across entire database
- Parent SID existence in Wazuh defaults
- MITRE technique ID format (T-number)
- Alert level consistency within tactic

## Supported Input Formats

| Format | Extension | Source |
|--------|-----------|--------|
| EVTX binary | `.evtx` | Direct Windows Event Logs |
| JSON export | `.json`, `.jsonl` | EvtxECmd, chainsaw, hayabusa, Mordor/Security-Datasets |
| XML export | `.xml` | Windows Event Viewer exports |
| Sigma YAML | `.yml` | SigmaHQ detection rules (analysis only) |

## Project Structure

```
EVTX-Wazuh-rules/
├── collector/              # Part 1: EVTX Collection Engine
│   ├── cli.py              # CLI commands (download-all, download-atomic, etc.)
│   ├── downloader.py       # Git clone / shallow download
│   ├── sigma_downloader.py # SigmaHQ rules downloader
│   ├── atomic_collector.py # Atomic Red Team test YAML → DetectionPattern
│   ├── registry.py         # Download tracking and checksums
│   └── wazuh_defaults.py   # Wazuh default rules downloader
│
├── generator/              # Part 2: Rule Database Generator
│   ├── cli.py              # CLI commands (generate, convert-sigma, etc.)
│   ├── evtx_parser.py      # Parse EVTX/JSON/XML to normalized events
│   ├── event_analyzer.py   # Extract detection patterns from events
│   ├── mitre_mapper.py     # Semantic MITRE ATT&CK classification (indicator→technique)
│   ├── navigator_export.py # MITRE ATT&CK Navigator layer export
│   ├── sigma_analyzer.py   # Analyze Sigma rules (Win/Linux/cloud logsource mappings)
│   ├── sigma_converter.py  # Sigma → Wazuh XML (modifiers, negation, count(), keywords)
│   ├── sigma_exporter.py   # Back-convert EVTX-derived rules → Sigma YAML
│   ├── composite_builder.py # Chained correlation rules (if_matched_sid/frequency)
│   ├── logtest_validator.py # Rule validation (stored/synthetic/reparsed + live API/SSH)
│   ├── fp_tracker.py       # False-positive tracking + level-penalty feedback
│   ├── rule_builder.py     # Build Wazuh XML rules from patterns
│   ├── rule_correlator.py  # Cross-reference with existing rules
│   ├── alert_leveler.py    # Assign severity levels (with FP feedback)
│   ├── id_manager.py       # Rule ID allocation (100000-119999, sized per tactic)
│   ├── validator.py        # Rule validation
│   └── exporter.py         # Export to XML files (3 views) + versioning/changelog
│
├── deployer/               # Deployment orchestration (backup/deploy/rollback)
│   ├── cli.py              # `python -m deployer deploy ...`
│   └── wazuh_deployer.py   # Backup → deploy → health check → rollback
│
├── web/                    # Read-only FastAPI dashboard ([web] extra)
│   ├── app.py              # Stats/rule/navigator endpoints + pure data fns
│   └── templates/index.html
│
├── database/               # Rule database (committed to git)
│   ├── metadata/           # rule_index.json, provenance.json, id_allocations.json,
│   │                       # sample_events.json, sigma_conversion_errors.json,
│   │                       # validation_results.json
│   ├── navigator_layer.json # MITRE ATT&CK Navigator layer (importable)
│   ├── drafts/             # Candidate rules awaiting review
│   └── rules/              # Approved rules (by_tactic/, by_technique/, by_source/)
│
├── sources/                # Source definitions (committed)
│   ├── evtx_sources.yaml
│   ├── sigma_sources.yaml
│   └── wazuh_default_sources.yaml
│
├── docs/                   # Documentation
│   ├── PLAYBOOK.md         # End-to-end workflow, quality gates, troubleshooting
│   ├── RULES_REPORT.md     # Full rule listing with MITRE mapping
│   ├── COVERAGE_MATRIX.md  # MITRE ATT&CK coverage heatmap
│   ├── SOURCES.md          # EVTX source attribution
│   ├── HANDOFF.md          # Project review and handoff notes
│   ├── CURATED_RULE_REVIEW.md # Detailed rule quality review
│   └── RULE_CLEANUP_PLAN.md   # Actionable cleanup queue with status
│
├── tests/                  # Unit tests (93 tests)
├── data/                   # Downloaded EVTX & defaults (GITIGNORED)
├── config.yaml             # Global configuration
├── requirements.txt        # Python dependencies
├── generate_report.py      # Markdown documentation generator
└── generate_excel_report.py # Excel tracker with dashboard, per-tactic sheets, deployment tracking
```

## Installation

```bash
pip install -e .            # core dependencies
pip install -e ".[dev]"     # + pytest, ruff, pre-commit
pip install -e ".[report]"  # + openpyxl for Excel reports
```

## Dependencies

- Python 3.10+
- `python-evtx` — Rust-based EVTX parser (fast, no C build dependencies)
- `pyyaml` — Config file parsing
- `lxml` — XML generation and validation
- `click` — CLI framework
- `rich` — Terminal output formatting
- `requests` — Wazuh REST API for live logtest validation
- `openpyxl` — Excel report generation (optional)

## Logtest Validation

The `logtest` command validates rules against source events using a three-tier event resolution strategy:

| Resolution | Description | Pass Rate |
|------------|-------------|-----------|
| `stored` | Original trigger event persisted from EVTX parsing | 93.1% (619 rules) |
| `synthetic` | Auto-generated event satisfying all field patterns | 46.5% (2,670 rules) |
| `reparsed` | Re-parses source EVTX to find matching event | Fallback |

Events that cannot be resolved are marked **inconclusive** (no false passes from wrong-event fallback).

Live validation modes are also available:

| Mode | Description | Requirements |
|------|-------------|--------------|
| `simulate` | Offline field matching against resolved events | None (default) |
| `live` (API) | Wazuh REST API `/logtest` endpoint | Wazuh API credentials in `config.yaml` |
| `live` (SSH) | SSH to Wazuh manager, runs `wazuh-logtest` binary | SSH key access to Wazuh host |

Live mode tries API first and falls back to SSH. Configure in `config.yaml`:

```yaml
wazuh:
  api_url: https://wazuh-manager:55000
  api_user: wazuh-wui
  api_password_file: ~/.wazuh_api_token
  api_verify_ssl: false

  ssh_host: wazuh-manager
  ssh_user: wazuh
  ssh_key: ~/.ssh/wazuh_key
  logtest_path: /var/ossec/bin/wazuh-logtest
  sudo: true
```

## Delivered (v2)

- ✅ Sigma negation handling (`not filter` → Wazuh level-0 suppression rules, `--with-negation`)
- ✅ Sigma `count()` aggregation → frequency/timeframe correlation rules
- ✅ Full Sigma modifier set (cidr, base64/base64offset, utf16/wide, lt/lte/gt/gte, windash) + `keywords` + JSON rules
- ✅ Multi-platform Sigma: Linux (auditd/syslog/sshd) and cloud (AWS/Azure/GCP/Okta/M365) → Wazuh
- ✅ Composite/chained rules (`if_matched_sid` + frequency + same_field) from templates
- ✅ MITRE ATT&CK Navigator layer export (sub-techniques preserved)
- ✅ Sigma back-export (EVTX-derived rules → Sigma YAML)
- ✅ Atomic Red Team ingestion path
- ✅ False-positive tracking with alert-level feedback
- ✅ Rule versioning + changelog
- ✅ Deployment orchestration (backup → deploy → health check → rollback)
- ✅ Read-only web dashboard (FastAPI)
- ✅ CI/CD: lint/test/validate on PRs + weekly auto-regeneration workflow

## Future Roadmap (v3)

- Sample-specific service-name rules refinement (101069-101090)
- Live logtest pass-rate CI gate against a real Wazuh manager
- Sigma `near` temporal correlation
- Richer Linux/cloud field-mapping coverage

## License

Apache License 2.0 — see [LICENSE](LICENSE).

## Author

**Saif Eddinne Belaarbi** — [GitHub](https://github.com/saifbelaarbi)

## Credits

- [SBousseaden](https://github.com/sbousseaden) — EVTX-ATTACK-SAMPLES
- [mdecrevoisier](https://github.com/mdecrevoisier) — EVTX-to-MITRE-Attack
- [Yamato Security](https://github.com/Yamato-Security) — hayabusa-sample-evtx
- [OTRF](https://github.com/OTRF) — Security-Datasets (Mordor)
- [Fox-IT](https://github.com/fox-it) — danderspritz-evtx
- [SigmaHQ](https://github.com/SigmaHQ) — Sigma detection rules
- [Wazuh Inc.](https://github.com/wazuh) — Wazuh SIEM and default ruleset
