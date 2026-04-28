# EVTX-Wazuh-Rules

A production-ready system for building and expanding a **Wazuh detection rule database** from real-world Windows EVTX attack samples. Parses EVTX logs from security research repositories, extracts malicious patterns, and generates categorized, MITRE ATT&CK-mapped Wazuh rules.

## Current Database

| Metric | Value |
|--------|-------|
| Total rules | **793** |
| EVTX files processed | 1,314 across 7 sources |
| Events analyzed | 2,035,484 |
| MITRE tactics covered | 8 / 12 |
| MITRE techniques | 9 |
| Alert level range | 4 - 13 |
| Sigma rules available | 2,267 convertible |
| Validation errors | 0 |

See [docs/RULES_REPORT.md](docs/RULES_REPORT.md) for the full rule listing, [docs/COVERAGE_MATRIX.md](docs/COVERAGE_MATRIX.md) for MITRE ATT&CK coverage, and [docs/SOURCES.md](docs/SOURCES.md) for source attribution.

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

**Part 1 — Collector** downloads EVTX samples and Wazuh default rules from GitHub. Downloaded binary files stay in `data/` (gitignored).

**Part 2 — Generator** parses events, extracts detection patterns, builds Wazuh XML rules, cross-references against existing rules and Wazuh defaults, assigns severity levels, validates, and exports in three views.

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
| Convertible to Wazuh | 2,267 (94.6%) |
| High/Critical severity | 1,160 |
| Top category | process_creation (1,177 rules) |

The Sigma analyzer (`generator/sigma_analyzer.py`) assesses which SigmaHQ detection rules can be converted to Wazuh format. Conversion covers process creation, registry, file events, PowerShell, network connections, DNS queries, named pipes, and more.

Wazuh default rules are downloaded from [wazuh/wazuh-ruleset](https://github.com/wazuh/wazuh-ruleset) for cross-referencing (133 rule files, 104 decoder files).

## Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Step 1: Download EVTX samples, Sigma rules, and Wazuh defaults
python -m collector download-all
python -m collector download-sigma
python -m collector download-defaults

# Step 2: Generate rules (as drafts for review)
python -m generator generate

# Step 2b: Or auto-approve high-confidence rules
python -m generator generate --auto-approve

# Step 3: Review and approve drafts
python -m generator review
python -m generator approve draft_XXXXXXXX_XXXXXX.xml

# Step 4: Validate the database
python -m generator validate

# Step 5: Deploy to Wazuh
python -m generator export --dest /var/ossec/etc/rules/ --view by_tactic
sudo systemctl restart wazuh-manager
```

## CLI Reference

### Collector (`python -m collector`)

| Command | Description |
|---------|-------------|
| `download-all` | Download all registered EVTX sources |
| `download <name>` | Download a specific EVTX source |
| `download-sigma` | Download SigmaHQ Sigma detection rules (Windows) |
| `download-defaults` | Download Wazuh default rules and decoders |
| `status` | Show download status table |
| `list-sources` | List all registered sources (EVTX + Sigma) |

### Generator (`python -m generator`)

| Command | Description |
|---------|-------------|
| `analyze [--source NAME]` | Parse EVTX files and show detection patterns |
| `generate [--source NAME] [--auto-approve]` | Generate Wazuh rules from EVTX samples |
| `review` | Show pending draft rules |
| `approve <draft_file>` | Promote a draft into the rule database |
| `validate` | Validate the entire rule database |
| `stats` | Show ID allocation and rule statistics |
| `export --dest PATH [--view VIEW]` | Export rules for Wazuh deployment |

### Report Generator

```bash
python generate_report.py
```

Produces three documentation files in `docs/`:
- **RULES_REPORT.md** — Full rule listing with alert levels, MITRE mapping, confidence scores
- **COVERAGE_MATRIX.md** — MITRE ATT&CK coverage heatmap and gap analysis
- **SOURCES.md** — EVTX source attribution and per-source breakdown

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
- Custom rule IDs in range **100000 - 120000**
- Partitioned by MITRE tactic (1,000 IDs each)
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
├── collector/           # Part 1: EVTX Collection Engine
│   ├── cli.py           # CLI commands (download-all, status, etc.)
│   ├── downloader.py    # Git clone / shallow download
│   ├── sigma_downloader.py # SigmaHQ rules downloader
│   ├── registry.py      # Download tracking and checksums
│   └── wazuh_defaults.py # Wazuh default rules downloader
│
├── generator/           # Part 2: Rule Database Generator
│   ├── cli.py           # CLI commands (generate, review, validate, etc.)
│   ├── evtx_parser.py   # Parse EVTX/JSON/XML to normalized events
│   ├── event_analyzer.py # Extract detection patterns from events
│   ├── sigma_analyzer.py # Analyze Sigma rules for Wazuh conversion
│   ├── rule_builder.py  # Build Wazuh XML rules from patterns
│   ├── rule_correlator.py # Cross-reference with existing rules
│   ├── alert_leveler.py # Assign severity levels
│   ├── id_manager.py    # Rule ID allocation (100000-120000)
│   ├── validator.py     # Rule validation
│   └── exporter.py      # Export to XML files (3 views)
│
├── database/            # Rule database (committed to git)
│   ├── metadata/        # rule_index.json, provenance.json, id_allocations.json
│   ├── drafts/          # Candidate rules awaiting review
│   └── rules/           # Approved rules (by_tactic/, by_technique/, by_source/)
│
├── sources/             # Source definitions (committed)
│   ├── evtx_sources.yaml
│   ├── sigma_sources.yaml
│   └── wazuh_default_sources.yaml
│
├── docs/                # Generated documentation
│   ├── RULES_REPORT.md
│   ├── COVERAGE_MATRIX.md
│   └── SOURCES.md
│
├── tests/               # Unit tests
├── data/                # Downloaded EVTX & defaults (GITIGNORED)
├── config.yaml          # Global configuration
├── requirements.txt     # Python dependencies
└── generate_report.py   # Documentation generator
```

## Dependencies

- Python 3.10+
- `evtx` — Rust-based EVTX parser (fast, no C build dependencies)
- `pyyaml` — Config file parsing
- `lxml` — XML generation and validation
- `click` — CLI framework
- `rich` — Terminal output formatting

## Future Roadmap (v2)

- Sigma-to-Wazuh converter (generate Wazuh rules directly from the 2,267 convertible Sigma rules)
- Composite/chained rules (multi-event detection using `if_matched_sid` and frequency)
- Automated wazuh-logtest validation against sample events
- CI/CD pipeline for rule generation on new EVTX samples
- MITRE ATT&CK Navigator layer export

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
