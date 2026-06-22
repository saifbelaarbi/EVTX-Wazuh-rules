<div align="center">

# 🛡️ EVTX-Wazuh-Rules

### Turn real-world attack telemetry into a production Wazuh detection ruleset

Build, expand, and validate a **MITRE ATT&CK-mapped Wazuh rule database** from Windows EVTX
attack samples and SigmaHQ — then onboard *any* new log source with two Claude agents.

[![CI](https://github.com/saifbelaarbi/EVTX-Wazuh-rules/actions/workflows/ci.yml/badge.svg)](https://github.com/saifbelaarbi/EVTX-Wazuh-rules/actions/workflows/ci.yml)
[![Docker](https://github.com/saifbelaarbi/EVTX-Wazuh-rules/actions/workflows/docker-publish.yml/badge.svg)](https://github.com/saifbelaarbi/EVTX-Wazuh-rules/actions/workflows/docker-publish.yml)
[![Dashboard](https://github.com/saifbelaarbi/EVTX-Wazuh-rules/actions/workflows/pages.yml/badge.svg)](https://saifbelaarbi.github.io/EVTX-Wazuh-rules/)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.10%2B-3776AB.svg?logo=python&logoColor=white)](pyproject.toml)

### 📊 [**Live coverage dashboard →**](https://saifbelaarbi.github.io/EVTX-Wazuh-rules/) · auto-rebuilt on every pipeline run

![Rules](https://img.shields.io/badge/rules-3%2C303-2ea44f.svg)
![Techniques](https://img.shields.io/badge/MITRE%20techniques-289-e8553e.svg)
![Tactics](https://img.shields.io/badge/ATT%26CK%20tactics-12%2F12-8957e5.svg)
![Tests](https://img.shields.io/badge/tests-176%20passing-2ea44f.svg)
![Wazuh](https://img.shields.io/badge/Wazuh-4.x-005792.svg)

[Quick start](#-quick-start) · [How it works](#-how-it-works) · [Asset onboarding agents](#-asset-onboarding-agents-part-two) · [CLI](#-cli-reference) · [Docker](#-docker)

</div>

---

## ✨ What you get

<table>
<tr>
<td width="33%" valign="top">

### 📦 3,303 rules
EVTX-derived + SigmaHQ-converted, every rule mapped to MITRE ATT&CK, leveled, and deduped
against Wazuh defaults.

</td>
<td width="33%" valign="top">

### 🧪 Validated
176 unit tests, 0 structural errors, **100% offline-simulation** pass rate, and a full
Docker-Compose integration test against a live Wazuh manager in CI.

</td>
<td width="33%" valign="top">

### 🤖 Agent onboarding
Point the **decoder-agent** at any log folder → it writes a Wazuh decoder + field schema; the
**rule-agent** turns that into detections.

</td>
</tr>
</table>

## 📊 Current database

| Metric | Value | | Metric | Value |
|--------|------:|---|--------|------:|
| Total rules | **3,303** | | MITRE tactics | **12 / 12** |
| EVTX-generated | 626 | | MITRE techniques | **289** |
| Sigma-converted | 2,673 | | Unit tests | 176 |
| Composite/correlation | 4 | | Validation errors | 0 |
| Offline sim pass rate | **100%** (3,244/3,244) | | Inconclusive (need live) | 59 |

<details>
<summary><b>Tactic & source distribution</b></summary>

| Tactic | Rules | | Source | Rules |
|--------|------:|---|--------|------:|
| Execution | 1,166 | | Sysmon | 2,266 |
| Persistence | 845 | | System | 591 |
| Privilege Escalation | 383 | | PowerShell | 226 |
| Credential Access | 295 | | Security | 156 |
| Command & Control | 193 | | Application | 60 |
| Discovery | 137 | | Composite | 4 |
| Lateral Movement | 78 | | | |
| Collection | 51 | | | |
| Impact | 44 | | | |
| Defense Evasion | 42 | | | |
| Exfiltration | 37 | | | |
| Initial Access | 32 | | | |

</details>

> 📄 Full listings: [RULES_REPORT.md](docs/RULES_REPORT.md) · [COVERAGE_MATRIX.md](docs/COVERAGE_MATRIX.md) · [SOURCES.md](docs/SOURCES.md) · [PLAYBOOK.md](docs/PLAYBOOK.md)

## 🚀 Quick start

```bash
pip install -e .

# 1 — Download EVTX samples, Sigma rules, Wazuh defaults
python -m collector download-all
python -m collector download-sigma
python -m collector download-defaults

# 2 — Generate + convert + validate
python -m generator generate --auto-approve
python -m generator convert-sigma --auto-approve --min-level medium
python -m generator validate

# 3 — Test against source events
python -m generator logtest --mode simulate --save

# 4 — Deploy to Wazuh
python -m generator export --dest /var/ossec/etc/rules/ --view by_tactic
sudo systemctl restart wazuh-manager
```

## 🐳 Docker

The whole pipeline — Wazuh manager + rule generation + **live** logtest — in one command:

```bash
docker compose up --build
```

Or just the generator:

```bash
docker run -v $(pwd)/database:/app/database saifbelaarbi/evtx-wazuh-rules
```

Published image: [`saifbelaarbi/evtx-wazuh-rules`](https://hub.docker.com/r/saifbelaarbi/evtx-wazuh-rules) · run it on GCP with one click via the [Deploy to GCP](.github/workflows/deploy-gcp.yml) workflow (logs stream to a GCS bucket + GitHub artifacts).

## 🔍 How it works

```
                       ┌──────────── Part 1: Collector ────────────┐
   7 EVTX repos  ─┐    │  download → registry → data/ (gitignored) │
   SigmaHQ        ─┼──▶ └───────────────────┬───────────────────────┘
   Wazuh defaults ─┘                        │
                       ┌──────────── Part 2: Generator ────────────┐
                       │  parse → analyze → MITRE map → build →     │
                       │  correlate → level → validate → export     │
                       └───────────────────┬───────────────────────┘
                                            ▼
                         database/rules/  (by_tactic · by_technique · by_source)
```

**Collector** pulls EVTX samples, SigmaHQ rules, and Wazuh default rulesets from GitHub.
**Generator** parses events, classifies ATT&CK techniques via semantic indicator mapping, builds
Wazuh XML, converts Sigma YAML, dedupes against existing + built-in rules, assigns severity, and
exports three parallel views of the same ruleset.

<details>
<summary><b>Pipeline modules</b></summary>

| Stage | Module | Role |
|-------|--------|------|
| Parse | `evtx_parser.py` | EVTX/JSON/XML → normalized events |
| Analyze | `event_analyzer.py` | events → `DetectionPattern` objects |
| Map | `mitre_mapper.py` | semantic ATT&CK classification (indicator → technique) |
| Build | `rule_builder.py` | patterns → Wazuh `<rule>` XML |
| Correlate | `rule_correlator.py` | dedupe vs database + Wazuh defaults |
| Level | `alert_leveler.py` | severity 3–15 (tactic + confidence + FP feedback) |
| Validate | `validator.py` → `logtest_validator.py` | structural + event-replay validation |
| Export | `exporter.py` | 3 views + versioning + changelog |
| Sigma | `sigma_converter.py` / `sigma_analyzer.py` | Sigma YAML → Wazuh (full modifier set) |

</details>

## 🤖 Asset onboarding agents (Part Two)

Beyond Windows EVTX, onboard **any** asset whose logs Wazuh doesn't decode out of the box —
a firewall, appliance, or app — using two cooperating **Claude Code subagents** in [`agents/`](agents/).

```
  raw log folder (one asset)
            │
            ▼
   ┌─────────────────┐   <asset>_decoder.xml    ┌──────────────┐   <asset>.xml
   │  decoder-agent  │──▶ + <asset>_schema.json ─▶│  rule-agent  │──▶ Wazuh rules
   └─────────────────┘     (field-schema           └──────────────┘
       parses fields         contract)                builds detections
```

```text
Use the decoder-agent on data/raw_logs/cisco-asa/ (asset slug: cisco-asa)
Use the rule-agent on database/decoders/cisco-asa_schema.json
```

The JSON **field schema** is the contract between them, so the rule-agent can only reference
fields the decoder actually parsed. A complete Cisco ASA example ships in the agents' `examples/`
folders. See [`agents/README.md`](agents/README.md).

## 🗂️ Rule organization

Same rules, three views — pick what fits your deployment:

```
database/rules/
├── by_tactic/      # one XML per ATT&CK tactic   → broad deployment
├── by_technique/   # one XML per technique        → surgical tuning
└── by_source/      # by Windows log source        → Wazuh-native layout
```

## 🧰 CLI reference

<details>
<summary><b>Collector — <code>python -m collector</code></b></summary>

| Command | Description |
|---------|-------------|
| `download-all` | Download all registered EVTX sources |
| `download <name>` | Download a specific EVTX source |
| `download-sigma` | Download SigmaHQ rules (Windows) |
| `download-defaults` | Download Wazuh default rules + decoders |
| `download-atomic` | Clone Atomic Red Team for the atomic ingestion path |
| `status` / `list-sources` | Show download status / registered sources |

</details>

<details>
<summary><b>Generator — <code>python -m generator</code></b></summary>

| Command | Description |
|---------|-------------|
| `generate [--source N] [--auto-approve] [--diff-only]` | Generate rules from EVTX |
| `convert-sigma [--min-level LVL] [--platform ...] [--with-negation]` | Convert Sigma → Wazuh |
| `generate-atomic` | Generate from a cloned Atomic Red Team repo |
| `build-composites` | Build chained correlation rules |
| `logtest [--mode simulate\|live] [--save]` | Validate rules against source events |
| `validate` | Structural validation (non-zero exit on errors) |
| `navigator` | Export MITRE ATT&CK Navigator layer JSON |
| `export-sigma` | Back-convert EVTX-derived rules → Sigma YAML |
| `report-fp` / `fp-summary` | False-positive tracking + level suggestions |
| `changelog` / `stats` / `review` / `approve` | Ops & review helpers |
| `serve` | Launch the read-only web dashboard (`[web]` extra) |
| `export --dest PATH [--view VIEW]` | Export rules for Wazuh deployment |

</details>

<details>
<summary><b>Deployer & reports</b></summary>

```bash
python -m deployer deploy --src DIR --dest PATH   # backup → deploy → health check → rollback
python generate_report.py                          # Markdown reports → docs/
python generate_excel_report.py                    # Excel tracker (needs openpyxl)
```

</details>

## 🛠️ Quality controls

- **IDs** — Wazuh custom range `100000–119999`, partitioned per ATT&CK tactic, atomic allocation.
- **Correlation** — every rule checked against the database, Wazuh defaults, and same-tactic peers.
- **Levels** — tactic base score + detection confidence + tool overrides (mimikatz 13, meterpreter 14).
- **MITRE mapping** — indicator table → event-ID defaults → path hint (no folder-name guessing).
- **Validation** — well-formedness, required elements, ID uniqueness, parent-SID existence, T-ID format.
- **OSRegex aware** — Wazuh inverts PCRE dot semantics (`.` literal, `\.` any char); all escaping is centralized and kept in sync.

## 📦 Installation

```bash
pip install -e .            # core
pip install -e ".[dev]"     # + pytest, ruff, pre-commit
pip install -e ".[report]"  # + openpyxl (Excel reports)
pip install -e ".[web]"     # + fastapi, uvicorn (dashboard)
```

**Requires** Python 3.10+ · `python-evtx` · `lxml` · `click` · `rich` · `pyyaml` · `requests`.

## 🙌 Credits

[SBousseaden](https://github.com/sbousseaden) ·
[mdecrevoisier](https://github.com/mdecrevoisier) ·
[Yamato Security](https://github.com/Yamato-Security) ·
[OTRF](https://github.com/OTRF) ·
[Fox-IT](https://github.com/fox-it) ·
[NVISO](https://github.com/NVISOsecurity) ·
[INE Labs](https://github.com/ine-labs) ·
[SigmaHQ](https://github.com/SigmaHQ) ·
[Wazuh Inc.](https://github.com/wazuh)

## 📄 License & author

Apache License 2.0 — see [LICENSE](LICENSE).
Built by **[Saif Eddinne Belaarbi](https://github.com/saifbelaarbi)**.
