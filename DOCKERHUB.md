# EVTX-Wazuh-Rules

Automated Wazuh detection rule database from EVTX attack samples and SigmaHQ rules — 3,289 rules, 12/12 MITRE ATT&CK tactics, 270+ techniques.

## Quick Start

```bash
# Run the full pipeline standalone
docker run --rm -v $(pwd)/output:/app/database saifbelaarbi/evtx-wazuh-rules

# Run with a Wazuh manager for live testing
curl -O https://raw.githubusercontent.com/saifbelaarbi/EVTX-Wazuh-rules/main/docker-compose.yml
docker compose up
```

## What It Does

The container runs the complete pipeline automatically:

1. **Downloads** EVTX samples from 7 security research repos + SigmaHQ rules + Wazuh defaults
2. **Generates** Wazuh XML rules from real-world attack telemetry
3. **Converts** 2,670+ Sigma YAML rules to Wazuh format
4. **Builds** composite correlation rules for multi-stage attack chains
5. **Validates** all rules (structural checks + offline simulation)
6. **Deploys** rules to a Wazuh manager (when using docker-compose)
7. **Tests** rules via Wazuh API logtest against the live engine
8. **Exports** MITRE ATT&CK Navigator layer + Sigma YAML back-exports

## Database Stats

| Metric | Value |
|--------|-------|
| Total rules | **3,289** |
| EVTX-generated | 619 |
| Sigma-converted | 2,670 |
| MITRE tactics | 12 / 12 |
| MITRE techniques | 270+ |
| Validation errors | 0 |

## With Docker Compose (Wazuh Integration)

The `docker-compose.yml` starts a Wazuh manager alongside the pipeline:

- Rules are deployed into the manager via shared volume
- Manager is restarted via API to reload rules
- Live API logtest validates rules against the real Wazuh engine
- Healthcheck ensures Wazuh is ready before the pipeline runs

```bash
git clone https://github.com/saifbelaarbi/EVTX-Wazuh-rules.git
cd EVTX-Wazuh-rules
docker compose up --build
```

## Output

Results are written to `/app/database/` (mount as a volume to persist):

```
database/
├── rules/
│   ├── by_tactic/      # One XML per MITRE tactic
│   ├── by_technique/   # One XML per technique ID
│   └── by_source/      # By log source (sysmon, security, etc.)
├── metadata/
│   ├── rule_index.json
│   ├── validation_results.json
│   └── changelog.json
├── exports/sigma/      # Sigma YAML back-exports
└── navigator_layer.json
```

## Configuration

Mount a custom `config.yaml` to override defaults:

```bash
docker run --rm \
  -v $(pwd)/my-config.yaml:/app/config.yaml \
  -v $(pwd)/output:/app/database \
  saifbelaarbi/evtx-wazuh-rules
```

Key settings in `config.yaml`:
- `wazuh.api_url` — Wazuh manager API endpoint
- `wazuh.api_user` / `api_password` — API credentials
- `wazuh.deploy_path` — Rule deployment directory

## Tags

- `latest` — Built from main branch on every push
- `v1.0.0`, `v1.1` — Semantic version releases
- `<sha>` — Specific commit builds

## Source

GitHub: [saifbelaarbi/EVTX-Wazuh-rules](https://github.com/saifbelaarbi/EVTX-Wazuh-rules)

## License

See repository for license details.
