# Phase 2 Reconciliation Report

> Generated: 2026-04-30 15:22:46 UTC

## Intake Gate

- Gate status: **blocked**
- Missing CSV inputs:
  - `agent_inventory.csv`
  - `deployed_rules.csv`
  - `candidate_rules.csv`
  - `rule_test_results.csv`
  - `deployment_status.csv`

## Raw Source Exports

- `260203 - Wazuh_Agent_TC.xlsx`
- `260203 - Wazuh_SOC_Manager.xlsx`

## Local Rule Snapshot

| Metric | Value |
|--------|-------|
| Total local rules | 1570 |
| EVTX-derived rules | 793 |
| Sigma-converted rules | 777 |
| Validation passed (local metadata) | 98 |

## Reconciliation

| Area | CSV Rule IDs | Known In Repo | Unknown/New |
|------|--------------|---------------|-------------|
| deployed_rules | 0 | 0 | 0 |
| candidate_rules | 0 | 0 | 0 |
| rule_test_results | 0 | 0 | - |
| deployment_status | 0 | 0 | - |

## Dataset Diagnostics

| Dataset | Present | Rows | Columns | Rule IDs | Agents |
|---------|---------|------|---------|----------|--------|
| agent_inventory | false | 0 | 0 | 0 | 0 |
| deployed_rules | false | 0 | 0 | 0 | 0 |
| candidate_rules | false | 0 | 0 | 0 | 0 |
| rule_test_results | false | 0 | 0 | 0 | 0 |
| deployment_status | false | 0 | 0 | 0 | 0 |

## Next Actions

1. Convert or export normalized CSVs into `phase2/csv_inputs/`.
2. Re-run `python phase2/reconcile_phase2.py` after the CSV refresh.
