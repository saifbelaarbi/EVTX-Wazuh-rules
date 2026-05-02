# CSV Run Status

Updated: 2026-04-30

## Required Files

- `agent_inventory.csv` - missing
- `deployed_rules.csv` - missing
- `candidate_rules.csv` - missing
- `rule_test_results.csv` - missing
- `deployment_status.csv` - missing

## Upstream Raw Inputs Present

- `phase2/source_exports/260203 - Wazuh_Agent_TC.xlsx`
- `phase2/source_exports/260203 - Wazuh_SOC_Manager.xlsx`

## Gate

Phase-two reconciliation is blocked until the required CSV files are dropped in this folder.

## Reconciliation Command

`python phase2/reconcile_phase2.py`

Latest outputs:

- `phase2/output/reconciliation_summary.json`
- `phase2/output/reconciliation_report.md`
