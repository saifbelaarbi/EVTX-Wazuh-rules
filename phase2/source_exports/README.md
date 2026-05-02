# Phase 2 Source Exports

Store raw upstream spreadsheet or export files here when they are delivered before CSV conversion.

Current use:

- Wazuh agent inventory spreadsheets
- Wazuh SOC manager rule export spreadsheets

Workflow:

1. Drop raw `.xlsx` or equivalent source exports here.
2. Convert them externally or with a separate helper into the normalized CSV filenames expected in `phase2/csv_inputs/`.
3. Treat this folder as transient intake, not a hand-maintained source of truth.
