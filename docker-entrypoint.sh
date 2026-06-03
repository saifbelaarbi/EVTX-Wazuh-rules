#!/bin/sh
set -e

echo "=== EVTX-Wazuh-Rules Pipeline ==="

# ── 1. Download sources ──
echo ""
echo ">> Downloading EVTX samples..."
python -m collector download-all

echo ""
echo ">> Downloading Sigma rules..."
python -m collector download-sigma

echo ""
echo ">> Downloading Wazuh defaults..."
python -m collector download-defaults

# ── 2. Generate rules ──
echo ""
echo ">> Generating rules from EVTX samples..."
python -m generator generate --auto-approve

echo ""
echo ">> Converting Sigma rules..."
python -m generator convert-sigma --auto-approve --min-level medium

echo ""
echo ">> Building composite correlation rules..."
python -m generator build-composites

# ── 3. Validate (structural) ──
echo ""
echo ">> Validating rule database..."
python -m generator validate

# ── 4. Offline simulation test ──
echo ""
echo ">> Running offline simulation logtest..."
python -m generator logtest --mode simulate --save

# ── 5. Deploy rules to Wazuh manager ──
echo ""
echo ">> Deploying rules to Wazuh manager..."
cp database/rules/by_tactic/*.xml /rules-deploy/ 2>/dev/null || true

# Restart Wazuh manager via API to reload rules
echo ">> Restarting Wazuh manager to load new rules..."

# Get API token (default credentials: wazuh-wui / wazuh-wui)
WAZUH_API="https://wazuh-manager:55000"
TOKEN=$(curl -sk -X POST "${WAZUH_API}/security/user/authenticate" \
    -u "wazuh-wui:wazuh-wui" 2>/dev/null | python -c "
import sys, json
try:
    data = json.load(sys.stdin)
    print(data['data']['token'])
except Exception:
    print('')
")

if [ -n "$TOKEN" ]; then
    # Restart manager
    curl -sk -X PUT "${WAZUH_API}/manager/restart" \
        -H "Authorization: Bearer ${TOKEN}" > /dev/null 2>&1
    echo ">> Waiting for Wazuh to reload rules..."
    sleep 15

    # ── 6. Live API logtest ──
    echo ""
    echo ">> Running live API logtest against Wazuh manager..."
    python -m generator logtest --mode api --save
else
    echo "!! Could not authenticate with Wazuh API — skipping live logtest"
    echo "   (offline simulation results are still available)"
fi

# ── 7. Generate reports & exports ──
echo ""
echo ">> Generating Navigator layer..."
python -m generator navigator

echo ""
echo ">> Exporting Sigma rules..."
python -m generator export-sigma

echo ""
echo ">> Generating reports..."
python generate_report.py 2>/dev/null || true

echo ""
echo "=== Pipeline complete ==="
echo "Results in ./database/"
echo "  rules/by_tactic/    - Wazuh XML rules"
echo "  metadata/           - rule_index, validation_results, changelog"
echo "  navigator_layer.json"
echo "  exports/sigma/      - Sigma YAML back-exports"
