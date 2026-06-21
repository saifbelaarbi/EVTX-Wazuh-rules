#!/bin/sh
set -e

# ── Logging setup: re-exec self through tee on first invocation ──
RUN_ID=$(date -u +%Y%m%dT%H%M%SZ)
LOG_DIR="database/logs"
mkdir -p "$LOG_DIR"
LOG_FILE="$LOG_DIR/pipeline-${RUN_ID}.log"
export RUN_ID LOG_FILE

if [ -z "$_EVTX_LOGGED" ]; then
    export _EVTX_LOGGED=1
    sh "$0" "$@" 2>&1 | tee "$LOG_FILE"
    exit $?
fi

echo "=== EVTX-Wazuh-Rules Pipeline ==="
echo ">> Run ID: ${RUN_ID}"
echo ">> Started: $(date -u +%Y-%m-%dT%H:%M:%SZ)"

# API connection (overridable via docker-compose environment)
WAZUH_API="${WAZUH_API_URL:-https://wazuh-manager:55000}"
WAZUH_USER="${WAZUH_API_USER:-wazuh-wui}"
WAZUH_PASS="${WAZUH_API_PASSWORD:-MyS3cr37P450r.*-}"

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
python -m generator build-composites --auto-approve

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

# Primary method: copy rule files into the shared volume.
# The volume is mounted at /var/ossec/etc/rules/ on the manager,
# so Wazuh's <rule_dir>etc/rules</rule_dir> auto-loads them.
DEPLOYED=0
for RULE_FILE in database/rules/by_tactic/*.xml; do
    [ -f "$RULE_FILE" ] || continue
    cp "$RULE_FILE" /rules-deploy/
    DEPLOYED=$((DEPLOYED + 1))
done
echo ">> Copied ${DEPLOYED} rule files to shared volume (/var/ossec/etc/rules/)"

TOKEN=$(curl -sk -X POST "${WAZUH_API}/security/user/authenticate" \
    -u "${WAZUH_USER}:${WAZUH_PASS}" 2>/dev/null | python -c "
import sys, json
try:
    data = json.load(sys.stdin)
    print(data['data']['token'])
except Exception:
    print('')
")

if [ -n "$TOKEN" ]; then
    # Restart manager to load new rules from the shared volume
    echo ">> Restarting Wazuh manager to load new rules..."
    curl -sk -X PUT "${WAZUH_API}/manager/restart" \
        -H "Authorization: Bearer ${TOKEN}" > /dev/null 2>&1
    echo ">> Waiting for Wazuh to reload rules (polling API, up to 120s)..."
    sleep 10
    i=0
    while [ "$i" -lt 22 ]; do
        READY=$(curl -sk -X POST "${WAZUH_API}/security/user/authenticate" \
            -u "${WAZUH_USER}:${WAZUH_PASS}" 2>/dev/null | python -c "
import sys, json
try:
    print(json.load(sys.stdin)['data']['token'][:8])
except Exception:
    print('')
")
        if [ -n "$READY" ]; then
            echo ">> Wazuh API back up after restart."
            break
        fi
        i=$((i + 1))
        sleep 5
    done

    # Re-auth after restart (old token expired)
    TOKEN=$(curl -sk -X POST "${WAZUH_API}/security/user/authenticate" \
        -u "${WAZUH_USER}:${WAZUH_PASS}" 2>/dev/null | python -c "
import sys, json
try:
    data = json.load(sys.stdin)
    print(data['data']['token'])
except Exception:
    print('')
")

    # Verify rules were loaded
    LOADED=$(curl -sk -X GET "${WAZUH_API}/rules?limit=1&offset=0&q=id>100000" \
        -H "Authorization: Bearer ${TOKEN}" 2>/dev/null | python -c "
import sys, json
try:
    r = json.load(sys.stdin)
    print(r.get('data', {}).get('total_affected_items', 0))
except Exception:
    print(0)
")
    echo ">> Wazuh reports ${LOADED} custom rules loaded (id>100000)"

    if [ "$LOADED" = "0" ]; then
        echo ">> [WARN] No custom rules loaded — check Wazuh manager logs:"
        echo ">>   docker compose exec wazuh-manager cat /var/ossec/logs/ossec.log | tail -50"
    fi

    # ── 6. Live API logtest ──
    echo ""
    echo ">> Running live API logtest against Wazuh manager..."
    python -m generator logtest --mode live --save
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
echo ">> Finished: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "Results in ./database/"
echo "  rules/by_tactic/    - Wazuh XML rules"
echo "  metadata/           - rule_index, validation_results, changelog"
echo "  navigator_layer.json"
echo "  exports/sigma/      - Sigma YAML back-exports"
echo "  logs/               - Pipeline run logs"

# ── Generate run summary JSON ──
python -c "
import json, os, glob
from datetime import datetime

summary = {
    'run_id': '${RUN_ID}',
    'finished': datetime.utcnow().isoformat() + 'Z',
    'rule_files': len(glob.glob('database/rules/by_tactic/*.xml')),
    'rule_count': 0,
    'validation_errors': 0,
    'logtest': {},
}

try:
    idx = json.load(open('database/metadata/rule_index.json'))
    summary['rule_count'] = len(idx)
except Exception:
    pass

try:
    val = json.load(open('database/metadata/validation_results.json'))
    if isinstance(val, dict):
        summary['logtest'] = {
            'mode': val.get('mode', ''),
            'total': val.get('total_rules', 0),
            'passed': val.get('passed', 0),
            'failed': val.get('failed', 0),
            'pass_rate': val.get('pass_rate', ''),
        }
except Exception:
    pass

out = 'database/logs/run-${RUN_ID}.json'
json.dump(summary, open(out, 'w'), indent=2)
print(f'>> Run summary saved to {out}')
print(json.dumps(summary, indent=2))
" 2>/dev/null || true
