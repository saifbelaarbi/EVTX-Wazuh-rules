#!/bin/sh
set -e

echo "=== EVTX-Wazuh-Rules Pipeline ==="

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

# ── 5. Deploy rules to Wazuh manager via API ──
echo ""
echo ">> Deploying rules to Wazuh manager..."

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
    # Upload each rule file via the Wazuh API (PUT /rules/files/<name>)
    # This places them where Wazuh expects and auto-includes them.
    UPLOADED=0
    FAILED=0
    for RULE_FILE in database/rules/by_tactic/*.xml; do
        [ -f "$RULE_FILE" ] || continue
        FNAME=$(basename "$RULE_FILE")
        RESP=$(curl -sk -X PUT "${WAZUH_API}/rules/files/${FNAME}" \
            -H "Authorization: Bearer ${TOKEN}" \
            -H "Content-Type: application/octet-stream" \
            --data-binary "@${RULE_FILE}" 2>/dev/null)
        ERR=$(echo "$RESP" | python -c "
import sys, json
try:
    r = json.load(sys.stdin)
    print(r.get('error', 0))
except Exception:
    print('parse_error')
")
        if [ "$ERR" = "0" ]; then
            UPLOADED=$((UPLOADED + 1))
        else
            FAILED=$((FAILED + 1))
            echo "  [WARN] Failed to upload ${FNAME}: ${RESP}" | head -c 200
            echo ""
        fi
    done
    echo ">> Uploaded ${UPLOADED} rule files via API (${FAILED} failed)"

    # Also copy to shared volume as backup
    cp database/rules/by_tactic/*.xml /rules-deploy/ 2>/dev/null || true

    # Restart manager to load new rules
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
echo "Results in ./database/"
echo "  rules/by_tactic/    - Wazuh XML rules"
echo "  metadata/           - rule_index, validation_results, changelog"
echo "  navigator_layer.json"
echo "  exports/sigma/      - Sigma YAML back-exports"
