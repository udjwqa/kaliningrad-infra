#!/usr/bin/env bash
# 2026-06-23: IPQS FP monitoring — track CGNAT escape effectiveness post-fix.
#
# Run: bash /opt/scoring-engine/tools/ipqs_fp_monitor.sh
# Cron (hourly): 0 * * * * bash /opt/scoring-engine/tools/ipqs_fp_monitor.sh >> /var/log/ipqs_fp.log 2>&1

set -e
export PGUSER="${PGUSER:-panel}"
export PGPASSWORD="${PGPASSWORD:-panel}"
export PGHOST="${PGHOST:-localhost}"
DB="${PGDATABASE:-panel}"

echo "============================================================"
echo "IPQS FP MONITOR — $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "============================================================"

echo ""
echo "--- 1) Last 24h IPQS rejections by country ---"
echo "Expected: drop in CI/NG/BD/IN hits после CGNAT escape deploy."
psql -d "$DB" -t -c "
SELECT country_code, rejection_code, COUNT(*) hits, COUNT(DISTINCT ip) uniq_ip
FROM request_logs
WHERE timestamp > now() - interval '24 hours'
  AND rejection_code LIKE 'ipqs%'
GROUP BY country_code, rejection_code
ORDER BY hits DESC LIMIT 20;
"

echo ""
echo "--- 2) Last 24h ALL rejections — share IPQS из общего ---"
psql -d "$DB" -t -c "
WITH t AS (
  SELECT rejection_code, COUNT(*) hits FROM request_logs
  WHERE timestamp > now() - interval '24 hours'
    AND rejection_code IS NOT NULL
  GROUP BY 1
)
SELECT rejection_code, hits, ROUND(100.0 * hits / SUM(hits) OVER (), 1) pct
FROM t ORDER BY hits DESC LIMIT 15;
"

echo ""
echo "--- 3) CGNAT escape hits (last 24h trace logs) ---"
psql -d "$DB" -t -c "
SELECT COUNT(*) as cgnat_skip_events
FROM request_logs
WHERE timestamp > now() - interval '24 hours'
  AND raw_payload::text LIKE '%cgnat_skip%';
"

echo ""
echo "--- 4) Auto-banlist current state ---"
psql -d "$DB" -t -c "
SELECT code, source, COUNT(*) entries, COUNT(DISTINCT ip) uniq_ip
FROM auto_banned_entries
GROUP BY code, source ORDER BY entries DESC;
"

echo ""
echo "--- 5) Per-app fraud_score_threshold overrides ---"
ADMIN_KEY=$(grep "^ADMIN_KEY=" /opt/scoring-engine/.env 2>/dev/null | cut -d= -f2)
if [ -n "$ADMIN_KEY" ]; then
    curl -s -H "X-Admin-Key: $ADMIN_KEY" "http://127.0.0.1:8000/api/apps" 2>/dev/null \
      | jq -r '.[] | select(.fraud_score_threshold != 90 or (.asn_whitelist // [] | length > 0)) | "\(.package_name) → threshold=\(.fraud_score_threshold) asn_whitelist=\(.asn_whitelist)"'
fi

echo ""
echo "============================================================"
echo "Если в (1) CI hits < 500 за 24h — fix работает (было ~18,239/нед)."
echo "Если (3) cgnat_skip_events > 0 — escape hatch активно используется."
echo "Если (5) пусто — все apps используют default threshold 90."
echo "============================================================"
