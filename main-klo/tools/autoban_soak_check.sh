#!/usr/bin/env bash
# 2026-06-23 (Smart Auto-Banlist P6): daily shadow-soak validation.
#
# Run: ./tools/autoban_soak_check.sh
#
# Метрика ip_diversity = unique_ip / total. Чем ниже — тем чище attacker pattern.
#   < 0.05  → enforce-ready (один IP бьёт многократно — точно бот)
#   > 0.5   → false positive risk (много разных IP — CGNAT/legit)
#   0.05–0.5 → review вручную
#
# legit_after_ban > 0 → код даёт FP (грей-вердикт после auto-ban → real user)

set -e
# Use scoring-engine creds (override via env if нужно)
export PGUSER="${PGUSER:-panel}"
export PGPASSWORD="${PGPASSWORD:-panel}"
export PGHOST="${PGHOST:-localhost}"
export PGPORT="${PGPORT:-5432}"
DB="${PGDATABASE:-panel}"

echo "============================================================"
echo "AUTOBAN SHADOW SOAK — 7-day analysis"
echo "Date: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "============================================================"

echo ""
echo "--- 1) Per-code aggregate (last 7 days, shadow + active) ---"
psql -d "$DB" -c "
SELECT
  code,
  COUNT(*) AS total,
  COUNT(DISTINCT ip) AS uniq_ip,
  COUNT(DISTINCT package_name) AS uniq_pkg,
  ROUND(COUNT(DISTINCT ip)::numeric / COUNT(*), 3) AS ip_diversity,
  COUNT(*) FILTER (WHERE would_ban) AS shadow_count,
  COUNT(*) FILTER (WHERE NOT would_ban) AS active_count
FROM auto_banned_entries
WHERE banned_at > now() - interval '7 days'
GROUP BY code
ORDER BY total DESC;"

echo ""
echo "--- 2) False positive check (banned IP got grey verdict within 24h after ban) ---"
psql -d "$DB" -c "
SELECT
  ab.code,
  COUNT(DISTINCT ab.ip) AS banned_ips,
  COUNT(DISTINCT rl.id) AS legit_after_ban,
  ROUND(COUNT(DISTINCT rl.id)::numeric / NULLIF(COUNT(DISTINCT ab.ip), 0), 3) AS fp_rate
FROM auto_banned_entries ab
LEFT JOIN request_logs rl
  ON ab.ip = rl.ip
  AND COALESCE(ab.package_name, '') = COALESCE(rl.package_name, '')
  AND rl.verdict = 'grey'
  AND rl.timestamp > ab.banned_at
  AND rl.timestamp < ab.banned_at + interval '24 hours'
WHERE ab.banned_at > now() - interval '7 days'
GROUP BY ab.code
ORDER BY fp_rate DESC NULLS LAST;"

echo ""
echo "--- 3) Top 20 IPs by strike_count (probable attackers) ---"
psql -d "$DB" -c "
SELECT ip, code, strike_count, banned_at, would_ban
FROM auto_banned_entries
WHERE banned_at > now() - interval '7 days'
ORDER BY strike_count DESC
LIMIT 20;"

echo ""
echo "--- 4) Active enforce vs shadow split ---"
psql -d "$DB" -c "
SELECT
  CASE WHEN would_ban THEN 'shadow' ELSE 'enforce' END AS mode,
  source,
  COUNT(*) AS entries
FROM auto_banned_entries
WHERE expires_at IS NULL OR expires_at > now()
GROUP BY mode, source
ORDER BY mode, source;"

echo ""
echo "============================================================"
echo "Flip criteria (apply per code after 7d):"
echo "  G1 codes — уже enforce-ready. Просто продолжаем."
echo "  G2 codes — если ip_diversity < 0.05 И fp_rate == 0 → AUTOBAN_G2_READY=true"
echo "  Если ip_diversity > 0.5 ИЛИ fp_rate > 0 → исключить код из AUTOBAN_CODES_G2"
echo "============================================================"
