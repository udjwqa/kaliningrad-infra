#!/bin/bash
# P1-4 (2026-06-21): daily retention — удаляет request_logs старше 30 дней.
# Cron: 15 3 * * * /opt/scoring-engine/scripts/retention.sh
LOG=/var/log/scoring-retention.log
echo "=== $(date) === retention start ===" >> $LOG
sudo -u postgres psql -d panel -c "DELETE FROM request_logs WHERE timestamp < NOW() - INTERVAL '30 days';" >> $LOG 2>&1
echo "=== $(date) === retention done ===" >> $LOG
