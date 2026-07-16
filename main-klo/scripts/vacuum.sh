#!/bin/bash
# P1-4 (2026-06-21): weekly VACUUM ANALYZE на request_logs (для возврата дискового пространства).
# Cron: 30 4 * * 0 /opt/scoring-engine/scripts/vacuum.sh
LOG=/var/log/scoring-retention.log
echo "=== $(date) === vacuum start ===" >> $LOG
sudo -u postgres psql -d panel -c "VACUUM ANALYZE request_logs;" >> $LOG 2>&1
echo "=== $(date) === vacuum done ===" >> $LOG
