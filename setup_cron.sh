#!/bin/bash
# =============================================================================
# setup_cron.sh — Display the cron entries for the VT Pipeline
# =============================================================================
# Run this script to see the cron entries to add.
# Then copy/paste them into: crontab -e
# =============================================================================

PIPELINE_DIR="/home/metamorphosis/workspace/vt_pipeline"
VENV_PYTHON="${PIPELINE_DIR}/.venv/bin/python3"
LOG_DIR="${PIPELINE_DIR}/logs"

echo "============================================================"
echo "  VT Pipeline — Cron Job Setup"
echo "============================================================"
echo ""
echo "Add the following lines to your crontab (crontab -e):"
echo ""
echo "# ── Daily: Update YARA export from Zintel (1:00 AM) ──────"
echo "0 1 * * * cd ${PIPELINE_DIR} && ${VENV_PYTHON} update_yara_export.py >> ${LOG_DIR}/yara_export_cron.log 2>&1"
echo ""
echo "# ── Twice weekly: VT Pipeline (Mon & Thu at 2:00 AM) ─────"
echo "0 2 * * 1,4 cd ${PIPELINE_DIR} && ${VENV_PYTHON} vt_pipeline.py >> ${LOG_DIR}/pipeline_cron.log 2>&1"
echo ""
echo "============================================================"
echo ""
echo "To install automatically, run:"
echo "  (crontab -l 2>/dev/null; echo '0 1 * * * cd ${PIPELINE_DIR} && ${VENV_PYTHON} update_yara_export.py >> ${LOG_DIR}/yara_export_cron.log 2>&1') | crontab -"
echo "  (crontab -l 2>/dev/null; echo '0 2 * * 1,4 cd ${PIPELINE_DIR} && ${VENV_PYTHON} vt_pipeline.py >> ${LOG_DIR}/pipeline_cron.log 2>&1') | crontab -"
echo ""
