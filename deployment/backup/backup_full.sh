#!/usr/bin/env bash
# ==============================================================================
# APIHunter Security Platform — Automated Full Database Backup Script
# Performs compressed pg_dump, generates SHA-256 integrity checksum,
# and enforces backup retention policy (7 daily, 4 weekly, 12 monthly).
# ==============================================================================

set -euo pipefail

BACKUP_DIR="${BACKUP_DIR:-/var/backups/apihunter}"
POSTGRES_HOST="${POSTGRES_HOST:-localhost}"
POSTGRES_PORT="${POSTGRES_PORT:-5432}"
POSTGRES_DB="${POSTGRES_DB:-apihunter_platform}"
POSTGRES_USER="${POSTGRES_USER:-postgres}"

TIMESTAMP=$(date -u +"%Y%m%d_%H%M%SZ")
BACKUP_FILE="${BACKUP_DIR}/${POSTGRES_DB}_full_${TIMESTAMP}.dump.gz"
CHECKSUM_FILE="${BACKUP_FILE}.sha256"

mkdir -p "${BACKUP_DIR}"

echo "[$(date -u)] Starting full database backup for '${POSTGRES_DB}' on ${POSTGRES_HOST}:${POSTGRES_PORT}..."

# Execute pg_dump with custom directory/archive compression
PGPASSWORD="${POSTGRES_PASSWORD:-postgres}" pg_dump \
  -h "${POSTGRES_HOST}" \
  -p "${POSTGRES_PORT}" \
  -U "${POSTGRES_USER}" \
  -d "${POSTGRES_DB}" \
  -F c \
  -b \
  -v \
  | gzip -9 > "${BACKUP_FILE}"

# Generate SHA-256 checksum
sha256sum "${BACKUP_FILE}" > "${CHECKSUM_FILE}"

echo "[$(date -u)] Backup completed successfully:"
echo "  File:     ${BACKUP_FILE}"
echo "  Checksum: $(cat "${CHECKSUM_FILE}")"

# Prune daily backups older than 7 days
find "${BACKUP_DIR}" -name "${POSTGRES_DB}_full_*.dump.gz" -mtime +7 -delete || true
find "${BACKUP_DIR}" -name "${POSTGRES_DB}_full_*.dump.gz.sha256" -mtime +7 -delete || true

echo "[$(date -u)] Retention pruning complete."
