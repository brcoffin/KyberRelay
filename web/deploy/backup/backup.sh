#!/usr/bin/env bash
# Encrypted backup of the Kyber-Zip web data dir (accounts, inboxes, API keys,
# audit log). Produces a single authenticated AES-256 (GnuPG) encrypted tarball,
# rotates local copies, and optionally uploads off-box (DO Spaces / S3). Run by
# the systemd timer.
set -euo pipefail

# Config (override in /etc/kyber-web/backup.env)
DATA_DIR="${KYBER_WEB_DATA:-/var/lib/kyber-web/data}"
DEST="${BACKUP_DIR:-/var/backups/kyber-web}"
PASSFILE="${BACKUP_PASSFILE:-/etc/kyber-web/backup.pass}"
KEEP="${BACKUP_KEEP:-14}"
[ -f /etc/kyber-web/backup.env ] && . /etc/kyber-web/backup.env

command -v gpg >/dev/null 2>&1 || { echo "gpg not installed (apt install gnupg)" >&2; exit 1; }
[ -f "$PASSFILE" ] || { echo "missing passphrase file: $PASSFILE" >&2; exit 1; }
[ -d "$DATA_DIR" ] || { echo "missing data dir: $DATA_DIR" >&2; exit 1; }
mkdir -p "$DEST"

stamp=$(date -u +%Y%m%d-%H%M%S)
file="$DEST/kyber-web-$stamp.tar.gz.gpg"

# tar the data dir and encrypt the stream with authenticated symmetric crypto
# (GnuPG AES-256 — integrity-protected, unlike raw openssl CBC, which would let
# a tampered backup decrypt silently). Nothing plaintext hits disk.
tar -C "$(dirname "$DATA_DIR")" -czf - "$(basename "$DATA_DIR")" \
  | gpg --batch --yes --quiet --pinentry-mode loopback \
        --passphrase-file "$PASSFILE" --cipher-algo AES256 \
        --symmetric --output "$file"
chmod 600 "$file"
echo "backup: wrote $file ($(du -h "$file" | cut -f1))"

# Rotate: keep the newest $KEEP encrypted backups locally.
ls -1t "$DEST"/kyber-web-*.tar.gz.gpg 2>/dev/null | tail -n +"$((KEEP + 1))" | xargs -r rm -f

# Optional off-box upload (requires aws CLI). Set BACKUP_S3_BUCKET (and creds /
# BACKUP_S3_ENDPOINT for DO Spaces) in /etc/kyber-web/backup.env.
if [ -n "${BACKUP_S3_BUCKET:-}" ]; then
  if command -v aws >/dev/null 2>&1; then
    aws s3 cp "$file" "$BACKUP_S3_BUCKET/" ${BACKUP_S3_ENDPOINT:+--endpoint-url "$BACKUP_S3_ENDPOINT"}
    echo "backup: uploaded to $BACKUP_S3_BUCKET"
  else
    echo "backup: BACKUP_S3_BUCKET set but 'aws' CLI not installed; kept local only" >&2
  fi
fi
