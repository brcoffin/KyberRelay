#!/usr/bin/env bash
# Restore an encrypted Kyber-Zip web backup.
# Usage: restore.sh <backup-file.tar.gz.enc> [target-parent-dir]
# Decrypts + extracts into the target (default /tmp/kyber-restore) for review;
# it does NOT overwrite the live data dir automatically.
set -euo pipefail

FILE="${1:?usage: restore.sh <backup.tar.gz.enc> [target-dir]}"
TARGET="${2:-/tmp/kyber-restore}"
PASSFILE="${BACKUP_PASSFILE:-/etc/kyber-web/backup.pass}"
[ -f /etc/kyber-web/backup.env ] && . /etc/kyber-web/backup.env

mkdir -p "$TARGET"
openssl enc -d -aes-256-cbc -pbkdf2 -pass "file:$PASSFILE" -in "$FILE" | tar -C "$TARGET" -xzf -
echo "restored into $TARGET/data"
echo "To go live: systemctl stop kyber-web && rsync -a --delete $TARGET/data/ /var/lib/kyber-web/data/ && chown -R kyber-web:kyber-web /var/lib/kyber-web && systemctl start kyber-web"
