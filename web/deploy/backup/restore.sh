#!/usr/bin/env bash
# Restore an encrypted Kyber-Zip web backup.
# Usage: restore.sh <backup-file.tar.gz.gpg> [target-parent-dir]
# Decrypts + extracts into the target (default /tmp/kyber-restore) for review;
# it does NOT overwrite the live data dir automatically. GnuPG verifies the
# backup's integrity on decrypt and fails loudly if it has been tampered with.
set -euo pipefail

FILE="${1:?usage: restore.sh <backup.tar.gz.gpg> [target-dir]}"
TARGET="${2:-/tmp/kyber-restore}"
PASSFILE="${BACKUP_PASSFILE:-/etc/kyber-web/backup.pass}"
[ -f /etc/kyber-web/backup.env ] && . /etc/kyber-web/backup.env

command -v gpg >/dev/null 2>&1 || { echo "gpg not installed (apt install gnupg)" >&2; exit 1; }
mkdir -p "$TARGET"
gpg --batch --yes --quiet --pinentry-mode loopback \
    --passphrase-file "$PASSFILE" --decrypt "$FILE" | tar -C "$TARGET" -xzf -
echo "restored into $TARGET/data"
echo "To go live: systemctl stop kyber-web && rsync -a --delete $TARGET/data/ /var/lib/kyber-web/data/ && chown -R kyber-web:kyber-web /var/lib/kyber-web && systemctl start kyber-web"
