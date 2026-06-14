# Encrypted backups (web service)

Backs up the web data dir — accounts (password-wrapped keys), inboxes, API keys,
and the audit log — as a single **authenticated AES-256 (GnuPG) encrypted
tarball**, with local rotation, a daily systemd timer, and optional off-box
upload. GnuPG's encryption is integrity-protected, so a tampered backup fails to
decrypt rather than silently restoring corrupted data.

> The relay's data is intentionally **not** backed up: blobs are one-time /
> TTL-expiring and ephemeral.

## Install (on the droplet, as root)

```sh
# from the repo's web/deploy/backup directory:
apt install -y gnupg                                  # required for encrypt/decrypt
install -m 0755 backup.sh  /usr/local/bin/kyber-web-backup
install -m 0755 restore.sh /usr/local/bin/kyber-web-restore
install -m 0644 kyber-web-backup.service /etc/systemd/system/
install -m 0644 kyber-web-backup.timer   /etc/systemd/system/
install -d -m 0755 /etc/kyber-web
# generate a backup passphrase (SAVE IT OFF THE SERVER — see warning below)
[ -f /etc/kyber-web/backup.pass ] || { openssl rand -base64 32 > /etc/kyber-web/backup.pass; chmod 600 /etc/kyber-web/backup.pass; }
cp backup.env.example /etc/kyber-web/backup.env   # then edit for off-box upload

systemctl daemon-reload
systemctl enable --now kyber-web-backup.timer
systemctl start kyber-web-backup.service          # run one now
ls -lh /var/backups/kyber-web/
```

## ⚠️ Save the passphrase off the server

The backups are encrypted with `/etc/kyber-web/backup.pass`. If the droplet is
lost and you only have the (off-box) encrypted backup but not this passphrase,
**the backup cannot be decrypted.** Copy the passphrase somewhere safe (password
manager) that does *not* live on the droplet.

## Off-box upload (do this — local-only backups don't survive droplet loss)

1. Create a **DigitalOcean Space** + access keys.
2. `apt install -y awscli`
3. Set `BACKUP_S3_BUCKET`, `BACKUP_S3_ENDPOINT`, `AWS_ACCESS_KEY_ID`,
   `AWS_SECRET_ACCESS_KEY` in `/etc/kyber-web/backup.env`.
4. `systemctl start kyber-web-backup.service` and confirm the object appears.

## Restore

```sh
kyber-web-restore /var/backups/kyber-web/kyber-web-YYYYmmdd-HHMMSS.tar.gz.gpg
# review /tmp/kyber-restore/data, then follow the printed command to go live
```

## Schedule

Daily at 03:17 UTC (`kyber-web-backup.timer`). Check it:

```sh
systemctl list-timers kyber-web-backup.timer
journalctl -u kyber-web-backup.service -e
```
