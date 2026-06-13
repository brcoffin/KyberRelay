#!/usr/bin/env bash
# Install the Kyber-Zip web service as a systemd service on Ubuntu/Debian.
#
# Run as root on the droplet, from a directory containing the built binary and
# this deploy/ folder. Example:
#   scp kyber-web deploy -r root@DROPLET:/root/web-install
#   ssh root@DROPLET 'cd /root/web-install && ./deploy/install.sh ./kyber-web'
set -euo pipefail

BIN_SRC="${1:-./kyber-web}"
HERE="$(cd "$(dirname "$0")" && pwd)"

[[ $EUID -eq 0 ]]   || { echo "Run as root (sudo)."; exit 1; }
[[ -f "$BIN_SRC" ]] || { echo "Binary not found: $BIN_SRC"; exit 1; }

# Dedicated unprivileged service account.
id -u kyber-web >/dev/null 2>&1 || \
    useradd --system --no-create-home --shell /usr/sbin/nologin kyber-web

install -m 0755 "$BIN_SRC" /usr/local/bin/kyber-web
install -d -o kyber-web -g kyber-web -m 0750 /var/lib/kyber-web /var/lib/kyber-web/data
install -d -m 0755 /etc/kyber-web
[[ -f /etc/kyber-web/kyber-web.env ]] || \
    install -m 0644 "$HERE/kyber-web.env.example" /etc/kyber-web/kyber-web.env
install -m 0644 "$HERE/kyber-web.service" /etc/systemd/system/kyber-web.service

systemctl daemon-reload
systemctl enable --now kyber-web
sleep 1
systemctl --no-pager --full status kyber-web || true

echo
echo "Web service running on 127.0.0.1:8090. Health check:"
echo "  curl -s http://127.0.0.1:8090/healthz"
echo "IMPORTANT: edit /etc/kyber-web/kyber-web.env and set WEB_BASE_URL to your"
echo "public https URL, then 'systemctl restart kyber-web'."
