#!/usr/bin/env bash
# Install the Kyber-Zip relay as a systemd service on Ubuntu/Debian.
#
# Run as root on the droplet, from a directory that contains the built binary
# and this deploy/ folder. Example:
#   scp kyber-relay deploy -r root@DROPLET:/root/relay-install
#   ssh root@DROPLET 'cd /root/relay-install && ./deploy/install.sh ./kyber-relay'
set -euo pipefail

BIN_SRC="${1:-./kyber-relay}"
HERE="$(cd "$(dirname "$0")" && pwd)"

[[ $EUID -eq 0 ]]      || { echo "Run as root (sudo)."; exit 1; }
[[ -f "$BIN_SRC" ]]    || { echo "Binary not found: $BIN_SRC"; exit 1; }

# Dedicated unprivileged service account.
id -u kyber-relay >/dev/null 2>&1 || \
    useradd --system --no-create-home --shell /usr/sbin/nologin kyber-relay

install -m 0755 "$BIN_SRC" /usr/local/bin/kyber-relay
install -d -o kyber-relay -g kyber-relay -m 0750 /var/lib/kyber-relay /var/lib/kyber-relay/data
install -d -m 0755 /etc/kyber-relay
[[ -f /etc/kyber-relay/kyber-relay.env ]] || \
    install -m 0644 "$HERE/kyber-relay.env.example" /etc/kyber-relay/kyber-relay.env
install -m 0644 "$HERE/kyber-relay.service" /etc/systemd/system/kyber-relay.service

systemctl daemon-reload
systemctl enable --now kyber-relay
sleep 1
systemctl --no-pager --full status kyber-relay || true

echo
echo "Relay running on 127.0.0.1:8080. Health check:"
echo "  curl -s http://127.0.0.1:8080/healthz"
echo "Edit /etc/kyber-relay/kyber-relay.env then 'systemctl restart kyber-relay' to reconfigure."
