#!/usr/bin/env bash
# Cross-compile the relay for a DigitalOcean droplet (linux/amd64).
# Run from any machine with Go installed; produces ./kyber-relay in relay/.
set -euo pipefail

cd "$(dirname "$0")/.."   # -> relay/

GOOS=linux GOARCH=amd64 CGO_ENABLED=0 \
    go build -trimpath -ldflags "-s -w" -o kyber-relay .

echo "Built $(pwd)/kyber-relay (linux/amd64, $(du -h kyber-relay | cut -f1))."
echo "Copy it to the droplet, e.g.:"
echo "  scp kyber-relay deploy/*.service deploy/kyber-relay.env.example root@DROPLET_IP:/root/"
