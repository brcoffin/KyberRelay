#!/usr/bin/env bash
# Cross-compile the web service for a DigitalOcean droplet (linux/amd64).
# Templates are embedded in the binary, so this single file is all you ship.
set -euo pipefail

cd "$(dirname "$0")/.."   # -> web/

GOOS=linux GOARCH=amd64 CGO_ENABLED=0 \
    go build -trimpath -ldflags "-s -w" -o kyber-web .

echo "Built $(pwd)/kyber-web (linux/amd64, $(du -h kyber-web | cut -f1))."
echo "Copy it to the droplet, e.g.:"
echo "  scp kyber-web deploy -r root@DROPLET_IP:/root/web-install/"
