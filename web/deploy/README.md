# Deploying the Kyber-Zip web service

Same shape as the relay deploy: a single Go binary behind Caddy (automatic
HTTPS) on an Ubuntu/Debian droplet. The web service and the relay can run on the
**same droplet** under different subdomains.

## 1. Droplet + DNS + firewall

- Basic droplet, **Ubuntu 24.04 LTS**, 1 vCPU / 1–2 GB RAM. Disk sized for peak
  *undelivered* data (uploads-per-TTL × avg size); attach a Block Storage volume
  and point `WEB_DATA_DIR` at it for heavy use.
- **A record** `send.yourdomain.com → droplet IP`.
- Open only 22 / 80 / 443:
  ```sh
  ufw allow 22,80,443/tcp && ufw enable
  ```

## 2. Build

On any machine with Go 1.24+ (templates are embedded — the binary is all you ship):

```sh
cd web
./deploy/build-linux.sh           # -> ./kyber-web (linux/amd64)
scp kyber-web deploy -r root@DROPLET_IP:/root/web-install/
```

## 3. Install the service

On the droplet:

```sh
cd /root/web-install
chmod +x deploy/install.sh
sudo ./deploy/install.sh ./kyber-web
```

Creates the `kyber-web` user, installs the binary, data dir
(`/var/lib/kyber-web`), config (`/etc/kyber-web/kyber-web.env`), and a hardened
systemd unit, then enables + starts it.

**Then set the public URL** (used to build share links):

```sh
sudo sed -i 's#https://send.example.com#https://send.yourdomain.com#' /etc/kyber-web/kyber-web.env
sudo systemctl restart kyber-web
curl -s http://127.0.0.1:8090/healthz      # -> ok
```

## 4. TLS via Caddy

```sh
sudo cp deploy/Caddyfile /etc/caddy/Caddyfile      # or append this site block
sudo sed -i 's/send.example.com/send.yourdomain.com/' /etc/caddy/Caddyfile
sudo systemctl reload caddy
```

(See `relay/deploy/README.md` for installing Caddy itself.) Then from any
browser: `https://send.yourdomain.com`.

### Running alongside the relay

Both services coexist on one droplet — just keep two site blocks in
`/etc/caddy/Caddyfile`:

```
relay.yourdomain.com { reverse_proxy 127.0.0.1:8080 }   # zero-knowledge relay
send.yourdomain.com  { reverse_proxy 127.0.0.1:8090 }   # hosted web service
```

## Operations

| Task | Command |
|---|---|
| Reconfigure | edit `/etc/kyber-web/kyber-web.env`, then `systemctl restart kyber-web` |
| Update binary | `scp` new build, `install -m755 kyber-web /usr/local/bin/`, `systemctl restart kyber-web` |
| Logs | `journalctl -u kyber-web -e` |
| Disk usage | `du -sh /var/lib/kyber-web/data` |

## Security reminder

Unlike the relay, this service is **not** zero-knowledge — it processes
plaintext while encrypting. At rest it stores only ciphertext (sealed under each
upload's passphrase), but you are trusting the running host. Always serve it
over **TLS**, and treat the droplet as sensitive.
