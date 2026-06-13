# Deploying the Kyber-Zip relay on DigitalOcean

The relay is a tiny Go service that streams encrypted blobs to/from disk and
does **no crypto** itself (everything is end-to-end encrypted client-side). So
it needs almost no CPU/RAM — **disk and bandwidth** are the only real sizing
levers.

## 1. Create the droplet

- **Basic droplet, Ubuntu 24.04 LTS.** 1 vCPU / 1 GB RAM / 25 GB SSD (~$6/mo) is
  enough for personal use; 2 GB / 50 GB gives headroom for a small team.
- Pick the **region closest to your users**.
- For frequent large files, attach a **Block Storage volume** and set
  `RELAY_DATA_DIR` to its mount point (e.g. `/mnt/relay-data`).

Disk rule of thumb: blobs live until downloaded or until `RELAY_TTL`, so size
disk for peak *undelivered* data ≈ uploads-per-TTL × average file size. Lower
`RELAY_TTL` to bound it.

## 2. DNS + firewall

- Add an **A record** `relay.yourdomain.com → droplet IP` (needed for HTTPS).
- Open only the ports you need (DO Cloud Firewall, or `ufw`):
  ```sh
  ufw allow 22,80,443/tcp && ufw enable
  ```
  The relay's own port (8080) stays on localhost — never exposed.

## 3. Build the binary

On any machine with Go (or on the droplet itself):

```sh
cd relay
./deploy/build-linux.sh        # produces ./kyber-relay (linux/amd64)
```

Copy it and the deploy files to the droplet:

```sh
scp kyber-relay -r deploy root@DROPLET_IP:/root/relay-install/
```

## 4. Install the service

On the droplet:

```sh
cd /root/relay-install
chmod +x deploy/install.sh
sudo ./deploy/install.sh ./kyber-relay
```

This creates an unprivileged `kyber-relay` user, installs the binary to
`/usr/local/bin`, the data dir to `/var/lib/kyber-relay`, the config to
`/etc/kyber-relay/kyber-relay.env`, and a hardened **systemd** unit — then
enables and starts it. Verify:

```sh
curl -s http://127.0.0.1:8080/healthz     # -> ok
systemctl status kyber-relay
journalctl -u kyber-relay -f              # live logs
```

## 5. TLS via Caddy (recommended)

```sh
# Install Caddy (Debian/Ubuntu) — see https://caddyserver.com/docs/install
sudo apt install -y debian-keyring debian-archive-keyring apt-transport-https curl
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | sudo gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | sudo tee /etc/apt/sources.list.d/caddy-stable.list
sudo apt update && sudo apt install -y caddy

# Configure (edit the domain first!)
sudo cp deploy/Caddyfile /etc/caddy/Caddyfile
sudo sed -i 's/relay.example.com/relay.yourdomain.com/' /etc/caddy/Caddyfile
sudo systemctl reload caddy
```

Caddy fetches a Let's Encrypt cert automatically and proxies HTTPS → the relay.
Test from your laptop:

```sh
curl -s https://relay.yourdomain.com/healthz     # -> ok
```

> Prefer no reverse proxy? Set `RELAY_TLS_CERT` / `RELAY_TLS_KEY` and
> `RELAY_ADDR=:443` in the env file and skip Caddy (see the env example).

## 6. Point the client at it

In the Kyber-Zip GUI **Receive** dialog (or CLI `--relay`), use:

```
https://relay.yourdomain.com
```

The GUI saves it to `%APPDATA%\kyber-zip\relay.txt`; the CLI `watch` / `recv` /
`recv-watch` commands pick it up from there if `--relay` is omitted.

## Operations

| Task | Command |
|---|---|
| Reconfigure | edit `/etc/kyber-relay/kyber-relay.env`, then `systemctl restart kyber-relay` |
| Update binary | `scp` new build, `install -m755 kyber-relay /usr/local/bin/`, `systemctl restart kyber-relay` |
| Logs | `journalctl -u kyber-relay -e` |
| Disk usage | `du -sh /var/lib/kyber-relay/data` |

## Security notes

- The relay is **zero-knowledge** — it only stores ciphertext encrypted to the
  recipient's public key. Even a full server compromise doesn't expose file
  contents.
- Always run it **behind TLS** (Caddy) on a public host so claim codes can't be
  observed in transit.
- The built-in rate limiter is a per-IP speed bump; put a real WAF/proxy in
  front for a hostile public deployment.
