# Kyber-Zip Relay

A zero-knowledge blob store for Kyber-Zip secure file transfer.

The relay only ever holds opaque ciphertext. The Kyber-Zip client encrypts each
payload to the recipient's ML-KEM public key **before** upload, so the relay
cannot read, decrypt, or silently tamper with file contents. It exists only to
hold a blob briefly and hand it to whoever presents the matching claim code.

Blobs are **one-time download** and also **expire after a TTL**, so nothing
lingers on the server.

## API

| Method | Path              | Description                                              |
|--------|-------------------|----------------------------------------------------------|
| `POST` | `/v1/blob`        | Store the request body. Returns `{"code","expires_in"}`. |
| `GET`  | `/v1/blob/{code}` | Stream the blob once, then delete it.                    |
| `GET`  | `/healthz`        | Liveness probe.                                          |

A `code` is 26 base32 characters (~128 bits of entropy) — infeasible to guess.

## Configuration (environment variables)

| Variable          | Default     | Meaning                                        |
|-------------------|-------------|------------------------------------------------|
| `RELAY_ADDR`      | `:8080`     | Listen address.                                |
| `RELAY_DATA_DIR`  | `./data`    | Directory for stored blobs.                    |
| `RELAY_MAX_BYTES` | `2147483648`| Max upload size in bytes (2 GiB).              |
| `RELAY_TTL`       | `24h`       | Delete blobs older than this (Go duration).    |
| `RELAY_TLS_CERT`  | *(unset)*   | PEM cert path. Set with key to serve HTTPS.    |
| `RELAY_TLS_KEY`   | *(unset)*   | PEM key path.                                  |

If `RELAY_TLS_CERT`/`RELAY_TLS_KEY` are unset the relay serves plaintext HTTP —
intended to run behind a TLS-terminating reverse proxy (Caddy, nginx). For a
public deployment, **always** terminate TLS so claim codes can't be sniffed.

## Build & run

Requires Go 1.22+.

```sh
cd relay
go build -o relay .      # produces ./relay (or relay.exe on Windows)
./relay                  # listens on :8080, stores blobs in ./data
```

Or run without building:

```sh
go run .
```

## Quick end-to-end test with curl

```sh
# Upload a file, capture the code
code=$(curl -s --data-binary @secret.kyz http://localhost:8080/v1/blob | \
       sed -E 's/.*"code":"([^"]+)".*/\1/')
echo "code: $code"

# Download it back (this consumes the blob)
curl -s http://localhost:8080/v1/blob/$code -o roundtrip.kyz

# A second download must 404 — one-time only
curl -s -o /dev/null -w "%{http_code}\n" http://localhost:8080/v1/blob/$code

# Verify the round trip
cmp secret.kyz roundtrip.kyz && echo "OK: identical"
```

## Deploying to a server

See [`deploy/`](deploy/) for a production setup on a DigitalOcean droplet
(or any Ubuntu/Debian host): a hardened systemd unit, a Caddy reverse-proxy
config with automatic HTTPS, a cross-compile script, an installer, and a
step-by-step guide.

## Notes

- Storage is the filesystem (`data/<code>`). It survives restarts; swap for an
  object store later if you outgrow a single host.
- The rate limiter is an in-memory per-IP speed bump (10 uploads/minute by
  default); state resets on restart. Put a real WAF/proxy in front for a
  hostile public deployment.
- Recipient **public-key authenticity** is the client's concern, not the
  relay's: the relay never sees or vouches for keys.
