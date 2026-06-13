# Kyber-Zip Web (hosted file transfer)

A convenience-first, browser-based file transfer service. Upload a file with a
passphrase, get a share link; the recipient opens the link, enters the
passphrase, and downloads — no install, no account.

This is the **link + passphrase** MVP. Unlike the desktop tool and relay (which
are zero-knowledge / end-to-end), this is a **server-side** model: the server
processes plaintext transiently while encrypting. At rest it stores only
ciphertext — files are compressed and encrypted with **AES-256-GCM** under a key
derived from the passphrase (PBKDF2), and the original filename is sealed inside
the ciphertext, so the on-disk data reveals neither contents nor name without
the passphrase. AES-256 is quantum-resistant, so this path is post-quantum-safe
even though it doesn't use ML-KEM (ML-KEM returns with the future accounts
model).

## API

| Method | Path | Description |
|---|---|---|
| `GET`  | `/` | Upload page |
| `POST` | `/api/upload` | multipart: `file`, `passphrase`, `ttl` (hours), `one_time` → `{id, url}` |
| `GET`  | `/d/{id}` | Download page (prompts for passphrase) |
| `POST` | `/api/download/{id}` | `passphrase` → decrypted file stream |
| `GET`  | `/healthz` | Liveness |

## Configuration (env)

| Var | Default | Meaning |
|---|---|---|
| `WEB_ADDR` | `127.0.0.1:8090` | Listen address (keep on localhost behind a proxy) |
| `WEB_DATA_DIR` | `./web-data` | Where ciphertext + metadata are stored |
| `WEB_BASE_URL` | `http://127.0.0.1:8090` | Public base URL used in share links |
| `WEB_MAX_BYTES` | `104857600` | Max upload size (100 MiB) |
| `WEB_TTL` | `24h` | Default expiry for uploads |

## Build & run

Requires Go 1.24+ (stdlib only — uses `crypto/pbkdf2`, AES-GCM, deflate).

```sh
cd web
go build -o web .
WEB_ADDR=:8090 WEB_BASE_URL=https://yourdomain.com ./web   # bare domain is canonical
```

Open http://localhost:8090.

## Deploy

See [`deploy/`](deploy/) for a full DigitalOcean/Ubuntu setup — cross-compile
script, hardened systemd unit, Caddy config (automatic HTTPS), installer, and a
step-by-step guide (including running it alongside the relay on one droplet).

## Roadmap

- **Accounts model** (planned): register/login, server-held **ML-KEM** keypair
  per user, send by username. The storage and crypto layers are kept separable
  so this can be added without reworking the link+passphrase path.
- Streaming encryption for very large files (current MVP buffers in memory,
  bounded by `WEB_MAX_BYTES`).
- Argon2id instead of PBKDF2 for passphrase hardening.
