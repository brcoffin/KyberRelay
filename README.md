# Kyber-Zip

Post-quantum encrypted archiving and secure file transfer.

Kyber-Zip compresses and encrypts files into a single `.kyz` archive that only
the holder of the matching private key can open. Key exchange uses **ML-KEM**
(the standardized form of Kyber) via liboqs; payloads are encrypted with
**AES-256-GCM**; data is compressed with deflate (miniz) before encryption.

It ships as a desktop **GUI** and a scriptable **CLI**, and includes a
zero-knowledge **relay** so encrypted archives can be transferred between
machines without the relay ever seeing plaintext.

---

## Contents

- [Building](#building)
- [Concepts](#concepts)
- [GUI](#gui)
- [CLI](#cli)
- [Secure transfer](#secure-transfer)
- [Automation: watched folders](#automation-watched-folders)
- [Security model](#security-model)

---

## Building

Requirements:
- CMake 3.16+ and a C11 compiler (MSVC on Windows).
- **Go 1.22+** — only to build the relay (`relay/`).
- Internet access on first configure: `FetchContent` pulls **liboqs**,
  **raylib**, and **libcurl** (built static, HTTP-only, Windows-native Schannel
  TLS).
- **libsodium** — provide it via vcpkg or your system package manager, or drop a
  prebuilt MSVC build under `lib/libsodium-msvc/` (git-ignored). CMake locates it
  via that path, `pkg-config`, or `find_library`.

```sh
cmake -S . -B build
cmake --build build --config Release
```

Outputs in `build/Release/`: `kyber-gui.exe`, `kyber-cli.exe`.

> The whole project links the **static CRT (/MT)** to match the bundled
> libsodium; mixing runtimes splits `FILE*`/`errno` state and breaks file I/O.

Build the relay separately:

```sh
cd relay
go build -o relay.exe .
```

---

## Concepts

- **Keypair** — an ML-KEM keypair (512/768/1024). The **public** key encrypts
  *to* a recipient; the **private** key decrypts. Keys live in a local keystore
  at `%APPDATA%\kyber-zip\keystore.dat`.
- **Archive (`.kyz`)** — one or more files, compressed then encrypted to a
  recipient's public key.
- **Relay** — a dumb, zero-knowledge blob store. Upload an encrypted `.kyz`,
  get a one-time **claim code**; the recipient downloads it by code. The relay
  only ever holds ciphertext.

---

## GUI

`kyber-gui.exe` provides:
- **Key Manager** — generate keypairs, import/export public keys and keypairs.
- **New / Open / Add Files / Add Folder** — stage files for a new archive or
  open an existing `.kyz` (drag-and-drop supported).
- **Encrypt / Decrypt** — create an archive for the selected key, or extract one.
- **Send / Receive** — upload the current archive to the relay (the claim code
  is shown and copied to the clipboard), or paste a code to download + open.
  The relay URL is entered once in **Receive** and saved to
  `%APPDATA%\kyber-zip\relay.txt`.

---

## CLI

```
kyber-cli <command> [options]
```

| Command | Purpose |
|---|---|
| `keygen <label> [--algorithm 512\|768\|1024]` | Generate a keypair |
| `keys [--remove <label>]` | List keystore keys + fingerprints (or delete one) |
| `verify <label> [expected-fp]` | Show a key's fingerprint, or check it against an expected value (a match marks the key **verified**) |
| `pack --recipient <label> [--output f.kyz] [--no-compress] <files...>` | Create an archive |
| `unpack --key <label> [--output dir] <archive.kyz>` | Decrypt + extract |
| `list --key <label> <archive.kyz>` | List archive contents |
| `watch --recipient <label> [...]` | **Auto-send**: watch a folder, encrypt+upload, log codes |
| `recv <code> --key <label> [--relay <url>] [--output dir]` | Download + decrypt one archive |
| `recv-watch --key <label> [...]` | **Auto-receive**: pull + decrypt as new codes appear |

For `watch`, `recv`, and `recv-watch`, the relay URL defaults to the one saved
by the GUI (`relay.txt`) if `--relay` is omitted.

---

## Secure transfer

Manual flow:

```sh
# Sender (has the recipient's PUBLIC key imported as "alice"):
kyber-cli pack --recipient alice --output report.kyz report.pdf
kyber-cli recv ...                      # (sender uploads via GUI Send, or see watch)

# Recipient (has the PRIVATE key "alice"):
kyber-cli recv <CODE> --key alice --output ./inbox
```

The relay is started wherever both ends can reach it:

```sh
RELAY_ADDR=:8080 RELAY_TTL=24h ./relay.exe      # see relay/README.md for TLS
```

To run it on a server (DigitalOcean droplet, systemd + automatic HTTPS via
Caddy), see **`relay/deploy/`** — it has a ready-to-use service unit, Caddyfile,
installer, and a step-by-step guide.

---

## Automation: watched folders

A hands-off pipeline using one archive **per file**, codes logged to a file.

**Sender** — drop files into `outbox/`; each is encrypted, uploaded, logged to
`sent-log.jsonl`, and the original moved to `sent/`:

```sh
kyber-cli watch --recipient alice --relay https://relay.example.com \
    --outbox outbox --sent sent --log sent-log.jsonl
```

Each `sent-log.jsonl` line:

```json
{"time":"2026-06-13T09:00:00","file":"report.pdf","size":12345,"code":"RQF4AJTPEQ6IAL4GF5FJQCQU64","relay":"https://relay.example.com"}
```

**Receiver** — pull + decrypt as new codes appear. `--codes` can point at a
plain text file (one code per line) **or directly at the sender's
`sent-log.jsonl`** (e.g. on a shared drive) — both formats are parsed:

```sh
kyber-cli recv-watch --key alice --relay https://relay.example.com \
    --codes sent-log.jsonl --inbox inbox --log received-log.jsonl
```

Behavior:
- A failed **upload** leaves the original in `outbox/` to retry next scan.
- A **permanently** failed download (code gone/invalid) is logged and not
  retried; a **transient** network error is retried.
- Already-handled codes are remembered in `received-log.jsonl` across restarts.
- `--interval <secs>` sets the scan period; `--settle <secs>` (sender) skips
  files modified within the window so partially-written files aren't sent.

Both watchers run until Ctrl+C and can be installed as services / scheduled
tasks for fully unattended operation.

---

## Security model

- **End-to-end encryption.** Archives are encrypted to the recipient's public
  key before they ever leave the machine. The relay, the network, and any
  shared code-delivery channel see only ciphertext.
- **Claim codes are capabilities, not secrets-of-record.** A code only controls
  *who can download the ciphertext* — not who can read it. Even if a code leaks,
  an attacker who grabs the blob cannot decrypt it without the private key. (The
  worst case is a leaked code being downloaded first, denying the intended
  recipient — a nuisance requiring a re-send, not a confidentiality break.)
  This is why logging codes to a file or sending them over ordinary channels is
  acceptable.
- **One-time download + TTL.** The relay deletes a blob on first download and
  sweeps anything older than its TTL.
- **Public-key authenticity is your responsibility.** Before trusting an
  imported public key, verify its **fingerprint** out-of-band (phone, in
  person, a channel you already trust) to prevent a man-in-the-middle from
  substituting their own key. The fingerprint is a short BLAKE2b digest of the
  key shown in the GUI Key Manager and by `kyber-cli keys`. The other party
  reads theirs aloud; you confirm with:

  ```sh
  kyber-cli verify alice "7AC7 A12C 7DBB 6C4A FB42"   # MATCH (exit 0) or MISMATCH (exit 1)
  ```

  Matching fingerprints mean you hold the genuine key; a mismatch means the key
  was tampered with or swapped.

  **Verified status.** A successful `verify` (or the **Mark Verified** button in
  the GUI Key Manager) records the key's fingerprint in
  `%APPDATA%\kyber-zip\verified.txt`. After that:
  - `kyber-cli keys` shows `[verified]` vs `[UNVERIFIED]`.
  - Encrypting to (or sending to) an unverified key **warns** — the GUI pops a
    confirmation before **Encrypt** and before **Send**; `kyber-cli pack` /
    `watch` print a warning to stderr.
  - `kyber-cli watch --require-verified` **refuses** to run against an
    unverified recipient (use it for unattended pipelines so automation can't
    silently send to an impostor).

  Status is keyed on the fingerprint, so re-importing a *different* key under
  the same label is correctly treated as unverified again.
- **Use TLS to the relay** in any real deployment so claim codes can't be
  observed in transit (the client supports HTTPS via Schannel; terminate TLS at
  the relay or a reverse proxy).
- Secret keys are wiped from memory on free.
