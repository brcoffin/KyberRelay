# Design scope: client-side (end-to-end) encryption

Scoping doc for moving KyberCrypt from **server-side** encryption to **client-side
/ end-to-end (E2E)** encryption. This is a design proposal, not an implemented
feature.

## 1. Where we are today

The account flow is post-quantum but **not** zero-knowledge:

- Each user has an ML-KEM-768 keypair. The public key is stored as-is; the
  private seed is AES-256-GCM-wrapped under an Argon2id key derived from the
  user's password (`accounts.go`).
- **Send** (`encryptAndStoreStream`): the browser uploads **plaintext**; the
  *server* encapsulates to the recipient's public key and seals the blob.
- **Receive** (`writeDecrypted`): the *server* decapsulates with the recipient's
  private key (unwrapped into the session at login) and streams **plaintext**
  back.
- Login posts the **raw password**; the server derives the Argon2id key and
  unwraps the private key.

Net: the server sits in the plaintext path on both ends and briefly holds the
password and the unwrapped private key. At-rest data is safe against a pure DB
leak, but a compromised/malicious server (or legal compulsion) can read files.

## 2. Goal & threat model delta

**Goal:** the server only ever sees ciphertext and never sees the password or the
plaintext private key. "We can't read your files" becomes technically true.

| Threat | Today | With E2E |
|---|---|---|
| DB / at-rest leak | mitigated | mitigated |
| Compromised server (RAM, logs) | **exposed** | mitigated |
| Legal compulsion to hand over plaintext | **possible** | not possible (only ciphertext) |
| Malicious JS served by the app | exposed | **still exposed** (see §5) |

## 3. Architecture

Three independent workstreams:

**A. Move file crypto into the browser.** The recipient's public key is already
published server-side. The sender's browser fetches it, does ML-KEM
encapsulation + the chunked AEAD (`stream.go`) **client-side**, and uploads only
ciphertext + KEM ciphertext. The recipient's browser downloads ciphertext and
decrypts locally. The server's `encryptAndStoreStream`/`writeDecrypted` become
pure store/serve of opaque bytes.
- Crypto libs: WebCrypto has neither ML-KEM nor Argon2id, so we need WASM —
  libsodium.js for AEAD/Argon2 (aligns with the project's libsodium preference)
  plus an ML-KEM implementation (compile Go's `crypto/mlkem` to WASM, or a JS PQ
  lib). The chunked-stream format already exists; port the framing to JS.

**B. Take the server out of the password / key-unwrap path.** Today login sends
the password. Adopt a **split-KDF** (à la Bitwarden/1Password): the browser
derives two values from the password — an *auth* secret sent to the server for
login, and a separate *key-encryption-key* that never leaves the browser and
unwraps the private seed locally. Stronger still: **OPAQUE** (an aPAKE) so the
password is never sent in any form. The wrapped-seed blob can still live
server-side (the server just can't open it).

**C. Large-file streaming in the browser.** Pro's 100 GiB cap can't be buffered
in a tab. Client-side encryption must stream via `ReadableStream`/File API, and
decrypted downloads likely need a **Service Worker** to synthesize the download
stream. This is the hardest engineering piece.

## 4. What it touches / breaks

- **No loss of server features** — the product has no server-side scanning,
  preview, or search to give up, so E2E is unusually feasible here.
- **Burn-after-download** still works (the server deletes ciphertext).
- **Password reset already means data loss** (key is password-wrapped); E2E
  doesn't worsen this. Pair with a downloadable **recovery key**.
- **`decrypt`-scope API keys conflict with E2E.** Today the server can
  reconstruct the key from a decrypt token. Under E2E the server can't decrypt,
  so programmatic decryption must move into the CLI/client. `send` scope is
  unaffected (public-key only).
- **Versioning/migration:** blobs are already versioned (stream v2); add an E2E
  marker. Existing accounts migrate on next login (re-wrap client-side, switch to
  split-KDF/OPAQUE auth). Run both paths during transition.

## 5. The honest caveat (web E2E)

E2E in a *web app* is only as trustworthy as the JS the server serves — a
compromised server can ship malicious JS and exfiltrate keys. This is the
standard critique (cf. Firefox Send). Partial mitigations: Subresource Integrity,
signed/reproducible releases, a pinned CSP. The **strongest** answer is a
**CLI/desktop client** that does crypto locally — which also fits the API-first
positioning and side-steps the browser-trust problem for the customers most
likely to pay a premium.

## 6. Effort & recommendation

- **Phase 1 — client-side unwrap + split-KDF auth (workstream B).** Closes the
  biggest gap (server never sees password or plaintext private key) without
  porting file crypto yet. *Medium.*
- **Phase 2 — browser file crypto + streaming (A + C).** Makes the *content* path
  E2E. *Large* (WASM ML-KEM, Service Worker downloads, large-file streaming).
- **Phase 3 — CLI/desktop client.** True E2E for the developer segment; strongest
  marketing claim. *Medium, parallelizable.*

**Recommendation:** it's the highest-leverage change for premium (Tresorit-tier)
positioning, but it's a v2-scale effort. Sequence B → C/A → CLI. Until web file
crypto lands, market it precisely as **"client-side encrypted"** with scope, and
reserve **"zero-knowledge"** for the CLI/desktop path — overclaiming on the web
app is both inaccurate (§5) and a reputational risk for a security product.
