# KyberCrypt Web API

Programmatic access to the hosted service. Base URL: `https://kybercrypt.com`
(the `send.kybercrypt.com` alias also works).

There are two surfaces:
- **Account API (`/api/v1/...`)** — authenticated with a per-user **API key** (Bearer token). Send to other users by username, list your inbox, download (decrypt).
- **Anonymous link+passphrase** (`/api/upload`, `/api/download/{id}`) — no account, browser-oriented multipart; documented at the bottom.

> Security note: this is the convenience (server-side) service — the server
> processes plaintext while encrypting. An API key can both **send and decrypt**
> on your behalf, so treat it like a password. Keys are shown once at creation.

## Authentication

Create a key while logged in: **/app → API keys → Create key** (or `POST /api/keys`
with a session cookie). Send it on every API request:

```
Authorization: Bearer kc_<id>.<secret>
```

### Scopes and expiry

Each key has a **scope** and an optional **expiry**:

- **`send`** — may call `POST /api/v1/send` only. Carries **no key material**, so
  it can never decrypt your inbox even if leaked. Safest for automated senders.
- **`decrypt`** — may send *and* list/download/delete your inbox (needs the
  wrapped private key).

Inbox/message endpoints return **403** for a send-only key, and any expired key
returns **401**. Set scope/expiry when creating the key (form fields `scope`,
`expires_days`).

## Endpoints

### `POST /api/v1/send`
Encrypt a file to a recipient (by username) and drop it in their inbox.
multipart/form-data: `recipient` (username), `file`.

```sh
curl -H "Authorization: Bearer $TOKEN" \
     -F recipient=bob -F file=@report.pdf \
     https://kybercrypt.com/api/v1/send
# -> {"id":"<msgid>","recipient":"bob"}
```

### `GET /api/v1/inbox`
List messages addressed to you.

```sh
curl -H "Authorization: Bearer $TOKEN" https://kybercrypt.com/api/v1/inbox
# -> {"messages":[{"id":"...","from":"alice","size":12345,"created":1781388097}]}
```

### `GET /api/v1/messages/{id}`
Download and decrypt one message. Returns the raw file with a
`Content-Disposition` filename.

```sh
curl -H "Authorization: Bearer $TOKEN" -OJ \
     https://kybercrypt.com/api/v1/messages/<msgid>
```

### `DELETE /api/v1/messages/{id}`
Delete a message from your inbox. Returns `204 No Content`.

```sh
curl -X DELETE -H "Authorization: Bearer $TOKEN" \
     https://kybercrypt.com/api/v1/messages/<msgid>
```

### Errors
JSON `{"error":"..."}` with status `401` (bad/missing key), `404` (no such
recipient/message), `413` (too large), `500`.

## Key management (session-authenticated)

Used by the dashboard; cookie session required.

| Method | Path | Body | Result |
|---|---|---|---|
| `POST` | `/api/keys` | `label` | `{"token","label"}` — token shown once |
| `GET`  | `/api/keys` | — | `{"keys":[{"key_id","label","created"}]}` |
| `POST` | `/api/keys/{id}/delete` | — | revoke (redirect) |

## Anonymous link + passphrase (no account)

| Method | Path | Body | Result |
|---|---|---|---|
| `POST` | `/api/upload` | multipart `file`, `passphrase`, `ttl` (hours), `one_time` | `{"id","url"}` |
| `POST` | `/api/download/{id}` | `passphrase` | decrypted file stream |

## See also

The **relay** (`relay.kybercrypt.com`) is a separate, zero-knowledge API used by
the desktop/CLI clients: `POST /v1/blob` → `{code}`, `GET /v1/blob/{code}`
(one-time download). It only ever stores ciphertext.
