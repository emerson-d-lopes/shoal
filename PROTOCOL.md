# Shoal sync protocol v1

Shoal is a self-hosted sync server for local-first apps. The server stores an
append-only log of encrypted operations per user. It never sees plaintext. All
merge logic lives in clients. One server instance serves any number of apps.

## Identity and keys

A user is a 12-word BIP39 mnemonic. Nothing else: no account, no email, no
password reset.

Key derivation from the mnemonic seed (BIP39, empty passphrase):

```
seed        = BIP39-seed(mnemonic)                     // 64 bytes
sign_key    = HKDF-SHA256(seed, info="shoal/v1/sign")  // 32 bytes -> ed25519 seed
enc_key     = HKDF-SHA256(seed, info="shoal/v1/enc")   // 32 bytes, XChaCha20-Poly1305
user_id     = base64url(ed25519 public key)            // server-side identity
```

The server knows only `user_id` (the public key). The encryption key never
leaves clients.

## Operations

An op is one change to one record. Wire format (JSON):

```json
{
  "op_id":      "uuid v4, client-generated, idempotency key",
  "collection": "mnemonic",
  "record_id":  "card/8f3c...",
  "hlc":        "0189a7c2f3e8-0003-a1b2c3d4",
  "payload":    "base64(XChaCha20-Poly1305(plaintext))"
}
```

- `collection` namespaces an app. One user syncs many apps through one log.
- `record_id` is an opaque string to the server. Clients use `table/uuid`.
- `hlc` is a hybrid logical clock timestamp (48-bit wall ms, 16-bit counter,
  32-bit node id, hex, lexicographically ordered). Clients use it for LWW
  merge. The server does not parse it.
- `payload` is the encrypted record body, or an encrypted tombstone marker for
  deletes. Nonce (24 bytes) is prepended to the ciphertext before base64.
- The AAD for the AEAD is `collection || 0x00 || record_id`, binding the
  ciphertext to its location so a server cannot silently move ops between
  records.

The server assigns each accepted op a `seq`: a strictly increasing integer per
user. `seq` is the pull cursor.

## Endpoints

All request bodies and responses are JSON. All endpoints except `/healthz`
require authentication (below).

### POST /v1/ops — push

Request: `{ "ops": [Op, ...] }` (max 1000 per batch).

Response: `{ "results": [{"op_id": "...", "seq": 42}, ...], "head": 57 }`

Idempotent: an `op_id` already stored is not re-appended and returns its
existing `seq`. Clients retry batches safely.

### GET /v1/ops?since=SEQ&collection=NAME&limit=N — pull

Returns ops with `seq > since` in seq order. `collection` filter optional.
`limit` defaults to 500, max 1000.

Response: `{ "ops": [OpWithSeq, ...], "head": 57 }`

Clients page until their cursor reaches `head`, then persist the cursor.

### GET /v1/poke — server-sent events

Emits event `poke` with data `{"head": N}` whenever new ops are stored for the
authenticated user. On poke, clients pull. Reconnection is client-driven
(standard SSE retry). A poke is a hint, never a data channel.

### GET /healthz

Unauthenticated. `200 {"status":"ok"}`.

## Authentication

Every authenticated request carries:

```
X-Shoal-Pubkey:    base64url(ed25519 public key)
X-Shoal-Timestamp: unix seconds
X-Shoal-Signature: base64url(ed25519 signature)
```

The signature covers:

```
method || "\n" || path-with-query || "\n" || timestamp || "\n" || SHA256(body)
```

(`SHA256` of the empty string for bodyless requests.)

The server rejects timestamps more than 300 seconds from its clock. Users are
created implicitly: the first valid signed push from an unknown public key
creates the user. Registration is not a separate step.

This scheme is deliberately minimal for a personal, self-hosted, TLS-fronted
deployment. Replay of an identical request within the timestamp window is
possible and harmless: pushes are idempotent by `op_id` and pulls are
read-only against the caller's own data.

## Server storage

```sql
CREATE TABLE users (
  pubkey     TEXT PRIMARY KEY,
  created_at INTEGER NOT NULL
);

CREATE TABLE ops (
  pubkey     TEXT    NOT NULL,
  seq        INTEGER NOT NULL,        -- per-user, assigned in one tx
  op_id      TEXT    NOT NULL,
  collection TEXT    NOT NULL,
  record_id  TEXT    NOT NULL,
  hlc        TEXT    NOT NULL,
  payload    BLOB    NOT NULL,
  created_at INTEGER NOT NULL,
  PRIMARY KEY (pubkey, seq),
  UNIQUE (pubkey, op_id)
);
CREATE INDEX ops_pull ON ops (pubkey, collection, seq);
```

The log is append-only. The server never updates or deletes ops (compaction is
a possible v2 feature and would be client-driven, since only clients can read
payloads).

## Client contract

- Every local write also appends the full new record state (not a diff) to a
  local outbox as one op. Full-state ops make merge order-insensitive under
  LWW and make compaction trivial later.
- Outbox drains to `POST /v1/ops` when online. Ops survive app restarts.
- Pull applies ops through a per-table merge strategy:
  - `lww`: apply if incoming `hlc` > stored `hlc` for that record.
  - `append-only`: insert if `record_id` unseen, else ignore.
- Deletes are tombstone ops (encrypted `{"_deleted":true}` payload), merged by
  LWW like any other write.
- Clients echo their own ops back on pull (the server does not track origin).
  Applying an op the client itself produced must be a no-op; the op_id or hlc
  makes that detectable.

## Non-goals of v1

- No sharing between users, no multi-writer permissions.
- No server-side compaction or garbage collection.
- No key rotation. A leaked mnemonic means: stand up a new identity, re-push
  from a healthy device.
- No transport other than HTTPS + SSE. Run behind a TLS reverse proxy.
