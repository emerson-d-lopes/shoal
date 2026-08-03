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

### POST /v1/compact — drop superseded ops

Request: `{ "collection": "mnemonic", "through": 1234 }`

Response: `{ "removed": 812, "remaining": 190, "head": 1240 }`

Within `collection`, and only at or below `through`, every `record_id` keeps
its highest-`hlc` op and the rest are deleted. Other collections, other users,
and everything above the watermark are untouched.

This is sound because ops carry full record state. Under last-writer-wins only
the newest op for a record can ever be applied, so the ones removed could not
have changed any client's converged state. A client still behind the compacted
range reaches the same result, having skipped intermediate values that LWW
would have discarded regardless.

It is **not** sound for a collection merged append-only, where every op
carries meaning the newest does not subsume. The request is scoped to one
collection so that an app which compacts cannot damage one that must not. The
server cannot tell the strategies apart, since it never reads payloads, so
this is the client's call to make.

`head` never moves. Compaction can delete the row holding the highest `seq`
(when a later push carried an older `hlc`), so the server tracks the
high-water mark separately from the rows that exist. `seq` is never reused,
and a cursor taken before a compaction is still valid after it.

Clients pass their own pull cursor as `through`, so they never ask the server
to discard history they have not merged.

Tombstones survive compaction, being the newest op for their record. A deleted
record therefore costs one op forever, which is the price of letting a device
that has been offline since before the delete learn about it.

### GET /v1/poke — server-sent events

Emits event `poke` with data `{"head": N}` whenever new ops are stored for the
authenticated user. On poke, clients pull. Reconnection is client-driven. A
poke is a hint, never a data channel.

Authentication is the same signed-header scheme as every other endpoint, so
`EventSource` cannot be used to consume it: the API sets no request headers.
Clients read the stream from `fetch` and frame the events themselves. A user
may hold `SHOAL_MAX_STREAMS_PER_USER` streams open at once, and opening one
spends from the same rate budget as a push or a pull.

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

An operator can restrict which keys are served (`SHOAL_ALLOWED_PUBKEYS`).
Requests from a key outside that list are refused with 403 even though the
signature verifies. Without a list every well-formed keypair is a user, which
is the intended behaviour on a private network and a liability on a public
one, since per-user limits then bound nothing in total.

This scheme is deliberately minimal for a personal, self-hosted, TLS-fronted
deployment. Replay of an identical request within the timestamp window is
possible and harmless: pushes are idempotent by `op_id` and pulls are
read-only against the caller's own data.

## Cross-origin requests

The three `X-Shoal-*` headers are not CORS-simple, so a browser preflights
every request. The server answers preflights and allows any origin by default,
narrowable with `SHOAL_ALLOWED_ORIGINS`. Origin is not a security boundary
here: authentication is a per-request signature, never a cookie, so a page
that lacks the mnemonic gains nothing by being allowed to send the request.

## Server storage

```sql
PRAGMA user_version = 1;

CREATE TABLE users (
  pubkey     TEXT PRIMARY KEY,
  created_at INTEGER NOT NULL
);

CREATE TABLE ops (
  pubkey     TEXT    NOT NULL REFERENCES users(pubkey),
  seq        INTEGER NOT NULL,        -- per-user, assigned in one tx
  op_id      TEXT    NOT NULL,
  collection TEXT    NOT NULL,
  record_id  TEXT    NOT NULL,
  hlc        TEXT    NOT NULL,
  payload    BLOB    NOT NULL,        -- raw bytes, decoded from the wire
  created_at INTEGER NOT NULL,
  PRIMARY KEY (pubkey, seq),
  UNIQUE (pubkey, op_id)
);
CREATE INDEX ops_pull ON ops (pubkey, collection, seq);
```

`payload` is stored as bytes, not as the base64 text that travels on the wire,
which is a third less disk for the column that dominates the file. Base64 is
decoded when a push is accepted, so a malformed payload is rejected with 400
rather than stored, and re-encoded on pull. The wire format is unchanged.

`users.head` is the highest `seq` ever assigned and never decreases.
`users.op_count` is how many rows currently exist. The two are equal until the
first compaction and diverge after it, which is why both are stored rather
than derived from `ops`: compaction leaves gaps, so `MAX(seq)` would overstate
the count and `COUNT(*)` would be an O(ops) scan on every push.

Ops are otherwise immutable. The server never rewrites one, and deletes only
through [compaction](#post-v1compact--drop-superseded-ops), at a client's
request.

`user_version` records the storage layout. Startup migrates an older file one
step at a time, each in a transaction that rolls back leaving the original
untouched if anything fails.

## What the server can see

"End-to-end encrypted" here means the server cannot read record contents. It
does not mean the log is opaque. Everything in the `ops` table except `payload`
is stored in the clear, so an operator with database access learns:

| Visible | What it reveals |
|---------|-----------------|
| `collection` | Which apps you run. The value is a plain name like `mnemonic`. |
| `record_id` | The client convention is `table/uuid`, so table names leak. `card/8f3c...` says the record is a card. |
| `hlc` | Wall-clock milliseconds of every write, plus a 32-bit node id that is stable per device, so writes can be attributed to a device and correlated over time. |
| `created_at`, `seq` | Server-side arrival time and total op count per user. |
| `payload` length | Approximate record size. |
| `pubkey` | A stable pseudonymous identifier for the user across all their apps. |

Put together, an operator can build an accurate picture of which apps you use,
how many records each holds, which device you were on, and when you were
active. Only the contents stay private.

A malicious server has further reach:

- It can withhold ops or report a stale `head`. Clients have no way to detect
  this. The log has no hash chain, so there is no integrity proof spanning ops.
- It can delete ops. Append-only is server policy, not something the protocol
  enforces.
- It cannot forge or alter an op. Payloads are AEAD ciphertext and requests
  carry ed25519 signatures.
- It cannot move an op to a different record. The AAD binds the ciphertext to
  `collection || 0x00 || record_id`.

This is an acceptable trade for the intended deployment, which is a server you
run yourself on your own tailnet. It is worth stating plainly before anyone
runs shoal somewhere they do not control.

Two properties follow from the key derivation and are worth being explicit
about:

- **No forward secrecy.** `enc_key` is derived once from the mnemonic seed and
  never rotates, so a mnemonic disclosed later decrypts the entire history,
  including ops captured before the disclosure.
- **Key loss is data loss.** There is no recovery path. The 12 words are the
  only copy of the key, and the server holds nothing that helps.

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
- No automatic server-side compaction. The server never decides on its own
  what to drop, because it cannot tell an LWW collection from an append-only
  one. Compaction happens only when a client asks.
- No key rotation. A leaked mnemonic means: stand up a new identity, re-push
  from a healthy device.
- No transport other than HTTPS + SSE. Run behind a TLS reverse proxy.
