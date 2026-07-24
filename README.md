# shoal

Self-hosted sync server for local-first apps. One small Rust binary stores an
append-only log of end-to-end encrypted operations per user. Clients merge,
the server only stores and orders ciphertext.

Built to sync my own apps ([tuna](https://github.com/emerson-d-lopes/tuna),
[mnemonic](https://github.com/emerson-d-lopes/mnemonic),
[habit-tracker](https://github.com/emerson-d-lopes/habit-tracker)) across
devices without a cloud account.

## Properties

- **End-to-end encrypted.** Payloads are XChaCha20-Poly1305 ciphertext. The
  server never holds a decryption key.
- **No accounts.** Identity is an ed25519 keypair derived from a 12-word
  BIP39 mnemonic. The same words on a new phone restore everything.
- **App-agnostic.** Apps are namespaced by a `collection` string. One server
  instance syncs any number of apps.
- **Offline-first.** The server is an availability convenience. Apps work
  fully without it and reconcile when it returns.
- **Small.** axum + SQLite, one binary, one file of state.

## How it works

Clients append full-state record ops to a local outbox and push them in signed
batches. The server assigns each op a per-user sequence number. Clients pull
ops past their cursor and merge with per-table strategies (last-writer-wins on
a hybrid logical clock, or append-only). An SSE endpoint pokes connected
clients when new ops land.

The full wire format, key derivation, auth scheme, and storage schema are in
[PROTOCOL.md](PROTOCOL.md).

## Run

```sh
docker build -t shoal .
docker run -d -p 7420:7420 -v shoal-data:/data shoal
```

Or bare: `cargo run --release`. Configuration is two environment variables,
`SHOAL_DB` (SQLite path, default `shoal.db`) and `SHOAL_BIND` (default
`0.0.0.0:7420`). Put TLS in front with your reverse proxy of choice.

## API

| Endpoint | Purpose |
|----------|---------|
| `POST /v1/ops` | Push a batch of encrypted ops (idempotent by `op_id`) |
| `GET /v1/ops?since=N` | Pull ops past a cursor, optional `collection` filter |
| `GET /v1/poke` | SSE stream, emits when new ops arrive for the caller |
| `GET /healthz` | Liveness |

All endpoints except `/healthz` require ed25519 request signatures. See
[PROTOCOL.md](PROTOCOL.md#authentication).

## Status

Server core is working with integration tests. Client SDKs (Kotlin for tuna,
TypeScript for the web apps) are in progress.

## License

MIT
