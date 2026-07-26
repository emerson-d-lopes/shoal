# shoal

Self-hosted sync server for local-first apps. One small Rust binary stores an
append-only log of end-to-end encrypted operations per user. Clients merge,
the server only stores and orders ciphertext.

Built to sync my own apps ([mnemonic](https://github.com/emerson-d-lopes/mnemonic),
[habit-tracker](https://github.com/emerson-d-lopes/habit-tracker)) across
devices without a cloud account.

## Properties

- **End-to-end encrypted.** Payloads are XChaCha20-Poly1305 ciphertext. The
  server never holds a decryption key. Record contents stay private, while
  metadata such as the app name, record id, and write times does not. See
  [what the server can see](PROTOCOL.md#what-the-server-can-see).
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
docker compose up -d --build
```

Or pull the prebuilt image instead of building:
`ghcr.io/emerson-d-lopes/shoal:latest` (published by CI on every main push).
Or bare: `cargo run --release`.

Configuration is environment variables:

| Variable | Default | Meaning |
|----------|---------|---------|
| `SHOAL_DB` | `shoal.db` | SQLite path |
| `SHOAL_BIND` | `0.0.0.0:7420` | Listen address |
| `SHOAL_RATE_PER_MIN` | `120` | Authenticated requests per user per minute |
| `SHOAL_MAX_OPS_PER_USER` | `1000000` | Stored op cap per user; pushes past it get 507 |

The compose file binds the port to loopback only, so a front door (below) is
required before any device can reach it.

## Deploy with Tailscale (recommended)

Keeps the server completely off the public internet. Your devices reach it
over your tailnet from anywhere, and Tailscale provides a real HTTPS
certificate, which app clients on Android require in release builds.

On the server machine:

```sh
docker compose up -d --build
tailscale serve --bg 7420
```

`tailscale serve` proxies `https://<machine>.<tailnet>.ts.net` to
`127.0.0.1:7420` with a managed certificate. If the command reports that
HTTPS is disabled, enable it once in the Tailscale admin console (DNS →
HTTPS Certificates) and re-run.

On each device: install Tailscale, join the same tailnet, then point the app
at `https://<machine>.<tailnet>.ts.net`. Verify from the device's browser:

```
https://<machine>.<tailnet>.ts.net/healthz   ->   {"status":"ok"}
```

Sync clients tolerate the server being unreachable (ops queue locally), so a
home machine that sleeps or reboots is fine.

## Deploy on the public internet (alternative)

Only if a tailnet does not work for you. Put a TLS reverse proxy in front
and forward the port. With [Caddy](https://caddyserver.com/):

```
sync.example.com {
    reverse_proxy 127.0.0.1:7420
}
```

Caddy obtains certificates automatically. You also need a DNS record (or
dynamic DNS) for the machine and a router forward for 443. Every request
still has to carry a valid ed25519 signature, and payloads are ciphertext,
but unlike the tailnet route the endpoint itself is reachable by anyone.

## Backup

State is one SQLite file. With the compose setup it lives in the
`shoal-data` volume as `/data/shoal.db`. Stop the container for a consistent
copy (clients queue locally in the meantime):

```sh
docker compose stop shoal
docker cp shoal:/data/shoal.db ./shoal-backup.db
docker compose start shoal
```

The log is append-only ciphertext, so backups are safe to store anywhere.
Restoring is copying the file back and restarting the container.

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

Server core is working, with integration tests and CI. The TypeScript client
is usable and has its own test suite. The Kotlin client for Android is in
progress.

## Security

Threat model and what an operator can observe:
[what the server can see](PROTOCOL.md#what-the-server-can-see). To report a
vulnerability, see [SECURITY.md](SECURITY.md).

## Related

[shoal-client](https://github.com/emerson-d-lopes/shoal-client) is the TypeScript client.
Protocol documentation is at [shoal.edfl.dev](https://shoal.edfl.dev).

## License

MIT or Apache-2.0, at your option. See [LICENSE-MIT](LICENSE-MIT) and
[LICENSE-APACHE](LICENSE-APACHE).

