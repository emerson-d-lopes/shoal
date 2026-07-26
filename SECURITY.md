# Security

## Reporting a vulnerability

Report privately through
[GitHub security advisories](https://github.com/emerson-d-lopes/shoal/security/advisories/new).
Please do not open a public issue for a vulnerability.

This is a personal project with no on-call rotation. Expect a first response
within about a week.

## Scope

In scope:

- Anything letting one user read, write, or delete another user's ops.
- Signature verification bypasses on authenticated endpoints.
- Weaknesses in the key derivation or the AEAD construction described in
  [PROTOCOL.md](PROTOCOL.md).
- Remote crashes, unbounded memory or disk growth, and other denial of service
  reachable by an authenticated user within the documented rate limits.

Out of scope, because they are documented and deliberate:

- Metadata the server stores in the clear. `collection`, `record_id`, `hlc`,
  and op sizes are all visible to an operator. See
  [What the server can see](PROTOCOL.md#what-the-server-can-see).
- Replay of an identical request inside the 300 second timestamp window.
  Pushes are idempotent by `op_id` and pulls only return the caller's own data.
- A malicious server withholding or deleting ops. The log has no integrity
  proof spanning ops, which is a stated limitation rather than a defect.
- Absence of key rotation and forward secrecy. Both are non-goals of v1.
- Anything requiring the 12-word mnemonic. It is the whole identity, and
  disclosure means full compromise with no recovery path.

## Deployment expectations

shoal expects a TLS reverse proxy in front of it and is designed to run on a
private network such as a tailnet. The default compose file binds to loopback
for that reason. Running it directly on the public internet is supported but
widens the exposure to anyone who can reach the port.
