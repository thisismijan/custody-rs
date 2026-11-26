# Proposal

## Why

Every later client and operator call (key registration in CRS-19 and CRS-3, accounts in CRS-5,
withdrawals in M1) must be provably from a registered key, and unsigned, tampered, replayed or
stale requests must never run (threat model `docs/threat-model.md`, section 3.1, threats S and T).
The repository has no service code yet, so the gateway and its request authentication come first.

## What Changes

- A new REST gateway service (one Rust crate with a library and a binary) is added to the
  workspace.
- Every request to the gateway's API must carry an RFC 9421 HTTP Message Signature over the
  method, authority, path, query and an RFC 9530 Content-Digest of the body, with `created`,
  `nonce` and `keyid` parameters. The gateway recomputes the digest from the received body,
  checks the `created` time against a fixed window, verifies the signature with the key's
  registered public key, and records the nonce only after the signature verifies, so a request
  is accepted at most once.
- The authority a request was signed for must be the gateway's configured authority, and the
  verified path is always the full received path.
- Any request that fails these checks gets 401 and the handler it targeted never runs.
- `GET /v1/whoami` returns the caller's client id, key id and key scopes.
- At startup the gateway loads one bootstrap operator public key from a file (the path where a
  Docker secret is mounted). It refuses to start when that file is missing or invalid. The key is
  never read from an environment variable or built into the binary.
- Registered keys and used nonces are held in memory behind a narrow store interface; CRS-19 adds
  the Postgres implementation (operator decision, 2026-11-26, option C).

## Capabilities

### New Capabilities

- `gateway-auth`: how the gateway authenticates every API request by its HTTP message signature,
  rejects tampered, unknown-key, replayed and stale requests, and reports the caller's identity.

### Modified Capabilities

None.

## Impact

- New crate `crates/gateway/Cargo.toml` (new), with `crates/gateway/src/lib.rs` (new),
  `crates/gateway/src/main.rs` (new, binary `gateway`) and integration tests under
  `crates/gateway/tests/` (new). It is added to the root workspace members in `Cargo.toml`, and
  `Cargo.lock` is regenerated.
- New dependencies (crates.io only, permissive licences, checked by the existing CI policy):
  an async HTTP server stack, Ed25519 signature verification with PEM public-key parsing, SHA-256,
  and base64. See design.md D1.
- New configuration read by the binary: `GATEWAY_LISTEN_ADDR` (listen address),
  `GATEWAY_BOOTSTRAP_KEY_FILE` (path of the bootstrap public key file; its default is
  the Docker secret mount path given in design.md D6), and `GATEWAY_AUTHORITY` (the authority clients
  sign for). None of them holds key material.
- Known limit until CRS-19: replay protection is per gateway instance and is lost on restart, so
  within the 60-second `created` window a captured request could be accepted once more by a second
  instance or just after a restart. No multi-instance gateway runs before CRS-19.
- Out of scope: scope and step-up enforcement (CRS-5, M1); key registration and revocation
  (CRS-19, CRS-3); explicit tests for missing covered components, wrong algorithm and oversized
  bodies (CRS-20). This change already buffers at most 1 MiB before verification and answers 413
  past it, so an unauthenticated caller cannot make it buffer an unbounded body, but CRS-20 owns
  the tests and the final value; mTLS; a container image or compose file (the first ticket that
  ships an image adds it, pinned by digest per threat model 3.8).
