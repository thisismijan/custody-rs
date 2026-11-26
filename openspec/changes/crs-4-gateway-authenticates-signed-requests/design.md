# Design

## Context

The workspace holds one crate, `crates/ci-checks`, which exists only to test the CI entry point
`ci/check.sh`. There is no service code, no database and no container setup. CI runs
`ci/check.sh` on the root workspace: a policy step, `cargo deny` (advisories, licences, sources),
then locked build, format, clippy with warnings as errors, and tests. Any crate added to the
workspace members is built and tested by CI with no workflow change.

What the policy step (`ci/policy.py`) enforces, and how this change meets it:
- No symbolic link anywhere in the workspace (outside `target/` and `.git/`). This change adds
  none.
- No cargo config file (a file named config or config.toml inside a .cargo directory) with any
  key, because the allowlist is empty. This change creates no such file.
- No `Cargo.toml` with a top-level `source`, `patch` or `replace` key. The
  `crates/gateway/Cargo.toml` (new) has only `[package]`, `[dependencies]`, `[dev-dependencies]` and
  `[[bin]]` if needed.
- `deny.toml` must equal the pinned policy. This change does not edit it.
- `Cargo.lock` must exist and match the manifests, because every cargo step runs with
  `--locked`. The implementer regenerates and commits `Cargo.lock` with the new crate.
The policy step does not constrain dependency versions, features or workspace layout. Those are
checked by `cargo deny` (advisories, licences, crates.io-only sources) against `deny.toml`.

Requirements are in this change's gateway-auth spec; motivation is in proposal.md. The rules come
from `docs/threat-model.md` section 3.1 (signature verification rules) and section 3.2 (bootstrap
operator key).

## Goals / Non-Goals

**Goals:**
- One authentication layer that every gateway API route sits behind, so a later route cannot be
  added without it by accident (it is added to the router that holds all `/v1` routes).
- Cheap checks before the signature check: header parsing, key lookup and the `created` window
  run before digest and signature work (threat model 3.1, D row).
- Stores behind a narrow interface, so CRS-19 adds a Postgres implementation without touching the
  verifier.

**Non-Goals:**
- Scope or step-up enforcement: `/v1/whoami` is available to any registered key. The caller's
  scopes are reported, not checked (CRS-5, M1).
- Tests for the request-size limit: the layer buffers at most 1 MiB (D2 step 5) and answers 413
  past it, but CRS-20 owns the tests for that limit and may change its value.
- Algorithm choice per key: every key is Ed25519 in this change. CRS-20 tests that a request's
  `alg` parameter cannot change it.
- A container image, compose file or Docker secret wiring: there is no image yet. The binary reads
  the key from a file path whose default is where Docker mounts a secret named
  `bootstrap_operator_public_key`.
- Logging beyond the startup line and startup errors. Structured, allow-listed logging belongs to
  #9 to #14 (threat model 3.1, I row).

## Decisions

### D1 Stack and dependencies
- New crate `crates/gateway` (`publish = false`, edition 2024) with a library (`src/lib.rs`) and a
  binary target named `gateway` (`src/main.rs`). It is added to the root `members`. Every
  dependency version is the latest stable release at implementation time, recorded in
  `Cargo.lock`.
- Runtime dependencies: `tokio` (multi-thread runtime, net, macros), `axum` (HTTP server and
  router), `ed25519-dalek` with the `pkcs8` and `pem` features (verification and PEM public-key
  parsing), `sha2` (SHA-256), `base64`, `sfv` (RFC 8941 structured field parsing and
  serialisation for `Signature-Input`, `Signature` and `Content-Digest`), `serde` and
  `serde_json`.
- Dev dependencies: `tower` (to send requests to the router in-process), `http-body-util` (to
  read response bodies), and `ed25519-dalek` signing (already the same crate).
- All of these are crates.io crates under licences `deny.toml` already allows. If `cargo deny`
  refuses one (advisory, licence or source), the implementer stops and reports it; `deny.toml` is
  never loosened in this change.

### D2 Verification pipeline (in order)
The authentication layer runs these steps for every request and returns 401 on the first
failure. The handler runs only after step 9 succeeds.
1. Read exactly one `Signature-Input` and one `Signature` header. Each must parse as an RFC 8941
   dictionary with exactly one member, and the two must share that member's label.
2. The `Signature-Input` member's inner list must be exactly `("@method" "@authority" "@path"
   "@query" "content-digest")`, in that order, and its parameters must include `created`
   (integer), `nonce` (string) and `keyid` (string). Optional `expires` (integer) and `alg`
   (string) are accepted. Any other parameter is rejected. Requiring the fixed list is what makes
   the server, not the signer, choose the covered components. CRS-20 owns the tests that prove
   a missing component is rejected.
3. Check the authority (step 6 rule) and look up `keyid` in the key store. Unknown key → 401.
4. Check time against the clock: reject when `created < now - 60`, `created > now + 5`, or
   `expires` is present and `expires <= now`.
5. Buffer the body with an explicit limit of 1 MiB (`axum::body::to_bytes` with that limit; no
   extractor default is relied on). A larger body gets 413 and is not read further. Exactly one
   `Content-Digest` field line must be present; zero or several → 401. That one line is both the
   value checked here and the value placed in the base in step 6. Parse `Content-Digest` as an RFC 8941 dictionary. Its `sha-256` member must be
   a byte sequence equal to SHA-256 of the received bytes. A missing header, a missing `sha-256`
   member or a mismatch → 401. Other digest members are ignored. A GET carries the digest of the
   empty body.
6. Build the RFC 9421 signature base (section 2.5) from the received request:
   - `"@method": <method>`
   - `"@authority": <Host header, or URI authority if no Host header, ASCII-lowercased>` (missing
     → 401). The port is kept exactly as received: no default port is added or removed, so
     `localhost:80` and `localhost` are different authorities. Before verification the value must
     equal the gateway's configured authority (D6, `GATEWAY_AUTHORITY`, also ASCII-lowercased,
     port as written); otherwise 401. Clients sign the authority exactly as they send it in Host.
     This stops a request signed for one deployment from being accepted by another that holds
     the same key.
   - `"@path": <the full path as received>`, taken from axum's `OriginalUri` extension when it is
     present (it is set before any `Router::nest` strips a prefix), else the request URI path.
     Nesting never changes the path that is verified.
   - `"@query": ?<raw query>` (`?` alone when there is no query)
   - `"content-digest": <Content-Digest header value as received>`
   - `"@signature-params": <the inner list and its parameters, serialised by the RFC 8941
     serialiser>`
   Lines are joined with `\n`, with no trailing newline.
7. Decode the `Signature` member as a 64-byte byte sequence and verify it over the base with the
   key's Ed25519 public key using strict verification. A failure → 401.
8. Ask the nonce store to record `(keyid, nonce)` with `created`. If it was already recorded → 401.
   This step runs only after step 7, so an unauthenticated request never uses up a nonce.
9. Put the caller identity (`client_id`, `key_id`, `scopes`) into the request extensions and run
   the handler.

Every 401 has the same body, `{"error":"unauthorized"}`, with `content-type: application/json`.

### D3 Stores (operator decision, 2026-11-26, option C)
- `trait KeyStore { async fn get(&self, key_id: &str) -> Option<RegisteredKey>; }` where
  `RegisteredKey { key_id, client_id, scopes: Vec<String>, public_key: VerifyingKey }`.
- `trait NonceStore { async fn record_if_new(&self, key_id: &str, nonce: &str, created: u64, now: u64) -> bool; }`.
  It returns `false` when `(key_id, nonce)` is already held.
- The traits use native `async fn` so the CRS-19 Postgres implementation fits. The router state is
  generic over both traits, which also avoids trait objects.
- `InMemoryKeyStore` is a map from key id to `RegisteredKey`, built once at startup and never
  written to afterwards in this change.
- `InMemoryNonceStore` holds a `HashMap<(String, String), u64>` (pair → created) and a `VecDeque`
  of pairs in insertion order, both behind one `std::sync::Mutex`. Check and insert happen under
  that lock, so two concurrent identical requests yield exactly one acceptance. It also exposes
  `prune(now)`, which pops entries from the front while `created + 65 <= now`, and
  `contains(key_id, nonce)`. `record_if_new` calls `prune(now)` first. Retention is 65 seconds
  (60 max age plus 5 skew), so a pruned nonce can never belong to a request that would still pass
  the window. Pruning walks only expired entries. Requests that arrive out of `created` order can
  keep an entry for at most 5 seconds longer, which is harmless.

### D4 Clock
`trait Clock: Send + Sync { fn now(&self) -> u64; }` returns Unix seconds. `SystemClock` is used
in the binary. Tests use a clock they set by hand, so time-window scenarios never sleep.

### D5 Router and seams in the library
- The router state is one named type:
  ```rust
  pub struct GatewayConfig { pub authority: String }   // the configured authority (D6)
  #[derive(Clone)]
  pub struct GatewayState<K: KeyStore, N: NonceStore, C: Clock> {
      pub config: Arc<GatewayConfig>,
      pub keys: Arc<K>,
      pub nonces: Arc<N>,
      pub clock: Arc<C>,
  }
  pub struct Caller { pub client_id: String, pub key_id: String, pub scopes: Vec<String> } // request extension
  ```
  The binary builds `GatewayState<InMemoryKeyStore, InMemoryNonceStore, SystemClock>`. Tests
  build the same type with a hand-set clock, and keep an `Arc` to the nonce store so they can
  inspect it.
- `pub fn app<K, N, C>(state: GatewayState<K, N, C>) -> Router` builds `/v1/whoami` behind the
  authentication layer.
- `pub fn authenticated<K, N, C>(router: Router, state: GatewayState<K, N, C>) -> Router` applies the same layer to any router. `app` uses
  it. Tests use it to wrap a probe route that counts its invocations and echoes its body, which is
  how "the handler does not run" is observed.
- `GET /v1/whoami` returns 200 with `{"client_id": ..., "key_id": ..., "scopes": [...]}`.

### D6 Startup (binary)
- `GATEWAY_BOOTSTRAP_KEY_FILE`: the path of a PEM SubjectPublicKeyInfo Ed25519 public key (the
  output of `openssl pkey -pubout`). Default `/run/secrets/bootstrap_operator_public_key`. The key
  is registered as `key_id` `bootstrap`, `client_id` `bootstrap`, `scopes` `["bootstrap"]`. CRS-19
  gives that scope its meaning.
- `GATEWAY_LISTEN_ADDR`: socket address, default `127.0.0.1:8080`. Port `0` binds a free port.
- `GATEWAY_AUTHORITY`: the authority (host and optional port) clients sign for, default
  `localhost:8080`. The library takes it as part of its configuration, so in-process tests set it.
- After binding, the binary prints exactly one line to stdout, `gateway listening on <bound
  address>`. Tests read the port from it.
- If the key file is missing, unreadable or not a valid Ed25519 PEM public key, the binary writes
  `gateway: cannot load bootstrap key from <path>: <reason>` to stderr and exits with code 1. It
  never prints the file's contents. There is no option to pass key material in an environment
  variable or argument.

### D7 Test seams (operator-approved option S2, 2026-11-26)
All tests are integration tests in `crates/gateway/tests/` (new), with a shared helper module
`tests/common/mod.rs`. The helper holds a fixed-seed Ed25519 test signing key and a second
unregistered one, a function that builds a correctly signed `http::Request` (Content-Digest,
`Signature-Input`, `Signature`, chosen `created`, `nonce`, optional `expires`), and a hand-set
clock.
- **Seam 1, in-process router** (`tower::ServiceExt::oneshot` on `app(...)` or on
  `authenticated(probe_router, ...)`): covers every scenario in the first five requirements of
  the spec. The pruning scenarios use the `InMemoryNonceStore` public API (`record_if_new`,
  `prune`, `contains`) directly. It catches the verification rules, the order of checks, the
  status codes, identical 401 bodies, nonce recording only after verification, and pruning. It
  misses startup configuration and HTTP as it arrives over a real socket.
- **Seam 2, real process over TCP**: starts the built binary (`env!("CARGO_BIN_EXE_gateway")`)
  with `GATEWAY_LISTEN_ADDR=127.0.0.1:0` and `GATEWAY_BOOTSTRAP_KEY_FILE` pointing at a file in a
  temporary directory. It reads the bound port from stdout and sends one signed HTTP/1.1 request
  over a plain `std::net::TcpStream`, with no HTTP client dependency. It covers the three startup
  scenarios, setting `GATEWAY_AUTHORITY` to the `127.0.0.1:<port>` it sends as Host. It catches key-file loading, startup refusal, and the real `Host` header feeding
  `@authority`. It misses the Docker secret mount inside a container, because there is no image
  yet.
- Why this is the smallest complete proof: seam 1 is the highest stable in-process seam, the
  public router, and proves every verification rule deterministically. Seam 2 adds the only
  behaviour seam 1 cannot reach, which is process startup from a key file. Nothing needs a fake
  beyond the clock.

## Rejected alternatives

- **Postgres stores now (option B):** pulls the first schema, migrations, roles, database
  credentials and a CI Postgres service into this ticket, beyond its small-context budget. CRS-19
  adds Postgres behind the D3 interface.
- **In-memory stores with no interface (option A):** CRS-19 would have to edit the verifier to
  change stores.
- **In-process tests only (seam option S1):** cannot prove the bootstrap key is loaded from a
  file or that startup fails without it, and that is a ticket security control.
- **A general RFC 9421 crate:** it would let the signer choose components and algorithms, which the
  threat model forbids, and it adds a large surface. The fixed-list base in D2 is small and fully
  specified.
- **Trusting the request's `alg` parameter:** the threat model forbids it. The key's own algorithm
  (Ed25519) is always used.
- **Recording the nonce before signature verification:** lets unauthenticated requests use up
  nonces (threat model 3.1).
- **Accepting any set or order of covered components:** the server must enforce a fixed policy
  (threat model 3.1).
- **Passing the bootstrap key in an environment variable or baking it into the image:** forbidden
  by the ticket's security controls and threat model 3.3.
- **API key with HMAC, mTLS-only, OAuth2 with DPoP (grooming options A, C, D, H2, H3):** H1 was
  chosen at grooming (public keys only, no shared secrets).

## Risks / Trade-offs

- [Replay protection is per instance and lost on restart until CRS-19] → Documented in
  proposal.md Impact. No multi-instance gateway runs before CRS-19, and the 60-second window
  bounds the exposure.
- [A dependency is refused by `cargo deny` (for example a new unmaintained advisory)] → The
  implementer stops and reports it; the policy is never loosened here.
- [Clock skew between client and server beyond 5 seconds causes 401s] → The allowance is fixed
  and documented here, and clients are expected to keep their clocks in sync.
- [The 1 MiB body limit is untested until CRS-20] → CRS-20 tests it and may change the value.
- [A misconfigured `GATEWAY_AUTHORITY` makes every request fail with 401] → Fails closed. The
  value is documented in D6, and the real-process test sets it.

## Migration Plan

Additive. A new crate with no existing callers. Rolling back means reverting the merge commit.
