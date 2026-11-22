# custody-rs threat model

Status: agreed with the maintainer, section by section (November 2026); revised after an
independent review.
Tracks issue #7.

## 1. Purpose and method

custody-rs is a crypto custodian, so most failures are security failures: funds moved by
someone who should not move them, balances that claim more than the chain holds, or actions
nobody can later attribute. This document names what we protect, where the trust boundaries
are, what can go wrong at each boundary, and which control answers each threat.

It is written **before any service code exists**, so every later control can point back to a
named threat, and every threat has either a control or an explicit, reasoned acceptance.

**Method: STRIDE per trust boundary.** A trust boundary is any place where data or control
crosses between parties that trust each other differently (for example a client and our
gateway, or a service and the database). At each boundary we walk the six STRIDE categories:

| Letter | Category | The question it asks |
|---|---|---|
| S | Spoofing | Can someone pretend to be a party they are not? |
| T | Tampering | Can data be changed in transit or at rest without detection? |
| R | Repudiation | Can a party deny an action and leave us unable to prove it? |
| I | Information disclosure | Can data reach someone who should not see it? |
| D | Denial of service | Can someone stop legitimate use? |
| E | Elevation of privilege | Can someone gain abilities they were not granted? |

**How to read the boundary tables.** Each row is one threat in one STRIDE category: the threat,
the control, where the control is delivered (an issue or milestone), and its status:

- **planned**: a control we will build, in the named issue or milestone;
- **designed only**: specified here and in the design record, deliberately not built in this
  project (for example production-only controls);
- **accepted risk**: we knowingly do not control it, with the reason stated;
- **deferred**: a control we intend to build later than the milestone that first exposes the threat.

Issue references: #1 is milestone M0 (foundations), #2 M1 (Bitcoin), #3 M2 (Ethereum),
#4 M3 (show it), #5 M4 (threshold signing), #6 M5+ (bonus); #8 to #14 are M0 issues.

Correctness invariants referenced here (I1 to I5) are defined in the project's design record:
I1 deposit uniqueness, I2 withdrawal uniqueness, I3 never over-state available funds,
I4 traceability, I5 reconciliation with the chain (if the ledger ever shows more than the
chain holds, withdrawals for that asset freeze).

## 2. Assets

| # | Asset | What it is | Protected at (boundary) | Worst-case impact if compromised |
|---|---|---|---|---|
| A1 | Signing keys | HD master seeds and derived private keys; also their public keys (xpubs), which are not secret but whose integrity matters | signer to mock HSM (keys never leave it); signer to signer from M4 | Theft: every hot-wallet fund moved by an attacker. Loss: funds unspendable. Swapped xpub: new deposits land on attacker addresses |
| A2 | Journal | The double-entry, append-only ledger and its cached balances | services to Postgres | Over-stated balances, so the system pays out funds it does not hold (breaks I3); edits could hide a theft |
| A3 | Audit trail | Append-only records of who or what caused every change | services to Postgres | Actions become deniable and investigations impossible (breaks I4) |
| A4 | Client API public keys | Ordinary and step-up keys, with their scopes | operator CLI to services (registration); services to Postgres | A substituted key lets an attacker act as the client; a substituted step-up key lets them move money |
| A5 | Withdrawal destination whitelists | The per-client set of allowed withdrawal addresses | client to gateway (whitelist-admin scope plus step-up key); services to Postgres | An attacker adds their own address and legitimate-looking withdrawals pay them |
| A6 | Outbox and event stream | Committed domain events and their delivery through JetStream | services to Postgres; services to NATS | A forged event triggers actions; a dropped event delays processing (idempotency and redelivery are meant to prevent loss) |
| A7 | Source, dependencies, build artefacts | The repository, third-party crates, CI and built containers | supply chain | Malicious code runs inside every service, including the signer |
| A8 | Service event-signing keys | Each service's private key for signing the events it publishes, and the public keys consumers verify against | services to NATS; secrets delivered as Docker secrets | A stolen key lets an attacker forge that service's events (for example a deposit confirmation, which would credit funds that never arrived) |

Public data is still an asset when its integrity matters: xpubs (A1) and client public keys (A4)
are not secret, but a swapped one is as damaging as a stolen private key.

## 3. Trust boundaries

Boundaries covered: client to gateway; operator CLI to services; services to Postgres;
services to NATS; signer to mock HSM; services to chain nodes; signer to signer (M4);
supply chain.

### 3.1 Client to gateway

Institutional clients' systems call the REST gateway over the network. Clients authenticate
with RFC 9421 HTTP Message Signatures from registered public keys; the server stores only public
keys. Each client has an **ordinary key** for everyday integration (read balances, open
accounts) and a separate **step-up key**, kept more tightly by the client (ideally in its own
HSM), that is required for money-moving and whitelist-changing requests. Every key carries
**scopes** that limit which endpoints it may call.

**Signature verification rules.** RFC 9421 lets the signer choose which parts of a request it
signs, so the server enforces a fixed policy rather than trusting the signer's choice:

- every request must cover `@method`, `@authority`, `@path`, `@query` and `content-digest`, and
  carry `created`, `nonce` and `keyid` parameters; a request covering less is rejected;
- the server recomputes the body digest itself (RFC 9530 Content-Digest) and rejects a mismatch;
- the signature algorithm is fixed per registered key; the request's `alg` parameter is never
  trusted to choose it;
- `created` must fall inside a window around server time, with a stated clock-skew allowance;
  values in the future beyond that allowance are rejected;
- a nonce is recorded only **after** the signature verifies, so unauthenticated requests
  cannot use up nonces.

| | Threat | Control | Delivered in | Status |
|---|---|---|---|---|
| S | An attacker impersonates a client, or replays a captured request | Signature from a registered public key under the verification rules above; unknown key returns 401; the `created` window plus a single-use nonce reject replayed and stale requests with 401 | #10 | planned |
| T | A request is changed in transit (amount, destination, path, query) | The required covered components include method, authority, path, query and the recomputed Content-Digest of the body, so any change fails verification | #10 | planned |
| R | A client denies sending a request | Only the client holds its private key, so a valid signature is evidence the server could not have forged. For every state-changing request, the audit record stores the signature evidence (signature input, signature, key id). This evidence is only as strong as key registration, which is dual-controlled (see 3.2) | #11 (account opening), M1 #2 (withdrawals, whitelist changes) | planned |
| I | One client reads another's accounts | Per-client authorisation: requests for another client's accounts return 403 | #11 | planned |
| I | An idempotency key collision returns another client's stored response | Idempotency keys are scoped to (client, key); the same key with a different request body returns 409 | #11 | planned |
| I | Service logs leak secrets or request contents | Logs never contain secrets, signatures or full request bodies (the audit trail, not logs, holds signature evidence); structured logging with an allow-list of fields, in every service | #9 to #14 | planned |
| I | Traffic is read on the network | Signatures give integrity, not confidentiality. The demo runs on localhost over plain HTTP; production requires TLS, normally terminated at a load balancer or proxy in front of the gateway | - | designed only |
| D | Garbage requests force expensive signature checks; the replay table grows without bound | Cheap checks run before signature verification (key exists, time window, body size limit); the nonce table is pruned by age, so its size is bounded by request rate times the window | #10 | planned |
| D | Request floods exhaust the gateway | Per-key and per-IP rate limiting | M5+ #6 | deferred |
| E | An ordinary (integration) key moves money or edits the whitelist | Scopes on every key (#11); the step-up key is required for `withdraw` and `whitelist-admin` (M1). A stolen ordinary key can only read and open accounts | #11, M1 #2 | planned |

### 3.2 Operator CLI to services

Custodian operators use `custodyctl` admin commands to register clients and their keys and to
read the audit trail. Whoever can register a client's step-up key can move that client's money,
so this boundary carries insider risk as well as outside attack.

In the demo, `custodyctl` calls an **admin API on the gateway**, signed exactly like client
requests (RFC 9421, same verification rules as 3.1) with operator keys that carry `operator`
scopes. A **bootstrap operator key** is supplied at deployment; its only use is to register the
first two operators, after which it is revoked. In production, admin traffic would move to a
**separate admin service on its own listener**, reachable only from an internal network.

**Dual control** means a change takes effect only after a second, different operator approves
it; the same operator cannot both request and approve.

| | Threat | Control | Delivered in | Status |
|---|---|---|---|---|
| S | Someone impersonates an operator | RFC 9421 signature from a registered operator key with `operator` scopes, under the 3.1 verification rules | #9 (admin API), #10 (verification) | planned |
| S | The bootstrap key is reused after setup | The bootstrap key can only register the first two operators and is revoked once they exist; any later use is rejected | #9 | planned |
| S | The bootstrap key holder chooses both initial operators alone, so dual control starts from one person | Registering the first two operators is a trusted setup step, performed once at deployment and recorded in the audit trail | - | accepted risk |
| T | An admin command is changed in transit | The required covered components and recomputed Content-Digest (3.1) | #9, #10 | planned |
| R | An operator denies registering or changing a key | The audit record names the operator, the action and the request, and stores the signature evidence | #9 | planned |
| I | Operator tooling exposes client data | Operator commands require explicit operator scopes; audit listings show metadata, and the server holds no client secrets | #9, #12 | planned |
| D | The admin interface is flooded | Operators are a small, known group and admin endpoints are not offered to client keys | - | accepted risk |
| E | One rogue or compromised operator registers an attacker's key for a client | Dual control: registering or replacing a client's step-up key, and changing the scopes of any client key, needs approval from a second, different operator before it takes effect | M0 #1 (new issue) | planned |
| E | One operator creates a second operator identity they control, defeating dual control | Registering an operator key or changing an operator's scopes is itself dual-controlled | M0 #1 (new issue) | planned |
| D | One operator revokes the other's key, leaving nobody to approve changes | Disabling or revoking an operator key is also dual-controlled | M0 #1 (new issue) | planned |
| E | Admin and client traffic share one listener, so a gateway flaw exposes admin functions | Separate admin service on an internal-only listener | - | designed only |

### 3.3 Services to Postgres

Postgres holds the journal, audit trail, outbox, key registry, whitelists and leases: the system's
source of truth. **Each service owns its data**: one Postgres instance, one schema per service,
each reachable only by that service's role. A service that needs another service's data gets it
over messaging (request/reply, or a local copy kept up to date from the owner's events), never
by reading the other schema. Migrations run under a separate migration role.

| | Threat | Control | Delivered in | Status |
|---|---|---|---|---|
| S | A process connects as a service, or leaked database credentials are used | One database role per service with least privilege; credentials delivered as Docker secrets mounted as files, never environment variables, so they stay out of `docker inspect`, process listings and logs | #9 to #14 | planned |
| S | Secrets handling in production | A secrets manager (for example Vault) issues and rotates credentials | - | designed only |
| T | Journal or audit rows are edited or deleted by the application | Application roles have no UPDATE or DELETE on journal or audit tables; the journal's sum-to-zero rule is checked in the same transaction as each posting | #11 (journal), #12 (audit) | planned |
| T | A database superuser edits or deletes journal or audit rows | Per-stream hash chains (each entry carries the hash of the previous entry in its account's journal stream or its subject's audit stream) whose chain heads are periodically signed or anchored outside the database. Without an outside anchor a superuser can recompute every later hash, so an unanchored chain only detects partial or application-level tampering | - | designed only |
| R | A change appears with no attributable cause | Every write carries its actor and cause (request id or chain event) into the audit record (I4) | #9, #11, #12 | planned |
| I | A database dump leaks data | The database holds no private keys or client secrets (public keys only; signing keys stay in the HSM), so a dump exposes balances and identities but cannot move funds | #9 to #14 | planned |
| I | Database traffic is read on the network | Localhost in the demo; TLS between services and Postgres in production | - | designed only |
| D | Connection exhaustion, runaway queries, lock contention on the shared hot-wallet account | Bounded connection pools, statement timeouts, and a contention design for the hot-wallet account | #11, M1 #2 | planned |
| D | Postgres is unavailable | Single instance; Postgres HA is out of scope | - | accepted risk |
| E | SQL injection; an application role gains schema or superuser powers | Parameterised queries only; application roles are never superuser and never own their schema; migrations use a separate role | #9 to #14 | planned |

### 3.4 Services to NATS

JetStream carries committed domain events from the outbox relay to consuming services, on a
3-node cluster. Postgres is the source of truth; NATS is a durable copy of what still needs
delivering. Consumers act on events, so a forged event could make them act wrongly; that is
why events are both permissioned at the broker and signed by their producer. If a forged event
(for example a fake deposit confirmation) were ever acted on, reconciliation (I5) would find
the ledger above the chain and freeze withdrawals: a detective backstop behind these
preventive controls.

| | Threat | Control | Delivered in | Status |
|---|---|---|---|---|
| S | A rogue process connects and publishes or subscribes as a service | One NATS user per service (nkey identities delivered as Docker secrets) with subject-level publish and subscribe permissions | #13, #14 | planned |
| T | An event is altered or injected at the broker or on the network | Each producing service signs its events (Ed25519) with its own key (A8); consumers verify the signature against the producer's public key before acting, and reject unsigned or wrongly signed events | #13 | planned |
| T | A validly signed event is replayed, or republished on a different subject | The signature covers the subject, the event type and the outbox id; consumers reject a subject mismatch and deduplicate on (producer, outbox id) | #13 | planned |
| R | Nobody can tell which service published an event | Each event carries its producing service and its outbox row id, and the producer's signature proves its origin | #13 | planned |
| I | Any NATS client reads every event | Subject-level subscribe permissions; events carry no secrets | #13 | planned |
| I | Event traffic is read on the network | TLS between services and NATS in production | - | designed only |
| D | Floods, unbounded streams, slow consumers accumulating unacknowledged messages | JetStream limits (maximum messages and bytes per stream, retention, maximum unacknowledged messages per consumer); streams are replicated on all three nodes (replication factor 3), so the cluster survives the loss of one node | #13, #14 | planned |
| E | A service publishes on another service's subjects (for example a fake deposit confirmation) | Subject-level publish permissions, plus the producer signature check: a consumer acts only on events signed by the service that owns the subject | #13 | planned |

### 3.5 Signer to mock HSM

The signer asks the mock blockchain-native HSM to derive keys and sign. Keys and derivation never
leave the HSM. The mock is a separate process; the security claim is about this trust boundary,
not about hardware, which a production HSM would add.

| | Threat | Control | Delivered in | Status |
|---|---|---|---|---|
| S | A rogue process asks the HSM to sign | The signer authenticates to the HSM with its own key over a mutually authenticated channel, and the HSM sits on a private Docker network only the signer joins | M1 #2 | planned |
| T | The signer hands the HSM an opaque digest that matches no real transaction (blind signing) | The HSM receives the full unsigned transaction and computes the signing digest itself, so it never signs a digest it cannot explain and its operation log records what was actually signed. This does not prove the transaction was approved; the HSM has no notion of approval before M5+ | M1 #2 | planned |
| T | A compromised signer gets the HSM to sign a payment the client never approved | The HSM enforces destination whitelist and amount limits itself, verifying the client's own step-up signatures on whitelist changes and withdrawals, so authorisation runs end to end from client key to HSM | M5+ #6 | deferred |
| T | A swapped xpub makes new deposit addresses pay an attacker | The xpub is read from the HSM at the key ceremony and stored with its fingerprint. Before a deposit address is issued, the deposit service asks the signer, which asks the HSM, to re-derive it and confirm it belongs to the HSM's key; issuance fails closed, so no address is issued without that confirmation | M1 #2 | planned |
| T | A mainnet key or address is used, breaking the "never mainnet" rule | Network pinning: the HSM and the address code refuse mainnet chain ids, mainnet address prefixes and mainnet xpub version bytes | M1 #2 (Bitcoin), M2 #3 (Ethereum chain id) | planned |
| R | A signature cannot be traced to the request that caused it | Append-only HSM operation log (key path, digest, requester, time), linked to the withdrawal's audit record | M1 #2 | planned |
| I | Private keys are extracted through the API | The HSM API has no export operation; keys exist only inside the HSM process and its encrypted-at-rest store, whose wrapping key is delivered as a Docker secret | M1 #2 | planned |
| I | A host root user dumps the mock HSM's memory | Real HSM hardware prevents this; the mock cannot | - | designed only |
| D | The HSM or signer is unavailable | Withdrawals queue and resume when it returns; deposits are unaffected (the signer is the documented single-instance exception until M4) | - | accepted risk |
| D | HSM key material is lost, making funds unspendable | Key backup and recovery | M5+ #6 | deferred |
| E | The signer gains capabilities beyond signing (export, raw key generation, arbitrary derivation) | The HSM offers the signer only "derive public key" and "sign", restricted to a configured derivation subtree. Master keys are generated inside the HSM by an operator key ceremony that needs approval from two different operators, and is audited | M1 #2 | planned |

### 3.6 Services to chain nodes

Chain watchers read blocks from Bitcoin and Ethereum nodes; withdrawals are broadcast through
them. What a node reports decides what is credited, so a lying node threatens I1 and I3.

| | Threat | Control | Delivered in | Status |
|---|---|---|---|---|
| S | The watcher talks to something impersonating our node's RPC endpoint | We run our own node per chain and the watcher authenticates to its RPC | M1 #2, M2 #3 | planned |
| S | Our node is eclipsed on the peer-to-peer network (isolated and fed a false view of the chain) | Several independent nodes per chain, with watchers comparing tips and block hashes and pausing credits on disagreement | - | designed only |
| T | A node reports a deposit that is not really in the chain, or a reorganisation removes a credited deposit | Credit only at confirmation depth N (I3); block hash and height stored with each credit (I1); reconciliation at tip minus N freezes withdrawals when the ledger shows more than the chain (I5). The response to a reorganisation deeper than N is decided in M1 design | M1 #2, M2 #3 | planned |
| T | A lying node or a compromised withdrawal processor sets an excessive fee, draining funds as fees | A maximum fee and fee rate per withdrawal, enforced by the withdrawal processor and re-checked by the signer before it requests a signature. For Bitcoin the fee is the input total minus the output total, so the signer's re-check is only as good as the input amounts it is given | M1 #2, M2 #3 | planned |
| R | Nobody can show which chain data caused a credit | Every credit and debit records its block hash, height and transaction reference | M1 #2, M2 #3 | planned |
| I | A third party learns which addresses we watch | Own nodes only; watched addresses are never sent to an external provider | M1 #2, M2 #3 | planned |
| D | A node is down, slow or stuck | Watching stalls and credits are delayed (safe: the system under-states); withdrawals queue; a stalled chain tip raises an alert | M1 #2, M2 #3 | planned |
| E | The node's RPC can move funds (for example the bitcoind wallet) | Bitcoin Core: node wallet disabled and the RPC user restricted by `rpcwhitelist` to read and broadcast methods. Ethereum: the node exposes only the API namespaces the watcher needs (Geth restricts by namespace, not per method). No custody key material ever sits in a node | M1 #2, M2 #3 | planned |
| E | The local anvil node ships unlocked development accounts that `eth_sendTransaction` can spend | custody-rs never uses those accounts for custody funds; custody addresses are derived from HSM keys | - | accepted risk |

### 3.7 Signer to signer (threshold nodes, M4)

From M4, t-of-n signer nodes each hold one key share and run a multi-round signing protocol:
any t nodes can sign together, and fewer than t learn nothing about the key. How the nodes
talk to each other (direct mutually authenticated channels, or the message broker with signed
messages) is an open design point, decided in M4 once research into the chosen protocol
library shows what it expects. The library's audit status is also confirmed in that research.

| | Threat | Control | Delivered in | Status |
|---|---|---|---|---|
| S | A rogue participant joins the protocol | Membership is fixed at the key-generation ceremony; each node authenticates with its own identity key | M4 #5 | planned |
| T | Protocol messages are tampered with or replayed across sessions | Every message is authenticated and bound to its session id and round; the chosen protocol library's own consistency checks reject bad shares | M4 #5 | planned |
| T | Per-signature secret nonces or presignatures are reused after a crash or a restore from backup, which can leak a key share | Nonces and presignatures are single-use and marked consumed durably before use; a restored node discards any it cannot prove unused | M4 #5 | planned |
| R | Nobody can tell which node misbehaved | Where the chosen protocol supports identifiable abort (naming the cheating party when a run fails), it is used and logged; confirmed during M4 research | M4 #5 | planned |
| I | A key share leaks | Each node keeps its share in its own HSM-style store; fewer than t shares reveal nothing about the key | M4 #5 | planned |
| D | Some nodes are down or refuse to take part | Signing continues while at least t nodes are available | M4 #5 | planned |
| D | Fewer than t nodes are available | Signing stops and withdrawals queue until enough nodes return | - | accepted risk |
| E | t colluding nodes sign anything | This is the threshold assumption itself. Production places nodes with different operators and tiers (online, offline air-gapped, off-site), per the signer topology design | - | designed only |

### 3.8 Supply chain

The repository, third-party crates, CI and built containers (A7). In practice this is the most
common way crypto projects are compromised.

| | Threat | Control | Delivered in | Status |
|---|---|---|---|---|
| S | A typosquatted or malicious crate, or a compromised maintainer | Dependency source allow-list (crates.io only, no git dependencies), advisory scanning against the RustSec database and a licence policy on every pull request; `Cargo.lock` committed and builds refuse to change it (`--locked`) | #8 | planned |
| T | CI or a third-party GitHub Action is tampered with | Actions pinned to exact commit SHAs, not tags; the CI token is read-only by default; container base images pinned by digest; no workflow triggered by `pull_request_target` or `workflow_run` checks out or runs code from a fork | #8 | planned |
| T | Unreviewed code reaches `main` | Branch protection: changes reach `main` only through a pull request, CI must pass, no force-pushes. With a single maintainer the merge itself is the review | M0 #1 (repository settings) | planned |
| R | Nobody can prove who authored a commit | `main` accepts only signed commits (SSH or GPG), tying every commit to the maintainer's key | M0 #1 (repository settings) | planned |
| I | Secrets leak through the repository or CI logs | GitHub secret scanning with push protection; CI needs no secrets | #8 | planned |
| D | crates.io is unavailable or a crate is yanked | The lockfile pins exact versions; builds wait for the registry | - | accepted risk |
| E | A dependency's build script or procedural macro runs malicious code at build time | Few, reviewed dependencies (each new one is called out in review); no git sources | #8 | planned |
| E | A reviewed dependency still runs malicious code at build time | Residual risk after review and advisory scanning | - | accepted risk |

## 4. Accepted and deferred risks

| Risk | Boundary | Status | Reason |
|---|---|---|---|
| Traffic between client and gateway is readable in the demo | Client to gateway | designed only | Localhost demo; signatures give integrity; production terminates TLS in front of the gateway |
| No rate limiting until M5+ | Client to gateway | deferred | No hostile traffic in the local demo; cheap-checks-first and a bounded replay table limit the cost of garbage requests |
| Admin interface can be flooded | Operator CLI to services | accepted risk | Small, known operator group; admin endpoints refuse client keys |
| The bootstrap key holder chooses both initial operators | Operator CLI to services | accepted risk | Trust has to start somewhere; it is a one-time, audited deployment step, after which the bootstrap key is revoked |
| Admin and client traffic share the gateway listener | Operator CLI to services | designed only | Production moves admin to a separate internal-only service |
| Secrets delivered as Docker secrets, not a secrets manager | Services to Postgres | designed only | Production uses a secrets manager (for example Vault) for issuance and rotation |
| A database superuser can edit or delete journal and audit rows undetected | Services to Postgres | designed only | Detection needs per-stream hash chains with heads anchored outside the database; not built because the demo has no untrusted superuser and a chain serialises writes per stream |
| Database traffic unencrypted | Services to Postgres | designed only | Localhost demo; production uses TLS |
| Postgres unavailable | Services to Postgres | accepted risk | Postgres HA is out of scope; the HA proof covers the application tier |
| Event traffic unencrypted | Services to NATS | designed only | Localhost demo; production uses TLS to NATS |
| A compromised signer can get any transaction signed; the HSM checks no policy | Signer to mock HSM | deferred (M5+) | Policy inside the HSM needs transaction parsing, an RFC 9421 verifier and policy state in the HSM. Until then the services enforce policy and a compromised signer bypasses them; the HSM log and reconciliation (I5) detect afterwards rather than prevent |
| Host root can dump the mock HSM's memory | Signer to mock HSM | designed only | A production HSM's hardware boundary prevents this; the mock is a process |
| Withdrawals pause while the signer or HSM is down | Signer to mock HSM | accepted risk | Single signer until M4; withdrawals queue and resume, deposits are unaffected |
| HSM key material lost, funds unspendable | Signer to mock HSM | deferred (M5+) | Testnet funds only; key backup and recovery are deferred by design |
| One node per chain is the only view of the chain | Services to chain nodes | designed only | A local regtest/anvil demo controls its only node; production cross-checks several independent nodes |
| Anvil's unlocked development accounts can send transactions | Services to chain nodes | accepted risk | Local development node only; custody funds never use those accounts |
| t colluding signer nodes can sign anything | Signer to signer | designed only | Inherent to threshold signing; production spreads nodes across operators and tiers |
| Signing stops when fewer than t signer nodes are available | Signer to signer | accepted risk | Withdrawals queue; this is the availability side of the threshold |
| crates.io outage or a yanked crate blocks builds | Supply chain | accepted risk | Lockfile pins versions; builds wait for the registry |
| A reviewed dependency runs malicious build-time code | Supply chain | accepted risk | Residual after review, source allow-list and advisory scanning |

## 5. Out of scope

This threat model covers custody-rs as built and demonstrated: local, containerised, on
regtest, anvil and testnets. It does not cover:

- **Mainnet and real funds.** The project never handles them (network pinning in 3.5 enforces this).
- **Physical security** of machines, data centres and HSM hardware.
- **The host operating system and container runtime.** A compromised host defeats every control
  here, including the mock HSM's boundary.
- **Client-side key management.** How clients protect their own private keys (ideally in their
  own HSM) is their responsibility; this model covers what custody-rs does with their signatures.
- **Social engineering of operators,** beyond the dual-control controls that limit what one
  deceived operator can do.
- **Cold storage and offline signing ceremonies,** which are part of the production signer
  topology design, not of this build.

## 6. What this threat model adds to the plan

Several controls above go beyond the acceptance criteria of the existing issues. They are folded
into the delivery plan in one revision after this document is merged:

- **Order of #9 and #10:** registration of client keys moves behind the gateway's signed admin
  API, so gateway authentication (#10) comes before key registration (#9), seeded with a
  bootstrap operator key that is revoked once two operators exist.
- **New M0 issue (dual control):** a second, different operator must approve registering or
  replacing a client's step-up key, changing any client key's scopes, registering or
  re-scoping an operator key, and disabling or revoking an operator key.
- **#8 (CI):** actions pinned to commit SHAs, read-only CI token, digest-pinned base images, no
  fork code under `pull_request_target` or `workflow_run`, `--locked` builds, secret scanning.
- **#10 (gateway authentication):** the signature verification rules in 3.1 (required covered
  components, recomputed Content-Digest, algorithm fixed per key, clock-skew allowance, nonce
  recorded after verification), body size limit, cheap checks first, nonce pruning.
- **#11 (accounts):** signature evidence in the audit record, idempotency keys scoped per client,
  bounded connection pools and statement timeouts.
- **#13 (event publishing):** NATS per-service users and subject permissions, producer-signed
  events covering subject, type and outbox id, consumer deduplication on (producer, outbox id).
- **#14 (relay and broker failover):** streams replicated on all three NATS nodes.
- **All M0 services (#9 to #14):** one schema and least-privilege role per service, secrets as
  Docker secrets, no secrets or full request bodies in logs.
- **M1 (#2):** signer to HSM channel and private network, digest rebuilding in the HSM, xpub
  fingerprint and a fail-closed HSM re-check of deposit addresses (requested through the
  signer), Bitcoin network pinning, maximum fee per withdrawal, derivation subtree restriction,
  dual-control key ceremony, HSM operation log.
- **M2 (#3):** maximum fee per withdrawal, Ethereum chain-id pinning and the Ethereum node
  namespace restriction.
- **M4 (#5):** durable single-use nonces and presignatures.
- **M5+ (#6):** rate limiting, policy enforcement inside the HSM, key backup and recovery.
- **Repository settings (M0 #1):** branch protection on `main` and required signed commits.
