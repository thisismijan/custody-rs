# Spec Delta

## Purpose

Defines how the custody gateway proves that every API request comes from a registered key, so
that unsigned, tampered, unknown-key, replayed or stale requests never run.

## ADDED Requirements

### Requirement: Correctly signed requests are accepted
The gateway SHALL accept a request whose RFC 9421 signature covers `@method`, `@authority`,
`@path`, `@query` and `content-digest`, carries `created`, `nonce` and `keyid` parameters,
verifies with the public key registered for that `keyid`, whose Content-Digest matches the
received body, whose `created` time is inside the accepted window, and whose nonce has not been
accepted before for that key.

#### Scenario: Signed whoami from the bootstrap key
- **GIVEN** the gateway's only registered key is the bootstrap operator key
- **WHEN** a GET /v1/whoami request correctly signed by that key, with Content-Digest, created time and a fresh nonce, is sent
- **THEN** the gateway returns 200 with a JSON body whose `client_id` is `bootstrap`, whose `key_id` is `bootstrap` and whose `scopes` is `["bootstrap"]`

#### Scenario: Signed request with a body reaches its handler
- **WHEN** a request with a non-empty body, correctly signed by a registered key with the Content-Digest of that body, is sent to an authenticated route
- **THEN** the route's handler runs once and its response is returned

#### Scenario: Signed request to a route under a path prefix
- **GIVEN** an authenticated route is mounted under a path prefix
- **WHEN** a request correctly signed over the full received path, prefix included, is sent to it
- **THEN** the route's handler runs once, and the same signature sent to the same inner path under a different prefix gets 401

### Requirement: Altered or unknown-key requests are rejected before any handler runs
The gateway SHALL return 401, and SHALL NOT run the targeted handler, for a request that is
unsigned, whose body no longer matches its Content-Digest, whose method, authority, path or query
differs from what was signed, whose signature does not verify, or whose `keyid` is not
registered, whose authority is not the gateway's configured authority, or that carries more than
one Content-Digest field line. The 401 response SHALL NOT say which check failed.

#### Scenario: Unsigned request
- **WHEN** a request without Signature and Signature-Input headers is sent to an authenticated route
- **THEN** the gateway returns 401 and the handler does not run

#### Scenario: Body altered after signing
- **WHEN** a correctly signed request with a body is sent with a different body but the original Content-Digest and signature
- **THEN** the gateway returns 401 and the handler does not run

#### Scenario: Method altered after signing
- **WHEN** a request signed as POST is sent as PUT with the same headers, body and signature
- **THEN** the gateway returns 401 and the handler does not run

#### Scenario: Authority altered after signing
- **WHEN** a request signed with one Host value is sent with a different Host value and the same signature
- **THEN** the gateway returns 401 and the handler does not run

#### Scenario: Signed for another gateway
- **WHEN** a request correctly signed with a Host value that is not the gateway's configured authority is sent with that Host value
- **THEN** the gateway returns 401 and the handler does not run

#### Scenario: Extra Content-Digest line for an altered body
- **WHEN** a correctly signed request is sent with an altered body and a second Content-Digest field line that matches the altered body
- **THEN** the gateway returns 401 and the handler does not run

#### Scenario: Path altered after signing
- **WHEN** a request signed for one path is sent to a different authenticated path with the same signature
- **THEN** the gateway returns 401 and the handler does not run

#### Scenario: Query altered after signing
- **WHEN** a request signed with one query string is sent with a different query string and the same signature
- **THEN** the gateway returns 401 and the handler does not run

#### Scenario: Signature altered
- **WHEN** a correctly signed request is sent with one byte of its signature value changed
- **THEN** the gateway returns 401 and the handler does not run

#### Scenario: Unknown key
- **WHEN** a request is correctly signed by a key whose `keyid` is not registered
- **THEN** the gateway returns 401 and the handler does not run

#### Scenario: Rejections do not reveal the failed check
- **WHEN** an unsigned request, a body-altered request and an unknown-key request are each sent
- **THEN** all three 401 responses have the same body

### Requirement: Replayed and stale requests are rejected
The gateway SHALL return 401, without running the handler, for a request whose nonce was already
accepted for the same key, whose `created` time is more than 60 seconds before the gateway's
clock or more than 5 seconds after it, or whose `expires` time, when present, is not after the
gateway's clock.

#### Scenario: Same request sent twice
- **WHEN** a correctly signed request is accepted and then the identical request is sent again
- **THEN** the second request gets 401 and the handler ran only for the first

#### Scenario: Created time too old
- **WHEN** a correctly signed request whose `created` time is 61 seconds before the gateway's clock is sent
- **THEN** the gateway returns 401 and the handler does not run

#### Scenario: Created time too far in the future
- **WHEN** a correctly signed request whose `created` time is 6 seconds after the gateway's clock is sent
- **THEN** the gateway returns 401 and the handler does not run

#### Scenario: Created time inside the skew allowance
- **WHEN** a correctly signed request whose `created` time is 4 seconds after the gateway's clock is sent
- **THEN** the gateway accepts it

#### Scenario: Expired signature
- **WHEN** a correctly signed request whose `expires` time is before the gateway's clock is sent
- **THEN** the gateway returns 401 and the handler does not run

### Requirement: A nonce is used up only by a verified request
The gateway SHALL record a nonce only after the request's signature verifies, so a request that
fails authentication never prevents a later valid request with the same nonce from being
accepted.

#### Scenario: Rejected request does not use up its nonce
- **WHEN** a request with nonce N and an altered signature is rejected, and then a correctly signed request from the same key with nonce N is sent
- **THEN** the second request is accepted

### Requirement: Used nonces are kept only while they can still be replayed
The nonce store SHALL forget a used nonce once 65 seconds have passed since its request's
`created` time, so its size is bounded by the request rate times the window.

#### Scenario: Expired nonce is pruned
- **WHEN** a nonce is recorded and the store is pruned 66 seconds after that request's created time
- **THEN** the store no longer holds that nonce

#### Scenario: Recent nonce is kept
- **WHEN** a nonce is recorded and the store is pruned 30 seconds after that request's created time
- **THEN** the store still holds that nonce

### Requirement: The bootstrap key is loaded from a file at startup
The gateway SHALL load the bootstrap operator's Ed25519 public key at startup from the PEM file
named by its configured key file path and register it as key `bootstrap`. It SHALL refuse to
start, exiting non-zero with a message that names the path, when the file is missing or does not
hold a valid Ed25519 public key.

#### Scenario: Gateway started with a valid key file
- **WHEN** the gateway process is started with a key file holding a valid Ed25519 public key and a signed GET /v1/whoami from the matching private key is sent to it over TCP
- **THEN** the gateway returns 200 with `client_id` `bootstrap`

#### Scenario: Key file missing
- **WHEN** the gateway process is started with a key file path where no file exists
- **THEN** the process exits non-zero and its error output names that path

#### Scenario: Key file invalid
- **WHEN** the gateway process is started with a key file that does not hold a valid Ed25519 public key
- **THEN** the process exits non-zero and its error output names that path
