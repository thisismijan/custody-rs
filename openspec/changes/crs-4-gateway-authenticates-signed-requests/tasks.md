## 1. Tests

- [x] 1.1 Prove Signed whoami from the bootstrap key.
- [x] 1.2 Prove Signed request with a body reaches its handler.
- [x] 1.3 Prove Signed request to a route under a path prefix.
- [x] 1.4 Prove Unsigned request.
- [x] 1.5 Prove Body altered after signing.
- [x] 1.6 Prove Method altered after signing.
- [x] 1.7 Prove Authority altered after signing.
- [x] 1.8 Prove Signed for another gateway.
- [x] 1.9 Prove Extra Content-Digest line for an altered body.
- [x] 1.10 Prove Path altered after signing.
- [x] 1.11 Prove Query altered after signing.
- [x] 1.12 Prove Signature altered.
- [x] 1.13 Prove Unknown key.
- [x] 1.14 Prove Rejections do not reveal the failed check.
- [x] 1.15 Prove Same request sent twice.
- [x] 1.16 Prove Created time too old.
- [x] 1.17 Prove Created time too far in the future.
- [x] 1.18 Prove Created time inside the skew allowance.
- [x] 1.19 Prove Expired signature.
- [x] 1.20 Prove Rejected request does not use up its nonce.
- [x] 1.21 Prove Expired nonce is pruned.
- [x] 1.22 Prove Recent nonce is kept.
- [x] 1.23 Prove Gateway started with a valid key file.
- [x] 1.24 Prove Key file missing.
- [x] 1.25 Prove Key file invalid.

## 2. Implementation

- [x] 2.1 Implement the specified behaviour so every scenario above holds.
