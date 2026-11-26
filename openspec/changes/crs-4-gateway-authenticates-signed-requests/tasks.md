## 1. Tests

- [ ] 1.1 Prove Signed whoami from the bootstrap key.
- [ ] 1.2 Prove Signed request with a body reaches its handler.
- [ ] 1.3 Prove Signed request to a route under a path prefix.
- [ ] 1.4 Prove Unsigned request.
- [ ] 1.5 Prove Body altered after signing.
- [ ] 1.6 Prove Method altered after signing.
- [ ] 1.7 Prove Authority altered after signing.
- [ ] 1.8 Prove Signed for another gateway.
- [ ] 1.9 Prove Extra Content-Digest line for an altered body.
- [ ] 1.10 Prove Path altered after signing.
- [ ] 1.11 Prove Query altered after signing.
- [ ] 1.12 Prove Signature altered.
- [ ] 1.13 Prove Unknown key.
- [ ] 1.14 Prove Rejections do not reveal the failed check.
- [ ] 1.15 Prove Same request sent twice.
- [ ] 1.16 Prove Created time too old.
- [ ] 1.17 Prove Created time too far in the future.
- [ ] 1.18 Prove Created time inside the skew allowance.
- [ ] 1.19 Prove Expired signature.
- [ ] 1.20 Prove Rejected request does not use up its nonce.
- [ ] 1.21 Prove Expired nonce is pruned.
- [ ] 1.22 Prove Recent nonce is kept.
- [ ] 1.23 Prove Gateway started with a valid key file.
- [ ] 1.24 Prove Key file missing.
- [ ] 1.25 Prove Key file invalid.

## 2. Implementation

- [ ] 2.1 Implement the specified behaviour so every scenario above holds.
