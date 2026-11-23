# Proposal

## Why

The repository has no CI, so nothing stops an unbuilt, unformatted, failing or unsafe change from
merging into a custodian's codebase. The threat model (`docs/threat-model.md`, section 3.8 Supply chain) also
requires that vulnerable, wrongly licensed or untrusted-source dependencies are refused before any
service code exists, so every later ticket inherits the checks.

## What Changes

- A minimal Rust workspace is created, with a pinned toolchain and a committed lockfile, so there is
  something to build and check.
- One check entry point runs, in order: the policy step, the dependency checks (known advisories,
  licences, sources), locked build, format check, lint (warnings are errors), and tests. The policy
  step and the dependency checks both run before anything compiles. Any failure fails the run and
  names the cause.
- A GitHub Actions workflow runs that entry point on every pull request to `main` (and on pushes to
  `main`).
- A dependency policy is committed: permissive licences only, crates.io as the only source, and
  every RustSec advisory fails unless it is explicitly ignored with a recorded reason.

## Capabilities

### New Capabilities

- `ci-checks`: the checks every change must pass before it can merge, covering code quality
  (build, format, lint, tests) and dependency supply chain (advisories, licences, sources).

### Modified Capabilities

None.

## Impact

- New files:
  - `Cargo.toml` (new), `Cargo.lock` (new), `rust-toolchain.toml` (new): the workspace.
  - `crates/ci-checks/Cargo.toml` (new) and its integration tests and fixtures under
    `crates/ci-checks/tests/` (new).
  - `ci/check.sh` (new): the check entry point.
  - `ci/policy.py` (new): the TOML policy checker.
  - `deny.toml` (new): the dependency policy.
  - `.github/workflows/ci.yml` (new): the workflow.
- Not created: any cargo config file (`<workspace-dir>/.cargo/config.toml`, `<workspace-dir>/.cargo/config`, or the same names
  in any subdirectory). The policy step only scans for them, and fails if one appears.
- New CI tools: `cargo-deny` (installed at a pinned version in CI), and Python 3.11 or later
  (standard library only, `tomllib`) for the policy step; the GitHub runner already has it.
- Operator follow-up after merge: add the CI job as a required status check on `main`
  (branch protection already requires pull requests and signed commits).
- Out of scope: workflow hardening (Actions SHA-pin enforcement, token scope, fork-code rules) and
  secret scanning, release pipelines, container publishing. The threat model's 3.8 table lists the
  hardening and secret scanning under #8; delivery plan v2 (operator-approved 2026-11-22) moved them
  to #18 (CRS-18) so each ticket stays within three acceptance criteria. The threat-model table is
  updated to match in a separate docs change.
- Out of scope for committed tests: yanked-crate detection (it needs the live crates.io index, so
  it runs in CI only), and formatting of files outside a crate's module tree, such as generated or
  `include!`d files (rustfmt only formats module trees; such files are not hand-edited).
