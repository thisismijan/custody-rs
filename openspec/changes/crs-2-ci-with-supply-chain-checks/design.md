# Design

## Context

The repository holds only docs and the OpenSpec scaffold: no Rust code, no CI. `main` is protected
(pull requests only, signed commits, no force-push); a required status check can be added only
once a CI job exists. See proposal.md for motivation and `docs/threat-model.md` section 3.8 (Supply
chain) for the threats this addresses; see proposal.md Impact for which of its controls belong to
#18 instead.

## Goals / Non-Goals

**Goals:**
- One check entry point that CI and a developer run identically, so a local pass predicts a CI pass.
- Every check failure names its cause (check name, and the dependency for supply-chain checks).
- Tests that prove each check's behaviour offline and deterministically.

**Non-Goals:**
- Enforcing workflow hardening (SHA-pin lint, token scope lint, fork-code rules) and secret
  scanning: #18 (CRS-18), per plan v2. This change still follows those rules in its own workflow.
- Container images: none are used by this change, so digest pinning has nothing to apply to yet.
  The first ticket that adds an image pins it by digest (threat model 3.8).
- Caching and speed tuning beyond what keeps the run reasonable.

## Decisions

### D1 Workspace layout
- Root `Cargo.toml` as a virtual workspace with `resolver = "2"`, committed `Cargo.lock`,
  `rust-toolchain.toml` pinning an exact stable version with `rustfmt` and `clippy`.
- Version rule for every pin in this change: use the latest stable release at implementation time,
  written as an exact version (Rust `x.y.z`, `cargo-deny` `x.y.z`, each action as a full 40-character
  commit SHA with the release tag in a trailing comment), and list the chosen values in the MR
  description. Later upgrades are ordinary changes.
- One member crate, `crates/ci-checks` (`publish = false`), whose integration tests exercise the
  check entry point. It is the only crate this ticket needs; product crates arrive with later tickets.
- Fixture workspaces live under `crates/ci-checks/tests/fixtures/` and are excluded from the root
  workspace (`exclude`), so the real build never compiles them.

### D2 One check entry point
- `ci/check.sh <workspace-dir>` (bash, `set -euo pipefail`) runs, stopping at the first failure:
  0. `policy`: refuse the advisory database override when `CI=true`; fail if `Cargo.lock` is
     missing, printing `Cargo.lock is missing`; then run `python3 -I ci/policy.py <workspace-dir>
     <deny.toml path>`, which parses files with Python's standard-library `tomllib` (operator
     choice, see D6) and fails, printing the file and the offending key or entry, when:
     - a scanned file (a cargo config file, any `Cargo.toml`) does not parse
       as TOML (fail closed: a file the checker cannot read is never treated as safe);
     - a cargo config file has any top-level key not on
       the config allowlist. The allowlist is empty today, because the repository needs no cargo
       config (the test-only source replacement lives in a test-created `CARGO_HOME`), so any key,
       including `source` and the `paths` override, fails. Adding a key is a reviewed edit to
       `ci/policy.py`;
     - a `Cargo.toml` has a top-level `source`, `patch` or `replace` key, however it is written
       (table header, bare table, dotted key, indented, spaced or quoted);
     - `deny.toml` differs from the pinned policy, or breaks the ignore rule, in D3.
     `ci/policy.py` first checks that Python is 3.11 or later and otherwise fails printing
     `python 3.11 or later is required`.
     Cargo config files: cargo reads `<dir>/.cargo/config.toml` and the legacy extensionless
     `.cargo/config` from the directory it runs in and from every parent directory, so the walk
     that finds every `Cargo.toml` also matches both names in every directory it visits, at any
     depth. The repository contains none and this change creates none.
     Scan scope (operator-confirmed): only `<workspace-dir>` and the directories below it, never
     parent directories. The real run (`ci/check.sh .`) skips each fixture's own directory
     (`crates/ci-checks/tests/fixtures/<name>/`), because each fixture is a separate workspace
     checked by its own test run, and `target/` and `.git/`. It still scans
     `crates/ci-checks/tests/fixtures/` itself and every directory above it, which are exactly the
     in-repository parents a fixture run's cargo reads config from. A fixture run scans only that
     fixture.
  1. `cargo build --locked --workspace --all-targets --all-features`
  2. `cargo fmt --all -- --check`
  3. `cargo clippy --locked --workspace --all-targets --all-features -- -D warnings`
  4. `cargo test --locked --workspace --all-targets --all-features`
  5. `cargo deny` (exact commands below) with the repository-root `deny.toml`
     (always the committed file, located relative to the script, never one inside the checked
     workspace), plus a path-dependency check over
     `cargo metadata --locked --all-features --format-version 1`: any package in the resolve with
     no registry source that is not a workspace member fails, naming the crate and path.
     `--all-features` keeps an optional path dependency behind a non-default feature in the
     resolve.
- Before each step it prints a line `check: <name>` and on failure `FAILED: <name>`, so output
  names the failing check. Tool output is passed through unchanged and supplies the rest of what
  the scenarios require: `cargo fmt --check` prints the unformatted file's path, `cargo test` prints
  the failing test's name, cargo 1.100 prints `cannot update the lock file <path> because --locked was passed to
  prevent this` for a stale lockfile (observed at the pinned version; older cargo printed `needs
  to be updated but --locked was passed`), and `cargo deny` prints the crate with the advisory id, licence or
  source. Tests assert these substrings.
- Every run executes every check; there is no skip setting. The only override is the test-only
  advisory database folder `CI_CHECK_ADVISORY_DB`, refused when `CI=true`.
- Advisory database wiring (operator decision, 2026-11-23, option A; replaces the earlier
  `file://` and `--disable-fetch` wiring, which cargo-deny 0.22.0 refuses): the committed
  `deny.toml` sets no `db-path` and no `db-urls`, so by default `cargo deny` fetches the live
  RustSec database. Observed at 0.22.0: `db-urls` must be a URL with a domain name (`file://` is
  refused), `check` has no `--disable-fetch`, and with the global `--offline` option cargo-deny
  reads the database already present at `<db-path>/advisory-db-<hash of the URL>` without
  fetching. So when `CI_CHECK_ADVISORY_DB` is set, the script copies the committed `deny.toml` to
  a temp file, adds to its `[advisories]` table `db-path = "<CI_CHECK_ADVISORY_DB>"` and the fixed
  placeholder `db-urls = ["https://example.invalid/advisory-db"]`, and runs
  `cargo deny --offline --locked --config <temp file> check advisories licenses sources`.
  `--offline`, `--locked` and `--config` are global options and go before `check`; `--locked`
  stops cargo-deny's own metadata resolution from updating `Cargo.lock`, as every cargo step
  here. Without the override the run is
  `cargo deny --locked --config <repo-root>/deny.toml check advisories licenses sources`, with no
  `--offline`, so CI always fetches the live database.
- Fixture database seeding: for the placeholder URL above, cargo-deny 0.22.0 uses the folder
  name `advisory-db-79ba8843f8f3e7ce` (observed, not documented). The test helper creates the
  fixture advisory git repository and clones it into
  `<CI_CHECK_ADVISORY_DB>/advisory-db-79ba8843f8f3e7ce`, keeping that name as one named constant
  next to the placeholder URL. If a cargo-deny upgrade changes the name, the advisory tests fail
  in setup and the constant is updated with the pin; never fall back to the live database in a
  test.
- Exact message when the override is refused (`CI=true` and `CI_CHECK_ADVISORY_DB` set):
  `CI_CHECK_ADVISORY_DB is not allowed in CI`, printed before any check runs, exit status 1.
- After the last check it prints `all checks passed: policy build fmt clippy test deny`, so a
  passing run shows what it ran.
- Why a script rather than steps in the workflow: the same command runs locally and in CI, and it
  is the seam the committed tests drive (see Test seams).

### D3 Dependency policy (`deny.toml`)
- Advisories: every RustSec advisory (vulnerability, unsound, unmaintained, yanked) fails. An
  accepted advisory is listed by exact id in `ignore` with a `reason`.
- Ignore rule, checked by `ci/policy.py` on the parsed file, so layout does not matter:
  `advisories.ignore` is absent or a list, and every entry is a table with exactly the keys `id`
  (matching `RUSTSEC-\d{4}-\d{4}`) and `reason` (a string with at least one non-space character).
  Any other entry (a bare id string, a `crate = ...` entry, a missing or empty reason, an extra
  key) fails the run, and the output prints that entry. The committed file has `ignore = []` under
  `[advisories]`.
- Graph: `[graph] all-features = true`, so dependencies behind non-default features are checked.
- Licences: allow `MIT`, `Apache-2.0`, `Apache-2.0 WITH LLVM-exception`, `BSD-2-Clause`,
  `BSD-3-Clause`, `ISC`, `Unicode-3.0`, `Zlib`; anything else fails. Unpublished crates are
  exempt (`[licenses.private] ignore = true`); this covers only workspace members because the
  path-dependency check rejects every other path crate and the policy step rejects `patch` and
  `replace`, so a member cannot stand in for a crates.io crate.
- Advisories `yanked = "deny"` applies in CI against the live crates.io index. Fixture crates use
  the reserved-looking prefix `custody-rs-fixture-` and must not make the offline fixture runs
  depend on the network; the first fixture test proves this.
- Sources: crates.io only; `unknown-registry = "deny"`, `unknown-git = "deny"`, no allowed git URLs.
- Pinned policy (operator decision, 2026-11-23, option A): `ci/policy.py` holds the complete
  expected contents of `deny.toml` as one Python dictionary. The parsed committed file, with
  `advisories.ignore` set aside, must equal that dictionary exactly: no extra key, no missing key,
  no changed value, at any depth. On a difference the run fails and prints the dotted key path
  (for example `advisories.db-urls` or `advisories.yanked`) and whether it was added, removed or
  changed. `advisories.ignore` is then checked by the ignore rule above. This closes every way of
  weakening the policy without an ignore entry, such as pointing `db-urls` or `db-path` at a stale
  database, `graph.exclude`, licence `exceptions` or `clarify`, `allow-git`, `allow-registry`, or
  setting `yanked` or `unmaintained` to allow. The test override's added `db-path` and `db-urls`
  go only into its temp copy, after the policy step has checked the committed file.
- The policy contents above are agent-owned defaults. Changing them is one reviewed edit to both
  `deny.toml` and the pinned dictionary in `ci/policy.py`.

### D4 Workflow (`.github/workflows/ci.yml`)
- Triggers: `pull_request` targeting `main`, and `push` to `main`. One job named `checks` on
  `ubuntu-latest`; `permissions: contents: read`.
- Steps: checkout, install the pinned toolchain from `rust-toolchain.toml`, install `cargo-deny`
  at a pinned version with `cargo install --locked`, run `ci/check.sh .`. The runner's own
  `python3` runs the policy step (no setup action); `ci/policy.py` refuses a version below 3.11.
- Third-party actions are referenced by full commit SHA from the start (cheap now; CRS-18 adds the
  lint that enforces it).

### D5 Test seams (operator-approved option B)
1. **Check entry point against fixture workspaces (committed tests).** Rust integration tests in
   `crates/ci-checks/tests/` run `ci/check.sh` on fixture workspaces and assert exit status and
   output text. Fixtures: `clean`, `build-error`, `unformatted`, `lint-warning`, `failing-test`,
   `stale-lockfile`, `advisory`, `advisory-ignored`, `gpl-licence`, `git-source`.
   - Controlled fakes: a fixture advisory database (a small git repository in RustSec format,
     created by the test in a temp dir and cloned into the seeded folder described in D2) with one
     advisory for a fixture crate; supply-chain fixtures
     resolve crates from a local vendored directory that replaces crates.io through a test-only
     `CARGO_HOME` config created by the test, never a repository file (source replacement keeps the
     crates.io source id, so advisory and licence matching behave as for a real crates.io crate);
     the git-source fixture depends on a local `file://` git repository created by the test.
   - Every fixture runs against the committed root `deny.toml`. The advisory-ignore fixtures copy
     it into a temp checkout and replace its `ignore = []` line with one entry, so the base policy
     cannot drift from what is tested.
   - Additional fixtures for the challenge gaps: `missing-lockfile`, `feature-lint-warning`,
     `feature-advisory`, `ignore-without-reason`, `ignore-bare-id`, `path-dependency`,
     `source-replacement`, `source-replacement-dotted`, `patched-manifest`,
     `patched-manifest-dotted`, `replace-table`, `unparseable-config`, `config-paths-override`,
     `nested-config` (a source replacement in `<member-crate-dir>/.cargo/config.toml`),
     `legacy-config` (a source replacement in an extensionless `.cargo/config` only),
     `feature-path-dependency` (an optional path dependency outside the members, enabled only by
     a non-default feature), `policy-added-key` (a copy of the committed `deny.toml` with
     `db-urls` added under `[advisories]`), `policy-changed-value` (a copy with `yanked` changed to
     `"allow"`);
     the CI override scenario
     runs the `clean` fixture with `CI=true`.
     Nothing needs the network, and results do not change when RustSec publishes new advisories.
   - CI environment: the real CI job sets `CI=true`, and `cargo test` passes it to the tests. The
     test helper that runs `ci/check.sh` removes `CI` from every child run's environment, except
     in the CI override test, which sets it on purpose. Without this every fixture run in CI would
     hit the override refusal.
   - Catches: each check's pass/fail logic, `--locked` behaviour, that output names the check and
     the offending file, test, crate, advisory, licence or source; the dependency policy's content.
   - Misses: whether GitHub actually runs the workflow on a pull request and reports its status.
2. **Live proof on GitHub (verification evidence, not a committed test).** Covers the scenarios of
   "Checks run on every pull request". The draft MR that `/execute` opens runs the workflow, which
   is the passing-path evidence. For the failing path, execute opens one throwaway pull request
   from a branch with a deliberate formatting violation, records the failed `checks` status read
   back through the forge, and leaves the pull request for the operator to close. Both results are
   recorded in the MR description. The test writer skips these two scenarios and reports them as
   proven by live evidence per this section.

Each spec scenario maps to exactly one seam: the two scenarios marked "(live evidence)" under
"Checks run on every pull request" map to seam 2 and get no committed test (tasks 1.1 and 1.2 are
done when the evidence is in the MR description); every other scenario maps to seam 1.

### D6 Reading TOML in the policy step (operator decision, 2026-11-23)
- The policy step parses TOML with Python's standard-library `tomllib` (Python 3.11+), because a
  text match on header spellings passes every form it does not recognise (bare tables, dotted
  keys, indented, spaced or quoted headers, `[replace]`), and source replacement is invisible to
  every later check.
- Python rather than a Rust checker: the policy step runs before cargo builds or fetches anything,
  so a hostile `.cargo/config` cannot affect the program that inspects it, and no crate
  dependency is added. Cost: a second language (one small script) and Python 3.11+ locally.

## Rejected alternatives

- **Text matching on TOML header spellings (original design, and the operator's options A and
  C):** fails open on every spelling it does not recognise.
- **A Rust checker using the `toml` crate:** cargo must build it first, and that build already
  reads `.cargo/config` and fetches crates, so a source replacement takes effect before the check
  that should refuse it; it also adds dependencies.
- **Checking only `deny.toml`'s ignore list, leaving other settings to review (option C):** a
  one-line `db-urls` or `graph.exclude` change weakens the policy and CI accepts it.
- **Allowlisting `deny.toml` keys and pinning only the weakening values (option B):** an allowed
  key whose value is not pinned can still be weakened.
- **Serving the fixture advisory database from a local git HTTP server (advisory option B):**
  unproven against cargo-deny's URL check, and a server per test adds moving parts.
- **Proving advisory detection only by live evidence (advisory option C):** loses the offline,
  repeatable proof of the advisory scenarios.
- **A `CI_CHECK_ONLY` setting to run a subset of checks:** fails open when misspelt, empty, or set
  in CI.

- **Fixture tests only (seam option A):** leaves the main claim (runs on every pull request)
  unproven.
- **Running the workflow locally with `act` (seam option C):** behaves differently from GitHub
  runners, needs Docker and large images, adds a tool to explain.
- **Checks written directly as workflow steps without a script:** local and CI runs would differ,
  and the only tests possible would inspect the YAML shape, which is a transient config-shape test.
- **`cargo-audit` alongside `cargo-deny`:** two tools for advisories; `cargo-deny` covers
  advisories, licences and sources with one policy file.
- **Shell test framework (bats) for the tests:** adds a tool; Rust integration tests use the
  toolchain already pinned.

## Risks / Trade-offs

- [Fixture tests run cargo inside cargo, every check every time, and are slow] → fixtures are
  tiny and share one target directory; accepted in exchange for having no skip setting that could
  fail open.
- [`tomllib` and cargo could disagree on what a file means] → a file `tomllib` cannot parse fails
  the run, any cargo config key outside the (empty) allowlist fails, and any manifest `source`,
  `patch` or `replace` key fails whatever it points at, so a disagreement fails closed.
- [Cargo adds a new config key that redirects dependencies] → the config allowlist already
  refuses it; manifests are checked by named keys because they legitimately hold many keys.
- [cargo-deny's handling of a local advisory database or source replacement, or its option
  placement for `--offline`, `--locked` and `--config`, differs from the assumption above] → the first fixture test written proves it; if it fails, stop and report
  rather than weaken the check.
- [Live RustSec database can fail CI on a new advisory unrelated to the change] → intended
  behaviour; resolve by updating the dependency or recording an ignore with a reason.
- [The seeded database folder name is an undocumented cargo-deny detail] → the advisory tests
  fail loudly in setup if it changes, and the name is one constant updated with the cargo-deny
  pin (operator chose this over a local HTTP server or live-only evidence).
- [`ubuntu-latest` changes over time] → acceptable for now; the toolchain itself is pinned.

## Migration Plan

Additive. Rollback is reverting the merge commit. After merge the operator adds `checks` as a
required status check on `main`.
