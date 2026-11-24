# ci-checks Specification

## Purpose
Defines the checks every change to custody-rs must pass before it can merge, so that unbuilt,
badly formatted, failing or supply-chain-unsafe code never reaches `main`.

## Requirements

### Requirement: Checks run on every pull request
The repository SHALL run the full set of checks on every pull request that targets `main`, and the
pull request's check status SHALL fail whenever any check fails.

#### Scenario: Passing pull request (live evidence)
- **WHEN** a pull request targeting `main` contains a change that passes every check
- **THEN** the checks run and the pull request's check status is success

#### Scenario: Failing pull request (live evidence)
- **WHEN** a pull request targeting `main` contains a change that fails any check
- **THEN** the checks run and the pull request's check status is failure

### Requirement: Code quality checks fail the run
The check run SHALL fail, and name the failing check, when the workspace does not build, is not
formatted, has a lint warning, or has a failing test. A clean workspace SHALL pass.

#### Scenario: Clean workspace passes
- **WHEN** the checks run on a workspace that builds, is formatted, has no lint warnings and whose tests pass
- **THEN** the run exits successfully

#### Scenario: Build failure
- **WHEN** the checks run on a workspace that does not compile
- **THEN** the run fails and its output names the build check

#### Scenario: Formatting violation
- **WHEN** the checks run on a workspace with a file that is not formatted
- **THEN** the run fails and its output names the format check and that file

#### Scenario: Lint warning
- **WHEN** the checks run on a workspace with code that produces a lint warning
- **THEN** the run fails and its output names the lint check

#### Scenario: Failing test
- **WHEN** the checks run on a workspace with a failing test
- **THEN** the run fails and its output names the failing test

#### Scenario: Lint warning behind a non-default feature
- **WHEN** the checks run on a workspace whose lint warning is only compiled when a non-default feature is enabled
- **THEN** the run fails and its output names the lint check

### Requirement: Every check runs on every run
The check run SHALL always run every check; no setting SHALL skip a check. The test-only advisory
database override SHALL be refused when the run is in CI, so CI always uses the live database.

#### Scenario: Advisory database override in CI
- **WHEN** the checks run with the advisory database override set and the `CI` environment variable set to `true`
- **THEN** the run fails before any check and its output says `CI_CHECK_ADVISORY_DB is not allowed in CI`

#### Scenario: Fixture checks inside a CI run
- **WHEN** the committed tests run in an environment where `CI` is set to `true`
- **THEN** every fixture check run other than the advisory database override test runs without `CI` set and uses the local advisory database

### Requirement: Builds use the committed lockfile
The check run SHALL build only with the committed lockfile and SHALL fail when the lockfile is
missing or out of date with the manifests, instead of resolving new dependency versions.

#### Scenario: Lockfile missing
- **WHEN** the checks run on a workspace that has no lockfile
- **THEN** the run fails before building and its output says `Cargo.lock is missing`

#### Scenario: Lockfile out of date
- **WHEN** the checks run on a workspace whose manifest declares a dependency that its lockfile does not record
- **THEN** the run fails and its output says the lock file needs to be updated

### Requirement: Dependencies with known advisories fail the run
The check run SHALL fail when any dependency matches an advisory in the advisory database, and its
output SHALL name the dependency and the advisory. An advisory is accepted only when the dependency
policy ignores its exact id with a recorded reason.

#### Scenario: Dependency with a known advisory
- **WHEN** the checks run on a workspace that depends on a crate version listed in an advisory
- **THEN** the run fails and its output names that crate and the advisory id

#### Scenario: Advisory ignored with a reason
- **WHEN** the dependency policy ignores that exact advisory id with a recorded reason
- **THEN** the dependency check passes for that advisory

#### Scenario: Advisory ignored without a reason
- **WHEN** the dependency policy ignores an advisory id without a recorded reason
- **THEN** the run fails and its output names that ignore entry

#### Scenario: Advisory ignored as a bare id
- **WHEN** the dependency policy's ignore list holds a bare advisory id string on a single line
- **THEN** the run fails and its output names that ignore entry

#### Scenario: Advisory on a dependency behind a non-default feature
- **WHEN** the checks run on a workspace whose dependency listed in an advisory is only enabled by a non-default feature
- **THEN** the run fails and its output names that crate and the advisory id

### Requirement: The dependency policy cannot be weakened
The check run SHALL fail when the committed dependency policy differs in any setting from the
policy the checker holds, other than advisory ignore entries that follow the ignore rule, and its
output SHALL name the differing setting.

#### Scenario: Setting added to the dependency policy
- **WHEN** the checks run with a dependency policy that adds an advisory database location the checker's policy does not have
- **THEN** the run fails and its output names that setting

#### Scenario: Setting changed in the dependency policy
- **WHEN** the checks run with a dependency policy that allows yanked crates where the checker's policy denies them
- **THEN** the run fails and its output names that setting

### Requirement: Dependencies with disallowed licences fail the run
The check run SHALL fail when any dependency's licence is not on the dependency policy's allowed
list, and its output SHALL name the dependency and its licence.

#### Scenario: Dependency with a disallowed licence
- **WHEN** the checks run on a workspace that depends on a crate licensed `GPL-3.0-only`
- **THEN** the run fails and its output names that crate and its licence

### Requirement: Dependencies from disallowed sources fail the run
The check run SHALL fail when any dependency comes from a source other than crates.io, including a
path outside the workspace, and its output SHALL name the dependency and its source. Workspace
members are the only allowed path crates.

#### Scenario: Dependency from a git source
- **WHEN** the checks run on a workspace that depends on a crate fetched from a git repository
- **THEN** the run fails and its output names that crate and its source

#### Scenario: Path dependency outside the workspace
- **WHEN** the checks run on a workspace that depends on a crate by a path outside its members
- **THEN** the run fails and its output names that crate and its path

#### Scenario: Path dependency behind a non-default feature
- **WHEN** the checks run on a workspace with an optional dependency, by a path outside its members, that only a non-default feature enables
- **THEN** the run fails and its output names that crate and its path

### Requirement: Repository cannot redirect dependency sources
The check run SHALL fail when the repository's cargo configuration or any manifest replaces the
crates.io source, patches a dependency or replaces a dependency, however the TOML is written, and
its output SHALL name the file. A repository cargo configuration file SHALL contain only keys on
an explicit allowlist, which is empty, so any key fails the run. A cargo configuration file or
manifest that cannot be parsed SHALL fail the run.

#### Scenario: Source replacement in repository configuration
- **WHEN** the checks run on a workspace whose cargo configuration file replaces the crates.io source
- **THEN** the run fails and its output names that configuration file

#### Scenario: Source replacement written as dotted keys
- **WHEN** the checks run on a workspace whose cargo configuration file replaces the crates.io source using dotted keys and no table header
- **THEN** the run fails and its output names that configuration file

#### Scenario: Source replacement in a subdirectory's configuration
- **WHEN** the checks run on a workspace whose member crate directory holds a cargo configuration file that replaces the crates.io source
- **THEN** the run fails and its output names that configuration file

#### Scenario: Source replacement in a legacy configuration file
- **WHEN** the checks run on a workspace whose only cargo configuration file is the extensionless legacy file and it replaces the crates.io source
- **THEN** the run fails and its output names that configuration file

#### Scenario: Path override in repository configuration
- **WHEN** the checks run on a workspace whose cargo configuration file has a `paths` override pointing at a local copy of a dependency
- **THEN** the run fails and its output names that configuration file and the `paths` key

#### Scenario: Patched dependency in a manifest
- **WHEN** the checks run on a workspace whose manifest patches a dependency
- **THEN** the run fails and its output names that manifest

#### Scenario: Patch written as a dotted key
- **WHEN** the checks run on a workspace whose manifest patches a dependency using a dotted key and no table header
- **THEN** the run fails and its output names that manifest

#### Scenario: Dependency replaced through a replace table
- **WHEN** the checks run on a workspace whose manifest has a `replace` table
- **THEN** the run fails and its output names that manifest

#### Scenario: Unparseable cargo configuration
- **WHEN** the checks run on a workspace whose cargo configuration file is not valid TOML
- **THEN** the run fails and its output names that configuration file

### Requirement: Symbolic links in the workspace fail the run
The check run SHALL fail when the workspace contains a symbolic link, to a file or a directory,
outside the build output and git directories, and its output SHALL name the link.

#### Scenario: Cargo configuration directory behind a symbolic link
- **WHEN** the checks run on a workspace whose `.cargo` directory is a symbolic link to a directory holding a configuration file that replaces the crates.io source
- **THEN** the run fails and its output names that link

#### Scenario: Symbolic link to a file
- **WHEN** the checks run on a workspace that contains a symbolic link to a file
- **THEN** the run fails and its output names that link
