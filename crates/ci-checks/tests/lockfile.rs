mod common;

use common::{run, stage};

#[test]
fn missing_lockfile_fails_before_building() {
    let workspace = stage("missing-lockfile");
    let result = run(workspace.path());
    result.assert_failed_at("policy");
    result.assert_contains("Cargo.lock is missing");
    result.assert_not_contains("check: build");
    result.assert_not_contains("check: deny");
}

#[test]
fn run_never_creates_a_missing_lockfile() {
    let workspace = stage("missing-lockfile");
    run(workspace.path());
    assert!(!workspace.path().join("Cargo.lock").exists());
}

#[test]
fn lockfile_out_of_date_fails_and_says_it_needs_updating() {
    let workspace = stage("stale-lockfile");
    let before = std::fs::read_to_string(workspace.path().join("Cargo.lock")).unwrap();
    let result = run(workspace.path());
    result.assert_failed_at("deny");
    result.assert_contains("cannot update the lock file");
    result.assert_contains("because --locked was passed");
    let after = std::fs::read_to_string(workspace.path().join("Cargo.lock")).unwrap();
    assert_eq!(before, after);
}
