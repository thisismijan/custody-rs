mod common;

use common::{Options, run, run_with, stage};
use std::process::Command;

const INNER_TEST: &str = "fixture_check_runs_with_local_advisory_database";

#[test]
fn advisory_database_override_is_refused_in_ci_before_any_check() {
    let workspace = stage("clean");
    let result = run_with(
        workspace.path(),
        &Options {
            ci: true,
            skip_advisory_db: true,
            env: vec![
                ("CI_CHECK_ADVISORY_DB", "/nonexistent/advisory-db"),
                ("CI_CHECK_ADVISORY_DB_URL", "/nonexistent/advisory-repo"),
            ],
            ..Options::default()
        },
    );
    assert!(!result.success, "output:\n{}", result.text);
    result.assert_contains("CI_CHECK_ADVISORY_DB is not allowed in CI");
    result.assert_not_contains("check:");
}

#[test]
fn fixture_check_runs_with_local_advisory_database() {
    let workspace = stage("clean");
    run(workspace.path()).assert_passed();
}

#[test]
fn fixture_runs_succeed_when_the_test_process_itself_has_ci_set() {
    let output = Command::new(std::env::current_exe().unwrap())
        .args([INNER_TEST, "--exact", "--test-threads=1"])
        .env("CI", "true")
        .output()
        .unwrap();
    let text = format!(
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.status.success(), "output:\n{text}");
    assert!(text.contains("1 passed"), "inner test did not run:\n{text}");
}
