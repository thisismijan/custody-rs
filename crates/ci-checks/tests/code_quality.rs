mod common;

use common::{run, stage};

#[test]
fn clean_workspace_passes() {
    let workspace = stage("clean");
    run(workspace.path()).assert_passed();
}

#[test]
fn build_failure_names_the_build_check() {
    let workspace = stage("build-error");
    let result = run(workspace.path());
    result.assert_failed_at("build");
    result.assert_not_contains("check: fmt");
}

#[test]
fn formatting_violation_names_the_format_check_and_the_file() {
    let workspace = stage("unformatted");
    let result = run(workspace.path());
    result.assert_failed_at("fmt");
    result.assert_contains("src/lib.rs");
    result.assert_not_contains("check: clippy");
}

#[test]
fn lint_warning_names_the_lint_check() {
    let workspace = stage("lint-warning");
    let result = run(workspace.path());
    result.assert_failed_at("clippy");
    result.assert_not_contains("check: test");
}

#[test]
fn failing_test_names_the_failing_test() {
    let workspace = stage("failing-test");
    let result = run(workspace.path());
    result.assert_failed_at("test");
    result.assert_contains("deliberately_failing_test");
    result.assert_not_contains("check: deny");
}

#[test]
fn lint_warning_behind_a_non_default_feature_names_the_lint_check() {
    let workspace = stage("feature-lint-warning");
    let result = run(workspace.path());
    result.assert_failed_at("clippy");
}
