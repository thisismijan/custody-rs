mod common;

use common::{run, stage};
use std::fs;
use std::os::unix::fs::symlink;

#[test]
fn nested_directory_named_target_is_still_scanned() {
    let workspace = stage("clean");
    let nested = workspace.path().join("nested/target");
    fs::create_dir_all(&nested).unwrap();
    symlink(
        workspace.path().join("src/lib.rs"),
        nested.join("hidden-link.rs"),
    )
    .unwrap();

    let result = run(workspace.path());

    result.assert_failed_at("policy");
    result.assert_contains("nested/target/");
    result.assert_contains("hidden-link.rs");
    result.assert_not_contains("check: build");
}

#[test]
fn root_target_directory_is_still_skipped() {
    let workspace = stage("clean");
    let target = workspace.path().join("target");
    fs::create_dir_all(&target).unwrap();
    symlink(
        workspace.path().join("src/lib.rs"),
        target.join("skipped-link.rs"),
    )
    .unwrap();

    run(workspace.path()).assert_passed();
}
