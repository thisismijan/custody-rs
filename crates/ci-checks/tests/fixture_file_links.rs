mod common;

use common::{run, stage, write_file};
use std::os::unix::fs::symlink;

#[test]
fn symbolic_link_to_a_file_inside_a_fixture_directory_is_refused() {
    let workspace = stage("clean");
    let fixture = workspace.path().join("crates/ci-checks/tests/fixtures/x");
    write_file(&fixture.join("src/lib.rs"), "pub fn marker() {}\n");
    symlink(fixture.join("src/lib.rs"), fixture.join("linked.rs")).unwrap();

    let result = run(workspace.path());

    result.assert_failed_at("policy");
    result.assert_contains("crates/ci-checks/tests/fixtures/x/linked.rs");
    result.assert_not_contains("check: deny");
    result.assert_not_contains("check: build");
}
