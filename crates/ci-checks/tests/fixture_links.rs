mod common;

use common::{run, stage, write_file};
use std::os::unix::fs::symlink;

const FIXTURES: &str = "crates/ci-checks/tests/fixtures";

#[test]
fn symbolic_link_inside_a_fixture_directory_is_refused() {
    let workspace = stage("clean");
    let fixture = workspace.path().join(FIXTURES).join("x");
    write_file(&fixture.join("src/lib.rs"), "pub fn marker() {}\n");
    symlink(fixture.join("src"), fixture.join("linked")).unwrap();

    let result = run(workspace.path());

    result.assert_failed_at("policy");
    result.assert_contains("crates/ci-checks/tests/fixtures/x/linked");
    result.assert_not_contains("check: deny");
    result.assert_not_contains("check: build");
}

#[test]
fn fixture_directory_is_exempt_from_the_manifest_check() {
    let workspace = stage("clean");
    write_file(
        &workspace.path().join(FIXTURES).join("y/Cargo.toml"),
        "[package]\nname = \"y\"\nversion = \"0.1.0\"\nedition = \"2021\"\npublish = false\n\n\
         [patch.crates-io]\ncustody-rs-fixture-x = { path = \"x\" }\n",
    );

    run(workspace.path()).assert_passed();
}
