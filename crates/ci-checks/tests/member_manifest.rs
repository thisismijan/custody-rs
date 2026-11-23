mod common;

use common::{run, stage, write_file};

#[test]
fn forbidden_key_in_a_member_manifest_names_that_manifest() {
    let workspace = stage("clean");
    write_file(
        &workspace.path().join("member/Cargo.toml"),
        "[package]\nname = \"member\"\nversion = \"0.1.0\"\nedition = \"2021\"\npublish = false\n\n\
         [patch.crates-io]\ncustody-rs-fixture-x = { path = \"x\" }\n",
    );

    let result = run(workspace.path());

    result.assert_failed_at("policy");
    result.assert_contains("member/Cargo.toml");
    result.assert_not_contains("check: deny");
}
