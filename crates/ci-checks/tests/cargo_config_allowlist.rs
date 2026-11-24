mod common;

use common::{run, stage, write_file};

#[test]
fn any_key_in_a_cargo_configuration_file_is_refused() {
    let workspace = stage("clean");
    write_file(
        &workspace.path().join(".cargo/config.toml"),
        "[build]\njobs = 1\n",
    );

    let result = run(workspace.path());

    result.assert_failed_at("policy");
    result.assert_contains(".cargo/config.toml");
    result.assert_contains("build");
    result.assert_not_contains("check: build");
}
