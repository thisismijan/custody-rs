mod common;

use common::{Run, Scratch, run, stage, write_file};
use std::fs;

const REPLACEMENT_TABLES: &str = "[source.crates-io]\nreplace-with = \"vendored\"\n\n\
                                  [source.vendored]\ndirectory = \"vendor\"\n";
const REPLACEMENT_DOTTED: &str =
    "source.crates-io.replace-with = \"vendored\"\nsource.vendored.directory = \"vendor\"\n";

fn run_with_file(relative: &str, content: &str) -> (Scratch, Run) {
    let workspace = stage("clean");
    write_file(&workspace.path().join(relative), content);
    let result = run(workspace.path());
    (workspace, result)
}

fn run_with_manifest_edit(edit: impl Fn(&str) -> String) -> Run {
    let workspace = stage("clean");
    let manifest = workspace.path().join("Cargo.toml");
    let text = fs::read_to_string(&manifest).unwrap();
    write_file(&manifest, &edit(&text));
    run(workspace.path())
}

fn assert_refused_before_cargo(result: &Run) {
    result.assert_failed_at("policy");
    result.assert_not_contains("check: build");
}

#[test]
fn source_replacement_in_repository_configuration_names_the_file() {
    let (_workspace, result) = run_with_file(".cargo/config.toml", REPLACEMENT_TABLES);
    assert_refused_before_cargo(&result);
    result.assert_contains(".cargo/config.toml");
}

#[test]
fn source_replacement_written_as_dotted_keys_names_the_file() {
    let (_workspace, result) = run_with_file(".cargo/config.toml", REPLACEMENT_DOTTED);
    assert_refused_before_cargo(&result);
    result.assert_contains(".cargo/config.toml");
}

#[test]
fn source_replacement_in_a_subdirectory_configuration_names_the_file() {
    let (_workspace, result) = run_with_file("member/.cargo/config.toml", REPLACEMENT_TABLES);
    assert_refused_before_cargo(&result);
    result.assert_contains("member/.cargo/config.toml");
}

#[test]
fn source_replacement_in_a_legacy_configuration_file_names_the_file() {
    let (_workspace, result) = run_with_file(".cargo/config", REPLACEMENT_TABLES);
    assert_refused_before_cargo(&result);
    result.assert_contains(".cargo/config");
    result.assert_not_contains(".cargo/config.toml");
}

#[test]
fn paths_override_in_repository_configuration_names_the_file_and_the_key() {
    let (_workspace, result) = run_with_file(".cargo/config.toml", "paths = [\"../local-copy\"]\n");
    assert_refused_before_cargo(&result);
    result.assert_contains(".cargo/config.toml");
    result.assert_contains("paths");
}

#[test]
fn unparseable_cargo_configuration_names_the_file() {
    let (_workspace, result) = run_with_file(".cargo/config.toml", "this is = not [valid toml\n");
    assert_refused_before_cargo(&result);
    result.assert_contains(".cargo/config.toml");
}

#[test]
fn patched_dependency_in_a_manifest_names_the_manifest() {
    let result = run_with_manifest_edit(|manifest| {
        format!("{manifest}\n[patch.crates-io]\ncustody-rs-fixture-x = {{ path = \"x\" }}\n")
    });
    assert_refused_before_cargo(&result);
    result.assert_contains("Cargo.toml");
}

#[test]
fn patch_written_as_a_dotted_key_names_the_manifest() {
    let result = run_with_manifest_edit(|manifest| {
        format!("patch.crates-io.custody-rs-fixture-x = {{ path = \"x\" }}\n\n{manifest}")
    });
    assert_refused_before_cargo(&result);
    result.assert_contains("Cargo.toml");
}

#[test]
fn dependency_replaced_through_a_replace_table_names_the_manifest() {
    let result = run_with_manifest_edit(|manifest| {
        format!("{manifest}\n[replace]\n\"custody-rs-fixture-x:0.1.0\" = {{ path = \"x\" }}\n")
    });
    assert_refused_before_cargo(&result);
    result.assert_contains("Cargo.toml");
}

#[test]
fn manifest_that_cannot_be_parsed_fails_the_run() {
    let result = run_with_manifest_edit(|manifest| format!("{manifest}\nnot valid = = toml\n"));
    assert_refused_before_cargo(&result);
    result.assert_contains("Cargo.toml");
}
