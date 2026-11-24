mod common;

use common::{
    Options, Scratch, git_dependency, prepare_registry, replace_once, run_with, stage, write_file,
    write_git_lock,
};
use std::fs;

const GPL_CRATE: &str = "custody-rs-fixture-gpl";
const GIT_CRATE: &str = "custody-rs-fixture-git";
const OUTSIDE_CRATE: &str = "custody-rs-fixture-outside";

#[test]
fn dependency_with_a_disallowed_licence_names_the_crate_and_the_licence() {
    let prepared = prepare_registry("gpl-licence", &[(GPL_CRATE, "GPL-3.0-only")]);
    let result = prepared.run();
    result.assert_failed_at("deny");
    result.assert_contains(GPL_CRATE);
    result.assert_contains("GPL-3.0-only");
}

#[test]
fn dependency_from_a_git_source_names_the_crate_and_the_source() {
    let workspace = stage("git-source");
    let infra = Scratch::new("git");
    let dependency = git_dependency(infra.path(), GIT_CRATE);
    let manifest = workspace.path().join("Cargo.toml");
    let text = fs::read_to_string(&manifest).unwrap();
    write_file(
        &manifest,
        &replace_once(&text, "@GIT_REPO@", &dependency.repo.display().to_string()),
    );
    write_git_lock(workspace.path(), GIT_CRATE, &dependency);
    let cargo_home = infra.path().join("cargo-home");
    fs::create_dir_all(&cargo_home).unwrap();

    let result = run_with(
        workspace.path(),
        &Options {
            cargo_home: Some(&cargo_home),
            ..Options::default()
        },
    );
    result.assert_failed_at("deny");
    result.assert_contains(GIT_CRATE);
    result.assert_contains(&dependency.repo.display().to_string());
}

#[test]
fn path_dependency_outside_the_workspace_names_the_crate_and_the_path() {
    let stage = stage("path-dependency");
    let result = common::run(&stage.path().join("workspace"));
    result.assert_failed_at("deny");
    result.assert_contains(OUTSIDE_CRATE);
    result.assert_contains("outside-crate");
}

#[test]
fn path_dependency_behind_a_non_default_feature_names_the_crate_and_the_path() {
    let stage = stage("feature-path-dependency");
    let result = common::run(&stage.path().join("workspace"));
    result.assert_failed_at("deny");
    result.assert_contains(OUTSIDE_CRATE);
    result.assert_contains("outside-crate");
}
