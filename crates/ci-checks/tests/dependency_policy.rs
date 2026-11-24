mod common;

use common::{Options, Scratch, checkout_with_deny, replace_once, run_with, stage};

fn run_clean_with_deny(edit: impl Fn(&str) -> String) -> common::Run {
    let workspace = stage("clean");
    let infra = Scratch::new("checkout");
    let checkout = checkout_with_deny(infra.path(), edit);
    run_with(
        workspace.path(),
        &Options {
            script_root: Some(&checkout),
            ..Options::default()
        },
    )
}

#[test]
fn setting_added_to_the_dependency_policy_fails_and_names_the_setting() {
    let result = run_clean_with_deny(|deny| {
        replace_once(
            deny,
            "[advisories]\n",
            "[advisories]\ndb-urls = [\"https://example.invalid/stale-db\"]\n",
        )
    });
    result.assert_failed_at("policy");
    result.assert_contains("advisories.db-urls");
    result.assert_not_contains("check: build");
}

#[test]
fn setting_changed_in_the_dependency_policy_fails_and_names_the_setting() {
    let result =
        run_clean_with_deny(|deny| replace_once(deny, "yanked = \"deny\"", "yanked = \"allow\""));
    result.assert_failed_at("policy");
    result.assert_contains("advisories.yanked");
    result.assert_not_contains("check: build");
}
