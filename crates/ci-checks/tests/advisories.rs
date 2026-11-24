mod common;

use common::{ADVISORY_ID, VULN_CRATE, checkout_with_deny, prepare_registry, replace_once};

const IGNORE_LINE: &str = "ignore = []";

fn run_with_ignore(fixture: &str, ignore: &str) -> common::Run {
    let prepared = prepare_registry(fixture, &[(VULN_CRATE, "MIT")]);
    let checkout = checkout_with_deny(prepared.infra(), |deny| {
        replace_once(deny, IGNORE_LINE, ignore)
    });
    prepared.run_from(Some(&checkout))
}

#[test]
fn dependency_with_a_known_advisory_names_the_crate_and_the_advisory() {
    let prepared = prepare_registry("advisory", &[(VULN_CRATE, "MIT")]);
    let result = prepared.run();
    result.assert_failed_at("deny");
    result.assert_contains(VULN_CRATE);
    result.assert_contains(ADVISORY_ID);
}

#[test]
fn advisory_ignored_with_a_reason_passes() {
    let entry = format!("ignore = [{{ id = \"{ADVISORY_ID}\", reason = \"fixture accepts it\" }}]");
    run_with_ignore("advisory", &entry).assert_passed();
}

#[test]
fn advisory_ignored_without_a_reason_fails_and_names_the_entry() {
    let entry = format!("ignore = [{{ id = \"{ADVISORY_ID}\" }}]");
    let result = run_with_ignore("advisory", &entry);
    result.assert_failed_at("policy");
    result.assert_contains(ADVISORY_ID);
    result.assert_not_contains("check: build");
}

#[test]
fn advisory_ignored_with_a_blank_reason_fails_and_names_the_entry() {
    let entry = format!("ignore = [{{ id = \"{ADVISORY_ID}\", reason = \"   \" }}]");
    let result = run_with_ignore("advisory", &entry);
    result.assert_failed_at("policy");
    result.assert_contains(ADVISORY_ID);
}

#[test]
fn advisory_ignored_as_a_bare_id_fails_and_names_the_entry() {
    let entry = format!("ignore = [\"{ADVISORY_ID}\"]");
    let result = run_with_ignore("advisory", &entry);
    result.assert_failed_at("policy");
    result.assert_contains(ADVISORY_ID);
    result.assert_not_contains("check: build");
}

#[test]
fn advisory_on_a_dependency_behind_a_non_default_feature_names_the_crate_and_the_advisory() {
    let prepared = prepare_registry("feature-advisory", &[(VULN_CRATE, "MIT")]);
    let result = prepared.run();
    result.assert_failed_at("deny");
    result.assert_contains(VULN_CRATE);
    result.assert_contains(ADVISORY_ID);
}
