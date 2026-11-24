mod common;

use common::{VULN_CRATE, prepare_registry, write_file};

#[test]
fn dependency_checks_fail_before_any_workspace_code_is_compiled() {
    let prepared = prepare_registry("advisory", &[(VULN_CRATE, "MIT")]);
    let marker = prepared.workspace.path().join("build-ran.marker");
    write_file(
        &prepared.workspace.path().join("build.rs"),
        "fn main() {\n    let dir = std::env::var(\"CARGO_MANIFEST_DIR\").unwrap();\n    \
         std::fs::write(std::path::Path::new(&dir).join(\"build-ran.marker\"), \"ran\").unwrap();\n}\n",
    );

    let result = prepared.run();

    result.assert_failed_at("deny");
    result.assert_not_contains("check: build");
    assert!(
        !marker.exists(),
        "the build script ran before the dependency check"
    );
}
