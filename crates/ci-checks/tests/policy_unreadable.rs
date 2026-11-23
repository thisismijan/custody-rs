mod common;

use common::{run, stage};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

struct RestoreOnDrop(PathBuf);

impl Drop for RestoreOnDrop {
    fn drop(&mut self) {
        let _ = fs::set_permissions(&self.0, fs::Permissions::from_mode(0o755));
    }
}

#[test]
fn unreadable_directory_fails_the_policy_step() {
    let workspace = stage("clean");
    let locked = workspace.path().join("locked-dir");
    fs::create_dir(&locked).unwrap();
    fs::set_permissions(&locked, fs::Permissions::from_mode(0o000)).unwrap();
    let _restore = RestoreOnDrop(locked);

    let result = run(workspace.path());

    result.assert_failed_at("policy");
    result.assert_contains("locked-dir");
    result.assert_not_contains("check: build");
}
