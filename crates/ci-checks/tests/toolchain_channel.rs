mod common;

use common::{Scratch, repo_root, write_file};
use std::path::Path;
use std::process::Command;

struct Outcome {
    success: bool,
    stdout: String,
    stderr: String,
}

fn channel_of(file: &Path) -> Outcome {
    let output = Command::new("bash")
        .arg(repo_root().join("ci/toolchain-channel.sh"))
        .arg(file)
        .output()
        .expect("bash can run ci/toolchain-channel.sh");
    Outcome {
        success: output.status.success(),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    }
}

fn channel_of_text(text: &str) -> Outcome {
    let scratch = Scratch::new("toolchain-channel");
    let file = scratch.path().join("rust-toolchain.toml");
    write_file(&file, text);
    channel_of(&file)
}

fn assert_rejected(outcome: &Outcome) {
    assert!(
        !outcome.success,
        "expected failure, stdout:\n{}",
        outcome.stdout
    );
    assert_eq!(outcome.stdout, "");
    assert!(
        !outcome.stderr.trim().is_empty(),
        "expected a message on stderr"
    );
}

#[test]
fn repository_toolchain_file_prints_the_pinned_channel() {
    let outcome = channel_of(&repo_root().join("rust-toolchain.toml"));
    assert!(outcome.success, "stderr:\n{}", outcome.stderr);
    assert_eq!(outcome.stdout.trim_end(), "1.100.0");
    assert_eq!(outcome.stdout.trim_end().lines().count(), 1);
}

#[test]
fn single_channel_in_the_toolchain_table_prints_that_value() {
    let outcome = channel_of_text(
        "[toolchain]\nchannel = \"1.99.2\"\ncomponents = [\"rustfmt\", \"clippy\"]\n",
    );
    assert!(outcome.success, "stderr:\n{}", outcome.stderr);
    assert_eq!(outcome.stdout.trim_end(), "1.99.2");
}

#[test]
fn second_channel_line_under_another_table_is_rejected() {
    let outcome = channel_of_text(
        "[toolchain]\nchannel = \"1.100.0\"\n\n[other]\nchannel = \"PATH=/evil\"\n",
    );
    assert_rejected(&outcome);
}

#[test]
fn channel_value_with_a_disallowed_character_is_rejected() {
    let outcome = channel_of_text("[toolchain]\nchannel = \"1.100.0;x\"\n");
    assert_rejected(&outcome);
}

#[test]
fn file_without_a_channel_is_rejected() {
    let outcome = channel_of_text("[toolchain]\ncomponents = [\"rustfmt\"]\n");
    assert_rejected(&outcome);
}

#[test]
fn channel_under_a_commented_other_header_is_rejected() {
    let outcome = channel_of_text(
        "[toolchain]\ncomponents = []\n\n[other] # comment\nchannel = \"1.100.0\"\n",
    );
    assert_rejected(&outcome);
}

#[test]
fn every_valid_toml_spelling_of_the_channel_is_read() {
    let spellings = [
        "[ toolchain ]\nchannel = \"1.99.2\"\n",
        "[toolchain] # pinned\nchannel = \"1.99.2\"\n",
        "[toolchain]\nchannel=\"1.99.2\"\n",
        "[toolchain]\nchannel = '1.99.2'\n",
        "[toolchain]\n\"channel\" = \"1.99.2\"\n",
        "[toolchain]\nchannel = \"1.99.2\" # pinned\n",
        "toolchain.channel = \"1.99.2\"\n",
        "toolchain = { channel = \"1.99.2\" }\n",
    ];
    for text in spellings {
        let outcome = channel_of_text(text);
        assert!(
            outcome.success,
            "input:\n{text}\nstderr:\n{}",
            outcome.stderr
        );
        assert_eq!(outcome.stdout, "1.99.2\n", "input:\n{text}");
    }
}
