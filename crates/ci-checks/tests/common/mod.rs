#![allow(dead_code)]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};

pub const ADVISORY_ID: &str = "RUSTSEC-2023-0001";
pub const VULN_CRATE: &str = "custody-rs-fixture-vuln";
// cargo-deny names a database folder after a hash of this URL, which check.sh puts in its temp config.
const ADVISORY_DB_URL: &str = "https://example.invalid/advisory-db";
const ADVISORY_DB_FOLDER: &str = "advisory-db-79ba8843f8f3e7ce";
const CRATES_IO: &str = "registry+https://github.com/rust-lang/crates.io-index";
const GIT_IDENTITY: [&str; 6] = [
    "-c",
    "user.name=fixture",
    "-c",
    "user.email=fixture@example.invalid",
    "-c",
    "commit.gpgsign=false",
];

static COUNTER: AtomicU32 = AtomicU32::new(0);

pub fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("repository root exists")
}

pub struct Scratch(PathBuf);

impl Scratch {
    pub fn new(label: &str) -> Scratch {
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!(
            "custody-rs-ci-checks-{}-{}-{}",
            std::process::id(),
            n,
            label
        ));
        fs::create_dir_all(&dir).expect("create scratch directory");
        Scratch(dir.canonicalize().expect("canonicalize scratch directory"))
    }

    pub fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

pub fn copy_dir(from: &Path, to: &Path) {
    fs::create_dir_all(to).expect("create destination directory");
    for entry in fs::read_dir(from).expect("read source directory") {
        let entry = entry.expect("read directory entry");
        let target = to.join(entry.file_name());
        if entry.file_type().expect("file type").is_dir() {
            copy_dir(&entry.path(), &target);
        } else {
            fs::copy(entry.path(), &target).expect("copy file");
        }
    }
}

pub fn stage(fixture: &str) -> Scratch {
    let source = repo_root()
        .join("crates/ci-checks/tests/fixtures")
        .join(fixture);
    assert!(source.is_dir(), "missing fixture {fixture}");
    let scratch = Scratch::new(fixture);
    copy_dir(&source, scratch.path());
    fs::copy(
        repo_root().join("rust-toolchain.toml"),
        scratch.path().join("rust-toolchain.toml"),
    )
    .expect("copy rust-toolchain.toml");
    scratch
}

pub fn replace_once(text: &str, from: &str, to: &str) -> String {
    assert_eq!(
        text.matches(from).count(),
        1,
        "expected exactly one occurrence of {from:?}"
    );
    text.replacen(from, to, 1)
}

pub fn write_file(path: &Path, content: &str) {
    fs::create_dir_all(path.parent().expect("file has a parent")).expect("create parent");
    fs::write(path, content).expect("write file");
}

pub struct Run {
    pub success: bool,
    pub text: String,
}

impl Run {
    pub fn assert_passed(&self) {
        assert!(self.success, "expected success, output:\n{}", self.text);
        assert!(
            self.text
                .contains("all checks passed: policy build fmt clippy test deny"),
            "missing pass line, output:\n{}",
            self.text
        );
    }

    pub fn assert_failed_at(&self, check: &str) {
        assert!(!self.success, "expected failure, output:\n{}", self.text);
        assert!(
            self.text.contains(&format!("FAILED: {check}")),
            "expected FAILED: {check}, output:\n{}",
            self.text
        );
        assert!(
            !self.text.contains("all checks passed"),
            "unexpected pass line, output:\n{}",
            self.text
        );
    }

    pub fn assert_contains(&self, needle: &str) {
        assert!(
            self.text.contains(needle),
            "expected output to contain {needle:?}, output:\n{}",
            self.text
        );
    }

    pub fn assert_not_contains(&self, needle: &str) {
        assert!(
            !self.text.contains(needle),
            "expected output not to contain {needle:?}, output:\n{}",
            self.text
        );
    }
}

#[derive(Default)]
pub struct Options<'a> {
    pub script_root: Option<&'a Path>,
    pub cargo_home: Option<&'a Path>,
    pub ci: bool,
    pub env: Vec<(&'a str, &'a str)>,
    pub skip_advisory_db: bool,
}

pub fn run(workspace: &Path) -> Run {
    run_with(workspace, &Options::default())
}

pub fn run_with(workspace: &Path, options: &Options) -> Run {
    let root = options
        .script_root
        .map(Path::to_path_buf)
        .unwrap_or_else(repo_root);
    let scratch = Scratch::new("advisory-db");
    let mut command = Command::new("bash");
    command
        .arg(root.join("ci/check.sh"))
        .arg(workspace)
        .current_dir(&root)
        .env_remove("CI");
    if options.ci {
        command.env("CI", "true");
    }
    if !options.skip_advisory_db {
        let db = advisory_db(scratch.path());
        command.env("CI_CHECK_ADVISORY_DB", &db.root);
    }
    if let Some(home) = options.cargo_home {
        command.env("CARGO_HOME", home);
    }
    for (key, value) in &options.env {
        command.env(key, value);
    }
    let output = command.output().expect("bash can run ci/check.sh");
    Run {
        success: output.status.success(),
        text: format!(
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ),
    }
}

struct AdvisoryDb {
    root: PathBuf,
}

fn git(dir: &Path, args: &[&str]) -> String {
    let output = Command::new("git")
        .args(args)
        .current_dir(dir)
        .output()
        .expect("git is available");
    assert!(
        output.status.success(),
        "git {args:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).trim().to_string()
}

fn git_commit_all(dir: &Path) -> String {
    git(dir, &["-c", "init.defaultBranch=main", "init", "-q"]);
    git(dir, &["add", "."]);
    let mut args: Vec<&str> = GIT_IDENTITY.to_vec();
    args.extend(["commit", "-q", "-m", "fixture"]);
    git(dir, &args);
    git(dir, &["rev-parse", "HEAD"])
}

fn advisory_markdown() -> String {
    format!(
        "```toml\n[advisory]\nid = \"{ADVISORY_ID}\"\npackage = \"{VULN_CRATE}\"\n\
         date = \"2023-01-01\"\nurl = \"https://example.invalid/{ADVISORY_ID}\"\n\
         categories = [\"code-execution\"]\nkeywords = [\"fixture\"]\n\n\
         [versions]\npatched = [\">= 1.0.0\"]\n```\n\n# Fixture advisory\n\n\
         Test-only advisory for a fixture crate.\n"
    )
}

fn advisory_db(scratch: &Path) -> AdvisoryDb {
    let repo = scratch.join("advisory-repo");
    write_file(
        &repo
            .join("crates")
            .join(VULN_CRATE)
            .join(format!("{ADVISORY_ID}.md")),
        &advisory_markdown(),
    );
    git_commit_all(&repo);

    let root = scratch.join("advisory-db");
    fs::create_dir_all(&root).expect("create advisory db root");
    let repo_arg = repo.display().to_string();
    let target = root.join(ADVISORY_DB_FOLDER);
    let target_arg = target.display().to_string();
    git(scratch, &["clone", "-q", &repo_arg, &target_arg]);
    AdvisoryDb { root }
}

pub struct Registry {
    pub cargo_home: PathBuf,
    vendor: PathBuf,
}

pub fn registry(scratch: &Path) -> Registry {
    let cargo_home = scratch.join("cargo-home");
    let vendor = scratch.join("vendor");
    fs::create_dir_all(&vendor).expect("create vendor directory");
    write_file(
        &cargo_home.join("config.toml"),
        &format!(
            "[source.crates-io]\nreplace-with = \"vendored\"\n\n\
             [source.vendored]\ndirectory = \"{}\"\n",
            vendor.display()
        ),
    );
    Registry { cargo_home, vendor }
}

fn checksum() -> String {
    "a".repeat(64)
}

impl Registry {
    pub fn add_crate(&self, name: &str, license: &str) {
        let dir = self.vendor.join(name);
        write_file(
            &dir.join("Cargo.toml"),
            &format!(
                "[package]\nname = \"{name}\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\
                 license = \"{license}\"\n"
            ),
        );
        write_file(&dir.join("src/lib.rs"), "pub fn marker() {}\n");
        write_file(
            &dir.join(".cargo-checksum.json"),
            &format!("{{\"files\":{{}},\"package\":\"{}\"}}", checksum()),
        );
    }
}

fn lock_header(dependencies: &[&str]) -> String {
    let mut lock = String::from(
        "# This file is automatically @generated by Cargo.\n\
         # It is not intended for manual editing.\nversion = 4\n\n\
         [[package]]\nname = \"app\"\nversion = \"0.1.0\"\ndependencies = [\n",
    );
    for dependency in dependencies {
        lock.push_str(&format!(" \"{dependency}\",\n"));
    }
    lock.push_str("]\n");
    lock
}

pub fn write_registry_lock(workspace: &Path, dependencies: &[&str]) {
    let mut lock = lock_header(dependencies);
    for dependency in dependencies {
        lock.push_str(&format!(
            "\n[[package]]\nname = \"{dependency}\"\nversion = \"0.1.0\"\n\
             source = \"{CRATES_IO}\"\nchecksum = \"{}\"\n",
            checksum()
        ));
    }
    write_file(&workspace.join("Cargo.lock"), &lock);
}

pub struct Prepared {
    pub workspace: Scratch,
    infra: Scratch,
    registry: Registry,
}

pub fn prepare_registry(fixture: &str, crates: &[(&str, &str)]) -> Prepared {
    let workspace = stage(fixture);
    let infra = Scratch::new("registry");
    let registry = registry(infra.path());
    for (name, license) in crates {
        registry.add_crate(name, license);
    }
    let names: Vec<&str> = crates.iter().map(|(name, _)| *name).collect();
    write_registry_lock(workspace.path(), &names);
    Prepared {
        workspace,
        infra,
        registry,
    }
}

impl Prepared {
    pub fn infra(&self) -> &Path {
        self.infra.path()
    }

    pub fn run(&self) -> Run {
        self.run_from(None)
    }

    pub fn run_from(&self, script_root: Option<&Path>) -> Run {
        run_with(
            self.workspace.path(),
            &Options {
                script_root,
                cargo_home: Some(&self.registry.cargo_home),
                ..Options::default()
            },
        )
    }
}

pub fn checkout_with_deny(scratch: &Path, edit: impl Fn(&str) -> String) -> PathBuf {
    let root = scratch.join("checkout");
    copy_dir(&repo_root().join("ci"), &root.join("ci"));
    fs::copy(repo_root().join("rust-toolchain.toml"), {
        fs::create_dir_all(&root).expect("create checkout");
        root.join("rust-toolchain.toml")
    })
    .expect("copy rust-toolchain.toml");
    let deny = fs::read_to_string(repo_root().join("deny.toml")).expect("read deny.toml");
    write_file(&root.join("deny.toml"), &edit(&deny));
    root
}

pub struct GitDependency {
    pub repo: PathBuf,
    pub revision: String,
}

pub fn git_dependency(scratch: &Path, name: &str) -> GitDependency {
    let repo = scratch.join("git-dependency");
    write_file(
        &repo.join("Cargo.toml"),
        &format!(
            "[package]\nname = \"{name}\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\
             license = \"MIT\"\n"
        ),
    );
    write_file(&repo.join("src/lib.rs"), "pub fn marker() {}\n");
    let revision = git_commit_all(&repo);
    GitDependency { repo, revision }
}

pub fn write_git_lock(workspace: &Path, name: &str, dependency: &GitDependency) {
    let mut lock = lock_header(&[name]);
    lock.push_str(&format!(
        "\n[[package]]\nname = \"{name}\"\nversion = \"0.1.0\"\n\
         source = \"git+file://{}#{}\"\n",
        dependency.repo.display(),
        dependency.revision
    ));
    write_file(&workspace.join("Cargo.lock"), &lock);
}
