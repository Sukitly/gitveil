pub mod support;

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use support::{GitFixture, assert_success, contains};

const CANARY: &str = "gitveil-secret-security-canary";

fn write(fixture: &GitFixture, path: &str, body: &str) {
    fs::write(fixture.root().join(path), body).expect("write fixture file");
}

/// Snapshot of everything under `.git/` except the private `gitveil/`
/// directory.
fn git_dir_snapshot(root: &Path) -> BTreeMap<String, Vec<u8>> {
    let mut snapshot = BTreeMap::new();
    let git_dir = root.join(".git");
    let mut stack = vec![git_dir.clone()];
    while let Some(directory) = stack.pop() {
        for entry in fs::read_dir(&directory).expect("read .git directory") {
            let entry = entry.expect(".git entry");
            let path = entry.path();
            let relative = path
                .strip_prefix(&git_dir)
                .expect("under .git")
                .to_string_lossy()
                .into_owned();
            if relative == "gitveil" || relative.starts_with("gitveil/") {
                continue;
            }
            if entry.file_type().expect("file type").is_dir() {
                stack.push(path);
            } else {
                snapshot.insert(relative, fs::read(&path).expect("read .git file"));
            }
        }
    }
    snapshot
}

#[test]
fn commands_never_write_to_git_outside_the_private_runtime_directory() {
    let fixture = GitFixture::new();
    fixture.initialize();
    write(&fixture, "secret.env", &format!("A={CANARY}\n"));

    let before = git_dir_snapshot(fixture.root());
    assert_success(fixture.run_gitveil(&["seal"]), "seal");
    assert_success(fixture.run_gitveil(&["status"]), "status");
    fs::remove_file(fixture.root().join("secret.env")).expect("remove plaintext");
    assert_success(fixture.run_gitveil(&["open"]), "open");
    assert_success(fixture.run_gitveil(&["verify"]), "verify");
    let after = git_dir_snapshot(fixture.root());

    let mut differing: Vec<&String> = before
        .iter()
        .filter(|(key, value)| after.get(*key) != Some(value))
        .map(|(key, _)| key)
        .chain(after.keys().filter(|key| !before.contains_key(*key)))
        .collect();
    differing.dedup();
    assert!(
        differing.is_empty(),
        "gitveil must not modify .git outside .git/gitveil; differing: {differing:?}"
    );
    let config = fs::read_to_string(fixture.root().join(".git/config")).expect("git config");
    for section in ["filter", "diff \"gitveil\"", "merge \"gitveil\"", "gitveil"] {
        assert!(
            !config.contains(&format!("[{section}")),
            "no gitveil filter/driver configuration may exist: {config}"
        );
    }
    assert!(
        !fixture.root().join(".gitattributes").exists(),
        "gitveil must not create .gitattributes"
    );
}

#[test]
fn configuration_commands_write_no_git_state_or_secret_output() {
    let fixture = GitFixture::new();
    let before_git = git_dir_snapshot(fixture.root());
    let before_index =
        assert_success(fixture.run_git(&["ls-files", "--stage", "-z"]), "index").stdout;
    let initialized = assert_success(
        fixture.run_gitveil(&["init", "--recipient", fixture.recipient()]),
        "init",
    );
    write(&fixture, ".env", &format!("TOKEN={CANARY}\n"));
    let added = assert_success(
        fixture.run_gitveil(&["add", ".env", "--format", "dotenv"]),
        "add",
    );
    let after_git = git_dir_snapshot(fixture.root());
    let after_index =
        assert_success(fixture.run_git(&["ls-files", "--stage", "-z"]), "index").stdout;

    assert_eq!(
        after_git, before_git,
        "init/add may only write .git/gitveil"
    );
    assert_eq!(
        after_index, before_index,
        "init/add must not write the index"
    );
    for output in [initialized, added] {
        assert!(!contains(&output.stdout, CANARY.as_bytes()));
        assert!(!contains(&output.stderr, CANARY.as_bytes()));
    }
}

#[test]
fn secrets_never_reach_git_objects_baseline_or_reports() {
    let fixture = GitFixture::new();
    fixture.initialize();
    write(
        &fixture,
        "secret.env",
        &format!("# secret comment {CANARY}\nA={CANARY}\n"),
    );
    let sealed = assert_success(fixture.run_gitveil(&["seal"]), "seal");
    assert!(!contains(&sealed.stdout, CANARY.as_bytes()));
    assert!(!contains(&sealed.stderr, CANARY.as_bytes()));

    assert_success(
        fixture.run_git(&["add", "secret.env.gitveil"]),
        "git add ciphertext",
    );
    assert_success(fixture.run_git(&["commit", "-qm", "seal"]), "commit");

    // Every reachable git object is free of the canary.
    let objects = assert_success(
        fixture.run_git(&["cat-file", "--batch-all-objects", "--batch"]),
        "dump git objects",
    );
    assert!(
        !contains(&objects.stdout, CANARY.as_bytes()),
        "plaintext must never enter the object database"
    );

    // Baseline state stores digests, not values or comments.
    for entry in fs::read_dir(fixture.state_dir()).expect("state directory") {
        let entry = entry.expect("state entry");
        let bytes = fs::read(entry.path()).expect("read baseline record");
        assert!(
            !contains(&bytes, CANARY.as_bytes()),
            "baseline records must not contain plaintext"
        );
    }

    // Status and verify reports never render values.
    let status = fixture.run_gitveil(&["status"]);
    assert!(!contains(&status.stdout, CANARY.as_bytes()));
    let verify = fixture.run_gitveil(&["verify"]);
    assert!(!contains(&verify.stdout, CANARY.as_bytes()));
}

#[test]
fn symlinked_managed_paths_are_rejected() {
    let fixture = GitFixture::new();
    fixture.initialize();
    write(&fixture, "outside.env", "A=target\n");
    std::os::unix::fs::symlink(
        fixture.root().join("outside.env"),
        fixture.root().join("secret.env"),
    )
    .expect("create symlink");
    let sealed = fixture.run_gitveil(&["seal"]);
    assert_eq!(sealed.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&sealed.stderr).contains("secret.env"),
        "symlink rejection must name the path"
    );
    assert!(
        !fixture.root().join("secret.env.gitveil").exists(),
        "no ciphertext may be produced for a symlinked plaintext"
    );
}
