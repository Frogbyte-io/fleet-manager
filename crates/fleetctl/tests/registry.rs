//! `fleetctl registry` (FM-1013): CLI contract tests over a temporary Git
//! repository, driving the real binary. `gh` is stubbed through PATH.

use std::{
    fs,
    io::Write as _,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

use serde_json::Value;

struct Out {
    code: i32,
    stdout: String,
    stderr: String,
}

fn run(dir: &Path, path_prefix: Option<&Path>, stdin: Option<&str>, args: &[&str]) -> Out {
    let mut command = Command::new(env!("CARGO_BIN_EXE_fleetctl"));
    command
        .current_dir(dir)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(prefix) = path_prefix {
        let old = std::env::var("PATH").unwrap_or_default();
        command.env("PATH", format!("{}:{old}", prefix.display()));
    }
    let mut child = command.spawn().expect("spawn fleetctl");
    if let Some(input) = stdin {
        child
            .stdin
            .take()
            .unwrap()
            .write_all(input.as_bytes())
            .unwrap();
    } else {
        drop(child.stdin.take());
    }
    let output = child.wait_with_output().unwrap();
    Out {
        code: output.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    }
}

fn git(dir: &Path, args: &[&str]) -> String {
    let output = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(["-c", "user.name=Test", "-c", "user.email=test@example.com"])
        .args(args)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).into_owned()
}

/// A working checkout with a bare `origin` and one commit on `main`.
fn repo() -> (tempfile::TempDir, PathBuf, PathBuf) {
    let temp = tempfile::tempdir().unwrap();
    let remote = temp.path().join("origin.git");
    let work = temp.path().join("work");
    fs::create_dir_all(&work).unwrap();
    let out = Command::new("git")
        .args(["init", "--bare", "-b", "main"])
        .arg(&remote)
        .output()
        .unwrap();
    assert!(out.status.success());
    git(&work, &["init", "-b", "main"]);
    git(&work, &["config", "user.name", "Test"]);
    git(&work, &["config", "user.email", "test@example.com"]);
    fs::write(work.join("README.md"), "fleet\n").unwrap();
    git(&work, &["add", "."]);
    git(&work, &["commit", "-m", "init"]);
    git(
        &work,
        &["remote", "add", "origin", remote.to_str().unwrap()],
    );
    git(&work, &["push", "origin", "main"]);
    git(&work, &["remote", "set-head", "origin", "main"]);
    (temp, work, remote)
}

fn entry_path(work: &Path) -> PathBuf {
    work.join("fleet/registry/domain/example.com.yaml")
}

#[test]
fn set_creates_patches_and_is_idempotent() {
    let (_temp, work, _) = repo();
    let created = run(
        &work,
        None,
        None,
        &[
            "--output",
            "json",
            "registry",
            "set",
            "domain/example.com",
            "--field",
            "registrar=Webhuset",
            "--field",
            "autoRenew=true",
        ],
    );
    assert_eq!(created.code, 0, "{}{}", created.stdout, created.stderr);
    let result: Value = serde_json::from_str(&created.stdout).unwrap();
    assert_eq!(result["created"], true);
    assert_eq!(result["path"], "fleet/registry/domain/example.com.yaml");
    let text = fs::read_to_string(entry_path(&work)).unwrap();
    assert!(text.contains("kind: RegistryEntry"), "{text}");
    assert!(text.contains("name: domain-example-com"), "{text}");
    assert!(text.contains("fqdn: example.com"), "{text}");
    assert_eq!(run(&work, None, None, &["registry", "validate"]).code, 0);

    // Idempotent: the same command again changes nothing.
    let again = run(
        &work,
        None,
        None,
        &[
            "registry",
            "set",
            "domain/example.com",
            "--field",
            "registrar=Webhuset",
        ],
    );
    assert_eq!(again.code, 0, "{}", again.stderr);
    assert_eq!(fs::read_to_string(entry_path(&work)).unwrap(), text);
    assert!(again.stdout.contains("up to date"), "{}", again.stdout);

    // Patch keeps comments, key order, and untouched fields.
    let commented = text.replace("fields:", "# hand-written note\n  fields:");
    fs::write(entry_path(&work), &commented).unwrap();
    let patched = run(
        &work,
        None,
        None,
        &[
            "registry",
            "set",
            "domain/example.com",
            "--field",
            "dnsHost=Cloudflare",
        ],
    );
    assert_eq!(patched.code, 0, "{}{}", patched.stdout, patched.stderr);
    let after = fs::read_to_string(entry_path(&work)).unwrap();
    assert!(after.contains("# hand-written note"), "{after}");
    assert!(after.contains("dnsHost: Cloudflare"), "{after}");
    assert!(after.contains("registrar: Webhuset"), "{after}");
    assert!(patched.stdout.contains("updated"), "{}", patched.stdout);
}

#[test]
#[allow(clippy::too_many_lines)]
fn set_from_json_unset_tags_relate_and_rm() {
    let (_temp, work, _) = repo();
    let created = run(
        &work,
        None,
        Some(r#"{"fields":{"registrar":"Porkbun"},"notes":"Moved in 2025.","tags":["client-x"]}"#),
        &["registry", "set", "domain/example.com", "--from-json", "-"],
    );
    assert_eq!(created.code, 0, "{}{}", created.stdout, created.stderr);
    let service = run(
        &work,
        None,
        None,
        &[
            "registry",
            "set",
            "service/aptabase",
            "--field",
            "name=Aptabase",
        ],
    );
    assert_eq!(service.code, 0, "{}{}", service.stdout, service.stderr);

    let tag = run(
        &work,
        None,
        None,
        &["registry", "tags", "add", "domain/example.com", "prod"],
    );
    assert_eq!(tag.code, 0, "{}{}", tag.stdout, tag.stderr);
    let text = fs::read_to_string(entry_path(&work)).unwrap();
    assert!(text.contains("client-x") && text.contains("prod"), "{text}");
    let untag = run(
        &work,
        None,
        None,
        &[
            "registry",
            "tags",
            "rm",
            "domain/example.com",
            "prod",
            "client-x",
        ],
    );
    assert_eq!(untag.code, 0, "{}{}", untag.stdout, untag.stderr);
    assert!(
        !fs::read_to_string(entry_path(&work))
            .unwrap()
            .contains("tags")
    );

    let relate = run(
        &work,
        None,
        None,
        &[
            "registry",
            "relate",
            "domain/example.com",
            "used-by",
            "service/aptabase",
        ],
    );
    assert_eq!(relate.code, 0, "{}{}", relate.stdout, relate.stderr);
    let text = fs::read_to_string(entry_path(&work)).unwrap();
    assert!(
        text.contains("used-by") && text.contains("service/aptabase"),
        "{text}"
    );
    let repeat = run(
        &work,
        None,
        None,
        &[
            "registry",
            "relate",
            "domain/example.com",
            "used-by",
            "service/aptabase",
        ],
    );
    assert!(repeat.stdout.contains("up to date"), "{}", repeat.stdout);
    assert_eq!(fs::read_to_string(entry_path(&work)).unwrap(), text);
    assert_eq!(run(&work, None, None, &["registry", "validate"]).code, 0);

    let unset = run(
        &work,
        None,
        None,
        &[
            "registry",
            "unset",
            "domain/example.com",
            "--field",
            "registrar",
            "--notes",
        ],
    );
    assert_eq!(unset.code, 0, "{}{}", unset.stdout, unset.stderr);
    let text = fs::read_to_string(entry_path(&work)).unwrap();
    assert!(
        !text.contains("registrar") && !text.contains("notes"),
        "{text}"
    );
    // The key field cannot be unset.
    let key = run(
        &work,
        None,
        None,
        &["registry", "unset", "domain/example.com", "--field", "fqdn"],
    );
    assert_ne!(key.code, 0);

    // rm reports who still points at it.
    let removed = run(&work, None, None, &["registry", "rm", "service/aptabase"]);
    assert_eq!(removed.code, 0, "{}{}", removed.stdout, removed.stderr);
    assert!(
        removed.stdout.contains("still referenced"),
        "{}",
        removed.stdout
    );
    assert!(!work.join("fleet/registry/service").exists());
}

#[test]
fn invalid_and_credential_values_are_refused_before_anything_is_written() {
    let (_temp, work, _) = repo();
    for args in [
        vec!["--field", "autoRenew=maybe"],
        vec!["--field", "nonexistent=1"],
        vec![
            "--field",
            "loginAt=api_key=0123456789abcdef0123456789abcdef",
        ],
        vec!["--notes", "password=hunter2hunter2hunter2"],
        vec!["--field", "expires=not-a-date"],
        vec!["--field", "fqdn=other.com"],
    ] {
        let mut full = vec!["registry", "set", "domain/example.com"];
        full.extend(args.iter());
        let out = run(&work, None, None, &full);
        assert_ne!(out.code, 0, "{args:?}: {}", out.stdout);
        let shown = format!("{}{}", out.stdout, out.stderr);
        assert!(!shown.contains("0123456789abcdef"), "{shown}");
        assert!(!shown.contains("hunter2"), "{shown}");
        assert!(!work.join("fleet").exists(), "{args:?} wrote a file");
    }
    // Keys that are not a single safe path component are refused.
    for key in ["domain/../x", "domain/a/b", "domain/.hidden", "domain/"] {
        assert_ne!(
            run(&work, None, None, &["registry", "set", key]).code,
            0,
            "{key}"
        );
    }
    assert_ne!(
        run(&work, None, None, &["registry", "set", "nosuchtype/x"]).code,
        0
    );
    assert!(!work.join("fleet").exists());
}

#[test]
fn validate_prints_diagnostics_and_exits_nonzero() {
    let (_temp, work, _) = repo();
    assert_eq!(run(&work, None, None, &["registry", "validate"]).code, 0);
    fs::create_dir_all(work.join("fleet/registry/domain")).unwrap();
    fs::write(
        work.join("fleet/registry/domain/bad.yaml"),
        "apiVersion: fleet.frogbyte.io/v1alpha1\nkind: RegistryEntry\nmetadata:\n  id: 01890f3e-9b4a-7cc2-98c3-d24e8f58d001\n  name: domain-bad\nspec:\n  type: domain\n  fields:\n    registrar: Nowhere\n",
    )
    .unwrap();
    let out = run(
        &work,
        None,
        None,
        &["--output", "json", "registry", "validate"],
    );
    assert_eq!(out.code, 1, "{}", out.stderr);
    let report: Value = serde_json::from_str(&out.stdout).unwrap();
    assert_eq!(report["valid"], false);
    assert!(
        report["errors"][0]["code"]
            .as_str()
            .unwrap()
            .starts_with("FM_SCHEMA_"),
        "{report}"
    );
    let text = run(&work, None, None, &["registry", "validate"]);
    assert_eq!(text.code, 1);
    assert!(text.stdout.contains("[FM_SCHEMA_"), "{}", text.stdout);
}

#[test]
fn publish_direct_pushes_to_the_default_branch_and_refuses_unrelated_staged_changes() {
    let (_temp, work, remote) = repo();
    run(
        &work,
        None,
        None,
        &[
            "registry",
            "set",
            "domain/example.com",
            "--field",
            "registrar=Webhuset",
        ],
    );

    // An unrelated staged change blocks the publish.
    fs::write(work.join("other.txt"), "x").unwrap();
    git(&work, &["add", "other.txt"]);
    let refused = run(
        &work,
        None,
        None,
        &["registry", "publish", "-m", "x", "--change-mode", "direct"],
    );
    assert_ne!(refused.code, 0);
    assert!(
        refused.stderr.contains("not Registry content"),
        "{}",
        refused.stderr
    );
    git(&work, &["restore", "--staged", "other.txt"]);

    let out = run(
        &work,
        None,
        None,
        &[
            "--output",
            "json",
            "registry",
            "publish",
            "-m",
            "example.com registrar",
            "--change-mode",
            "direct",
        ],
    );
    assert_eq!(out.code, 0, "{}{}", out.stdout, out.stderr);
    let result: Value = serde_json::from_str(&out.stdout).unwrap();
    assert_eq!(result["published"], true);
    assert_eq!(result["mode"], "direct");
    let head = git(&work, &["rev-parse", "HEAD"]);
    assert_eq!(git(&remote, &["rev-parse", "main"]), head);
    // The unrelated untracked file was not committed.
    assert!(!git(&work, &["show", "--stat", "HEAD"]).contains("other.txt"));

    // Nothing left to publish.
    let again = run(
        &work,
        None,
        None,
        &["registry", "publish", "-m", "x", "--change-mode", "direct"],
    );
    assert_eq!(again.code, 0);
    assert!(
        again.stdout.contains("nothing published"),
        "{}",
        again.stdout
    );
}

#[test]
fn publish_refuses_an_invalid_tree() {
    let (_temp, work, _) = repo();
    fs::create_dir_all(work.join("fleet/registry/domain")).unwrap();
    fs::write(work.join("fleet/registry/domain/bad.yaml"), "kind: nope\n").unwrap();
    let out = run(
        &work,
        None,
        None,
        &["registry", "publish", "-m", "x", "--change-mode", "direct"],
    );
    assert_ne!(out.code, 0);
    assert!(out.stderr.contains("validation error"), "{}", out.stderr);
}

#[cfg(unix)]
fn stub_gh(dir: &Path, script: &str) {
    use std::os::unix::fs::PermissionsExt as _;
    let path = dir.join("gh");
    fs::write(&path, script).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
}

#[cfg(unix)]
#[test]
fn publish_pull_request_mode_uses_gh_when_available() {
    let (temp, work, remote) = repo();
    let bin = temp.path().join("bin");
    fs::create_dir_all(&bin).unwrap();
    let log = temp.path().join("gh.log");
    stub_gh(
        &bin,
        &format!(
            "#!/bin/sh\nprintf '%s\\n' \"$@\" > '{}'\necho https://github.com/o/r/pull/7\n",
            log.display()
        ),
    );
    run(
        &work,
        None,
        None,
        &[
            "registry",
            "set",
            "domain/example.com",
            "--field",
            "registrar=Webhuset",
        ],
    );
    let out = run(
        &work,
        Some(&bin),
        None,
        &[
            "--output",
            "json",
            "registry",
            "publish",
            "-m",
            "Add example.com",
            "--change-mode",
            "pull-request",
        ],
    );
    assert_eq!(out.code, 0, "{}{}", out.stdout, out.stderr);
    let result: Value = serde_json::from_str(&out.stdout).unwrap();
    assert_eq!(result["pullRequest"], "https://github.com/o/r/pull/7");
    let branch = result["branch"].as_str().unwrap();
    assert!(branch.starts_with("registry/add-example-com-"), "{branch}");
    // The branch is on the remote; main is untouched.
    assert!(git(&remote, &["branch", "--list", branch]).contains(branch));
    assert_ne!(
        git(&remote, &["rev-parse", "main"]),
        git(&work, &["rev-parse", "HEAD"])
    );
    let args = fs::read_to_string(&log).unwrap();
    assert!(args.contains("pr\ncreate"), "{args}");
    assert!(args.contains("--base\nmain"), "{args}");
    assert!(args.contains("Add example.com"), "{args}");
}

#[cfg(unix)]
#[test]
fn publish_pull_request_mode_without_gh_prints_the_compare_url() {
    let (temp, work, _) = repo();
    // A PATH with git but no gh: a directory of symlinks to git only.
    let bin = temp.path().join("bin");
    fs::create_dir_all(&bin).unwrap();
    let git_path = String::from_utf8(Command::new("which").arg("git").output().unwrap().stdout)
        .unwrap()
        .trim()
        .to_owned();
    std::os::unix::fs::symlink(git_path, bin.join("git")).unwrap();
    git(
        &work,
        &[
            "remote",
            "set-url",
            "origin",
            "https://user:tok3n@github.com/o/r.git",
        ],
    );
    git(
        &work,
        &[
            "remote",
            "set-url",
            "--push",
            "origin",
            temp.path().join("origin.git").to_str().unwrap(),
        ],
    );
    run(
        &work,
        None,
        None,
        &[
            "registry",
            "set",
            "domain/example.com",
            "--field",
            "registrar=Webhuset",
        ],
    );

    let mut command = Command::new(env!("CARGO_BIN_EXE_fleetctl"));
    let out = command
        .current_dir(&work)
        .env("PATH", &bin)
        .args([
            "--output",
            "json",
            "registry",
            "publish",
            "-m",
            "Add it",
            "--change-mode",
            "pull-request",
        ])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "{stdout}{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let result: Value = serde_json::from_str(&stdout).unwrap();
    assert!(result["pullRequest"].is_null());
    let url = result["compareUrl"].as_str().unwrap();
    assert!(
        url.starts_with("https://github.com/o/r/compare/main...registry/add-it-"),
        "{url}"
    );
    assert!(!stdout.contains("tok3n"), "{stdout}");
}

#[test]
fn read_commands_target_the_registry_api() {
    let args = |words: &[&str]| words.iter().map(ToString::to_string).collect::<Vec<_>>();
    let parsed = fleetctl::parse(&args(&[
        "registry", "find", "aptabase", "--type", "service", "--limit", "5",
    ]))
    .unwrap();
    let fleetctl::Command::Registry(action) = parsed.command else {
        panic!()
    };
    assert!(!action.is_local());
    let parsed = fleetctl::parse(&args(&["registry", "get", "domain/example.com"])).unwrap();
    assert!(matches!(parsed.command, fleetctl::Command::Registry(_)));
    assert!(fleetctl::parse(&args(&["registry", "get", "domain"])).is_err());
    assert!(fleetctl::parse(&args(&["registry", "bogus"])).is_err());
    assert!(fleetctl::parse(&args(&["registry", "set", "domain/x", "--bogus", "1"])).is_err());
    assert!(fleetctl::parse(&args(&["registry", "publish"])).is_err());
}

fn entry_yaml(id_tail: &str, name: &str, fqdn: &str, extra: &str) -> String {
    format!(
        "apiVersion: fleet.frogbyte.io/v1alpha1\nkind: RegistryEntry\nmetadata:\n  id: 01890f3e-9b4a-7cc2-98c3-d24e8f58d{id_tail}\n  name: {name}\nspec:\n  type: domain\n  fields:\n    fqdn: {fqdn}\n{extra}"
    )
}

fn write(work: &Path, rel: &str, text: &str) {
    let path = work.join(rel);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, text).unwrap();
}

#[cfg(unix)]
fn install_hook(remote: &Path, script: &str) {
    use std::os::unix::fs::PermissionsExt as _;
    let hook = remote.join("hooks/pre-receive");
    fs::write(&hook, script).unwrap();
    fs::set_permissions(&hook, fs::Permissions::from_mode(0o755)).unwrap();
}

#[cfg(unix)]
#[test]
fn a_rejected_push_keeps_the_commit_says_so_and_a_rerun_pushes_it() {
    let (_temp, work, remote) = repo();
    install_hook(
        &remote,
        "#!/bin/sh\necho 'policy: pushes are closed' >&2\nexit 1\n",
    );
    run(
        &work,
        None,
        None,
        &[
            "registry",
            "set",
            "domain/example.com",
            "--field",
            "registrar=Webhuset",
        ],
    );
    let direct = [
        "registry",
        "publish",
        "-m",
        "example.com",
        "--change-mode",
        "direct",
    ];
    let failed = run(&work, None, None, &direct);
    assert_ne!(failed.code, 0);
    assert!(
        failed.stderr.contains("policy: pushes are closed"),
        "{}",
        failed.stderr
    );
    assert!(
        failed.stderr.contains("committed locally as "),
        "{}",
        failed.stderr
    );
    assert!(
        failed
            .stderr
            .contains("nothing was pushed; fix and run `git push`"),
        "{}",
        failed.stderr
    );
    let local = git(&work, &["rev-parse", "HEAD"]);
    assert_ne!(git(&remote, &["rev-parse", "main"]), local);

    // With the remote fixed, publishing again pushes the waiting commit.
    fs::remove_file(remote.join("hooks/pre-receive")).unwrap();
    let again = run(
        &work,
        None,
        None,
        &[
            "--output",
            "json",
            "registry",
            "publish",
            "-m",
            "again",
            "--change-mode",
            "direct",
        ],
    );
    assert_eq!(again.code, 0, "{}{}", again.stdout, again.stderr);
    let result: Value = serde_json::from_str(&again.stdout).unwrap();
    assert_eq!(result["committed"], false);
    assert_eq!(result["pushedExisting"], 1);
    assert_eq!(git(&remote, &["rev-parse", "main"]), local);
}

#[test]
fn direct_mode_refuses_to_push_local_non_registry_commits() {
    let (_temp, work, remote) = repo();
    fs::write(work.join("code.txt"), "not registry\n").unwrap();
    git(&work, &["add", "code.txt"]);
    git(&work, &["commit", "-m", "unrelated"]);
    run(
        &work,
        None,
        None,
        &[
            "registry",
            "set",
            "domain/example.com",
            "--field",
            "registrar=Webhuset",
        ],
    );
    let out = run(
        &work,
        None,
        None,
        &["registry", "publish", "-m", "x", "--change-mode", "direct"],
    );
    assert_ne!(out.code, 0);
    assert!(
        out.stderr.contains("1 commit(s) ahead of origin/main"),
        "{}",
        out.stderr
    );
    assert!(out.stderr.contains("code.txt"), "{}", out.stderr);
    // Nothing was committed or pushed by the refused publish.
    assert!(!git(&work, &["log", "--oneline"]).contains("x\n"));
    assert_ne!(
        git(&remote, &["rev-parse", "main"]),
        git(&work, &["rev-parse", "HEAD"])
    );
}

#[test]
fn a_credential_already_in_the_file_is_never_left_in_place() {
    let (_temp, work, _) = repo();
    let secret = "api_key=0123456789abcdef0123456789abcdef";
    let text = entry_yaml(
        "001",
        "domain-example-com",
        "example.com",
        &format!("  notes: \"{secret}\"\n"),
    );
    write(&work, "fleet/registry/domain/example.com.yaml", &text);
    let out = run(
        &work,
        None,
        None,
        &[
            "registry",
            "set",
            "domain/example.com",
            "--field",
            "registrar=Webhuset",
        ],
    );
    assert_ne!(out.code, 0);
    assert!(
        out.stderr.contains("FM_SCHEMA_SEMANTIC_CREDENTIAL_VALUE"),
        "{}",
        out.stderr
    );
    assert!(!out.stderr.contains("0123456789abcdef"));
    assert_eq!(fs::read_to_string(entry_path(&work)).unwrap(), text);
    // Removing it is allowed.
    let fixed = run(
        &work,
        None,
        None,
        &["registry", "unset", "domain/example.com", "--notes"],
    );
    assert_eq!(fixed.code, 0, "{}{}", fixed.stdout, fixed.stderr);
}

#[test]
fn publish_refuses_files_under_the_registry_dir_that_are_not_registry_yaml() {
    let (_temp, work, _) = repo();
    run(
        &work,
        None,
        None,
        &[
            "registry",
            "set",
            "domain/example.com",
            "--field",
            "registrar=Webhuset",
        ],
    );
    write(&work, "fleet/registry/domain/.env", "TOKEN=x\n");
    write(&work, "fleet/registry/notes.txt", "hello\n");
    let out = run(
        &work,
        None,
        None,
        &["registry", "publish", "-m", "x", "--change-mode", "direct"],
    );
    assert_ne!(out.code, 0);
    assert!(
        out.stderr.contains(".env") && out.stderr.contains("notes.txt"),
        "{}",
        out.stderr
    );
    assert!(out.stderr.contains("not Registry YAML"), "{}", out.stderr);
    assert!(!git(&work, &["log", "--oneline"]).contains("x\n"));
}

#[test]
fn publish_validates_branch_and_base_names() {
    let (_temp, work, _) = repo();
    run(
        &work,
        None,
        None,
        &[
            "registry",
            "set",
            "domain/example.com",
            "--field",
            "registrar=Webhuset",
        ],
    );
    let same = run(
        &work,
        None,
        None,
        &[
            "registry",
            "publish",
            "-m",
            "x",
            "--change-mode",
            "pull-request",
            "--branch",
            "main",
        ],
    );
    assert!(same.stderr.contains("must differ"), "{}", same.stderr);
    let bad = run(
        &work,
        None,
        None,
        &[
            "registry",
            "publish",
            "-m",
            "x",
            "--change-mode",
            "pull-request",
            "--base",
            "bad..name",
        ],
    );
    assert!(
        bad.stderr.contains("--base is not a valid branch name"),
        "{}",
        bad.stderr
    );
}

#[test]
fn a_multi_document_file_is_refused_for_editing() {
    let (_temp, work, _) = repo();
    let one = entry_yaml("001", "domain-example-com", "example.com", "");
    let two = entry_yaml("002", "domain-other-com", "other.com", "");
    write(
        &work,
        "fleet/registry/domain/both.yaml",
        &format!("{one}---\n{two}"),
    );
    let out = run(
        &work,
        None,
        None,
        &[
            "registry",
            "set",
            "domain/other.com",
            "--field",
            "registrar=X",
        ],
    );
    assert_ne!(out.code, 0);
    assert!(out.stderr.contains("several documents"), "{}", out.stderr);
}

#[test]
fn an_unparsable_yaml_file_stops_an_edit() {
    let (_temp, work, _) = repo();
    write(&work, "fleet/registry/domain/broken.yaml", "a: [unclosed\n");
    let out = run(
        &work,
        None,
        None,
        &["registry", "set", "domain/example.com"],
    );
    assert_ne!(out.code, 0);
    assert!(
        out.stderr.contains("broken.yaml cannot be read"),
        "{}",
        out.stderr
    );
}

#[test]
fn a_flow_style_file_falls_back_to_the_canonical_layout_and_warns() {
    let (_temp, work, _) = repo();
    let text = "# keep me\napiVersion: fleet.frogbyte.io/v1alpha1\nkind: RegistryEntry\nmetadata: { id: 01890f3e-9b4a-7cc2-98c3-d24e8f58d001, name: domain-example-com }\nspec:\n  type: domain\n  fields: {\n    fqdn: example.com,\n    registrar: Webhuset\n  }\n";
    write(&work, "fleet/registry/domain/example.com.yaml", text);
    let out = run(
        &work,
        None,
        None,
        &[
            "--output",
            "json",
            "registry",
            "set",
            "domain/example.com",
            "--field",
            "dnsHost=Cloudflare",
        ],
    );
    assert_eq!(out.code, 0, "{}{}", out.stdout, out.stderr);
    let result: Value = serde_json::from_str(&out.stdout).unwrap();
    assert_eq!(result["formatting"], "canonical", "{result}");
    assert!(
        result["warnings"][0]
            .as_str()
            .unwrap()
            .contains("canonical layout"),
        "{result}"
    );
    let after = fs::read_to_string(entry_path(&work)).unwrap();
    assert!(
        after.contains("dnsHost: Cloudflare") && after.contains("registrar: Webhuset"),
        "{after}"
    );
    assert!(!after.contains("keep me"));
    assert_eq!(run(&work, None, None, &["registry", "validate"]).code, 0);
}

#[test]
fn relations_dedupe_case_insensitively_and_reserved_stems_are_suffixed() {
    let (_temp, work, _) = repo();
    run(
        &work,
        None,
        None,
        &["registry", "set", "domain/example.com"],
    );
    run(
        &work,
        None,
        None,
        &["registry", "set", "service/aptabase", "--field", "name=A"],
    );
    run(
        &work,
        None,
        None,
        &[
            "registry",
            "relate",
            "domain/example.com",
            "used-by",
            "service/aptabase",
        ],
    );
    let again = run(
        &work,
        None,
        None,
        &[
            "registry",
            "relate",
            "domain/example.com",
            "used-by",
            "service/Aptabase",
        ],
    );
    assert!(again.stdout.contains("up to date"), "{}", again.stdout);
    let con = run(
        &work,
        None,
        None,
        &["--output", "json", "registry", "set", "domain/con"],
    );
    assert_eq!(con.code, 0, "{}{}", con.stdout, con.stderr);
    assert!(work.join("fleet/registry/domain/con_.yaml").exists());
    // The same key in another case finds the same entry, not a new file.
    let upper = run(
        &work,
        None,
        None,
        &["registry", "set", "domain/Example.com"],
    );
    assert!(upper.stdout.contains("up to date"), "{}", upper.stdout);
}

#[cfg(unix)]
#[test]
fn validate_reads_the_git_file_set_and_refuses_symlinks() {
    let (_temp, work, _) = repo();
    // An ignored invalid file is outside the set; an untracked one is in.
    fs::write(work.join(".gitignore"), "ignored.yaml\n").unwrap();
    fs::write(work.join("ignored.yaml"), "kind: nope\n").unwrap();
    assert_eq!(run(&work, None, None, &["registry", "validate"]).code, 0);
    fs::write(work.join("untracked.yaml"), "kind: nope\n").unwrap();
    assert_eq!(run(&work, None, None, &["registry", "validate"]).code, 1);
    fs::remove_file(work.join("untracked.yaml")).unwrap();
    std::os::unix::fs::symlink("README.md", work.join("link.yaml")).unwrap();
    let out = run(&work, None, None, &["registry", "validate"]);
    assert_ne!(out.code, 0);
    assert!(out.stderr.contains("symlink"), "{}", out.stderr);
}

#[cfg(unix)]
#[test]
fn a_failing_gh_reports_the_pushed_branch() {
    let (temp, work, remote) = repo();
    let bin = temp.path().join("bin");
    fs::create_dir_all(&bin).unwrap();
    stub_gh(&bin, "#!/bin/sh\necho 'gh: no auth' >&2\nexit 1\n");
    run(
        &work,
        None,
        None,
        &[
            "registry",
            "set",
            "domain/example.com",
            "--field",
            "registrar=Webhuset",
        ],
    );
    let out = run(
        &work,
        Some(&bin),
        None,
        &[
            "registry",
            "publish",
            "-m",
            "Add it",
            "--change-mode",
            "pull-request",
        ],
    );
    assert_ne!(out.code, 0);
    assert!(
        out.stderr
            .contains("was pushed, but the pull request was not opened"),
        "{}",
        out.stderr
    );
    assert!(out.stderr.contains("gh: no auth"), "{}", out.stderr);
    let branches = git(&remote, &["branch", "--list", "registry/*"]);
    assert!(branches.contains("registry/add-it-"), "{branches}");
}
